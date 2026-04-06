// firmware/src/policy.rs
//
// Client approval policy engine. Connection slots are persisted to NVS.
// The slot -- not the ephemeral client pubkey -- is the stable identity.

use std::time::Instant;

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use heartwood_common::nip46::Nip46Method;
use heartwood_common::policy::{
    ApprovalTier, ConnectSlot, CONNECT_SAFE_METHODS, TOFU_SAFE_METHODS,
    find_slot_by_pubkey, find_slot_by_secret, next_slot_index,
};

/// Maximum concurrent client sessions.
pub const MAX_SESSIONS: usize = 32;

/// Rate limit: requests per window.
const RATE_LIMIT_MAX: u32 = 60;

/// Rate limit window in seconds.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Per-master connection slot store.
pub struct MasterSlots {
    pub master_slot: u8,
    pub slots: Vec<ConnectSlot>,
}

/// Per-client session state (rate limiting + active identity).
pub struct ClientSession {
    pub client_pubkey: [u8; 32],
    pub master_slot: u8,
    pub active_identity: Option<usize>,
    pub request_count: u32,
    pub window_start: Instant,
}

impl ClientSession {
    pub fn new(client_pubkey: [u8; 32], master_slot: u8) -> Self {
        Self {
            client_pubkey,
            master_slot,
            active_identity: None,
            request_count: 0,
            window_start: Instant::now(),
        }
    }

    /// Check and update rate limit. Returns true if within limit.
    pub fn check_rate_limit(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start).as_secs();

        if elapsed >= RATE_LIMIT_WINDOW_SECS {
            self.request_count = 1;
            self.window_start = now;
            return true;
        }

        self.request_count += 1;
        self.request_count <= RATE_LIMIT_MAX
    }
}

/// The full policy state for the device.
pub struct PolicyEngine {
    /// Per-master connection slot stores.
    pub master_slots: Vec<MasterSlots>,
    /// Active client sessions.
    pub sessions: Vec<ClientSession>,
    /// Whether a bridge session is authenticated.
    pub bridge_authenticated: bool,
    /// Dirty flag: slots changed since last NVS write.
    pub slots_dirty: bool,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            master_slots: Vec::new(),
            sessions: Vec::new(),
            bridge_authenticated: false,
            slots_dirty: false,
        }
    }

    /// Determine the approval tier for a request.
    pub fn check(
        &self,
        master_slot: u8,
        client_pubkey: &str,
        method: &Nip46Method,
        event_kind: Option<u64>,
    ) -> ApprovalTier {
        // Methods that always auto-approve (ping, connect, get_public_key).
        if method.always_auto_approve() {
            return ApprovalTier::AutoApprove;
        }

        // Methods that always require button (heartwood_derive).
        if method.always_requires_button() {
            return ApprovalTier::ButtonRequired;
        }

        // OLED-notify methods.
        if method.is_oled_notify() {
            return ApprovalTier::OledNotify;
        }

        // Look up slot for this client pubkey.
        // Slots are consulted regardless of bridge authentication mode --
        // slots created after physical button approval are valid in
        // both legacy and passthrough modes.
        let slots = self
            .master_slots
            .iter()
            .find(|ms| ms.master_slot == master_slot);

        let slots = match slots {
            Some(ms) => &ms.slots,
            None => return ApprovalTier::ButtonRequired,
        };

        let slot = find_slot_by_pubkey(slots, client_pubkey);

        let slot = match slot {
            Some(s) => s,
            None => return ApprovalTier::ButtonRequired,
        };

        if !slot.auto_approve {
            return ApprovalTier::ButtonRequired;
        }

        // Check method is in allowed list.
        let method_str = method.as_str();
        if !slot.allowed_methods.is_empty()
            && !slot.allowed_methods.iter().any(|m| m == method_str)
        {
            return ApprovalTier::ButtonRequired;
        }

        // For sign_event, check kind is in allowed list.
        if matches!(method, Nip46Method::SignEvent) {
            if let Some(kind) = event_kind {
                if !slot.allowed_kinds.is_empty()
                    && !slot.allowed_kinds.contains(&kind)
                {
                    return ApprovalTier::ButtonRequired;
                }
            }
        }

        ApprovalTier::AutoApprove
    }

    /// Find or create a client session. Returns mutable reference.
    pub fn get_or_create_session(
        &mut self,
        client_pubkey: [u8; 32],
        master_slot: u8,
    ) -> Option<&mut ClientSession> {
        let existing = self.sessions.iter().position(|s| {
            s.client_pubkey == client_pubkey && s.master_slot == master_slot
        });

        if let Some(idx) = existing {
            return Some(&mut self.sessions[idx]);
        }

        if self.sessions.len() >= MAX_SESSIONS {
            log::warn!("Max sessions reached -- rejecting new client");
            return None;
        }

        self.sessions.push(ClientSession::new(client_pubkey, master_slot));
        self.sessions.last_mut()
    }

    /// Clear all state (bridge disconnected).
    pub fn clear(&mut self) {
        self.master_slots.clear();
        self.sessions.clear();
        self.bridge_authenticated = false;
    }

    // -------------------------------------------------------------------------
    // Slot CRUD
    // -------------------------------------------------------------------------

    /// List all slots for a master slot.
    pub fn list_slots(&self, master_slot: u8) -> &[ConnectSlot] {
        self.master_slots
            .iter()
            .find(|ms| ms.master_slot == master_slot)
            .map(|ms| ms.slots.as_slice())
            .unwrap_or(&[])
    }

    /// Mutable access to the slot vec for a master slot, creating the entry if absent.
    pub(crate) fn slots_mut(&mut self, master_slot: u8) -> &mut Vec<ConnectSlot> {
        if !self.master_slots.iter().any(|ms| ms.master_slot == master_slot) {
            self.master_slots.push(MasterSlots { master_slot, slots: Vec::new() });
        }
        // Safe: we just ensured the entry exists.
        self.master_slots
            .iter_mut()
            .find(|ms| ms.master_slot == master_slot)
            .map(|ms| &mut ms.slots)
            .unwrap()
    }

    /// Create a new connection slot with the given label and secret.
    /// Returns the new slot index, or None if all 16 slots are occupied.
    /// New slots are granted CONNECT_SAFE_METHODS with auto_approve=true,
    /// signing_approved=false.
    pub fn create_slot(&mut self, master_slot: u8, label: String, secret: String) -> Option<u8> {
        let slot_index = {
            let slots = self.list_slots(master_slot);
            next_slot_index(slots)?
        };
        let new_slot = ConnectSlot {
            slot_index,
            label,
            secret,
            current_pubkey: None,
            allowed_methods: CONNECT_SAFE_METHODS.iter().map(|s| s.to_string()).collect(),
            allowed_kinds: vec![],
            auto_approve: true,
            signing_approved: false,
        };
        self.slots_mut(master_slot).push(new_slot);
        self.slots_dirty = true;
        Some(slot_index)
    }

    /// Update fields on an existing slot. Returns true if the slot was found.
    pub fn update_slot(
        &mut self,
        master_slot: u8,
        slot_index: u8,
        label: Option<String>,
        allowed_methods: Option<Vec<String>>,
        allowed_kinds: Option<Vec<u64>>,
        auto_approve: Option<bool>,
    ) -> bool {
        let slots = self.slots_mut(master_slot);
        if let Some(slot) = slots.iter_mut().find(|s| s.slot_index == slot_index) {
            if let Some(l) = label {
                slot.label = l;
            }
            if let Some(methods) = allowed_methods {
                // Security: the management API cannot grant sign_event.
                // Only the physical button can do that (via upgrade_to_signing).
                // Filter out sign_event if the slot hasn't been button-approved.
                if !slot.signing_approved {
                    let filtered: Vec<String> = methods.into_iter()
                        .filter(|m| m != "sign_event")
                        .collect();
                    slot.allowed_methods = filtered;
                } else {
                    slot.allowed_methods = methods;
                }
            }
            if let Some(kinds) = allowed_kinds {
                // Kind restrictions are stored regardless of signing_approved.
                // They take effect once the user physically approves the first
                // sign_event (which upgrades the slot and adds sign_event to
                // allowed_methods). Pre-configuring kinds before approval is
                // fine -- it just means the second sign onwards uses these rules.
                slot.allowed_kinds = kinds;
            }
            if let Some(approve) = auto_approve {
                slot.auto_approve = approve;
            }
            self.slots_dirty = true;
            true
        } else {
            false
        }
    }

    /// Remove a slot by index. Returns true if found and removed.
    pub fn revoke_slot(&mut self, master_slot: u8, slot_index: u8) -> bool {
        let slots = self.slots_mut(master_slot);
        let before = slots.len();
        slots.retain(|s| s.slot_index != slot_index);
        let removed = slots.len() < before;
        if removed {
            self.slots_dirty = true;
        }
        removed
    }

    /// Find a slot by the current client pubkey (immutable).
    pub fn find_slot_by_pubkey(&self, master_slot: u8, pubkey: &str) -> Option<&ConnectSlot> {
        find_slot_by_pubkey(self.list_slots(master_slot), pubkey)
    }

    /// Find a slot by its secret (constant-time comparison).
    pub fn find_slot_by_secret(&self, master_slot: u8, secret: &str) -> Option<&ConnectSlot> {
        find_slot_by_secret(self.list_slots(master_slot), secret)
    }

    /// Assign a client pubkey to a slot (called on connect with valid secret).
    /// Returns true if the slot was found.
    pub fn assign_pubkey_to_slot(
        &mut self,
        master_slot: u8,
        slot_index: u8,
        pubkey: String,
    ) -> bool {
        let slots = self.slots_mut(master_slot);
        if let Some(slot) = slots.iter_mut().find(|s| s.slot_index == slot_index) {
            slot.current_pubkey = Some(pubkey);
            self.slots_dirty = true;
            true
        } else {
            false
        }
    }

    /// Upgrade a slot to signing tier after first physical button approval.
    /// Sets signing_approved=true and expands allowed_methods to TOFU_SAFE_METHODS.
    /// Returns true if the slot was found.
    pub fn upgrade_to_signing(&mut self, master_slot: u8, slot_index: u8) -> bool {
        let slots = self.slots_mut(master_slot);
        if let Some(slot) = slots.iter_mut().find(|s| s.slot_index == slot_index) {
            slot.signing_approved = true;
            slot.allowed_methods = TOFU_SAFE_METHODS.iter().map(|s| s.to_string()).collect();
            self.slots_dirty = true;
            true
        } else {
            false
        }
    }

    // -------------------------------------------------------------------------
    // NVS persistence
    // -------------------------------------------------------------------------

    /// Persist all slots for a master slot to NVS if changed since last write.
    pub fn persist_slots(&mut self, nvs: &mut EspNvs<NvsDefault>, master_slot: u8) {
        if !self.slots_dirty {
            return;
        }
        let key = format!("connslots_{master_slot}");
        let ms = self.master_slots.iter().find(|ms| ms.master_slot == master_slot);
        match ms {
            Some(ms) => {
                match serde_json::to_string(&ms.slots) {
                    Ok(json) => {
                        if let Err(e) = nvs.set_blob(&key, json.as_bytes()) {
                            log::error!("Failed to persist slots for slot {master_slot}: {e:?}");
                        }
                    }
                    Err(e) => log::error!("Failed to serialise slots: {e}"),
                }
            }
            None => {
                let _ = nvs.remove(&key);
            }
        }
        self.slots_dirty = false;
    }

    /// Load persisted slots from NVS for all master slots.
    ///
    /// Migration: if the new `connslots_{slot}` key is absent but the old
    /// `policy_{slot}` key exists alongside `master_{slot}_conn`, a single
    /// default slot (index 0, label "default") is synthesised from the old
    /// secret. The old `policy_{slot}` key is deleted; `master_{slot}_conn`
    /// is left for Task 5 to clean up.
    pub fn load_from_nvs(nvs: &mut EspNvs<NvsDefault>, master_count: u8) -> Self {
        let mut engine = Self::new();
        let mut needs_persist = false;

        for slot in 0..master_count {
            let new_key = format!("connslots_{slot}");
            let mut buf = [0u8; 8192];

            // --- Try new format first ---
            if let Ok(Some(data)) = nvs.get_blob(&new_key, &mut buf) {
                if let Ok(slots) = serde_json::from_slice::<Vec<ConnectSlot>>(data) {
                    let count = slots.len();
                    engine.master_slots.push(MasterSlots { master_slot: slot, slots });
                    log::info!("Loaded {count} persisted slots for master slot {slot}");
                    continue;
                }
            }

            // --- Migration: check old format ---
            let old_policy_key = format!("policy_{slot}");
            let old_secret_key = format!("master_{slot}_conn");
            let mut secret_buf = [0u8; 128];

            let has_old_secret = nvs
                .get_blob(&old_secret_key, &mut secret_buf)
                .ok()
                .flatten()
                .is_some();

            if has_old_secret {
                // Retrieve the raw secret bytes and hex-encode them.
                let secret_bytes = nvs
                    .get_blob(&old_secret_key, &mut secret_buf)
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                let secret_hex = heartwood_common::hex::hex_encode(secret_bytes);

                let migrated_slot = ConnectSlot {
                    slot_index: 0,
                    label: "default".to_string(),
                    secret: secret_hex,
                    current_pubkey: None,
                    allowed_methods: CONNECT_SAFE_METHODS.iter().map(|s| s.to_string()).collect(),
                    allowed_kinds: vec![],
                    auto_approve: true,
                    signing_approved: false,
                };

                log::info!(
                    "Migrated legacy policy for master slot {slot} to connslots format"
                );

                // Remove old policy key; master_{slot}_conn is cleaned up in Task 5.
                let _ = nvs.remove(&old_policy_key);

                engine.master_slots.push(MasterSlots {
                    master_slot: slot,
                    slots: vec![migrated_slot],
                });
                needs_persist = true;
            }
        }

        if needs_persist {
            engine.slots_dirty = true;
        }
        engine
    }
}
