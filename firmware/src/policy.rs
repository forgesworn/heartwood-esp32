// firmware/src/policy.rs
//
// Client approval policy engine. Connection slots are persisted to NVS.
// The slot -- not the ephemeral client pubkey -- is the stable identity.

use std::time::Instant;

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use heartwood_common::nip46::Nip46Method;
use heartwood_common::policy::{
    authorize_pubkey_on_unique_slot, evaluate_slot_policy, find_slot_by_pubkey,
    find_slot_by_secret, grant_slot_signing, next_slot_index, remove_ambiguous_pubkeys,
    strict_slot_denies_method, validate_exact_slot_policy, ApprovalTier, ConnectSlot,
    ExactSlotPolicy, CONNECT_SAFE_METHODS,
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

/// In-memory rollback point around a request that may change slot authority.
/// Callers persist after dispatch; if that write fails, restoring this snapshot
/// prevents a success response from leaving volatile authority active in RAM.
#[derive(Clone)]
pub struct SlotStateSnapshot {
    master_slot: u8,
    slots: Option<Vec<ConnectSlot>>,
    slots_dirty: bool,
}

/// Per-client session state (rate limiting + active identity).
pub struct ClientSession {
    pub client_pubkey: [u8; 32],
    pub master_slot: u8,
    pub active_identity: Option<usize>,
    pub request_count: u32,
    pub window_start: Instant,
    /// Monotonic recency stamp from `PolicyEngine::session_seq` — drives
    /// least-recently-used eviction when the table is full.
    pub last_seen: u64,
}

impl ClientSession {
    pub fn new(client_pubkey: [u8; 32], master_slot: u8) -> Self {
        Self {
            client_pubkey,
            master_slot,
            active_identity: None,
            request_count: 0,
            window_start: Instant::now(),
            last_seen: 0,
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
    /// Monotonic counter stamped onto sessions on every access — recency
    /// order for LRU eviction without depending on clock resolution.
    session_seq: u64,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            master_slots: Vec::new(),
            sessions: Vec::new(),
            bridge_authenticated: false,
            slots_dirty: false,
            session_seq: 0,
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
        // Protocol plumbing remains global even for an exact v2 slot.
        if matches!(
            method,
            Nip46Method::Connect
                | Nip46Method::Ping
                | Nip46Method::GetPublicKey
                | Nip46Method::SwitchRelays
        ) {
            return ApprovalTier::AutoApprove;
        }

        // Look up slot for this client pubkey.
        // Slots are consulted regardless of bridge authentication mode --
        // slots created after physical button approval are valid in
        // both legacy and passthrough modes.
        let slots = self
            .master_slots
            .iter()
            .find(|ms| ms.master_slot == master_slot);

        let slot = slots.and_then(|ms| find_slot_by_pubkey(&ms.slots, client_pubkey));

        // Exact v2 policy is a hard method ceiling, including Heartwood
        // extensions that legacy clients may button-approve or auto-run. Check
        // it before those legacy invariants so an omitted extension is denied,
        // not merely downgraded to a physical prompt.
        if let Some(slot) = slot {
            if strict_slot_denies_method(slot, method.as_str()) {
                return ApprovalTier::Denied;
            }
        }

        // Legacy Heartwood extension invariants remain unchanged.
        if method.always_requires_button() {
            return ApprovalTier::ButtonRequired;
        }
        if method.is_oled_notify() {
            return ApprovalTier::OledNotify;
        }
        if method.always_auto_approve() {
            return ApprovalTier::AutoApprove;
        }

        let slot = match slot {
            Some(s) => s,
            None => return ApprovalTier::ButtonRequired,
        };

        evaluate_slot_policy(slot, method.as_str(), event_kind)
    }

    /// Find or create a client session. Returns mutable reference.
    pub fn get_or_create_session(
        &mut self,
        client_pubkey: [u8; 32],
        master_slot: u8,
    ) -> Option<&mut ClientSession> {
        self.session_seq += 1;
        let seq = self.session_seq;

        let existing = self
            .sessions
            .iter()
            .position(|s| s.client_pubkey == client_pubkey && s.master_slot == master_slot);

        if let Some(idx) = existing {
            let session = &mut self.sessions[idx];
            session.last_seen = seq;
            return Some(session);
        }

        if self.sessions.len() >= MAX_SESSIONS {
            // Evict the least-recently-used session instead of rejecting the
            // new client. Sessions are per-boot request state (rate window,
            // active identity) that rebuilds transparently on the evicted
            // client's next request; rejecting here left a full table
            // silently ignoring every new client until reboot.
            if let Some(idx) = self
                .sessions
                .iter()
                .enumerate()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(idx, _)| idx)
            {
                let evicted = self.sessions.swap_remove(idx);
                log::info!(
                    "Session table full -- evicted least-recent client {}…",
                    &heartwood_common::hex::hex_encode(&evicted.client_pubkey)[..8]
                );
            }
        }

        let mut session = ClientSession::new(client_pubkey, master_slot);
        session.last_seen = seq;
        self.sessions.push(session);
        self.sessions.last_mut()
    }

    /// Clear all state (bridge disconnected).
    pub fn clear(&mut self) {
        self.master_slots.clear();
        self.sessions.clear();
        self.bridge_authenticated = false;
        self.session_seq = 0;
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
        if !self
            .master_slots
            .iter()
            .any(|ms| ms.master_slot == master_slot)
        {
            self.master_slots.push(MasterSlots {
                master_slot,
                slots: Vec::new(),
            });
        }
        // Safe: we just ensured the entry exists.
        self.master_slots
            .iter_mut()
            .find(|ms| ms.master_slot == master_slot)
            .map(|ms| &mut ms.slots)
            .unwrap()
    }

    /// Capture the complete slot state for one master before request dispatch.
    pub fn snapshot_slot_state(&self, master_slot: u8) -> SlotStateSnapshot {
        SlotStateSnapshot {
            master_slot,
            slots: self
                .master_slots
                .iter()
                .find(|entry| entry.master_slot == master_slot)
                .map(|entry| entry.slots.clone()),
            slots_dirty: self.slots_dirty,
        }
    }

    /// Restore a request's slot state after its durable write failed.
    pub fn restore_slot_state(&mut self, snapshot: SlotStateSnapshot) {
        match snapshot.slots {
            Some(slots) => match self
                .master_slots
                .iter_mut()
                .find(|entry| entry.master_slot == snapshot.master_slot)
            {
                Some(entry) => entry.slots = slots,
                None => self.master_slots.push(MasterSlots {
                    master_slot: snapshot.master_slot,
                    slots,
                }),
            },
            None => self
                .master_slots
                .retain(|entry| entry.master_slot != snapshot.master_slot),
        }
        self.slots_dirty = snapshot.slots_dirty;
    }

    /// Restore the prior in-memory authority and make that compensation
    /// durable. A failed write/read-back is ambiguous: the new blob may have
    /// landed even though it could not be verified, so RAM-only rollback is
    /// insufficient. RAM is restored first (fail closed for this boot), then
    /// the old snapshot is written and read back through the same authority
    /// boundary. A failed compensation leaves `slots_dirty` set for recovery.
    pub fn restore_slot_state_durably(
        &mut self,
        nvs: &mut EspNvs<NvsDefault>,
        snapshot: SlotStateSnapshot,
    ) -> bool {
        let master_slot = snapshot.master_slot;
        let prior_dirty = snapshot.slots_dirty;
        self.restore_slot_state(snapshot);
        self.slots_dirty = true;
        let restored = self.persist_slots(nvs, master_slot);
        self.slots_dirty = if restored { prior_dirty } else { true };
        restored
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
            strict_permissions: false,
            authorized_pubkeys: vec![],
        };
        self.slots_mut(master_slot).push(new_slot);
        self.slots_dirty = true;
        Some(slot_index)
    }

    /// Create a slot with an exact policy supplied by the authenticated remote
    /// operator. Validation happens before mutation, and signing authority is
    /// derived from the explicit `sign_event` method instead of a second flag.
    pub fn create_slot_with_exact_policy(
        &mut self,
        master_slot: u8,
        label: String,
        secret: String,
        policy: ExactSlotPolicy,
    ) -> Option<u8> {
        let slot_index = {
            let slots = self.list_slots(master_slot);
            next_slot_index(slots)?
        };
        self.slots_mut(master_slot).push(ConnectSlot {
            slot_index,
            label,
            secret,
            current_pubkey: None,
            allowed_methods: policy.allowed_methods,
            allowed_kinds: policy.allowed_kinds,
            auto_approve: policy.auto_approve,
            signing_approved: policy.signing_approved,
            strict_permissions: true,
            authorized_pubkeys: vec![],
        });
        self.slots_dirty = true;
        Some(slot_index)
    }

    /// Replace a slot's automatic authority as one validated unit. This is used
    /// only by the authenticated v2 management protocol; legacy USB/button
    /// flows retain their existing physical-approval rules.
    pub fn set_exact_slot_policy(
        &mut self,
        master_slot: u8,
        slot_index: u8,
        allowed_methods: Vec<String>,
        allowed_kinds: Vec<u64>,
        auto_approve: bool,
    ) -> Result<(), String> {
        let policy = validate_exact_slot_policy(allowed_methods, allowed_kinds, auto_approve)
            .map_err(str::to_string)?;
        let slot = self
            .slots_mut(master_slot)
            .iter_mut()
            .find(|slot| slot.slot_index == slot_index)
            .ok_or_else(|| "slot not found".to_string())?;
        slot.allowed_methods = policy.allowed_methods;
        slot.allowed_kinds = policy.allowed_kinds;
        slot.auto_approve = policy.auto_approve;
        slot.signing_approved = policy.signing_approved;
        slot.strict_permissions = true;
        self.slots_dirty = true;
        Ok(())
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
                    let filtered: Vec<String> =
                        methods.into_iter().filter(|m| m != "sign_event").collect();
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

    /// Authorise a client pubkey on a slot (called on connect with valid secret).
    /// Adds it to the slot's authorised set and makes it the current binding,
    /// preserving any previously-bound client on that same shared-secret slot.
    /// The pubkey is removed from every other slot for this master first, so one
    /// client can never inherit an older slot's policy by vector ordering.
    /// Returns true if the target slot was found.
    pub fn assign_pubkey_to_slot(
        &mut self,
        master_slot: u8,
        slot_index: u8,
        pubkey: String,
    ) -> bool {
        let assigned = authorize_pubkey_on_unique_slot(
            self.slots_mut(master_slot),
            slot_index,
            &pubkey,
        );
        if assigned {
            self.slots_dirty = true;
        }
        assigned
    }

    /// Upgrade a slot to signing tier after first physical button approval.
    /// Adds only sign_event, preserving any method/kind ceiling the operator
    /// configured before the first signature. A default connect slot already
    /// contains every CONNECT_SAFE_METHOD, so its historical result is still
    /// the complete TOFU set.
    /// Returns true if the slot was found.
    pub fn upgrade_to_signing(&mut self, master_slot: u8, slot_index: u8) -> bool {
        let slots = self.slots_mut(master_slot);
        if let Some(slot) = slots.iter_mut().find(|s| s.slot_index == slot_index) {
            // Exact v2 authority is installed only as one validated unit. A
            // later legacy "approve" must never insert sign_event (with empty
            // kinds meaning all kinds) into a crypto-only strict slot.
            if slot.strict_permissions {
                return false;
            }
            grant_slot_signing(slot);
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
    /// Transaction recovery relies on ESP-IDF NVS's single-key atomicity: a
    /// `connslots_N` blob is assumed to be wholly old or wholly new, never a
    /// torn mixture. Exact immediate read-back proves which desired value is
    /// present; callers compensate with their prior snapshot when it does not.
    pub fn persist_slots(&mut self, nvs: &mut EspNvs<NvsDefault>, master_slot: u8) -> bool {
        if !self.slots_dirty {
            return true;
        }
        let key = format!("connslots_{master_slot}");
        let ms = self
            .master_slots
            .iter()
            .find(|ms| ms.master_slot == master_slot);
        let persisted = match ms {
            Some(ms) => match serde_json::to_string(&ms.slots) {
                Ok(json) => {
                    if let Err(e) = nvs.set_blob(&key, json.as_bytes()) {
                        log::error!("Failed to persist slots for slot {master_slot}: {e:?}");
                    }
                    // A success return from set_blob is not the authority
                    // boundary. Read the exact bytes back before a caller may
                    // ACK a new client or signing grant.
                    match nvs.blob_len(&key) {
                        Ok(Some(len)) if len == json.len() => {
                            let mut verify = vec![0u8; len];
                            matches!(
                                nvs.get_blob(&key, &mut verify),
                                Ok(Some(stored)) if stored == json.as_bytes()
                            )
                        }
                        Ok(Some(len)) => {
                            log::error!(
                                "Slot persistence read-back length mismatch for slot {master_slot}: {len} != {}",
                                json.len()
                            );
                            false
                        }
                        Ok(None) => {
                            log::error!(
                                "Slot persistence read-back missing for slot {master_slot}"
                            );
                            false
                        }
                        Err(e) => {
                            log::error!(
                                "Slot persistence read-back failed for slot {master_slot}: {e:?}"
                            );
                            false
                        }
                    }
                }
                Err(e) => {
                    log::error!("Failed to serialise slots: {e}");
                    false
                }
            },
            None => {
                if let Err(e) = nvs.remove(&key) {
                    log::error!("Failed to remove persisted slots for slot {master_slot}: {e:?}");
                }
                match nvs.blob_len(&key) {
                    Ok(None) => true,
                    Ok(Some(_)) => {
                        log::error!(
                            "Persisted slots still present after remove for slot {master_slot}"
                        );
                        false
                    }
                    Err(e) => {
                        log::error!(
                            "Could not verify persisted slot removal for slot {master_slot}: {e:?}"
                        );
                        false
                    }
                }
            }
        };
        if persisted {
            self.slots_dirty = false;
        }
        persisted
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
        let mut persist_migrations: Vec<u8> = Vec::new();

        for slot in 0..master_count {
            let new_key = format!("connslots_{slot}");
            let mut buf = [0u8; 8192];

            // --- Try new format first ---
            if let Ok(Some(data)) = nvs.get_blob(&new_key, &mut buf) {
                if let Ok(mut slots) = serde_json::from_slice::<Vec<ConnectSlot>>(data) {
                    if remove_ambiguous_pubkeys(&mut slots) {
                        log::warn!(
                            "Removed client pubkey shared by multiple slots for master slot {slot}; re-pair required"
                        );
                        persist_migrations.push(slot);
                    }
                    let count = slots.len();
                    engine.master_slots.push(MasterSlots {
                        master_slot: slot,
                        slots,
                    });
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
                    strict_permissions: false,
                    authorized_pubkeys: vec![],
                };

                log::info!("Migrated legacy policy for master slot {slot} to connslots format");

                // Remove old policy key; master_{slot}_conn is cleaned up in Task 5.
                let _ = nvs.remove(&old_policy_key);

                engine.master_slots.push(MasterSlots {
                    master_slot: slot,
                    slots: vec![migrated_slot],
                });
                persist_migrations.push(slot);
            }
        }

        // Make each repaired master durable before normal request handling. If
        // NVS is unavailable, RAM remains fail-closed for this boot and the
        // dirty flag asks a later request to retry persistence.
        let mut persist_failed = false;
        for master_slot in persist_migrations {
            engine.slots_dirty = true;
            if !engine.persist_slots(nvs, master_slot) {
                persist_failed = true;
            }
        }
        engine.slots_dirty = persist_failed;
        engine
    }
}

#[cfg(test)]
mod tests {
    use super::PolicyEngine;
    use heartwood_common::policy::validate_exact_slot_policy;

    #[test]
    fn slot_snapshot_restores_authority_and_prior_dirty_state() {
        let mut engine = PolicyEngine::new();
        let first = engine
            .create_slot(0, "first".into(), "11".repeat(32))
            .unwrap();
        let second = engine
            .create_slot(0, "second".into(), "22".repeat(32))
            .unwrap();
        assert!(engine.assign_pubkey_to_slot(0, first, "aa".repeat(32)));
        engine.slots_dirty = false;

        let snapshot = engine.snapshot_slot_state(0);
        assert!(engine.assign_pubkey_to_slot(0, second, "aa".repeat(32)));
        assert_eq!(
            engine.find_slot_by_pubkey(0, &"aa".repeat(32)).map(|slot| slot.slot_index),
            Some(second),
        );

        engine.restore_slot_state(snapshot);
        assert_eq!(
            engine.find_slot_by_pubkey(0, &"aa".repeat(32)).map(|slot| slot.slot_index),
            Some(first),
        );
        assert!(!engine.slots_dirty);
    }

    #[test]
    fn slot_snapshot_removes_entry_created_by_failed_request() {
        let mut engine = PolicyEngine::new();
        let snapshot = engine.snapshot_slot_state(3);
        assert!(engine
            .create_slot(3, "volatile".into(), "33".repeat(32))
            .is_some());
        engine.restore_slot_state(snapshot);
        assert!(engine.list_slots(3).is_empty());
        assert!(!engine.slots_dirty);
    }

    #[test]
    fn session_table_evicts_least_recent_when_full() {
        let mut engine = PolicyEngine::new();
        for i in 0..super::MAX_SESSIONS {
            let mut pk = [0u8; 32];
            pk[0] = i as u8;
            assert!(engine.get_or_create_session(pk, 0).is_some());
        }

        // Touch the first client so it becomes the most recently used.
        let first = [0u8; 32];
        assert!(engine.get_or_create_session(first, 0).is_some());

        // A new client is admitted by evicting the least-recent (client 1),
        // never by rejection.
        let new_client = [0xFF; 32];
        assert!(engine.get_or_create_session(new_client, 0).is_some());
        assert_eq!(engine.sessions.len(), super::MAX_SESSIONS);
        assert!(engine.sessions.iter().any(|s| s.client_pubkey == new_client));
        assert!(engine.sessions.iter().any(|s| s.client_pubkey == first));
        let mut evicted = [0u8; 32];
        evicted[0] = 1;
        assert!(!engine.sessions.iter().any(|s| s.client_pubkey == evicted));
    }

    #[test]
    fn legacy_signing_upgrade_cannot_broaden_a_strict_crypto_slot() {
        let mut engine = PolicyEngine::new();
        let exact = validate_exact_slot_policy(vec!["nip44_encrypt".into()], vec![], true)
            .unwrap();
        let index = engine
            .create_slot_with_exact_policy(0, "crypto only".into(), "44".repeat(32), exact)
            .unwrap();
        engine.slots_dirty = false;

        assert!(!engine.upgrade_to_signing(0, index));
        let slot = &engine.list_slots(0)[0];
        assert!(slot.strict_permissions);
        assert!(!slot.signing_approved);
        assert!(!slot.allowed_methods.iter().any(|method| method == "sign_event"));
        assert!(!engine.slots_dirty);
    }
}
