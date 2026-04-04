// firmware/src/policy.rs
//
// Client approval policy engine. Policies are pushed from the bridge
// and persisted to NVS. TOFU auto-approval adds policies on first use.

use std::time::Instant;

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use heartwood_common::nip46::Nip46Method;
use heartwood_common::policy::{ApprovalTier, ClientPolicy};

/// Maximum concurrent client sessions.
pub const MAX_SESSIONS: usize = 32;

/// Rate limit: requests per window.
const RATE_LIMIT_MAX: u32 = 60;

/// Rate limit window in seconds.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Per-master policy store.
pub struct MasterPolicies {
    pub master_slot: u8,
    pub policies: Vec<ClientPolicy>,
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
    /// Per-master policies (pushed from bridge).
    pub master_policies: Vec<MasterPolicies>,
    /// Active client sessions.
    pub sessions: Vec<ClientSession>,
    /// Whether a bridge session is authenticated.
    pub bridge_authenticated: bool,
    /// Dirty flag: policies changed since last NVS write.
    pub policies_dirty: bool,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            master_policies: Vec::new(),
            sessions: Vec::new(),
            bridge_authenticated: false,
            policies_dirty: false,
        }
    }

    /// Set policies for a master, replacing any existing ones.
    pub fn set_policies(&mut self, master_slot: u8, policies: Vec<ClientPolicy>) {
        self.master_policies.retain(|mp| mp.master_slot != master_slot);
        self.master_policies.push(MasterPolicies {
            master_slot,
            policies,
        });
        self.policies_dirty = true;
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

        // Look up client policy for this master.
        // Policies are consulted regardless of bridge authentication mode —
        // TOFU policies created after physical button approval are valid in
        // both legacy and passthrough modes.
        let policies = self
            .master_policies
            .iter()
            .find(|mp| mp.master_slot == master_slot);

        let policies = match policies {
            Some(mp) => &mp.policies,
            None => return ApprovalTier::ButtonRequired,
        };

        let policy = policies
            .iter()
            .find(|p| p.client_pubkey == client_pubkey);

        let policy = match policy {
            Some(p) => p,
            None => return ApprovalTier::ButtonRequired,
        };

        if !policy.auto_approve {
            return ApprovalTier::ButtonRequired;
        }

        // Check method is in allowed list.
        let method_str = method.as_str();
        if !policy.allowed_methods.is_empty()
            && !policy.allowed_methods.iter().any(|m| m == method_str)
        {
            return ApprovalTier::ButtonRequired;
        }

        // For sign_event, check kind is in allowed list.
        if matches!(method, Nip46Method::SignEvent) {
            if let Some(kind) = event_kind {
                if !policy.allowed_kinds.is_empty()
                    && !policy.allowed_kinds.contains(&kind)
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
            log::warn!("Max sessions reached — rejecting new client");
            return None;
        }

        self.sessions.push(ClientSession::new(client_pubkey, master_slot));
        self.sessions.last_mut()
    }

    /// Clear all state (bridge disconnected).
    pub fn clear(&mut self) {
        self.master_policies.clear();
        self.sessions.clear();
        self.bridge_authenticated = false;
    }

    /// Add a TOFU-generated policy for a client.
    pub fn add_tofu_policy(&mut self, master_slot: u8, policy: ClientPolicy) {
        match self.master_policies.iter_mut().find(|mp| mp.master_slot == master_slot) {
            Some(mp) => mp.policies.push(policy),
            None => {
                self.master_policies.push(MasterPolicies {
                    master_slot,
                    policies: vec![policy],
                });
            }
        }
        self.policies_dirty = true;
    }

    /// Persist all policies for a master slot to NVS if changed since last write.
    pub fn persist_policies(&mut self, nvs: &mut EspNvs<NvsDefault>, master_slot: u8) {
        if !self.policies_dirty {
            return;
        }
        let policies = self.master_policies.iter().find(|mp| mp.master_slot == master_slot);
        let key = format!("policy_{master_slot}");
        match policies {
            Some(mp) => {
                match serde_json::to_string(&mp.policies) {
                    Ok(json) => {
                        if let Err(e) = nvs.set_blob(&key, json.as_bytes()) {
                            log::error!("Failed to persist policies for slot {master_slot}: {e:?}");
                        }
                    }
                    Err(e) => log::error!("Failed to serialise policies: {e}"),
                }
            }
            None => { let _ = nvs.remove(&key); }
        }
        self.policies_dirty = false;
    }

    /// Load persisted policies from NVS for all master slots.
    pub fn load_from_nvs(nvs: &EspNvs<NvsDefault>, master_count: u8) -> Self {
        let mut engine = Self::new();
        for slot in 0..master_count {
            let key = format!("policy_{slot}");
            let mut buf = [0u8; 4096];
            if let Ok(Some(data)) = nvs.get_blob(&key, &mut buf) {
                if let Ok(policies) = serde_json::from_slice::<Vec<ClientPolicy>>(data) {
                    let count = policies.len();
                    engine.master_policies.push(MasterPolicies { master_slot: slot, policies });
                    log::info!("Loaded {count} persisted policies for slot {slot}");
                }
            }
        }
        engine
    }
}
