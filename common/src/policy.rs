// common/src/policy.rs
//
// Client approval policy types shared between firmware and bridge.

use serde::{Deserialize, Serialize};

/// A client's approval policy for a specific master.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPolicy {
    /// Hex-encoded client public key (64 chars).
    pub client_pubkey: String,
    /// Human-readable label (e.g. "Bark browser").
    #[serde(default)]
    pub label: String,
    /// Which NIP-46 methods are auto-approved.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// Which event kinds are auto-approved for sign_event.
    /// Empty = all kinds allowed.
    #[serde(default)]
    pub allowed_kinds: Vec<u64>,
    /// Whether to auto-approve matching requests (true) or just OLED-notify (false).
    #[serde(default)]
    pub auto_approve: bool,
}

/// Methods auto-approved on connect when the client provides a valid secret.
/// These are non-signing operations -- safe to grant without physical approval.
pub const CONNECT_SAFE_METHODS: &[&str] = &[
    "nip44_encrypt",
    "nip44_decrypt",
    "nip04_encrypt",
    "nip04_decrypt",
    "get_public_key",
];

/// Methods auto-approved after first physical button approval.
/// Includes signing -- only granted after the user explicitly approves once.
pub const TOFU_SAFE_METHODS: &[&str] = &[
    "sign_event",
    "nip44_encrypt",
    "nip44_decrypt",
    "nip04_encrypt",
    "nip04_decrypt",
    "get_public_key",
];

/// Approval decision for a specific request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalTier {
    /// Proceed immediately without user interaction.
    AutoApprove,
    /// Show briefly on OLED (1s) but don't wait for button.
    OledNotify,
    /// Full OLED display with countdown bar, wait for button approval.
    ButtonRequired,
}

// ---------------------------------------------------------------------------
// Pure policy helpers (testable on host, used by firmware PolicyEngine)
// ---------------------------------------------------------------------------

/// Create a connect-time TOFU policy (no signing -- only granted on valid secret).
pub fn make_connect_policy(client_pubkey: &str) -> ClientPolicy {
    ClientPolicy {
        client_pubkey: client_pubkey.to_string(),
        label: String::new(),
        allowed_methods: CONNECT_SAFE_METHODS.iter().map(|s| s.to_string()).collect(),
        allowed_kinds: vec![],
        auto_approve: true,
    }
}

/// Create a full TOFU policy for a client after first physical button approval.
/// Includes sign_event -- only call this after the user has pressed the button.
pub fn make_tofu_policy(client_pubkey: &str) -> ClientPolicy {
    ClientPolicy {
        client_pubkey: client_pubkey.to_string(),
        label: String::new(),
        allowed_methods: TOFU_SAFE_METHODS.iter().map(|s| s.to_string()).collect(),
        allowed_kinds: vec![],
        auto_approve: true,
    }
}

/// Find a policy by client pubkey.
pub fn find_policy<'a>(policies: &'a [ClientPolicy], client_pubkey: &str) -> Option<&'a ClientPolicy> {
    policies.iter().find(|p| p.client_pubkey == client_pubkey)
}

/// Remove a client policy by pubkey. Returns true if found and removed.
pub fn revoke_policy(policies: &mut Vec<ClientPolicy>, client_pubkey: &str) -> bool {
    let before = policies.len();
    policies.retain(|p| p.client_pubkey != client_pubkey);
    policies.len() < before
}

/// Upsert a client policy. Replaces if client_pubkey matches, otherwise adds.
pub fn upsert_policy(policies: &mut Vec<ClientPolicy>, policy: ClientPolicy) {
    if let Some(existing) = policies.iter_mut().find(|p| p.client_pubkey == policy.client_pubkey) {
        *existing = policy;
    } else {
        policies.push(policy);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pubkey(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn sample_policy(c: char) -> ClientPolicy {
        ClientPolicy {
            client_pubkey: sample_pubkey(c),
            label: format!("Client {c}"),
            allowed_methods: vec!["sign_event".into()],
            allowed_kinds: vec![1, 7],
            auto_approve: true,
        }
    }

    // --- Serde roundtrip ---

    #[test]
    fn serde_roundtrip() {
        let policy = sample_policy('a');
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: ClientPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.client_pubkey, policy.client_pubkey);
        assert_eq!(decoded.label, "Client a");
        assert_eq!(decoded.allowed_kinds, vec![1, 7]);
        assert!(decoded.auto_approve);
    }

    #[test]
    fn serde_defaults() {
        // Minimal JSON with only the required field.
        let json = r#"{"client_pubkey":"aa"}"#;
        let policy: ClientPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.client_pubkey, "aa");
        assert_eq!(policy.label, "");
        assert!(policy.allowed_methods.is_empty());
        assert!(policy.allowed_kinds.is_empty());
        assert!(!policy.auto_approve);
    }

    #[test]
    fn serde_vec_roundtrip() {
        let policies = vec![sample_policy('a'), sample_policy('b')];
        let json = serde_json::to_string(&policies).unwrap();
        let decoded: Vec<ClientPolicy> = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].label, "Client a");
        assert_eq!(decoded[1].label, "Client b");
    }

    // --- TOFU defaults ---

    #[test]
    fn tofu_policy_has_correct_defaults() {
        let policy = make_tofu_policy(&sample_pubkey('x'));
        assert!(policy.auto_approve);
        assert!(policy.label.is_empty());
        assert!(policy.allowed_kinds.is_empty());
        assert_eq!(policy.allowed_methods.len(), TOFU_SAFE_METHODS.len());
        for method in TOFU_SAFE_METHODS {
            assert!(policy.allowed_methods.contains(&method.to_string()));
        }
    }

    #[test]
    fn tofu_safe_methods_includes_essentials() {
        assert!(TOFU_SAFE_METHODS.contains(&"sign_event"));
        assert!(TOFU_SAFE_METHODS.contains(&"nip44_encrypt"));
        assert!(TOFU_SAFE_METHODS.contains(&"nip44_decrypt"));
        assert!(TOFU_SAFE_METHODS.contains(&"get_public_key"));
    }

    // --- Connect-safe methods ---

    #[test]
    fn connect_safe_methods_excludes_signing() {
        assert!(!CONNECT_SAFE_METHODS.contains(&"sign_event"));
    }

    #[test]
    fn connect_safe_methods_includes_crypto() {
        assert!(CONNECT_SAFE_METHODS.contains(&"nip44_encrypt"));
        assert!(CONNECT_SAFE_METHODS.contains(&"nip44_decrypt"));
        assert!(CONNECT_SAFE_METHODS.contains(&"nip04_encrypt"));
        assert!(CONNECT_SAFE_METHODS.contains(&"nip04_decrypt"));
        assert!(CONNECT_SAFE_METHODS.contains(&"get_public_key"));
    }

    #[test]
    fn connect_safe_is_subset_of_tofu_safe() {
        for method in CONNECT_SAFE_METHODS {
            assert!(TOFU_SAFE_METHODS.contains(method),
                "{} is in CONNECT_SAFE but not TOFU_SAFE", method);
        }
    }

    #[test]
    fn connect_policy_has_correct_defaults() {
        let policy = make_connect_policy(&sample_pubkey('x'));
        assert!(policy.auto_approve);
        assert!(policy.label.is_empty());
        assert!(policy.allowed_kinds.is_empty());
        assert_eq!(policy.allowed_methods.len(), CONNECT_SAFE_METHODS.len());
        assert!(!policy.allowed_methods.contains(&"sign_event".to_string()));
        for method in CONNECT_SAFE_METHODS {
            assert!(policy.allowed_methods.contains(&method.to_string()));
        }
    }

    // --- Find ---

    #[test]
    fn find_existing_policy() {
        let policies = vec![sample_policy('a'), sample_policy('b')];
        let found = find_policy(&policies, &sample_pubkey('b'));
        assert!(found.is_some());
        assert_eq!(found.unwrap().label, "Client b");
    }

    #[test]
    fn find_missing_policy() {
        let policies = vec![sample_policy('a')];
        assert!(find_policy(&policies, &sample_pubkey('z')).is_none());
    }

    #[test]
    fn find_in_empty_list() {
        let policies: Vec<ClientPolicy> = vec![];
        assert!(find_policy(&policies, &sample_pubkey('a')).is_none());
    }

    // --- Revoke ---

    #[test]
    fn revoke_existing_policy() {
        let mut policies = vec![sample_policy('a'), sample_policy('b'), sample_policy('c')];
        assert!(revoke_policy(&mut policies, &sample_pubkey('b')));
        assert_eq!(policies.len(), 2);
        assert!(find_policy(&policies, &sample_pubkey('b')).is_none());
        // Others untouched.
        assert!(find_policy(&policies, &sample_pubkey('a')).is_some());
        assert!(find_policy(&policies, &sample_pubkey('c')).is_some());
    }

    #[test]
    fn revoke_missing_policy() {
        let mut policies = vec![sample_policy('a')];
        assert!(!revoke_policy(&mut policies, &sample_pubkey('z')));
        assert_eq!(policies.len(), 1);
    }

    #[test]
    fn revoke_from_empty_list() {
        let mut policies: Vec<ClientPolicy> = vec![];
        assert!(!revoke_policy(&mut policies, &sample_pubkey('a')));
    }

    // --- Upsert ---

    #[test]
    fn upsert_adds_new_policy() {
        let mut policies = vec![sample_policy('a')];
        upsert_policy(&mut policies, sample_policy('b'));
        assert_eq!(policies.len(), 2);
        assert_eq!(find_policy(&policies, &sample_pubkey('b')).unwrap().label, "Client b");
    }

    #[test]
    fn upsert_replaces_existing_policy() {
        let mut policies = vec![sample_policy('a')];
        let mut updated = sample_policy('a');
        updated.label = "Updated".into();
        updated.auto_approve = false;
        upsert_policy(&mut policies, updated);
        assert_eq!(policies.len(), 1);
        let found = find_policy(&policies, &sample_pubkey('a')).unwrap();
        assert_eq!(found.label, "Updated");
        assert!(!found.auto_approve);
    }

    #[test]
    fn upsert_into_empty_list() {
        let mut policies: Vec<ClientPolicy> = vec![];
        upsert_policy(&mut policies, sample_policy('a'));
        assert_eq!(policies.len(), 1);
    }

    // --- Approval tier ---

    #[test]
    fn approval_tier_values_are_distinct() {
        assert_ne!(ApprovalTier::AutoApprove, ApprovalTier::ButtonRequired);
        assert_ne!(ApprovalTier::AutoApprove, ApprovalTier::OledNotify);
        assert_ne!(ApprovalTier::OledNotify, ApprovalTier::ButtonRequired);
    }
}
