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

/// Methods auto-approved after first TOFU approval.
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
