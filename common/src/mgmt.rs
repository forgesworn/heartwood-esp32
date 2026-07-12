//! Pure authentication + replay rules for relay-mediated management (kind
//! 24134). No I/O, no hardware, no crypto — just the decisions the firmware
//! applies once an inbound management event has been parsed and (for the replay
//! check) NIP-44-decrypted.
//!
//! This lives in `common`, apart from `firmware/src/relay.rs`, so the
//! security-critical rules can be unit-tested on the host — the firmware crate
//! only builds for the ESP32 target and cannot run host tests.
//!
//! ## The rules
//!
//! 1. **Operator-only.** A command runs only if the event author equals the
//!    baked operator key (`op_mgmt`) — the sole management authority. NIP-44
//!    already gives confidentiality *and* forgery-resistance (you cannot encrypt
//!    under the device⇄operator conversation key without the operator secret),
//!    so a relay or third party cannot mint a valid command. Matching the author
//!    is the explicit authority gate on top of that.
//!
//! 2. **No replay.** Every state-changing or credential-returning request carries the current
//!    device-issued mutation challenge. Firmware compares it with the challenge
//!    persisted in NVS, then persists a fresh random challenge *before* it
//!    dispatches the mutation. A captured request is therefore stale forever,
//!    including after reboot and after its request id leaves the bounded recent
//!    id set. Public/read-only discovery methods do not consume the challenge;
//!    `client_uri` does because it returns a bearer credential.
//!
//! The request's unpredictable inner id remains a useful RAM-only
//! duplicate-delivery guard while several relays are live. It is bounded
//! (`SEEN_MAX` in `relay.rs`) and deliberately not persisted: Sapwood polls reads
//! every four seconds, so persistence would create needless NVS wear. An evicted
//! mutation id still carries a consumed challenge and fails closed.
#[allow(unused_imports)]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};

use sha2::{Digest, Sha256};

use crate::hex::{hex_decode, hex_encode};
use crate::policy::ConnectSlot;


/// Whether an event author is the authorised operator.
///
/// Plain equality of x-only pubkeys. The caller checks this *before* decrypting
/// so a stranger's event is dropped cheaply; decryption would fail for a
/// non-operator regardless, since they cannot derive the conversation key.
pub fn is_operator(author: &[u8; 32], op_mgmt: &[u8; 32]) -> bool {
    author == op_mgmt
}

/// Non-secret stable identity for a client slot credential. Management callers
/// bind numeric slot operations to this value so a stale UI cannot act on a
/// different app after revoke + index reuse. Valid slot secrets hash their raw
/// 32 bytes; malformed legacy state hashes its stored bytes deterministically.
pub fn credential_fingerprint(secret_hex: &str) -> String {
    let mut hasher = Sha256::new();
    match hex_decode(secret_hex) {
        Ok(secret) => hasher.update(&secret),
        Err(_) => hasher.update(secret_hex.as_bytes()),
    }
    hex_encode(&hasher.finalize())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialFingerprintMatch {
    Match,
    Missing,
    Malformed,
    Mismatch,
}

pub fn classify_credential_fingerprint(
    expected: Option<&str>,
    actual: &str,
) -> CredentialFingerprintMatch {
    let Some(expected) = expected else {
        return CredentialFingerprintMatch::Missing;
    };
    if expected.len() != 64
        || !expected
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return CredentialFingerprintMatch::Malformed;
    }
    if expected == actual {
        CredentialFingerprintMatch::Match
    } else {
        CredentialFingerprintMatch::Mismatch
    }
}

/// Public management representation of a client slot. The bearer secret is
/// deliberately absent; callers get only its stable non-secret fingerprint so
/// later numeric-index actions can bind to the exact credential they observed.
pub fn client_summary(slot: &ConnectSlot) -> serde_json::Value {
    serde_json::json!({
        "slot_index": slot.slot_index,
        "label": slot.label.clone(),
        "secret_fingerprint": credential_fingerprint(&slot.secret),
        "auto_approve": slot.auto_approve,
        "signing_approved": slot.signing_approved,
        "strict_permissions": slot.strict_permissions,
        "current_pubkey": slot.current_pubkey.clone(),
        "authorized_pubkeys": slot.authorized_pubkeys.clone(),
        "allowed_kinds": slot.allowed_kinds.clone(),
        "allowed_methods": slot.allowed_methods.clone(),
    })
}

/// Outcome of the replay/freshness check on a request's inner id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// First time we've seen this id — safe to execute.
    Fresh,
    /// Empty/missing id — reject (a well-formed request always carries one).
    Empty,
    /// Id already in the seen-set — a replay; reject.
    Seen,
}

/// Classify a request's inner id against the seen-set. Pure: never mutates.
pub fn classify_replay(inner_id: &str, seen: &[String]) -> Replay {
    if inner_id.is_empty() {
        return Replay::Empty;
    }
    if seen.iter().any(|s| s == inner_id) {
        return Replay::Seen;
    }
    Replay::Fresh
}

/// Record an accepted id in the bounded RAM seen-set, evicting the oldest first
/// if full. Assumes `inner_id` was just classified `Fresh`.
pub fn remember(inner_id: &str, seen: &mut Vec<String>, max: usize) {
    if max == 0 {
        return;
    }
    seen.push(inner_id.to_string());
    while seen.len() > max {
        seen.remove(0);
    }
}

/// Challenge gate result for one authenticated management request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationChallenge {
    /// This is a known read-only method and must remain usable without a nonce.
    NotRequired,
    /// A mutation omitted the challenge entirely.
    Missing,
    /// The supplied value was not a 32-byte lowercase/uppercase hex string.
    Malformed,
    /// A different mutation consumed this challenge already.
    Stale,
    /// The supplied challenge is current and may be atomically rotated.
    Current,
}

/// Only these methods are allowed to bypass the mutation challenge. Unknown
/// methods default to state-changing, so adding a future dispatch arm cannot
/// accidentally create an unprotected mutation.
pub fn requires_mutation_challenge(method: &str) -> bool {
    !matches!(
        method,
        "get_management_challenge"
            | "get_network_config"
            | "list_clients"
            | "list_identities"
            | "get_status"
    )
}

/// Pure validation for the persisted one-time mutation challenge. The firmware
/// owns rotation/persistence; keeping this decision in `common` makes the
/// fail-closed method classification host-testable.
pub fn classify_mutation_challenge(
    method: &str,
    supplied: Option<&str>,
    current: &str,
) -> MutationChallenge {
    if !requires_mutation_challenge(method) {
        return MutationChallenge::NotRequired;
    }
    let Some(supplied) = supplied else {
        return MutationChallenge::Missing;
    };
    if supplied.len() != 64 || !supplied.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return MutationChallenge::Malformed;
    }
    if current.len() != 64 || !current.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return MutationChallenge::Stale;
    }
    if supplied.eq_ignore_ascii_case(current) {
        MutationChallenge::Current
    } else {
        MutationChallenge::Stale
    }
}

/// Exact read-back check used after persisting the next challenge. Keeping the
/// decision pure makes missing, truncated, and mismatched NVS results testable
/// without pretending host tests exercise the ESP-IDF storage driver itself.
pub fn persisted_challenge_matches(expected: &[u8; 32], stored: Option<&[u8]>) -> bool {
    matches!(stored, Some(value) if value == expected.as_slice())
}

/// Build a NIP-46 `bunker://` connection URI addressed to one identity.
///
/// Shared by `create_client` (which passes `Some(secret)` to bind the connecting
/// client key to a policy slot) and `list_identities` (which passes `None` —
/// pure discovery). Discovery and authorisation are deliberately orthogonal: the
/// `#p` pubkey selects *which identity signs*, while a secret binds a *client
/// key* to a slot's policy. That is why discovery URIs carry no secret — one
/// secret shared across identities would make distinct client keys collide on a
/// single slot. `relays` are advertised so the client knows where to publish; an
/// empty list yields a bare `bunker://<pubkey>`.
pub fn bunker_uri(pubkey_hex: &str, relays: &[String], secret: Option<&str>) -> String {
    let mut params: Vec<String> = relays.iter().map(|r| format!("relay={r}")).collect();
    if let Some(s) = secret {
        params.push(format!("secret={s}"));
    }
    if params.is_empty() {
        format!("bunker://{pubkey_hex}")
    } else {
        format!("bunker://{pubkey_hex}?{}", params.join("&"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OP: [u8; 32] = [0x11; 32];

    fn other_key() -> [u8; 32] {
        let mut k = OP;
        k[0] ^= 0x01; // flip one bit — a different author
        k
    }

    #[test]
    fn operator_is_accepted() {
        assert!(is_operator(&OP, &OP));
    }

    #[test]
    fn non_operator_is_rejected() {
        // The core security claim: an event from anyone but op_mgmt fails the gate.
        assert!(!is_operator(&other_key(), &OP));
    }

    #[test]
    fn bunker_uri_discovery_carries_no_secret() {
        // list_identities shape: relays advertised, no secret appended.
        let relays = vec!["wss://a.example".to_string(), "wss://b.example".to_string()];
        assert_eq!(
            bunker_uri("abcd", &relays, None),
            "bunker://abcd?relay=wss://a.example&relay=wss://b.example"
        );
    }

    #[test]
    fn bunker_uri_with_secret_appends_it_after_relays() {
        // create_client shape: secret last, so the addressed pubkey stays first.
        let relays = vec!["wss://a.example".to_string()];
        assert_eq!(
            bunker_uri("abcd", &relays, Some("s3cr3t")),
            "bunker://abcd?relay=wss://a.example&secret=s3cr3t"
        );
    }

    #[test]
    fn bunker_uri_without_relays_is_bare() {
        assert_eq!(bunker_uri("abcd", &[], None), "bunker://abcd");
        assert_eq!(bunker_uri("abcd", &[], Some("x")), "bunker://abcd?secret=x");
    }

    #[test]
    fn fresh_id_is_fresh() {
        let seen: Vec<String> = vec!["aaa".into(), "bbb".into()];
        assert_eq!(classify_replay("ccc", &seen), Replay::Fresh);
    }

    #[test]
    fn empty_id_is_rejected() {
        let seen: Vec<String> = Vec::new();
        assert_eq!(classify_replay("", &seen), Replay::Empty);
    }

    #[test]
    fn duplicate_id_is_a_replay() {
        let seen: Vec<String> = vec!["aaa".into(), "bbb".into()];
        assert_eq!(classify_replay("bbb", &seen), Replay::Seen);
    }

    #[test]
    fn remember_then_classify_detects_replay() {
        let mut seen: Vec<String> = Vec::new();
        assert_eq!(classify_replay("req-1", &seen), Replay::Fresh);
        remember("req-1", &mut seen, 64);
        // The same command, replayed, is now caught.
        assert_eq!(classify_replay("req-1", &seen), Replay::Seen);
    }

    #[test]
    fn ram_seen_set_suppresses_live_duplicate_delivery() {
        let mut seen: Vec<String> = Vec::new();
        remember("req-A", &mut seen, 64);
        assert_eq!(classify_replay("req-A", &seen), Replay::Seen);
    }

    #[test]
    fn consumed_challenge_still_rejects_a_mutation_after_id_eviction() {
        let mut seen: Vec<String> = Vec::new();
        for i in 0..70 {
            remember(&format!("req-{i}"), &mut seen, 64);
        }
        assert_eq!(seen.len(), 64);
        // 70 inserts, window 64: req-0..req-5 evicted, req-6..req-69 retained.
        assert_eq!(classify_replay("req-69", &seen), Replay::Seen); // newest kept
        assert_eq!(classify_replay("req-6", &seen), Replay::Seen); // oldest kept
        // The id-only layer is deliberately bounded.
        assert_eq!(classify_replay("req-5", &seen), Replay::Fresh); // just evicted
        assert_eq!(classify_replay("req-0", &seen), Replay::Fresh); // long evicted

        // The captured mutation carried the old challenge. Rotation before its
        // first dispatch makes it stale forever, independently of id eviction.
        let consumed = "11".repeat(32);
        let current = "22".repeat(32);
        assert_eq!(
            classify_mutation_challenge("revoke_client", Some(&consumed), &current),
            MutationChallenge::Stale,
        );
    }

    #[test]
    fn zero_max_remembers_nothing() {
        let mut seen: Vec<String> = Vec::new();
        remember("req-x", &mut seen, 0);
        assert!(seen.is_empty());
    }

    #[test]
    fn all_current_read_methods_bypass_the_mutation_challenge() {
        for method in [
            "get_management_challenge",
            "get_network_config",
            "list_clients",
            "list_identities",
            "get_status",
        ] {
            assert!(!requires_mutation_challenge(method), "{method}");
            assert_eq!(
                classify_mutation_challenge(method, None, "11"),
                MutationChallenge::NotRequired,
            );
        }
    }

    #[test]
    fn current_mutations_and_unknown_future_methods_fail_closed() {
        for method in [
            "stage_network_config",
            "activate_network_config",
            "commit_network_config",
            "abort_network_config",
            "create_client",
            "create_client_v2",
            "nostrconnect",
            "nostrconnect_v2",
            "approve_signing",
            "revoke_client",
            "update_client",
            "client_uri",
            "set_identity_meta",
            "future_mutation",
            "",
        ] {
            assert!(requires_mutation_challenge(method), "{method}");
        }
    }

    #[test]
    fn mutation_challenge_rejects_missing_malformed_and_stale_values() {
        let current = "ab".repeat(32);
        assert_eq!(
            classify_mutation_challenge("update_client", None, &current),
            MutationChallenge::Missing,
        );
        assert_eq!(
            classify_mutation_challenge("update_client", Some("abcd"), &current),
            MutationChallenge::Malformed,
        );
        assert_eq!(
            classify_mutation_challenge("update_client", Some(&"zz".repeat(32)), &current),
            MutationChallenge::Malformed,
        );
        assert_eq!(
            classify_mutation_challenge("update_client", Some(&"cd".repeat(32)), &current),
            MutationChallenge::Stale,
        );
        assert_eq!(
            classify_mutation_challenge("update_client", Some(&current.to_uppercase()), &current),
            MutationChallenge::Current,
        );
    }

    #[test]
    fn power_loss_after_rotation_cannot_reenable_the_undispatched_request() {
        let request_challenge = "10".repeat(32);
        assert_eq!(
            classify_mutation_challenge(
                "create_client_v2",
                Some(&request_challenge),
                &request_challenge,
            ),
            MutationChallenge::Current,
        );

        // Firmware persists this replacement before calling dispatch. Simulate
        // a reset immediately after that durable write: no slot was created,
        // but the captured request can no longer pass after reboot.
        let persisted_after_reboot = "20".repeat(32);
        assert_eq!(
            classify_mutation_challenge(
                "create_client_v2",
                Some(&request_challenge),
                &persisted_after_reboot,
            ),
            MutationChallenge::Stale,
        );
    }

    #[test]
    fn second_manager_loses_a_race_instead_of_mutating_a_reused_slot() {
        let shared_discovery = "31".repeat(32);
        assert_eq!(
            classify_mutation_challenge(
                "revoke_client",
                Some(&shared_discovery),
                &shared_discovery,
            ),
            MutationChallenge::Current,
        );

        // Manager A's revoke rotates first. Manager B's captured update for the
        // same numeric slot is rejected rather than applying to whatever now
        // occupies that slot.
        let after_manager_a = "32".repeat(32);
        assert_eq!(
            classify_mutation_challenge(
                "update_client",
                Some(&shared_discovery),
                &after_manager_a,
            ),
            MutationChallenge::Stale,
        );
    }

    #[test]
    fn challenge_persistence_requires_exact_immediate_read_back() {
        let expected = [0x71; 32];
        let different = [0x72; 32];
        assert!(persisted_challenge_matches(&expected, Some(&expected)));
        assert!(!persisted_challenge_matches(&expected, None));
        assert!(!persisted_challenge_matches(&expected, Some(&expected[..31])));
        assert!(!persisted_challenge_matches(&expected, Some(&different)));
    }

    #[test]
    fn credential_fingerprint_is_stable_nonsecret_and_slot_specific() {
        let first = "11".repeat(32);
        let second = "22".repeat(32);
        let fingerprint = credential_fingerprint(&first);
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(fingerprint, first);
        assert_eq!(fingerprint, credential_fingerprint(&first));
        assert_ne!(fingerprint, credential_fingerprint(&second));
    }

    #[test]
    fn client_summary_exposes_strictness_and_fingerprint_but_never_secret() {
        let slot = ConnectSlot {
            slot_index: 7,
            label: "exact signer".into(),
            secret: "41".repeat(32),
            current_pubkey: Some("42".repeat(32)),
            allowed_methods: vec!["sign_event".into()],
            allowed_kinds: vec![1],
            auto_approve: true,
            signing_approved: true,
            strict_permissions: true,
            authorized_pubkeys: vec!["43".repeat(32)],
        };
        let summary = client_summary(&slot);
        assert_eq!(summary["slot_index"], 7);
        assert_eq!(summary["strict_permissions"], true);
        assert_eq!(
            summary["secret_fingerprint"],
            credential_fingerprint(&slot.secret),
        );
        assert!(summary.get("secret").is_none());
    }

    #[test]
    fn expected_credential_fingerprint_fails_closed() {
        let actual = credential_fingerprint(&"11".repeat(32));
        assert_eq!(
            classify_credential_fingerprint(Some(&actual), &actual),
            CredentialFingerprintMatch::Match,
        );
        assert_eq!(
            classify_credential_fingerprint(None, &actual),
            CredentialFingerprintMatch::Missing,
        );
        assert_eq!(
            classify_credential_fingerprint(Some("abcd"), &actual),
            CredentialFingerprintMatch::Malformed,
        );
        assert_eq!(
            classify_credential_fingerprint(Some(&actual.to_uppercase()), &actual),
            CredentialFingerprintMatch::Malformed,
        );
        assert_eq!(
            classify_credential_fingerprint(Some(&"00".repeat(32)), &actual),
            CredentialFingerprintMatch::Mismatch,
        );
    }
}
