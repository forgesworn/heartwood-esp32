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
//! 2. **No replay.** The request's *inner* id — the one carried inside the
//!    NIP-44 ciphertext, so it cannot be forged or altered without the operator
//!    secret — must be non-empty and previously unseen. The firmware keeps a
//!    bounded seen-set and **persists it across reboots** (NVS). That is the gap
//!    this module closes: a RAM-only seen-set let a captured command be replayed
//!    after a restart; a persisted one does not (within the bound below).
//!
//! ## Known bound
//!
//! The seen-set is bounded (`SEEN_MAX` in `relay.rs`). An id evicted to make room
//! for newer ones is no longer remembered, so a replay of a command older than
//! the last `SEEN_MAX` *could* slip through after a reboot. This is acceptable
//! because the relay method set is deliberately low-stakes (create/update/revoke
//! a client slot, approve signing, read status) — nothing that touches the seed
//! or the trust root, which stay physical (USB) by design. The eviction test
//! below documents this limit explicitly.
#[allow(unused_imports)]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};


/// Whether an event author is the authorised operator.
///
/// Plain equality of x-only pubkeys. The caller checks this *before* decrypting
/// so a stranger's event is dropped cheaply; decryption would fail for a
/// non-operator regardless, since they cannot derive the conversation key.
pub fn is_operator(author: &[u8; 32], op_mgmt: &[u8; 32]) -> bool {
    author == op_mgmt
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

/// Record an accepted id in the bounded seen-set, evicting the oldest first if
/// full. The caller persists the updated set (NVS) so it survives a reboot.
/// Assumes `inner_id` was just classified `Fresh`.
pub fn remember(inner_id: &str, seen: &mut Vec<String>, max: usize) {
    if max == 0 {
        return;
    }
    seen.push(inner_id.to_string());
    while seen.len() > max {
        seen.remove(0);
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
    fn persisted_seen_set_survives_a_reboot() {
        // Accept a command, "persist" the seen-set, then rebuild the context
        // from that persisted set (what NVS load does after a restart). The
        // replay must still be caught — this is the reboot gap being closed.
        let mut seen: Vec<String> = Vec::new();
        remember("req-A", &mut seen, 64);
        let persisted = seen.clone();

        let reloaded = persisted; // simulate NVS round-trip across reboot
        assert_eq!(classify_replay("req-A", &reloaded), Replay::Seen);
    }

    #[test]
    fn seen_set_is_bounded_and_evicts_oldest() {
        let mut seen: Vec<String> = Vec::new();
        for i in 0..70 {
            remember(&format!("req-{i}"), &mut seen, 64);
        }
        assert_eq!(seen.len(), 64);
        // 70 inserts, window 64: req-0..req-5 evicted, req-6..req-69 retained.
        assert_eq!(classify_replay("req-69", &seen), Replay::Seen); // newest kept
        assert_eq!(classify_replay("req-6", &seen), Replay::Seen); // oldest kept
        // Documented bound: an id evicted past the window is no longer remembered,
        // so a replay of a command older than SEEN_MAX can slip through. Accepted
        // because the relay method set is low-stakes (no seed/trust-root ops).
        assert_eq!(classify_replay("req-5", &seen), Replay::Fresh); // just evicted
        assert_eq!(classify_replay("req-0", &seen), Replay::Fresh); // long evicted
    }

    #[test]
    fn zero_max_remembers_nothing() {
        let mut seen: Vec<String> = Vec::new();
        remember("req-x", &mut seen, 0);
        assert!(seen.is_empty());
    }
}
