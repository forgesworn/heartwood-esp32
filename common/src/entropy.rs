// common/src/entropy.rs
//
// Entropy stacking for on-device key generation.
//
// Key material is never drawn from a single entropy source. Independent
// sources — the SAR-ADC noise draw (`fill_random_strong`), the RF-fed
// `esp_fill_random` when the radio is up, and user button-press timing from
// the entropy game — are hashed together so that NO single source can bias
// the output: if any one input is unpredictable to the attacker, the result
// is unpredictable, even if every other source is fully compromised or
// broken. This is the construction that rescued Coldcard dice-roll users in
// the July 2026 advisory: their TRNG was silently a software PRNG for five
// years, and only seeds mixed with user-supplied entropy survived.
//
// Both functions are pure and no_std so they can be unit-tested on the host
// and audited without any ESP-IDF involvement.

use sha2::{Digest, Sha256};

/// Domain separator for the final stack mix. Versioned: if the construction
/// ever changes, the separator changes, so old and new outputs can't collide.
pub const STACK_DOMAIN: &[u8] = b"heartwood-entropy-v1";

/// Domain separator for the game-timestamp digest.
pub const GAME_DOMAIN: &[u8] = b"heartwood-game-v1";

/// Stack independent entropy sources into 32 bytes:
///
/// ```text
/// SHA256(STACK_DOMAIN || len(source_0) || source_0 || len(source_1) || source_1 || ...)
/// ```
///
/// Length-prefixing each source prevents boundary ambiguity (["ab","c"] vs
/// ["a","bc"]). Sources are mixed, never XORed or substituted — a later
/// source cannot cancel or overwrite an earlier one.
///
/// Callers MUST include at least one hardware-RNG source; this function has
/// no way to verify that, so the rule is enforced by convention and review.
pub fn stack(sources: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(STACK_DOMAIN);
    for source in sources {
        h.update((source.len() as u32).to_be_bytes());
        h.update(source);
    }
    h.finalize().into()
}

/// Digest the entropy game's press timestamps into a 32-byte game source:
///
/// ```text
/// SHA256(GAME_DOMAIN || count || timestamps_us[0..count] as big-endian u64s)
/// ```
///
/// Min-entropy assumption (stated for auditors, deliberately conservative):
/// human button-press timing under a reaction-time task carries ~1-2 bits of
/// conditioned min-entropy per press once rhythm, autocorrelation and bounce
/// are discounted — far below the raw microsecond-resolution figure. At 64
/// presses that is >= 64 bits of user entropy, and it is always stacked with
/// a hardware source via [`stack`], so even a fully-predictable game (an
/// attacker watching the user play) cannot weaken the result below the
/// hardware source's strength.
pub fn digest_timestamps(timestamps_us: &[u64]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(GAME_DOMAIN);
    h.update((timestamps_us.len() as u32).to_be_bytes());
    for &t in timestamps_us {
        h.update(t.to_be_bytes());
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_is_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(stack(&[&a, &b]), stack(&[&a, &b]));
    }

    #[test]
    fn every_source_changes_the_output() {
        let hw = [7u8; 32];
        let game_a = digest_timestamps(&[1000, 2000, 3000]);
        let game_b = digest_timestamps(&[1000, 2000, 3001]);

        // Different game input -> different output even with identical hardware draw.
        assert_ne!(stack(&[&hw, &game_a]), stack(&[&hw, &game_b]));

        // No game at all -> different again (skip path must not collide).
        assert_ne!(stack(&[&hw]), stack(&[&hw, &game_a]));
    }

    #[test]
    fn source_order_matters() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(stack(&[&a, &b]), stack(&[&b, &a]));
    }

    #[test]
    fn length_prefixing_prevents_boundary_ambiguity() {
        // Without length prefixes these two source lists would hash identically.
        assert_ne!(stack(&[b"ab", b"c"]), stack(&[b"a", b"bc"]));
    }

    #[test]
    fn digest_timestamps_is_deterministic_and_count_sensitive() {
        let ts = [42u64, 1_000_000, 9_999_999];
        assert_eq!(digest_timestamps(&ts), digest_timestamps(&ts));
        // A prefix of the same stream must not collide with the full stream.
        assert_ne!(digest_timestamps(&ts[..2]), digest_timestamps(&ts));
        assert_ne!(digest_timestamps(&[]), digest_timestamps(&ts));
    }
}
