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

/// Outcome of the boot-time RNG self-test. Only [`RngState::Verified`] permits
/// fresh key or secret generation.
///
/// The state machine lives here, away from ESP-IDF, because the case that
/// matters most cannot be reached on a bench without erasing a board: the boot
/// straight after a factory reset, where the stored proof is gone and there is
/// nothing to compare this boot's draw against. That case used to PASS, which
/// made the check blind on the exact boot an owner provisions on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngState {
    /// This boot's draw differs from the previous boot's. Generation allowed.
    Verified,
    /// No previous draw to compare against (first boot after a flash or a
    /// factory reset). The proof is stored; one more boot proves the draw
    /// changes. Generation refused, and it is NOT a fault.
    NeedsSecondBoot,
    /// The draw was constant, repeated last boot's, or the proof could not be
    /// read or written. Generation refused.
    Failed,
}

impl RngState {
    /// One line fit for a NACK payload and an operator log. Empty when nothing
    /// is being refused.
    pub fn refusal(self) -> &'static str {
        match self {
            Self::Verified => "",
            Self::NeedsSecondBoot => {
                "RNG continuity unverified after a wipe: power-cycle the signer once, then retry"
            }
            Self::Failed => "RNG self-test failed this boot — refusing to mint key material",
        }
    }

    /// Whether fresh key or secret generation may proceed.
    pub fn allows_generation(self) -> bool {
        matches!(self, Self::Verified)
    }
}

/// What the stored continuity proof said about this boot's draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofLookup {
    /// A stored proof matched this boot's draw: the RNG repeated itself.
    Matched,
    /// A stored proof differed: the draw moved, which is what we want.
    Differed,
    /// No usable proof stored (first boot after a flash, or after a wipe that
    /// erased it, or a corrupt slot).
    Absent,
    /// The proof could not be read, so continuity can never be established.
    Unreadable,
}

/// Decide the self-test outcome from the three facts a boot can establish.
///
/// `draw_constant` — every byte of the 32-byte draw was identical.
/// `proof` — what the stored proof said.
/// `proof_stored` — whether THIS boot's proof was persisted: `Some(true)` on a
/// successful write, `Some(false)` on a failed one, `None` when no write was
/// attempted because the outcome was already decided.
///
/// A failed write is fatal even when the draw looks fine: without a proof the
/// NEXT boot cannot verify continuity either, and silently degrading is the
/// failure mode this whole mechanism exists to prevent.
pub fn self_test_outcome(
    draw_constant: bool,
    proof: ProofLookup,
    proof_stored: Option<bool>,
) -> RngState {
    if draw_constant
        || matches!(proof, ProofLookup::Matched | ProofLookup::Unreadable)
        || proof_stored != Some(true)
    {
        return RngState::Failed;
    }
    match proof {
        ProofLookup::Differed => RngState::Verified,
        // Nothing to compare against. Storing the proof is not evidence; the
        // next boot's draw is. Refuse until then.
        ProofLookup::Absent => RngState::NeedsSecondBoot,
        ProofLookup::Matched | ProofLookup::Unreadable => RngState::Failed,
    }
}

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
    fn a_wiped_board_must_not_pass_its_first_boot() {
        // The regression that started all this: a factory reset erases the
        // continuity proof, and the boot immediately afterwards is the one an
        // owner provisions on. Passing there makes the check blind exactly
        // when it matters.
        assert_eq!(
            self_test_outcome(false, ProofLookup::Absent, Some(true)),
            RngState::NeedsSecondBoot
        );
        assert!(!self_test_outcome(false, ProofLookup::Absent, Some(true)).allows_generation());
    }

    #[test]
    fn only_a_compared_and_stored_draw_verifies() {
        assert_eq!(
            self_test_outcome(false, ProofLookup::Differed, Some(true)),
            RngState::Verified
        );
        assert!(self_test_outcome(false, ProofLookup::Differed, Some(true)).allows_generation());
    }

    #[test]
    fn every_other_combination_fails_closed() {
        use ProofLookup::*;
        for proof in [Matched, Differed, Absent, Unreadable] {
            for stored in [Some(true), Some(false), None] {
                for constant in [true, false] {
                    let state = self_test_outcome(constant, proof, stored);
                    let should_pass =
                        !constant && proof == Differed && stored == Some(true);
                    let should_wait =
                        !constant && proof == Absent && stored == Some(true);
                    let expected = if should_pass {
                        RngState::Verified
                    } else if should_wait {
                        RngState::NeedsSecondBoot
                    } else {
                        RngState::Failed
                    };
                    assert_eq!(
                        state, expected,
                        "constant={constant} proof={proof:?} stored={stored:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_repeated_draw_fails_even_when_everything_else_is_healthy() {
        // The Coldcard case: the draw is well-formed, non-constant, and stores
        // fine. It is simply the same one as last boot.
        assert_eq!(
            self_test_outcome(false, ProofLookup::Matched, Some(true)),
            RngState::Failed
        );
    }

    #[test]
    fn a_failed_proof_write_is_fatal_not_a_warning() {
        // Without a stored proof the NEXT boot cannot verify continuity either.
        assert_eq!(
            self_test_outcome(false, ProofLookup::Differed, Some(false)),
            RngState::Failed
        );
    }

    #[test]
    fn refusals_tell_the_two_states_apart() {
        let wipe = RngState::NeedsSecondBoot.refusal();
        let fault = RngState::Failed.refusal();
        assert!(wipe.contains("power-cycle"), "{wipe}");
        assert!(!fault.contains("power-cycle"), "{fault}");
        assert_ne!(wipe, fault);
        assert!(RngState::Verified.refusal().is_empty());
    }

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
