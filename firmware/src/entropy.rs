// firmware/src/entropy.rs
//
// Boot-time RNG self-test and stacked entropy draws.
//
// Lesson taken from the Coldcard July 2026 advisory: their hardware TRNG code
// was correct, but for five years seed generation silently resolved to a
// software PRNG fallback — nothing in the build or runtime noticed that the
// strong source wasn't in the call path. We can't audit our way out of that
// class of bug, so we TEST it: every boot draws from `fill_random_strong`,
// hashes the draw, and compares it against the hash stored from the previous
// boot. A hardware RNG that repeats a full 32-byte draw across resets is
// broken (or a stub); provisioning refuses to generate keys in that state.
//
// A stuck RNG is only provably stuck once a draw REPEATS, so a boot with no
// stored proof has nothing to compare against. That gap was written off as a
// one-off "first boot after flashing" cost. It was not: factory reset erases
// the whole NVS partition (`persistent_wipe::erase_all`), proof included, and
// the boot straight afterwards is exactly the boot the owner provisions on. So
// every generate-after-reset ran on the one boot where the check could not
// fire. A boot with no proof therefore stores the draw and stays UNVERIFIED:
// key generation waits for a second boot to prove the draw changed. That costs
// one power-cycle after a reset or a flash, and buys a check that actually
// covers the ceremony it exists for.
//
// Deliberate scope choices:
//   - One NVS write per boot; wear is negligible.
//   - Failure does NOT brick the device: existing keys keep signing (their
//     entropy is already spent), but NEW key/secret generation is gated on
//     `rng_ok()` — fail closed exactly where fresh entropy matters.

use core::sync::atomic::{AtomicU8, Ordering};

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use sha2::{Digest, Sha256};

/// NVS blob key holding the SHA-256 of last boot's self-test draw.
const NVS_RNG_PROOF_KEY: &str = "rng_proof";

/// Outcome of the boot-time RNG self-test. Only [`RngState::Verified`] permits
/// fresh key or secret generation.
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
    /// One line fit for a NACK payload and an operator log.
    pub fn refusal(self) -> &'static str {
        match self {
            Self::Verified => "",
            Self::NeedsSecondBoot => {
                "RNG continuity unverified after a wipe: power-cycle the signer once, then retry"
            }
            Self::Failed => "RNG self-test failed this boot — refusing to mint key material",
        }
    }
}

/// Set by [`boot_self_test`]; read by every fresh-entropy generation path.
/// Starts at `Failed` so a self-test that never ran cannot mint anything.
static RNG_STATE: AtomicU8 = AtomicU8::new(STATE_FAILED);

const STATE_FAILED: u8 = 0;
const STATE_NEEDS_SECOND_BOOT: u8 = 1;
const STATE_VERIFIED: u8 = 2;

/// The boot-time RNG self-test outcome.
pub fn rng_state() -> RngState {
    match RNG_STATE.load(Ordering::Relaxed) {
        STATE_VERIFIED => RngState::Verified,
        STATE_NEEDS_SECOND_BOOT => RngState::NeedsSecondBoot,
        _ => RngState::Failed,
    }
}

/// Whether the boot-time RNG self-test passed. Key generation must refuse
/// to run when this is false.
pub fn rng_ok() -> bool {
    rng_state() == RngState::Verified
}

/// Why generation is being refused, for screens and NACK payloads. Empty when
/// nothing is being refused.
pub fn rng_refusal() -> &'static str {
    rng_state().refusal()
}

/// Draw 32 bytes from the guaranteed entropy source and verify the hardware
/// RNG is live: the draw must be non-constant and must not repeat last boot's
/// draw. Stores this boot's hash for the next comparison. Call once at boot,
/// after NVS init, before any key generation can be requested.
pub fn boot_self_test(nvs: &mut EspNvs<NvsDefault>) {
    let mut draw = [0u8; 32];
    crate::fill_random_strong(&mut draw);

    // A constant 32-byte "random" draw means the entropy source is dead on its
    // face — check the draw itself before it is hashed away.
    if all_equal(&draw) {
        draw.iter_mut().for_each(|b| *b = 0);
        log::error!("RNG self-test FAILED: constant draw — refusing key generation");
        return;
    }

    let hash: [u8; 32] = Sha256::digest(draw).into();
    draw.iter_mut().for_each(|b| *b = 0);

    let mut previous = [0u8; 32];
    let compared = match nvs.get_blob(NVS_RNG_PROOF_KEY, &mut previous) {
        Ok(Some(bytes)) if bytes.len() == 32 => {
            if previous == hash {
                log::error!(
                    "RNG self-test FAILED: draw identical to last boot — refusing key generation"
                );
                return;
            }
            true
        }
        Ok(_) => {
            // First boot after a flash or a factory reset (or an empty/corrupt
            // slot): nothing to compare against. Store the proof, but do NOT
            // pass — this is the boot an owner provisions on.
            false
        }
        Err(e) => {
            // Unreadable proof means we can never verify continuity — fail closed.
            log::error!("RNG self-test FAILED: proof unreadable ({e}) — refusing key generation");
            return;
        }
    };

    if let Err(e) = nvs.set_blob(NVS_RNG_PROOF_KEY, &hash) {
        // If we can't persist the proof, the NEXT boot can't verify
        // continuity — fail closed rather than degrade silently.
        log::error!("RNG self-test FAILED: proof write failed ({e}) — refusing key generation");
        return;
    }

    if !compared {
        RNG_STATE.store(STATE_NEEDS_SECOND_BOOT, Ordering::Relaxed);
        log::warn!(
            "RNG self-test: no previous draw to compare against, proof seeded. \
             Power-cycle once before generating keys."
        );
        return;
    }

    RNG_STATE.store(STATE_VERIFIED, Ordering::Relaxed);
    log::info!("RNG self-test passed");
}

/// Fill `out` (up to 32 bytes) with stacked entropy for key generation.
///
/// Always includes a fresh `fill_random_strong` draw; when the owner played
/// the entropy game its timestamp digest is mixed in as a second independent
/// source. The mix (see `heartwood_common::entropy`) guarantees neither
/// source alone can bias the output. 16 bytes → a 12-word phrase, 32 bytes →
/// 24 words.
///
/// Returns `false` when the boot self-test failed — callers must treat that
/// as a hard refusal, not a fallback to TRNG-only.
pub fn stacked_entropy(game_digest: Option<&[u8; 32]>, out: &mut [u8]) -> bool {
    if !rng_ok() || out.is_empty() || out.len() > 32 {
        return false;
    }
    let mut hw = [0u8; 32];
    crate::fill_random_strong(&mut hw);

    let mut stacked = match game_digest {
        Some(game) => heartwood_common::entropy::stack(&[&hw, game]),
        None => heartwood_common::entropy::stack(&[&hw]),
    };
    hw.iter_mut().for_each(|b| *b = 0);

    out.copy_from_slice(&stacked[..out.len()]);
    stacked.iter_mut().for_each(|b| *b = 0);
    true
}

fn all_equal(buf: &[u8; 32]) -> bool {
    buf.iter().all(|&b| b == buf[0])
}
