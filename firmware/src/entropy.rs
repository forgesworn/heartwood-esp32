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
// Deliberate scope choices:
//   - One NVS write per boot; wear is negligible.
//   - First boot after flashing (no stored proof) passes and stores the draw:
//     a factory-stuck RNG is only provably stuck once it repeats, i.e. from
//     the second boot onwards. Commented here so the gap is audited, not
//     discovered.
//   - Failure does NOT brick the device: existing keys keep signing (their
//     entropy is already spent), but NEW key/secret generation is gated on
//     `rng_ok()` — fail closed exactly where fresh entropy matters.

use core::sync::atomic::{AtomicBool, Ordering};

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use sha2::{Digest, Sha256};

/// NVS blob key holding the SHA-256 of last boot's self-test draw.
const NVS_RNG_PROOF_KEY: &str = "rng_proof";

/// Set by [`boot_self_test`]; read by every fresh-entropy generation path.
static RNG_OK: AtomicBool = AtomicBool::new(false);

/// Whether the boot-time RNG self-test passed. Key generation must refuse
/// to run when this is false.
pub fn rng_ok() -> bool {
    RNG_OK.load(Ordering::Relaxed)
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
    match nvs.get_blob(NVS_RNG_PROOF_KEY, &mut previous) {
        Ok(Some(bytes)) if bytes.len() == 32 => {
            if previous == hash {
                log::error!(
                    "RNG self-test FAILED: draw identical to last boot — refusing key generation"
                );
                return;
            }
        }
        Ok(_) => {
            // First boot after flashing (or an empty/corrupt slot): nothing to
            // compare against yet — store and pass.
            log::info!("RNG self-test: no previous draw recorded, seeding proof");
        }
        Err(e) => {
            // Unreadable proof means we can never verify continuity — fail closed.
            log::error!("RNG self-test FAILED: proof unreadable ({e}) — refusing key generation");
            return;
        }
    }

    if let Err(e) = nvs.set_blob(NVS_RNG_PROOF_KEY, &hash) {
        // If we can't persist the proof, the NEXT boot can't verify
        // continuity — fail closed rather than degrade silently.
        log::error!("RNG self-test FAILED: proof write failed ({e}) — refusing key generation");
        return;
    }

    RNG_OK.store(true, Ordering::Relaxed);
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
