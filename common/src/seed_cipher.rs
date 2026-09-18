// common/src/seed_cipher.rs
//
// PIN-derived seed encryption at rest (P5) — the eFuse-free device-theft
// mitigation. Encrypts the 32-byte master seed with a key derived from an
// on-device PIN, so a flash dump yields ciphertext instead of the seed.
//
// Construction (encrypt-then-MAC, the same shape NIP-44 v2 uses):
//   km        = PBKDF2-HMAC-SHA256(pin, salt, ITERATIONS)  -> 64 bytes
//   enc_key   = km[0..32]      mac_key = km[32..64]
//   ct        = ChaCha20(enc_key, nonce) XOR seed          (32 bytes)
//   tag       = HMAC-SHA256(mac_key, nonce || ct)          (32 bytes)
//   legacy    = salt(16) || nonce(12) || ct(32) || tag(32) = 92 bytes
//   current   = magic(4) || version(1) || rounds(4) || salt || nonce || ct || tag
//
// Decryption recomputes km from the PIN, verifies the tag in constant time
// (wrong PIN -> different km -> tag mismatch -> Err), then decrypts.
//
// HONEST LIMITATION (see docs/2026-07-02-pin-seed-encryption-design.md and
// SECURITY-MODEL.md): with no secure element and no eFuses, the key is derived
// ENTIRELY from the PIN. An attacker who owns the flash can brute-force the PIN
// offline; the slow KDF raises the per-guess cost but a short PIN is an
// enumerable space. This is a real uplift (no longer instant game-over) but is
// NOT hardware-wallet-grade at-rest security.

use alloc::vec::Vec;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const SEED_LEN: usize = 32;
pub const TAG_LEN: usize = 32;
/// The original, fixed-cost on-disk format. It remains readable forever: a
/// board that was sealed before the cost was recorded must never be mistaken
/// for an unprotected board after an update.
pub const LEGACY_BLOB_LEN: usize = SALT_LEN + NONCE_LEN + SEED_LEN + TAG_LEN; // 92
const HEADER_MAGIC: [u8; 4] = *b"HWSC";
const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = HEADER_MAGIC.len() + 1 + 4;
/// Total on-disk length of a newly encrypted seed blob.
pub const BLOB_LEN: usize = HEADER_LEN + LEGACY_BLOB_LEN; // 101
/// Largest encrypted-seed blob understood by this firmware. NVS readers use
/// this rather than assuming every board was sealed by the current release.
pub const MAX_BLOB_LEN: usize = BLOB_LEN;

/// The immutable cost of the original, unversioned 92-byte record. It must
/// never follow a future default retune: these blobs have no stored count.
pub const LEGACY_PBKDF2_ITERATIONS: u32 = 100_000;
/// PBKDF2 iteration count written into new records. Deliberately slow to raise
/// the per-guess cost of an offline PIN brute-force. **Bench-tune this** to
/// ~1–2 s on the slowest board (the Heltec / lx106); it is a cost knob, not a
/// correctness one. New blobs record the count, so this can change after a
/// measured retune without changing how legacy blobs unlock.
pub const PBKDF2_ITERATIONS: u32 = LEGACY_PBKDF2_ITERATIONS;
/// Refuse a corrupted header before it can turn an unlock attempt into an
/// arbitrary-length CPU burn.
///
/// This is **not** a round number and must not be raised to one. The rounds
/// field is read from flash and the work it names is performed BEFORE
/// anything is authenticated — the MAC key is PBKDF2 output block 2, so the
/// header's own MAC cannot be checked until after the KDF has run. A cheap
/// range check on the parsed count is therefore the only pre-KDF defence that
/// exists, and its value has to be tied to what the slowest supported path
/// can actually finish.
///
/// The binding case is the **software** path, not the accelerator: a board
/// whose accelerator is absent or has failed its self-check derives in
/// software, and that is where a corrupted count hurts.
///
///   measured, Heltec V4 (S3, 240 MHz, software):
///       29 s for 100,000 iterations  ->  290 us per iteration
///   task watchdog (sdkconfig.defaults, Kconfig maximum):
///       60 s
///   budget for one slot, leaving margin:
///       150,000 x 290 us = 43.5 s, i.e. 16.5 s (27%) inside the window
///
/// The previous value of 1,000,000 was 290 s of software work against that
/// 60 s window — three to five times more than the board could survive, so a
/// blob with a corrupted rounds field was a reboot loop rather than a clean
/// "wrong PIN". 150,000 also leaves genuine headroom above the shipped
/// [`PBKDF2_ITERATIONS`] for a future measured retune without another format
/// change, while capping the damage a flipped bit can do at 1.5x a legitimate
/// unseal rather than 10x.
///
/// The KDF additionally feeds the watchdog from inside its round loop now
/// (see [`crate::kdf`]), so the window is a budget rather than a cliff — but
/// the ceiling is set from the cliff, because the in-loop feed is a courtesy
/// to other tasks and not a guarantee.
pub const MAX_PBKDF2_ITERATIONS: u32 = 150_000;

#[derive(Debug, PartialEq, Eq)]
pub enum SeedCipherError {
    /// Blob is neither a legacy nor a current encrypted-seed record.
    BadLength,
    /// A current-size blob does not identify a format this firmware knows.
    UnsupportedFormat,
    /// A current-size blob names an impossible or unsafe amount of KDF work.
    InvalidIterations,
    /// The MAC did not verify — wrong PIN or a tampered blob.
    WrongPinOrTampered,
}

/// Derive the 64-byte (enc || mac) key material from a PIN and salt.
///
/// This goes through [`crate::kdf::pbkdf2_for_seed`], which is the unchanged
/// pure-Rust `pbkdf2` crate everywhere — host tools, host tests, heartwoodd —
/// except on a board that installed a device KDF hook at boot. Such a board
/// has already proved that hook byte-identical against a known-answer vector
/// before its first real derivation, and drops back to software itself if it
/// could not. See docs/2026-09-18-pbkdf2-cost-and-sha-acceleration.md.
fn derive_km(pin: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    let mut km = [0u8; 64];
    crate::kdf::pbkdf2_for_seed(pin, salt, iterations, &mut km);
    km
}

/// The KDF cost a blob names, without doing any of that work.
///
/// Callers that want to refuse an unreasonable blob before paying for it use
/// this. [`decrypt_seed`] applies the identical check in its own length
/// dispatch, which is reached before [`derive_km`] — the ceiling is the only
/// pre-KDF defence there is, because the header's MAC key is PBKDF2 output
/// block 2 and so cannot be checked until the work has already been done.
pub fn blob_iterations(blob: &[u8]) -> Result<u32, SeedCipherError> {
    match blob.len() {
        LEGACY_BLOB_LEN => Ok(LEGACY_PBKDF2_ITERATIONS),
        BLOB_LEN => parse_current_header(blob),
        _ => Err(SeedCipherError::BadLength),
    }
}

/// Whether `len` is a format length which may represent an encrypted seed.
/// This deliberately answers only the length question; callers still pass the
/// bytes to [`decrypt_seed`] before treating the seed as usable.
pub const fn is_blob_len(len: usize) -> bool {
    len == LEGACY_BLOB_LEN || len == BLOB_LEN
}

fn header(iterations: u32) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[..4].copy_from_slice(&HEADER_MAGIC);
    out[4] = FORMAT_VERSION;
    out[5..].copy_from_slice(&iterations.to_be_bytes());
    out
}

fn parse_current_header(blob: &[u8]) -> Result<u32, SeedCipherError> {
    if blob[..4] != HEADER_MAGIC || blob[4] != FORMAT_VERSION {
        return Err(SeedCipherError::UnsupportedFormat);
    }
    let iterations =
        u32::from_be_bytes(blob[5..HEADER_LEN].try_into().expect("fixed header length"));
    if iterations == 0 || iterations > MAX_PBKDF2_ITERATIONS {
        return Err(SeedCipherError::InvalidIterations);
    }
    Ok(iterations)
}

fn encrypt_seed_with_iterations(
    pin: &[u8],
    seed: &[u8; SEED_LEN],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    iterations: u32,
) -> Vec<u8> {
    assert!(
        iterations > 0 && iterations <= MAX_PBKDF2_ITERATIONS,
        "invalid PBKDF2 iteration count"
    );
    let header = header(iterations);
    let mut km = derive_km(pin, salt, iterations);
    let (enc_key, mac_key) = km.split_at(32);

    let mut ct = *seed;
    let mut cipher = ChaCha20::new(enc_key.into(), nonce.into());
    cipher.apply_keystream(&mut ct);

    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
    // The KDF cost and format identifier are authenticated too. The count also
    // chooses the key, but making the framing explicit keeps this invariant
    // true if the KDF construction changes in a later format.
    mac.update(&header);
    mac.update(nonce);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();

    let mut blob = Vec::with_capacity(BLOB_LEN);
    blob.extend_from_slice(&header);
    blob.extend_from_slice(salt);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag);

    km.zeroize();
    ct.zeroize();
    blob
}

/// Encrypt a 32-byte seed under a PIN. `salt` and `nonce` must be random and
/// fresh per encryption (the caller supplies them so this stays deterministic
/// and host-testable; the device draws them from its TRNG). Returns the
/// [`BLOB_LEN`]-byte blob with an authenticated format/cost header. Existing
/// 92-byte blobs remain accepted by [`decrypt_seed`].
pub fn encrypt_seed(
    pin: &[u8],
    seed: &[u8; SEED_LEN],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    encrypt_seed_with_iterations(pin, seed, salt, nonce, PBKDF2_ITERATIONS)
}

/// Decrypt a blob under a PIN. A wrong PIN (or any tampering) fails the
/// constant-time MAC check and returns [`SeedCipherError::WrongPinOrTampered`]
/// — never a garbage seed.
pub fn decrypt_seed(pin: &[u8], blob: &[u8]) -> Result<[u8; SEED_LEN], SeedCipherError> {
    let (header, iterations, body) = match blob.len() {
        LEGACY_BLOB_LEN => (None, LEGACY_PBKDF2_ITERATIONS, blob),
        BLOB_LEN => (
            Some(&blob[..HEADER_LEN]),
            parse_current_header(blob)?,
            &blob[HEADER_LEN..],
        ),
        _ => return Err(SeedCipherError::BadLength),
    };
    let salt = &body[0..SALT_LEN];
    let nonce = &body[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ct = &body[SALT_LEN + NONCE_LEN..SALT_LEN + NONCE_LEN + SEED_LEN];
    let tag = &body[SALT_LEN + NONCE_LEN + SEED_LEN..];

    let mut km = derive_km(pin, salt, iterations);
    let (enc_key, mac_key) = km.split_at(32);

    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
    if let Some(header) = header {
        mac.update(header);
    }
    mac.update(nonce);
    mac.update(ct);
    if mac.verify_slice(tag).is_err() {
        km.zeroize();
        return Err(SeedCipherError::WrongPinOrTampered);
    }

    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(ct);
    let mut cipher = ChaCha20::new(enc_key.into(), nonce.into());
    cipher.apply_keystream(&mut seed);

    km.zeroize();
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &[u8] = b"123456";
    const SEED: [u8; 32] = [0x42; 32];
    const SALT: [u8; 16] = [7u8; 16];
    const NONCE: [u8; 12] = [9u8; 12];

    #[test]
    fn roundtrip() {
        let blob = encrypt_seed(PIN, &SEED, &SALT, &NONCE);
        assert_eq!(blob.len(), BLOB_LEN);
        assert_eq!(decrypt_seed(PIN, &blob).unwrap(), SEED);
    }

    #[test]
    fn ciphertext_is_not_the_seed() {
        let blob = encrypt_seed(PIN, &SEED, &SALT, &NONCE);
        // The ciphertext region must not equal the plaintext seed.
        let ct =
            &blob[HEADER_LEN + SALT_LEN + NONCE_LEN..HEADER_LEN + SALT_LEN + NONCE_LEN + SEED_LEN];
        assert_ne!(ct, &SEED[..]);
    }

    #[test]
    fn wrong_pin_fails() {
        let blob = encrypt_seed(PIN, &SEED, &SALT, &NONCE);
        assert_eq!(
            decrypt_seed(b"654321", &blob),
            Err(SeedCipherError::WrongPinOrTampered)
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut blob = encrypt_seed(PIN, &SEED, &SALT, &NONCE);
        blob[HEADER_LEN + SALT_LEN + NONCE_LEN] ^= 1; // flip a ciphertext bit
        assert_eq!(
            decrypt_seed(PIN, &blob),
            Err(SeedCipherError::WrongPinOrTampered)
        );
    }

    #[test]
    fn tampered_salt_fails() {
        let mut blob = encrypt_seed(PIN, &SEED, &SALT, &NONCE);
        blob[HEADER_LEN] ^= 1; // different salt -> different km -> tag mismatch
        assert_eq!(
            decrypt_seed(PIN, &blob),
            Err(SeedCipherError::WrongPinOrTampered)
        );
    }

    #[test]
    fn bad_length_fails() {
        assert_eq!(
            decrypt_seed(PIN, &[0u8; 10]),
            Err(SeedCipherError::BadLength)
        );
    }

    #[test]
    fn distinct_salt_nonce_give_distinct_blobs() {
        let a = encrypt_seed(PIN, &SEED, &SALT, &NONCE);
        let b = encrypt_seed(PIN, &SEED, &[8u8; 16], &[3u8; 12]);
        assert_ne!(a, b);
        // …but both decrypt back to the same seed.
        assert_eq!(decrypt_seed(PIN, &a).unwrap(), SEED);
        assert_eq!(decrypt_seed(PIN, &b).unwrap(), SEED);
    }

    #[test]
    fn vault_key_roundtrip() {
        // The host-held vault key is a 32-byte binary secret fed through the
        // same KDF/AEAD path as the ASCII PIN — pin length is not special-cased.
        let vault_key = [0xA5u8; 32];
        let blob = encrypt_seed(&vault_key, &SEED, &SALT, &NONCE);
        assert_eq!(decrypt_seed(&vault_key, &blob).unwrap(), SEED);

        // A one-bit-different vault key must fail the AEAD check.
        let mut wrong = vault_key;
        wrong[0] ^= 1;
        assert_eq!(
            decrypt_seed(&wrong, &blob),
            Err(SeedCipherError::WrongPinOrTampered)
        );
    }

    #[test]
    fn legacy_blob_still_unlocks_at_the_legacy_cost() {
        let mut km = derive_km(PIN, &SALT, LEGACY_PBKDF2_ITERATIONS);
        let (enc_key, mac_key) = km.split_at(32);
        let mut ct = SEED;
        ChaCha20::new(enc_key.into(), (&NONCE).into()).apply_keystream(&mut ct);
        let mut mac = HmacSha256::new_from_slice(mac_key).unwrap();
        mac.update(&NONCE);
        mac.update(&ct);
        let tag = mac.finalize().into_bytes();
        let mut legacy = Vec::with_capacity(LEGACY_BLOB_LEN);
        legacy.extend_from_slice(&SALT);
        legacy.extend_from_slice(&NONCE);
        legacy.extend_from_slice(&ct);
        legacy.extend_from_slice(&tag);
        km.zeroize();
        ct.zeroize();

        assert_eq!(legacy.len(), LEGACY_BLOB_LEN);
        assert_eq!(decrypt_seed(PIN, &legacy).unwrap(), SEED);
    }

    #[test]
    fn current_blob_authenticates_its_cost_and_format() {
        let mut blob = encrypt_seed_with_iterations(PIN, &SEED, &SALT, &NONCE, 2);
        assert_eq!(decrypt_seed(PIN, &blob).unwrap(), SEED);

        blob[HEADER_LEN - 1] ^= 1;
        assert_eq!(
            decrypt_seed(PIN, &blob),
            Err(SeedCipherError::WrongPinOrTampered)
        );

        let mut unsupported = encrypt_seed(PIN, &SEED, &SALT, &NONCE);
        unsupported[4] = FORMAT_VERSION + 1;
        assert_eq!(
            decrypt_seed(PIN, &unsupported),
            Err(SeedCipherError::UnsupportedFormat)
        );
    }

    #[test]
    fn corrupted_iteration_count_refuses_before_the_kdf() {
        let mut blob = encrypt_seed(PIN, &SEED, &SALT, &NONCE);
        blob[5..HEADER_LEN].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            decrypt_seed(PIN, &blob),
            Err(SeedCipherError::InvalidIterations)
        );

        blob[5..HEADER_LEN].copy_from_slice(&(MAX_PBKDF2_ITERATIONS + 1).to_be_bytes());
        assert_eq!(
            decrypt_seed(PIN, &blob),
            Err(SeedCipherError::InvalidIterations)
        );
    }

    /// The ceiling is checked by parsing the header, which is all that can be
    /// done before the KDF: the MAC key IS PBKDF2 output block 2, so the
    /// header's authentication tag cannot be verified until after the work
    /// the header asked for has been performed. `blob_iterations` is that
    /// pre-KDF check on its own, and `decrypt_seed` reaches `derive_km` only
    /// through it.
    #[test]
    fn the_iteration_ceiling_is_checked_before_any_kdf_work() {
        let mut blob = encrypt_seed(PIN, &SEED, &SALT, &NONCE);

        // At the ceiling: accepted by the pre-KDF check (not run here — it is
        // 150,000 rounds).
        blob[5..HEADER_LEN].copy_from_slice(&MAX_PBKDF2_ITERATIONS.to_be_bytes());
        assert_eq!(blob_iterations(&blob), Ok(MAX_PBKDF2_ITERATIONS));

        // One above: refused, with no KDF performed.
        blob[5..HEADER_LEN].copy_from_slice(&(MAX_PBKDF2_ITERATIONS + 1).to_be_bytes());
        assert_eq!(
            blob_iterations(&blob),
            Err(SeedCipherError::InvalidIterations)
        );
        assert_eq!(
            decrypt_seed(PIN, &blob),
            Err(SeedCipherError::InvalidIterations)
        );

        // A wildly corrupted count is refused the same way, instantly.
        blob[5..HEADER_LEN].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            decrypt_seed(PIN, &blob),
            Err(SeedCipherError::InvalidIterations)
        );

        // Both stored formats answer the question without hashing anything.
        assert_eq!(
            blob_iterations(&[0u8; LEGACY_BLOB_LEN]),
            Ok(LEGACY_PBKDF2_ITERATIONS)
        );
        assert_eq!(blob_iterations(&[0u8; 10]), Err(SeedCipherError::BadLength));
    }

    /// The ceiling must stay above what this firmware writes, and below what
    /// the slowest supported path can finish inside the 60 s task watchdog.
    /// The arithmetic is on the constant; this pins it so a future retune
    /// cannot quietly break either end.
    #[test]
    fn the_ceiling_brackets_the_shipped_cost_and_the_watchdog() {
        assert!(PBKDF2_ITERATIONS <= MAX_PBKDF2_ITERATIONS);
        assert!(LEGACY_PBKDF2_ITERATIONS <= MAX_PBKDF2_ITERATIONS);

        // 290 us per iteration, measured on a V4 software unseal.
        const MEASURED_US_PER_ITERATION: u64 = 290;
        const WATCHDOG_US: u64 = 60_000_000;
        let worst = MAX_PBKDF2_ITERATIONS as u64 * MEASURED_US_PER_ITERATION;
        assert!(
            worst < WATCHDOG_US,
            "ceiling of {MAX_PBKDF2_ITERATIONS} is {worst} us of software work, \
             which does not fit the {WATCHDOG_US} us watchdog window"
        );
        // …and with at least 20% of the window to spare.
        assert!(worst * 10 <= WATCHDOG_US * 8);
    }
}
