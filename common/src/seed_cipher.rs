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
/// arbitrary-length CPU burn. This is deliberately a generous ceiling, not a
/// policy target; a retune still needs an actual slow-board measurement.
pub const MAX_PBKDF2_ITERATIONS: u32 = 1_000_000;

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
fn derive_km(pin: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    let mut km = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha256>(pin, salt, iterations, &mut km);
    km
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
}
