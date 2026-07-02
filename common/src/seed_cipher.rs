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
//   blob      = salt(16) || nonce(12) || ct(32) || tag(32) = 92 bytes
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
/// Total on-disk length of an encrypted seed blob.
pub const BLOB_LEN: usize = SALT_LEN + NONCE_LEN + SEED_LEN + TAG_LEN; // 92

/// PBKDF2 iteration count. Deliberately slow to raise the per-guess cost of an
/// offline PIN brute-force. **Bench-tune this** to ~1–2 s on the slowest board
/// (the Heltec / lx106); it is a cost knob, not a correctness one, and can be
/// raised on new devices without breaking old blobs (the count is not stored —
/// so if it ever changes, existing blobs must be re-encrypted; keep it fixed
/// per protocol version, or store it in the blob if it must vary).
pub const PBKDF2_ITERATIONS: u32 = 100_000;

#[derive(Debug, PartialEq, Eq)]
pub enum SeedCipherError {
    /// Blob is not exactly [`BLOB_LEN`] bytes.
    BadLength,
    /// The MAC did not verify — wrong PIN or a tampered blob.
    WrongPinOrTampered,
}

/// Derive the 64-byte (enc || mac) key material from a PIN and salt.
fn derive_km(pin: &[u8], salt: &[u8]) -> [u8; 64] {
    let mut km = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha256>(pin, salt, PBKDF2_ITERATIONS, &mut km);
    km
}

/// Encrypt a 32-byte seed under a PIN. `salt` and `nonce` must be random and
/// fresh per encryption (the caller supplies them so this stays deterministic
/// and host-testable; the device draws them from its TRNG). Returns the
/// [`BLOB_LEN`]-byte blob `salt || nonce || ciphertext || tag`.
pub fn encrypt_seed(
    pin: &[u8],
    seed: &[u8; SEED_LEN],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let mut km = derive_km(pin, salt);
    let (enc_key, mac_key) = km.split_at(32);

    let mut ct = *seed;
    let mut cipher = ChaCha20::new(enc_key.into(), nonce.into());
    cipher.apply_keystream(&mut ct);

    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(nonce);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();

    let mut blob = Vec::with_capacity(BLOB_LEN);
    blob.extend_from_slice(salt);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag);

    km.zeroize();
    ct.zeroize();
    blob
}

/// Decrypt a blob under a PIN. A wrong PIN (or any tampering) fails the
/// constant-time MAC check and returns [`SeedCipherError::WrongPinOrTampered`]
/// — never a garbage seed.
pub fn decrypt_seed(pin: &[u8], blob: &[u8]) -> Result<[u8; SEED_LEN], SeedCipherError> {
    if blob.len() != BLOB_LEN {
        return Err(SeedCipherError::BadLength);
    }
    let salt = &blob[0..SALT_LEN];
    let nonce = &blob[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ct = &blob[SALT_LEN + NONCE_LEN..SALT_LEN + NONCE_LEN + SEED_LEN];
    let tag = &blob[SALT_LEN + NONCE_LEN + SEED_LEN..];

    let mut km = derive_km(pin, salt);
    let (enc_key, mac_key) = km.split_at(32);

    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
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
        let ct = &blob[SALT_LEN + NONCE_LEN..SALT_LEN + NONCE_LEN + SEED_LEN];
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
        blob[SALT_LEN + NONCE_LEN] ^= 1; // flip a ciphertext bit
        assert_eq!(
            decrypt_seed(PIN, &blob),
            Err(SeedCipherError::WrongPinOrTampered)
        );
    }

    #[test]
    fn tampered_salt_fails() {
        let mut blob = encrypt_seed(PIN, &SEED, &SALT, &NONCE);
        blob[0] ^= 1; // different salt -> different km -> tag mismatch
        assert_eq!(
            decrypt_seed(PIN, &blob),
            Err(SeedCipherError::WrongPinOrTampered)
        );
    }

    #[test]
    fn bad_length_fails() {
        assert_eq!(decrypt_seed(PIN, &[0u8; 10]), Err(SeedCipherError::BadLength));
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
}
