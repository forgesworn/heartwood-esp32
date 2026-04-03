// common/src/nip04.rs
//
// NIP-04 — legacy direct messages (AES-256-CBC + PKCS7).
//
// NIP-04 is deprecated in favour of NIP-44 (XChaCha20 + HMAC).  It is
// included here solely for backwards compatibility with older clients.
//
// Wire format produced by encrypt():
//   "<base64_ciphertext>?iv=<base64_iv>"
//
// Security notes:
//   - The shared secret is the raw ECDH x-coordinate with no key derivation.
//     This is cryptographically weak; prefer NIP-44 for new code.
//   - CBC mode without authentication is malleable — no integrity guarantee.
//   - Both k256 and secp256k1 backends are supported via cfg (same pattern as
//     nip44.rs and derive.rs).

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use cbc::{
    cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Decryptor, Encryptor,
};

// ---------------------------------------------------------------------------
// ECDH — backend-specific
// ---------------------------------------------------------------------------

/// Derive the shared secret for NIP-04.
///
/// Returns the raw x-coordinate of the ECDH shared point.  No HKDF is applied
/// — this is the intentionally weak construction specified by NIP-04.
///
/// `our_secret` — 32-byte private key scalar.
/// `peer_pubkey` — 32-byte x-only public key (no prefix byte).
#[cfg(feature = "k256-backend")]
pub fn get_shared_secret(
    our_secret: &[u8; 32],
    peer_pubkey: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    use k256::{
        ecdh::diffie_hellman,
        elliptic_curve::{sec1::FromEncodedPoint, CurveArithmetic},
        EncodedPoint, SecretKey,
    };

    let sk = SecretKey::from_slice(our_secret).map_err(|_| "invalid secret key")?;

    let mut compressed = [0u8; 33];
    compressed[0] = 0x02; // even-y prefix
    compressed[1..].copy_from_slice(peer_pubkey);
    let encoded =
        EncodedPoint::from_bytes(&compressed).map_err(|_| "invalid peer pubkey encoding")?;

    let pk = Option::<<k256::Secp256k1 as CurveArithmetic>::AffinePoint>::from(
        k256::AffinePoint::from_encoded_point(&encoded),
    )
    .ok_or("invalid peer pubkey point")?;

    let shared = diffie_hellman(sk.to_nonzero_scalar(), &pk);
    let raw = shared.raw_secret_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(raw.as_ref());
    Ok(out)
}

/// Derive the shared secret for NIP-04 (secp256k1-backend).
#[cfg(feature = "secp256k1-backend")]
pub fn get_shared_secret(
    our_secret: &[u8; 32],
    peer_pubkey: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    use secp256k1::{ecdh::shared_secret_point, PublicKey, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(our_secret).map_err(|_| "invalid secret key")?;

    let mut full_pk_bytes = [0u8; 33];
    full_pk_bytes[0] = 0x02; // even-y prefix
    full_pk_bytes[1..].copy_from_slice(peer_pubkey);
    let pk = PublicKey::from_slice(&full_pk_bytes).map_err(|_| "invalid peer pubkey")?;

    let shared_point = shared_secret_point(&pk, &sk);
    let mut out = [0u8; 32];
    out.copy_from_slice(&shared_point[..32]);
    Ok(out)
}

// ---------------------------------------------------------------------------
// PKCS7 padding helpers
// ---------------------------------------------------------------------------

/// Apply PKCS7 padding to reach a multiple of 16 bytes.
fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let block_size = 16usize;
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(core::iter::repeat(pad_len as u8).take(pad_len));
    padded
}

/// Remove PKCS7 padding and return the unpadded slice.
fn pkcs7_unpad(data: &[u8]) -> Result<&[u8], &'static str> {
    if data.is_empty() {
        return Err("empty data after decryption");
    }
    let pad_byte = *data.last().unwrap() as usize;
    if pad_byte == 0 || pad_byte > 16 {
        return Err("invalid PKCS7 padding value");
    }
    if data.len() < pad_byte {
        return Err("PKCS7 padding exceeds data length");
    }
    // Verify all padding bytes are consistent.
    let (content, padding) = data.split_at(data.len() - pad_byte);
    if padding.iter().any(|&b| b as usize != pad_byte) {
        return Err("PKCS7 padding bytes are inconsistent");
    }
    Ok(content)
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` using AES-256-CBC with the given `shared_secret` and `iv`.
///
/// The caller must supply a cryptographically random 16-byte IV for each
/// message.  IV reuse under the same key leaks XOR of first plaintext blocks.
///
/// Returns a string in NIP-04 wire format: `"<ciphertext_b64>?iv=<iv_b64>"`.
pub fn encrypt(
    shared_secret: &[u8; 32],
    plaintext: &str,
    iv: &[u8; 16],
) -> Result<String, &'static str> {
    let padded = pkcs7_pad(plaintext.as_bytes());

    // Encrypt with AES-256-CBC.
    let encryptor =
        Encryptor::<Aes256>::new(shared_secret.into(), iv.into());
    let ciphertext = encryptor.encrypt_padded_vec_mut::<NoPadding>(&padded);

    let ct_b64 = BASE64.encode(&ciphertext);
    let iv_b64 = BASE64.encode(iv);
    Ok(format!("{ct_b64}?iv={iv_b64}"))
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

/// Decrypt a NIP-04 ciphertext string (`"<ct_b64>?iv=<iv_b64>"`).
///
/// Returns the plaintext string on success, or a descriptive error.
pub fn decrypt(
    shared_secret: &[u8; 32],
    ciphertext: &str,
) -> Result<String, &'static str> {
    // Parse the wire format.
    let (ct_b64, iv_b64) = ciphertext
        .split_once("?iv=")
        .ok_or("invalid NIP-04 format: missing '?iv=' separator")?;

    let ct_bytes = BASE64
        .decode(ct_b64.trim())
        .map_err(|_| "invalid base64 in ciphertext")?;
    let iv_bytes = BASE64
        .decode(iv_b64.trim())
        .map_err(|_| "invalid base64 in IV")?;

    if ct_bytes.is_empty() {
        return Err("ciphertext is empty");
    }
    if iv_bytes.len() != 16 {
        return Err("IV must be exactly 16 bytes");
    }

    let iv: &[u8; 16] = iv_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "IV length mismatch")?;

    // Decrypt with AES-256-CBC (NoPadding — we handle PKCS7 ourselves).
    let decryptor = Decryptor::<Aes256>::new(shared_secret.into(), iv.into());
    let decrypted = decryptor
        .decrypt_padded_vec_mut::<NoPadding>(&ct_bytes)
        .map_err(|_| "AES-CBC decryption failed")?;

    let unpadded = pkcs7_unpad(&decrypted)?;
    core::str::from_utf8(unpadded)
        .map(|s| s.to_string())
        .map_err(|_| "decrypted plaintext is not valid UTF-8")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn alice_secret() -> [u8; 32] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ]
    }

    fn bob_secret() -> [u8; 32] {
        [
            0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17,
            0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f,
            0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
            0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x01,
        ]
    }

    fn pubkey_for(secret: &[u8; 32]) -> [u8; 32] {
        crate::derive::backend::pubkey_from_secret(secret).expect("test secret should be valid")
    }

    fn fixed_iv() -> [u8; 16] {
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ]
    }

    // ------------------------------------------------------------------

    #[test]
    fn test_nip04_encrypt_decrypt_roundtrip() {
        let alice_sk = alice_secret();
        let bob_sk = bob_secret();
        let alice_pk = pubkey_for(&alice_sk);
        let bob_pk = pubkey_for(&bob_sk);

        // Shared secrets must be symmetric.
        let shared_alice = get_shared_secret(&alice_sk, &bob_pk).unwrap();
        let shared_bob = get_shared_secret(&bob_sk, &alice_pk).unwrap();
        assert_eq!(
            shared_alice, shared_bob,
            "NIP-04 shared secret must be symmetric"
        );

        let plaintext = "Hello, NIP-04 world!";
        let iv = fixed_iv();

        // Alice encrypts; Bob decrypts.
        let ciphertext = encrypt(&shared_alice, plaintext, &iv).unwrap();
        let recovered = decrypt(&shared_bob, &ciphertext).unwrap();

        assert_eq!(recovered, plaintext, "roundtrip must recover the original plaintext");
    }

    #[test]
    fn test_nip04_decrypt_wrong_key_fails() {
        let alice_sk = alice_secret();
        let bob_pk = pubkey_for(&bob_secret());
        let shared = get_shared_secret(&alice_sk, &bob_pk).unwrap();

        let ciphertext = encrypt(&shared, "secret message", &fixed_iv()).unwrap();

        // A completely different key should fail to produce valid PKCS7 padding.
        let wrong_key: [u8; 32] = [0xde; 32];
        let result = decrypt(&wrong_key, &ciphertext);
        assert!(result.is_err(), "decryption with wrong key must fail");
    }

    #[test]
    fn test_nip04_invalid_format_fails() {
        let shared_secret = [0u8; 32];

        // Missing the '?iv=' separator.
        let result = decrypt(&shared_secret, "bm90dmFsaWQ=");
        assert!(
            result.is_err(),
            "ciphertext without '?iv=' separator must fail"
        );

        // Corrupted base64 in the ciphertext part.
        let result = decrypt(&shared_secret, "!!!invalid_b64!!!?iv=AAAAAAAAAAAAAAAAAAAAAA==");
        assert!(result.is_err(), "invalid base64 ciphertext must fail");

        // Wrong IV length (too short).
        let result = decrypt(&shared_secret, "AAAA?iv=AAAA");
        assert!(result.is_err(), "IV of wrong length must fail");
    }
}
