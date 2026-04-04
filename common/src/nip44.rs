// common/src/nip44.rs
//
// NIP-44 v2 — conversation key derivation, encryption, and decryption.
//
// Protocol:
//   1. Derive a conversation key via ECDH + HKDF-SHA256.
//   2. For each message, derive per-message keys via HKDF-expand with the
//      conversation key as PRK and a 32-byte random nonce as info (→ 76 bytes).
//   3. Encrypt with ChaCha20 (12-byte nonce from HKDF output).
//   4. Authenticate with HMAC-SHA256.
//   5. Base64-encode the output.
//
// Wire format (before base64):
//   version(1) || nonce(32) || ciphertext(N) || hmac(32)
//
// where version = 0x02 for NIP-44 v2.
//
// Both k256 and secp256k1 backends are supported (same cfg pattern as
// derive.rs).  Tests run against the k256 backend.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// NIP-44 v2 version byte.
const VERSION: u8 = 0x02;

// ---------------------------------------------------------------------------
// Conversation key
// ---------------------------------------------------------------------------

/// Derive a 32-byte conversation key from our secret key and a peer's x-only
/// public key (32 bytes, no prefix).
///
/// Computes ECDH to obtain the shared point's x-coordinate, then applies
/// HKDF-SHA256 with salt `"nip44-v2"` to derive the conversation key.
pub fn get_conversation_key(
    our_secret: &[u8; 32],
    peer_pubkey: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    let shared_x = ecdh_shared_x(our_secret, peer_pubkey)?;
    conversation_key_from_shared_x(&shared_x)
}

/// Internal: HKDF-extract that takes a shared x-coordinate → conversation key.
///
/// Per NIP-44 v2: `hkdf_extract(sha256, shared_x, "nip44-v2")`.
/// This is extract only — no expand step.
fn conversation_key_from_shared_x(shared_x: &[u8; 32]) -> Result<[u8; 32], &'static str> {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), shared_x);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    Ok(out)
}

// ---------------------------------------------------------------------------
// ECDH backends
// ---------------------------------------------------------------------------

/// Compute the x-coordinate of the ECDH shared point.
/// `peer_pubkey` is the x-only (32-byte) public key; we add an even-y prefix
/// to make it a compressed SEC1 point.
#[cfg(feature = "k256-backend")]
fn ecdh_shared_x(
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
    let encoded = EncodedPoint::from_bytes(&compressed)
        .map_err(|_| "invalid peer pubkey encoding")?;

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

#[cfg(feature = "secp256k1-backend")]
fn ecdh_shared_x(
    our_secret: &[u8; 32],
    peer_pubkey: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    use secp256k1::{ecdh::shared_secret_point, PublicKey, SecretKey};

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
// Padding
// ---------------------------------------------------------------------------

/// Pad plaintext for encryption per NIP-44 v2.
///
/// Format: 2-byte big-endian length || plaintext || zero bytes.
/// Total length = 2 + calc_padded_len(msg_len).
/// The 2-byte length prefix is outside the padded message block.
fn pad(plaintext: &str) -> Result<Vec<u8>, &'static str> {
    let msg = plaintext.as_bytes();
    let msg_len = msg.len();
    if msg_len == 0 {
        return Err("plaintext must not be empty");
    }
    if msg_len > 65535 {
        return Err("plaintext too long (max 65535 bytes)");
    }

    let padded_msg_len = calc_padded_len(msg_len);
    let total_len = 2 + padded_msg_len;

    let mut buf = vec![0u8; total_len];
    buf[0] = ((msg_len >> 8) & 0xff) as u8;
    buf[1] = (msg_len & 0xff) as u8;
    buf[2..2 + msg_len].copy_from_slice(msg);
    // remaining bytes are zero (already zeroed)
    Ok(buf)
}

/// Calculate padded message length per NIP-44 v2.
///
/// For messages ≤ 32 bytes, pads to 32.
/// For longer messages, rounds up to the next boundary that leaks minimal
/// length information (based on powers of two with chunking).
fn calc_padded_len(msg_len: usize) -> usize {
    if msg_len <= 32 {
        return 32;
    }
    // chunk = floor(log2(msg_len - 1)) - 4
    let bits = usize::BITS - (msg_len - 1).leading_zeros();
    let chunk = (bits as usize) - 1 - 4;
    let chunk_size = 1usize << chunk;
    // s = floor((msg_len - 1) / chunk_size) + 1
    let s = (msg_len - 1) / chunk_size + 1;
    s * chunk_size
}

/// Remove NIP-44 padding and return the original plaintext string.
fn unpad(data: &[u8]) -> Result<&str, &'static str> {
    if data.len() < 2 {
        return Err("padded data too short");
    }
    let msg_len = ((data[0] as usize) << 8) | (data[1] as usize);
    if 2 + msg_len > data.len() {
        return Err("declared length exceeds data");
    }
    core::str::from_utf8(&data[2..2 + msg_len]).map_err(|_| "invalid UTF-8 in plaintext")
}


// ---------------------------------------------------------------------------
// Message key derivation
// ---------------------------------------------------------------------------

/// Derive per-message keys from the conversation key and a 32-byte nonce.
///
/// Uses HKDF-expand only (conversation key is already the PRK from the
/// extract step during conversation key derivation). The nonce is the info
/// parameter, producing 76 bytes: chacha_key(32) + chacha_nonce(12) + hmac_key(32).
fn derive_message_keys(
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<([u8; 32], [u8; 12], [u8; 32]), &'static str> {
    let hk = Hkdf::<Sha256>::from_prk(conversation_key)
        .map_err(|_| "HKDF from_prk failed")?;
    let mut okm = [0u8; 76];
    hk.expand(nonce.as_slice(), &mut okm)
        .map_err(|_| "HKDF expand (message keys) failed")?;

    let mut chacha_key = [0u8; 32];
    let mut chacha_nonce = [0u8; 12];
    let mut hmac_key = [0u8; 32];

    chacha_key.copy_from_slice(&okm[..32]);
    chacha_nonce.copy_from_slice(&okm[32..44]);
    hmac_key.copy_from_slice(&okm[44..76]);

    Ok((chacha_key, chacha_nonce, hmac_key))
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` under `conversation_key` using the supplied `nonce`.
///
/// The caller is responsible for providing a cryptographically random 32-byte
/// nonce for each message.  Nonce reuse under the same conversation key is
/// catastrophic — it fully reveals both plaintexts.
///
/// Returns a base64-encoded string in NIP-44 v2 wire format.
pub fn encrypt(
    conversation_key: &[u8; 32],
    plaintext: &str,
    nonce: &[u8; 32],
) -> Result<String, &'static str> {
    let padded = pad(plaintext)?;
    let (chacha_key, chacha_nonce, hmac_key) = derive_message_keys(conversation_key, nonce)?;

    // Encrypt padded plaintext in-place with ChaCha20.
    let mut ciphertext = padded;
    let mut cipher = ChaCha20::new(
        chacha_key.as_slice().into(),
        chacha_nonce.as_slice().into(),
    );
    cipher.apply_keystream(&mut ciphertext);

    // HMAC-SHA256 over nonce || ciphertext (version byte excluded per NIP-44).
    let mut mac = HmacSha256::new_from_slice(&hmac_key)
        .map_err(|_| "HMAC init failed")?;
    mac.update(nonce);
    mac.update(&ciphertext);
    let tag = mac.finalize().into_bytes();

    // Build wire format: version(1) || nonce(32) || ciphertext(N) || hmac(32)
    let mut payload = Vec::with_capacity(1 + 32 + ciphertext.len() + 32);
    payload.push(VERSION);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&tag);

    Ok(BASE64.encode(&payload))
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

/// Decrypt a NIP-44 v2 ciphertext produced by [`encrypt`].
///
/// Verifies the HMAC before decrypting (encrypt-then-MAC).
/// Returns an error on any verification or format failure.
pub fn decrypt(
    conversation_key: &[u8; 32],
    ciphertext_b64: &str,
) -> Result<String, &'static str> {
    let payload = BASE64
        .decode(ciphertext_b64.trim())
        .map_err(|_| "invalid base64")?;

    // Minimum: version(1) + nonce(32) + padded_content(32) + hmac(32) = 97
    if payload.len() < 97 {
        return Err("ciphertext too short");
    }

    // Check version byte.
    if payload[0] != VERSION {
        return Err("unsupported NIP-44 version");
    }

    // Split payload: version(1) || nonce(32) || ciphertext(N) || hmac(32)
    let nonce_bytes: &[u8; 32] = payload[1..33]
        .try_into()
        .map_err(|_| "nonce extraction failed")?;
    let hmac_offset = payload.len() - 32;
    let encrypted = &payload[33..hmac_offset];
    let received_tag = &payload[hmac_offset..];

    let (chacha_key, chacha_nonce, hmac_key) = derive_message_keys(conversation_key, nonce_bytes)?;

    // Verify MAC over nonce || ciphertext (version byte excluded per NIP-44).
    let mut mac = HmacSha256::new_from_slice(&hmac_key)
        .map_err(|_| "HMAC init failed")?;
    mac.update(&payload[1..hmac_offset]); // nonce || ciphertext (skip version byte)
    mac.verify_slice(received_tag)
        .map_err(|_| "HMAC verification failed")?;

    // Decrypt in-place.
    let mut plaintext_padded = encrypted.to_vec();
    let mut cipher = ChaCha20::new(
        chacha_key.as_slice().into(),
        chacha_nonce.as_slice().into(),
    );
    cipher.apply_keystream(&mut plaintext_padded);

    // Unpad and return.
    let text = unpad(&plaintext_padded)?;
    Ok(text.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // A pair of valid secp256k1 secrets and their corresponding pubkeys.
    // Generated via crate::derive::backend::pubkey_from_secret.
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

    /// Derive the x-only public key for a given secret using the crate backend.
    fn pubkey_for(secret: &[u8; 32]) -> [u8; 32] {
        crate::derive::backend::pubkey_from_secret(secret).expect("test secret should be valid")
    }

    fn fixed_nonce() -> [u8; 32] {
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ]
    }

    // ------------------------------------------------------------------

    #[test]
    fn test_pad_unpad_roundtrip() {
        let msg = "Hello, Nostr!";
        let padded = pad(msg).unwrap();
        let result = unpad(&padded).unwrap();
        assert_eq!(result, msg);
    }

    #[test]
    fn test_pad_length_minimum() {
        // Short messages must pad to 2 (length prefix) + 32 (min padded len) = 34.
        let padded = pad("hi").unwrap();
        assert_eq!(padded.len(), 34, "padded length should be 2 + 32");
    }

    #[test]
    fn test_pad_empty_rejected() {
        // NIP-44 does not allow empty plaintext.
        assert!(pad("").is_err(), "empty plaintext must be rejected");
    }

    #[test]
    fn test_calc_padded_len() {
        assert_eq!(calc_padded_len(1), 32);
        assert_eq!(calc_padded_len(32), 32);
        assert_eq!(calc_padded_len(33), 34);
        assert_eq!(calc_padded_len(64), 64);
        assert_eq!(calc_padded_len(65), 68);
    }

    #[test]
    fn test_conversation_key_deterministic() {
        let alice_sk = alice_secret();
        let bob_pk = pubkey_for(&bob_secret());

        let key1 = get_conversation_key(&alice_sk, &bob_pk).unwrap();
        let key2 = get_conversation_key(&alice_sk, &bob_pk).unwrap();
        assert_eq!(key1, key2, "conversation key must be deterministic");
    }

    #[test]
    fn test_conversation_key_symmetric() {
        // Alice's view: ECDH(alice_sk, bob_pk) should equal Bob's view: ECDH(bob_sk, alice_pk)
        let alice_sk = alice_secret();
        let bob_sk = bob_secret();
        let alice_pk = pubkey_for(&alice_sk);
        let bob_pk = pubkey_for(&bob_sk);

        let key_alice = get_conversation_key(&alice_sk, &bob_pk).unwrap();
        let key_bob = get_conversation_key(&bob_sk, &alice_pk).unwrap();

        assert_eq!(
            key_alice, key_bob,
            "ECDH must be symmetric: Alice and Bob must derive the same conversation key"
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let alice_sk = alice_secret();
        let bob_sk = bob_secret();
        let bob_pk = pubkey_for(&bob_sk);
        let alice_pk = pubkey_for(&alice_sk);

        let conv_key_alice = get_conversation_key(&alice_sk, &bob_pk).unwrap();
        let conv_key_bob = get_conversation_key(&bob_sk, &alice_pk).unwrap();
        assert_eq!(conv_key_alice, conv_key_bob);

        let nonce = fixed_nonce();
        let plaintext = "This is a secret message for Bob.";

        let encrypted = encrypt(&conv_key_alice, plaintext, &nonce).unwrap();
        let decrypted = decrypt(&conv_key_bob, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_empty_string_rejected() {
        let alice_sk = alice_secret();
        let bob_pk = pubkey_for(&bob_secret());
        let conv_key = get_conversation_key(&alice_sk, &bob_pk).unwrap();
        let nonce = fixed_nonce();

        assert!(encrypt(&conv_key, "", &nonce).is_err(), "empty plaintext must be rejected");
    }

    #[test]
    fn test_encrypt_is_deterministic_with_same_nonce() {
        let alice_sk = alice_secret();
        let bob_pk = pubkey_for(&bob_secret());
        let conv_key = get_conversation_key(&alice_sk, &bob_pk).unwrap();
        let nonce = fixed_nonce();
        let msg = "deterministic test";

        let enc1 = encrypt(&conv_key, msg, &nonce).unwrap();
        let enc2 = encrypt(&conv_key, msg, &nonce).unwrap();
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let alice_sk = alice_secret();
        let bob_pk = pubkey_for(&bob_secret());
        let conv_key = get_conversation_key(&alice_sk, &bob_pk).unwrap();
        let nonce = fixed_nonce();

        let encrypted = encrypt(&conv_key, "secret", &nonce).unwrap();

        // Use a different conversation key — derived from a different pair.
        let wrong_key: [u8; 32] = [0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                                   0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                                   0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                                   0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef];
        let result = decrypt(&wrong_key, &encrypted);
        assert!(result.is_err(), "decryption with wrong key must fail");
    }

    #[test]
    fn test_decrypt_invalid_base64_fails() {
        let conv_key = [0u8; 32];
        let result = decrypt(&conv_key, "not!valid!base64!!!");
        assert!(result.is_err(), "invalid base64 must return an error");
    }

    #[test]
    fn test_decrypt_too_short_fails() {
        let conv_key = [0u8; 32];
        // Base64 of only 10 bytes — well below the 97-byte minimum.
        let short = BASE64.encode(&[0u8; 10]);
        let result = decrypt(&conv_key, &short);
        assert!(result.is_err(), "too-short ciphertext must return an error");
    }

    #[test]
    fn test_decrypt_wrong_version_fails() {
        let alice_sk = alice_secret();
        let bob_pk = pubkey_for(&bob_secret());
        let conv_key = get_conversation_key(&alice_sk, &bob_pk).unwrap();
        let nonce = fixed_nonce();

        let encrypted = encrypt(&conv_key, "test", &nonce).unwrap();
        let mut raw = BASE64.decode(&encrypted).unwrap();
        raw[0] = 0x01; // alter the version byte
        let tampered = BASE64.encode(&raw);

        let result = decrypt(&conv_key, &tampered);
        assert!(result.is_err(), "wrong version byte must return an error");
    }

    // ------------------------------------------------------------------
    // Official NIP-44 test vectors from paulmillr/nip44
    // https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json
    // ------------------------------------------------------------------

    fn hex_to_32(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn test_official_conversation_key_vector_0() {
        // Vector 0 from v2.valid.get_conversation_key
        let sec1 = hex_to_32("315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268");
        let pub2 = hex_to_32("c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133");
        let expected = hex_to_32("3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1");

        let result = get_conversation_key(&sec1, &pub2).unwrap();
        assert_eq!(result, expected, "conversation key must match official vector 0");
    }

    #[test]
    fn test_official_conversation_key_vector_1() {
        // Vector 1 from v2.valid.get_conversation_key
        let sec1 = hex_to_32("a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e");
        let pub2 = hex_to_32("03bb7947065dde12ba991ea045132581d0954f042c84e06d8c00066e23c1a800");
        let expected = hex_to_32("4d14f36e81b8452128da64fe6f1eae873baae2f444b02c950b90e43553f2178b");

        let result = get_conversation_key(&sec1, &pub2).unwrap();
        assert_eq!(result, expected, "conversation key must match official vector 1");
    }

    #[test]
    fn test_official_conversation_key_vector_2() {
        // Vector 2 from v2.valid.get_conversation_key
        let sec1 = hex_to_32("98a5902fd67518a0c900f0fb62158f278f94a21d6f9d33d30cd3091195500311");
        let pub2 = hex_to_32("aae65c15f98e5e677b5050de82e3aba47a6fe49b3dab7863cf35d9478ba9f7d1");
        let expected = hex_to_32("9c00b769d5f54d02bf175b7284a1cbd28b6911b06cda6666b2243561ac96bad7");

        let result = get_conversation_key(&sec1, &pub2).unwrap();
        assert_eq!(result, expected, "conversation key must match official vector 2");
    }

    #[test]
    fn test_official_encrypt_decrypt_vector_0() {
        // Vector 0 from v2.valid.encrypt_decrypt
        let conv_key = hex_to_32("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d");
        let nonce = hex_to_32("0000000000000000000000000000000000000000000000000000000000000001");
        let plaintext = "a";
        let expected_payload = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb";

        let encrypted = encrypt(&conv_key, plaintext, &nonce).unwrap();
        assert_eq!(encrypted, expected_payload, "encrypted payload must match official vector 0");

        let decrypted = decrypt(&conv_key, expected_payload).unwrap();
        assert_eq!(decrypted, plaintext, "decrypted plaintext must match official vector 0");
    }

    #[test]
    fn test_official_encrypt_decrypt_vector_1() {
        // Vector 1 from v2.valid.encrypt_decrypt (Unicode content)
        let conv_key = hex_to_32("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d");
        let nonce = hex_to_32("f00000000000000000000000000000f00000000000000000000000000000000f");
        let plaintext = "🍕🫃";
        let expected_payload = "AvAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAPSKSK6is9ngkX2+cSq85Th16oRTISAOfhStnixqZziKMDvB0QQzgFZdjLTPicCJaV8nDITO+QfaQ61+KbWQIOO2Yj";

        let encrypted = encrypt(&conv_key, plaintext, &nonce).unwrap();
        assert_eq!(encrypted, expected_payload, "encrypted payload must match official vector 1");

        let decrypted = decrypt(&conv_key, expected_payload).unwrap();
        assert_eq!(decrypted, plaintext, "decrypted plaintext must match official vector 1");
    }
}
