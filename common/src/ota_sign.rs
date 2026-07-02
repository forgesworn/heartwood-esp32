// common/src/ota_sign.rs
//
// OTA release-signature scheme: ed25519 over the firmware image's SHA-256
// digest, domain-separated by board.
//
// The signer (CI, via the `ota-sign` host tool) and the verifier (the device,
// in `firmware/src/ota.rs`) must agree on the exact message bytes, so both go
// through `ota_signing_message` here. The message binds:
//
//   * a protocol label ("heartwood-ota-v1") — a signature can never be
//     confused with any other ed25519 use of the release key;
//   * the board id AS THE DEVICE REPORTS IT (`board::BOARD`, e.g. "heltec-v4",
//     "esp32c6") — a signed image for one board cannot be replayed onto
//     another;
//   * the image's SHA-256 digest — the device recomputes this over the bytes
//     it actually wrote to flash, so the signature covers the real image, not
//     a claimed hash.
//
// Signing the 32-byte digest rather than the multi-megabyte image keeps
// verification a single pass: the device already streams the image through
// SHA-256 during transfer.
//
// Deliberately NOT bound: the firmware version. Verifying older signed
// releases must keep working so an owner can roll back a bad update — the
// device has no update health-check, so a forced-forward-only scheme would
// turn one bad release into a dead OTA path.

use alloc::vec::Vec;

use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};

/// Domain-separation label. Bump the suffix if the message layout ever changes.
const DOMAIN: &[u8] = b"heartwood-ota-v1";

/// ed25519 signature length in bytes.
pub const OTA_SIGNATURE_LEN: usize = 64;

/// ed25519 public-key length in bytes.
pub const OTA_PUBKEY_LEN: usize = 32;

/// ed25519 seed (private-key) length in bytes.
pub const OTA_SEED_LEN: usize = 32;

/// The exact byte string the release key signs for one firmware image:
/// `DOMAIN || 0x00 || board || 0x00 || sha256(image)`.
///
/// The NUL separators make the encoding injective — no (board, digest) pair
/// can collide with another's message bytes.
pub fn ota_signing_message(board: &str, digest: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DOMAIN.len() + 1 + board.len() + 1 + digest.len());
    msg.extend_from_slice(DOMAIN);
    msg.push(0);
    msg.extend_from_slice(board.as_bytes());
    msg.push(0);
    msg.extend_from_slice(digest);
    msg
}

/// Verify a release signature over an image digest for this board.
///
/// Fail-closed: any malformed key or signature (including the all-zero
/// placeholder key a repo carries before its real release key is generated)
/// returns `false`.
pub fn verify_ota_signature(
    pubkey: &[u8; OTA_PUBKEY_LEN],
    board: &str,
    digest: &[u8; 32],
    signature: &[u8; OTA_SIGNATURE_LEN],
) -> bool {
    let pk = match PublicKey::from_slice(pubkey) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = match Signature::from_slice(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    pk.verify(ota_signing_message(board, digest), &sig).is_ok()
}

/// Sign an image digest for a board. Deterministic (RFC 8032, no noise) so a
/// re-run of the release pipeline produces byte-identical signatures.
///
/// Host-side only in practice (the `ota-sign` tool and tests); the device
/// never holds the seed.
pub fn sign_ota_digest(
    seed: &[u8; OTA_SEED_LEN],
    board: &str,
    digest: &[u8; 32],
) -> [u8; OTA_SIGNATURE_LEN] {
    let kp = KeyPair::from_seed(Seed::new(*seed));
    *kp.sk.sign(ota_signing_message(board, digest), None)
}

/// The public key corresponding to a seed — what gets committed to the repo
/// and baked into the firmware.
pub fn ota_pubkey_from_seed(seed: &[u8; OTA_SEED_LEN]) -> [u8; OTA_PUBKEY_LEN] {
    let kp = KeyPair::from_seed(Seed::new(*seed));
    *kp.pk
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7u8; 32];
    const DIGEST: [u8; 32] = [0xAB; 32];

    #[test]
    fn roundtrip_verifies() {
        let pk = ota_pubkey_from_seed(&SEED);
        let sig = sign_ota_digest(&SEED, "heltec-v4", &DIGEST);
        assert!(verify_ota_signature(&pk, "heltec-v4", &DIGEST, &sig));
    }

    #[test]
    fn signing_is_deterministic() {
        assert_eq!(
            sign_ota_digest(&SEED, "heltec-v4", &DIGEST),
            sign_ota_digest(&SEED, "heltec-v4", &DIGEST)
        );
    }

    #[test]
    fn tampered_digest_is_rejected() {
        let pk = ota_pubkey_from_seed(&SEED);
        let sig = sign_ota_digest(&SEED, "heltec-v4", &DIGEST);
        let mut other = DIGEST;
        other[0] ^= 1;
        assert!(!verify_ota_signature(&pk, "heltec-v4", &other, &sig));
    }

    #[test]
    fn cross_board_replay_is_rejected() {
        let pk = ota_pubkey_from_seed(&SEED);
        let sig = sign_ota_digest(&SEED, "heltec-v4", &DIGEST);
        assert!(!verify_ota_signature(&pk, "heltec-v3", &DIGEST, &sig));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let other_pk = ota_pubkey_from_seed(&[9u8; 32]);
        let sig = sign_ota_digest(&SEED, "heltec-v4", &DIGEST);
        assert!(!verify_ota_signature(&other_pk, "heltec-v4", &DIGEST, &sig));
    }

    #[test]
    fn placeholder_zero_key_fails_closed() {
        let sig = sign_ota_digest(&SEED, "heltec-v4", &DIGEST);
        assert!(!verify_ota_signature(&[0u8; 32], "heltec-v4", &DIGEST, &sig));
    }

    #[test]
    fn corrupt_signature_is_rejected() {
        let pk = ota_pubkey_from_seed(&SEED);
        let mut sig = sign_ota_digest(&SEED, "heltec-v4", &DIGEST);
        sig[63] ^= 0x80;
        assert!(!verify_ota_signature(&pk, "heltec-v4", &DIGEST, &sig));
    }
}
