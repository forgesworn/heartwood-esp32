//! Cable trust-on-first-use identity.
//!
//! A board keeps one random Ed25519 seed in its own NVS namespace. It never
//! signs a note, Nostr event or firmware image: this module signs only the
//! bounded `identify` challenge transcript. A host may pin the returned
//! public key on first use and detect a different physical board later.

use alloc::vec::Vec;

use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};

/// Ed25519 seed and public-key size, in bytes.
pub const IDENTITY_SEED_LEN: usize = 32;
pub const IDENTITY_PUBKEY_LEN: usize = 32;
/// Ed25519 signature size, in bytes.
pub const IDENTITY_SIGNATURE_LEN: usize = 64;
/// The caller chooses a fresh challenge in this bounded range.
pub const IDENTITY_NONCE_MIN_LEN: usize = 16;
pub const IDENTITY_NONCE_MAX_LEN: usize = 32;

// This is deliberately compatible with lnurl-vault's existing `identify`
// consumer. The NUL separator makes the encoding injective and prevents a
// challenge signature being confused with another Ed25519 operation.
const DOMAIN: &[u8] = b"lnurlvault-id-v1";

/// A public response to an `identify` challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceIdentityProof {
    pub pubkey: [u8; IDENTITY_PUBKEY_LEN],
    pub signature: [u8; IDENTITY_SIGNATURE_LEN],
}

/// Return whether a seed is blank. An all-zero Ed25519 seed is syntactically
/// valid, but serving it would make every failed first boot share one identity.
pub fn seed_is_blank(seed: &[u8; IDENTITY_SEED_LEN]) -> bool {
    seed.iter().all(|byte| *byte == 0)
}

/// Build the exact domain-separated message signed for an `identify` nonce.
///
/// The bounded nonce keeps this interface a challenge-response proof instead
/// of a general-purpose signing oracle.
pub fn signing_message(nonce: &[u8]) -> Option<Vec<u8>> {
    if !(IDENTITY_NONCE_MIN_LEN..=IDENTITY_NONCE_MAX_LEN).contains(&nonce.len()) {
        return None;
    }
    let mut message = Vec::with_capacity(DOMAIN.len() + 1 + nonce.len());
    message.extend_from_slice(DOMAIN);
    message.push(0);
    message.extend_from_slice(nonce);
    Some(message)
}

/// Derive the board's public key and sign one bounded challenge.
pub fn sign_challenge(
    seed: &[u8; IDENTITY_SEED_LEN],
    nonce: &[u8],
) -> Option<DeviceIdentityProof> {
    if seed_is_blank(seed) {
        return None;
    }
    let message = signing_message(nonce)?;
    let pair = KeyPair::from_seed(Seed::new(*seed));
    Some(DeviceIdentityProof {
        pubkey: *pair.pk,
        signature: *pair.sk.sign(message, None),
    })
}

/// Verify an `identify` response, for host-side pinning tests and consumers.
pub fn verify_challenge(
    pubkey: &[u8; IDENTITY_PUBKEY_LEN],
    nonce: &[u8],
    signature: &[u8; IDENTITY_SIGNATURE_LEN],
) -> bool {
    let Some(message) = signing_message(nonce) else {
        return false;
    };
    let Ok(pubkey) = PublicKey::from_slice(pubkey) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    pubkey.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_A: [u8; IDENTITY_SEED_LEN] = [7u8; IDENTITY_SEED_LEN];
    const SEED_B: [u8; IDENTITY_SEED_LEN] = [8u8; IDENTITY_SEED_LEN];
    const NONCE: [u8; IDENTITY_NONCE_MIN_LEN] = [0xa5u8; IDENTITY_NONCE_MIN_LEN];

    #[test]
    fn proof_verifies_only_for_its_board_and_challenge() {
        let proof = sign_challenge(&SEED_A, &NONCE).unwrap();
        assert!(verify_challenge(&proof.pubkey, &NONCE, &proof.signature));

        let other = sign_challenge(&SEED_B, &NONCE).unwrap();
        assert_ne!(proof.pubkey, other.pubkey);
        assert!(!verify_challenge(&proof.pubkey, &NONCE, &other.signature));

        let mut changed = NONCE;
        changed[0] ^= 1;
        assert!(!verify_challenge(&proof.pubkey, &changed, &proof.signature));
    }

    #[test]
    fn transcript_is_bounded_and_domain_separated() {
        assert!(signing_message(&[0u8; IDENTITY_NONCE_MIN_LEN - 1]).is_none());
        assert!(signing_message(&[0u8; IDENTITY_NONCE_MAX_LEN + 1]).is_none());
        let message = signing_message(&NONCE).unwrap();
        assert_eq!(&message[..DOMAIN.len()], DOMAIN);
        assert_eq!(message[DOMAIN.len()], 0);
        assert_eq!(&message[DOMAIN.len() + 1..], NONCE);
    }

    #[test]
    fn blank_seed_is_never_a_device_identity() {
        assert!(seed_is_blank(&[0u8; IDENTITY_SEED_LEN]));
        assert!(sign_challenge(&[0u8; IDENTITY_SEED_LEN], &NONCE).is_none());
        assert!(!seed_is_blank(&SEED_A));
    }
}
