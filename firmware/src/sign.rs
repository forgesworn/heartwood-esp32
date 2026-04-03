// firmware/src/sign.rs
//
// BIP-340 Schnorr signing and verification via k256.

use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use signature::hazmat::{PrehashSigner, PrehashVerifier};

/// Sign a 32-byte hash with a BIP-340 Schnorr key. Returns a 64-byte signature.
pub fn sign_hash(private_key: &[u8; 32], hash: &[u8; 32]) -> Result<[u8; 64], &'static str> {
    let signing_key =
        SigningKey::from_bytes(private_key).map_err(|_| "invalid signing key")?;
    let sig: Signature = signing_key
        .sign_prehash(hash)
        .map_err(|_| "signing failed")?;
    Ok(sig.to_bytes())
}

/// Verify a BIP-340 Schnorr signature against a public key and hash.
pub fn verify_signature(
    public_key: &[u8; 32],
    hash: &[u8; 32],
    sig_bytes: &[u8; 64],
) -> Result<(), &'static str> {
    let vk =
        VerifyingKey::from_bytes(public_key).map_err(|_| "invalid verifying key")?;
    let sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| "invalid signature bytes")?;
    vk.verify_prehash(hash, &sig)
        .map_err(|_| "signature verification failed")
}
