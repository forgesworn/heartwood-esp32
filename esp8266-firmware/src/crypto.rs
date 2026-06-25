//! Signing primitives — the BIP-340 path the `esp8266-spike` proved compiles
//! for xtensa-lx106 (k256, no_std, no-alloc).

use k256::schnorr::SigningKey;

/// Derive the 32-byte x-only public key from a 32-byte master secret.
/// `None` if the secret is not a valid secp256k1 scalar.
pub fn pubkey(seed: &[u8; 32]) -> Option<[u8; 32]> {
    let sk = SigningKey::from_bytes(seed).ok()?;
    let bytes = sk.verifying_key().to_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_ref());
    Some(out)
}

/// BIP-340 Schnorr sign a 32-byte message (a Nostr event id) with the master
/// secret. Deterministic. Returns the 64-byte signature.
pub fn sign(seed: &[u8; 32], message: &[u8; 32]) -> Option<[u8; 64]> {
    use k256::schnorr::signature::Signer;
    let sk = SigningKey::from_bytes(seed).ok()?;
    let sig: k256::schnorr::Signature = sk.try_sign(message).ok()?;
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.to_bytes().as_ref());
    Some(out)
}
