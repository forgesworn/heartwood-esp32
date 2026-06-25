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
/// secret. Returns the 64-byte signature.
///
/// Signs the id **directly** and **deterministically**:
/// - Nostr signs the event id itself, so we must NOT re-hash it. The `Signer`
///   trait's `try_sign` does `sign_raw(Sha256(msg), …)` — that would sign
///   `sha256(event_id)`, and every signature would fail verification. We call
///   `sign_prehash_with_aux_rand`, which signs the 32-byte digest as-is.
/// - `aux_rand = 0` makes the BIP-340 nonce deterministic (derived from the key +
///   message), so signing needs **no RNG** — important on a radio-off lx106 whose
///   hardware RNG is poorly seeded.
pub fn sign(seed: &[u8; 32], message: &[u8; 32]) -> Option<[u8; 64]> {
    let sk = SigningKey::from_bytes(seed).ok()?;
    let sig = sk.sign_prehash_with_aux_rand(message, &[0u8; 32]).ok()?;
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.to_bytes().as_ref());
    Some(out)
}
