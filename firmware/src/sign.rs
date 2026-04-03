// firmware/src/sign.rs
//
// BIP-340 Schnorr signing and verification via libsecp256k1 (C FFI).
// Replaces k256 which hangs on Xtensa LX7 due to unaligned memory access.

use secp256k1::{Keypair, Message, Secp256k1, SignOnly, XOnlyPublicKey};

/// Sign a 32-byte hash with a BIP-340 Schnorr key. Returns a 64-byte signature.
///
/// Accepts a shared `Secp256k1<SignOnly>` context to avoid repeated ~130KB
/// heap allocations on ESP32.
pub fn sign_hash(
    secp: &Secp256k1<SignOnly>,
    private_key: &[u8; 32],
    hash: &[u8; 32],
) -> Result<[u8; 64], &'static str> {
    let keypair = Keypair::from_seckey_slice(secp, private_key)
        .map_err(|_| "invalid signing key")?;
    let msg = Message::from_digest(*hash);
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    Ok(*sig.as_ref())
}

/// Verify a BIP-340 Schnorr signature against a public key and hash.
pub fn verify_signature(
    public_key: &[u8; 32],
    hash: &[u8; 32],
    sig_bytes: &[u8; 64],
) -> Result<(), &'static str> {
    let secp = Secp256k1::verification_only();
    let xonly = XOnlyPublicKey::from_slice(public_key)
        .map_err(|_| "invalid verifying key")?;
    let sig = secp256k1::schnorr::Signature::from_slice(sig_bytes)
        .map_err(|_| "invalid signature bytes")?;
    let msg = Message::from_digest(*hash);
    secp.verify_schnorr(&sig, &msg, &xonly)
        .map_err(|_| "signature verification failed")
}
