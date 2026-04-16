// common/src/derive.rs
//
// nsec-tree child key derivation via HMAC-SHA256.
// Matches heartwood-core byte-for-byte.
//
// Two backends: k256 (default, for host/tests) and secp256k1 (C FFI, for
// Xtensa firmware where k256's field arithmetic hangs).
//
// Only one backend may be active at a time. Activating both is a compile error.

#[cfg(all(feature = "k256-backend", feature = "secp256k1-backend"))]
compile_error!("heartwood-common: `k256-backend` and `secp256k1-backend` are mutually exclusive — enable exactly one");

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::encoding::encode_npub;
use crate::types::{Identity, TreeRoot, DOMAIN_PREFIX};
use crate::validate::validate_purpose;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Backend: secret → (valid secp256k1 scalar?, x-only pubkey bytes)
// ---------------------------------------------------------------------------

#[cfg(feature = "k256-backend")]
pub(crate) mod backend {
    use k256::schnorr::SigningKey;

    /// Validate a 32-byte secret as a secp256k1 scalar and return the x-only
    /// public key bytes, or None if the scalar is invalid (zero / ≥ order).
    pub fn pubkey_from_secret(secret: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let sk = SigningKey::from_bytes(secret).map_err(|_| "invalid secret key")?;
        Ok(sk.verifying_key().to_bytes().into())
    }
}

#[cfg(feature = "secp256k1-backend")]
pub(crate) mod backend {
    use secp256k1::{Keypair, Secp256k1};

    pub fn pubkey_from_secret(secret: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let secp = Secp256k1::signing_only();
        let keypair = Keypair::from_seckey_slice(&secp, secret)
            .map_err(|_| "invalid secret key")?;
        let (xonly, _) = keypair.x_only_public_key();
        Ok(xonly.serialize())
    }
}

#[cfg(not(any(feature = "k256-backend", feature = "secp256k1-backend")))]
compile_error!("heartwood-common requires either `k256-backend` or `secp256k1-backend` feature");

// ---------------------------------------------------------------------------
// Public API (backend-agnostic)
// ---------------------------------------------------------------------------

/// Derive a tree root secret from a raw nsec via HMAC-SHA256.
///
/// Matches PROTOCOL.md §1.2 and the reference implementations in
/// `nsec-tree/src/root-nsec.ts` and `heartwood-core/src/root.rs`:
///
///   tree_root = HMAC-SHA256(key = nsec_bytes, msg = utf8("nsec-tree-root"))
///
/// The returned 32-byte secret can be passed to `create_tree_root` to get a
/// fully usable `TreeRoot` for child derivation. This is the on-demand path
/// used by Bunker mode, where the stored master secret is a raw nsec.
pub fn nsec_to_tree_root(nsec: &[u8; 32]) -> Result<zeroize::Zeroizing<[u8; 32]>, &'static str> {
    let mut mac = HmacSha256::new_from_slice(nsec)
        .map_err(|_| "HMAC init failed")?;
    mac.update(b"nsec-tree-root");
    let result = mac.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&result.into_bytes());
    Ok(zeroize::Zeroizing::new(root))
}

/// Create a TreeRoot directly from a 32-byte secret (no HMAC intermediate).
///
/// The secret goes straight to the signing backend — this is the raw-secret
/// path, NOT the nsec import path (which applies an extra HMAC).
pub fn create_tree_root(secret: &[u8; 32]) -> Result<TreeRoot, &'static str> {
    let pubkey_bytes = backend::pubkey_from_secret(secret)?;
    let npub = encode_npub(&pubkey_bytes);
    Ok(TreeRoot::new(zeroize::Zeroizing::new(*secret), npub))
}

/// Build the HMAC context message for child key derivation.
///
/// Format: `b"nsec-tree\0" || purpose_utf8 || 0x00 || index_u32_big_endian`
fn build_context(purpose: &str, index: u32) -> Vec<u8> {
    let purpose_bytes = purpose.as_bytes();
    let mut msg = Vec::with_capacity(DOMAIN_PREFIX.len() + purpose_bytes.len() + 1 + 4);
    msg.extend_from_slice(DOMAIN_PREFIX);
    msg.extend_from_slice(purpose_bytes);
    msg.push(0x00);
    msg.extend_from_slice(&index.to_be_bytes());
    msg
}

/// Derive a child identity from a TreeRoot.
///
/// Uses HMAC-SHA256 with the root secret as key and a context message
/// containing the domain prefix, purpose, and index. Skips indices that
/// produce invalid secp256k1 scalars.
///
/// The purpose string is validated against PROTOCOL.md §3 rules (non-empty,
/// ≤255 bytes, no null bytes, not whitespace-only, no `|`) before derivation.
/// Previously this function hashed any caller-supplied `&str` without
/// checking, which meant a null byte in purpose would silently corrupt the
/// derivation message framing — an attacker who could inject bytes into a
/// NIP-46 RPC parameter could collide derivations between purposes.
pub fn derive(root: &TreeRoot, purpose: &str, index: u32) -> Result<Identity, &'static str> {
    validate_purpose(purpose)?;

    let secret = root.secret();
    let mut current_index = index;

    loop {
        let context = build_context(purpose, current_index);

        let mut mac =
            HmacSha256::new_from_slice(secret).map_err(|_| "HMAC init failed")?;
        mac.update(&context);
        let result = mac.finalize();
        let mut derived: [u8; 32] = result.into_bytes().into();

        match backend::pubkey_from_secret(&derived) {
            Ok(public_key) => {
                return Ok(Identity {
                    npub: encode_npub(&public_key),
                    private_key: zeroize::Zeroizing::new(derived),
                    public_key,
                    purpose: String::from(purpose),
                    index: current_index,
                });
            }
            Err(_) => {
                derived.zeroize();
                if current_index == u32::MAX {
                    return Err("index overflow: no valid key found");
                }
                current_index += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Phase 1 test vector — must match heartwood-core byte-for-byte.
    #[test]
    fn test_child_derivation_matches_heartwood_core() {
        let root_secret: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];

        let root = create_tree_root(&root_secret).unwrap();
        let identity = derive(&root, "persona/test", 0).unwrap();

        assert_eq!(
            identity.npub,
            "npub1rx8u4wk9ytu8aak4f9wcaqdgk0lj4rjhdu4j9n7dj2mg68l9cdqs2fjf2t",
            "derived npub does not match heartwood-core"
        );
    }

    /// nsec-to-tree-root HMAC vector — must match PROTOCOL.md §6.1 Vector 1
    /// and the reference implementations in nsec-tree and heartwood-core.
    #[test]
    fn test_nsec_to_tree_root_matches_frozen_vector() {
        let nsec_bytes = [0x01u8; 32];
        let root_secret = nsec_to_tree_root(&nsec_bytes).expect("nsec_to_tree_root must succeed");

        assert_eq!(
            crate::hex::hex_encode(&*root_secret),
            "8d2db9ce9548534e7ae924d05e311355e3a12744214c88e65b39fa2bf2df6d6f",
            "tree_root does not match PROTOCOL.md §6.1 Vector 1"
        );

        let root = create_tree_root(&root_secret).expect("invalid root secret");
        assert_eq!(
            root.master_npub,
            "npub13sp7q3awvrqpa9p2svm7w8ghudghlnrraekwl7qh8w7j8747vjwskvzy2u",
            "master npub does not match PROTOCOL.md §6.1 Vector 1"
        );
        root.destroy();
    }
}
