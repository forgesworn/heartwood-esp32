// common/src/derive.rs
//
// nsec-tree child key derivation via HMAC-SHA256.
// Matches heartwood-core byte-for-byte.

use hmac::{Hmac, Mac};
use k256::schnorr::SigningKey;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::encoding::encode_npub;
use crate::types::{Identity, TreeRoot, DOMAIN_PREFIX};

type HmacSha256 = Hmac<Sha256>;

/// Create a TreeRoot directly from a 32-byte secret (no HMAC intermediate).
pub fn create_tree_root(secret: &[u8; 32]) -> Result<TreeRoot, &'static str> {
    let signing_key =
        SigningKey::from_bytes(secret).map_err(|_| "invalid secret key")?;
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes: [u8; 32] = verifying_key.to_bytes().into();
    let npub = encode_npub(&pubkey_bytes);
    Ok(TreeRoot::new(zeroize::Zeroizing::new(*secret), npub))
}

/// Build the HMAC context message for child key derivation.
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
pub fn derive(root: &TreeRoot, purpose: &str, index: u32) -> Result<Identity, &'static str> {
    let secret = root.secret();
    let mut current_index = index;

    loop {
        let context = build_context(purpose, current_index);

        let mut mac =
            HmacSha256::new_from_slice(secret).map_err(|_| "HMAC init failed")?;
        mac.update(&context);
        let result = mac.finalize();
        let mut derived: [u8; 32] = result.into_bytes().into();

        match SigningKey::from_bytes(&derived) {
            Ok(signing_key) => {
                let verifying_key = signing_key.verifying_key();
                let public_key: [u8; 32] = verifying_key.to_bytes().into();

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
}
