// heartwood-esp32/src/derive.rs
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
///
/// The secret goes straight to SigningKey — this is the raw-secret path,
/// NOT the nsec import path (which applies an extra HMAC).
pub fn create_tree_root(secret: &[u8; 32]) -> Result<TreeRoot, &'static str> {
    let signing_key =
        SigningKey::from_bytes(secret).map_err(|_| "invalid secret key")?;
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes: [u8; 32] = verifying_key.to_bytes().into();
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
