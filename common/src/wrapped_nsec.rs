//! nsec-tree WRAPPED-NSEC.md v1. Ciphertext plus the same tree root recovers
//! an imported raw key; this does not establish derivation or app authority.
use crate::{derive::public_key_xonly, encoding::encode_npub};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use alloc::{format, string::String, vec::Vec};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"NSTW\x01\x01\x01";
const INFO: &[u8] = b"nsec-tree/wrapped-nsec/v1";
pub const RECORD_LEN: usize = 181;
const INVALID: &str = "invalid wrapped account or root";

pub struct UnwrappedNsec {
    pub private_key: Zeroizing<[u8; 32]>,
    pub public_key: [u8; 32],
    pub npub: String,
}

/// Check the slot's actual key against its displayed identity before applying
/// the mode-specific root conversion. Cached metadata is not a key check.
pub fn verify_slot_key(secret: &[u8; 32], expected_npub: &str) -> Result<(), &'static str> {
    let public = public_key_xonly(secret).map_err(|_| INVALID)?;
    if encode_npub(&public) != expected_npub {
        return Err(INVALID);
    }
    Ok(())
}

fn cipher(root: &[u8; 32], salt: &[u8]) -> Result<Aes256Gcm, &'static str> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), root)
        .expand(INFO, key.as_mut())
        .map_err(|_| INVALID)?;
    Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| INVALID)
}

/// The signer supplies fresh cryptographic entropy. This callback must fill
/// all 44 bytes or fail; neither salt nor nonce comes from a host request.
pub fn wrap_nsec(
    root: &[u8; 32],
    raw: &[u8; 32],
    mut fill: impl FnMut(&mut [u8]) -> Result<(), ()>,
) -> Result<String, &'static str> {
    let public = public_key_xonly(raw).map_err(|_| INVALID)?;
    let mut entropy = [0u8; 44];
    fill(&mut entropy).map_err(|_| "entropy unavailable")?;
    let mut header = [0u8; 51];
    header[..7].copy_from_slice(MAGIC);
    header[7..].copy_from_slice(&entropy);
    let mut payload = Zeroizing::new([0u8; 64]);
    payload[..32].copy_from_slice(raw);
    payload[32..].copy_from_slice(&public);
    let nonce = Nonce::from(<[u8; 12]>::try_from(&header[39..]).map_err(|_| INVALID)?);
    let encrypted = cipher(root, &header[7..39])?
        .encrypt(
            &nonce,
            Payload {
                msg: payload.as_ref(),
                aad: &header,
            },
        )
        .map_err(|_| INVALID)?;
    let mut record = Vec::with_capacity(131);
    record.extend_from_slice(&header);
    record.extend_from_slice(&encrypted);
    Ok(format!("nstw1:{}", URL_SAFE_NO_PAD.encode(record)))
}

pub fn unwrap_nsec(
    root: &[u8; 32],
    record: &str,
    expected: Option<&str>,
) -> Result<UnwrappedNsec, &'static str> {
    if record.len() != RECORD_LEN || !record.starts_with("nstw1:") {
        return Err(INVALID);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(&record.as_bytes()[6..])
        .map_err(|_| INVALID)?;
    if bytes.len() != 131 || bytes[..7] != *MAGIC || URL_SAFE_NO_PAD.encode(&bytes) != record[6..] {
        return Err(INVALID);
    }
    let nonce = Nonce::from(<[u8; 12]>::try_from(&bytes[39..51]).map_err(|_| INVALID)?);
    let payload = Zeroizing::new(
        cipher(root, &bytes[7..39])?
            .decrypt(
                &nonce,
                Payload {
                    msg: &bytes[51..],
                    aad: &bytes[..51],
                },
            )
            .map_err(|_| INVALID)?,
    );
    if payload.len() != 64 {
        return Err(INVALID);
    }
    let mut private_key = Zeroizing::new([0u8; 32]);
    private_key.copy_from_slice(&payload[..32]);
    let public_key = public_key_xonly(&private_key).map_err(|_| INVALID)?;
    let npub = encode_npub(&public_key);
    if payload[32..] != public_key || expected.is_some_and(|e| e != npub) {
        return Err(INVALID);
    }
    Ok(UnwrappedNsec {
        private_key,
        public_key,
        npub,
    })
}
