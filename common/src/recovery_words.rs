//! ForgeSworn Recovery Words v1.
//!
//! Seven BIP-39-list header words carry a magic value, format version,
//! recovery kind, passphrase flag, public fingerprint, and checksum. A
//! canonical BIP-39 payload follows. The complete sequence is deliberately
//! not a valid BIP-39 mnemonic, preventing a wallet from silently applying a
//! different derivation. The byte layout is frozen in `nsec-tree/RECOVERY.md`.

#[allow(unused_imports)]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use bip39::{Language, Mnemonic};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::types::MasterMode;

pub const RECOVERY_WORDS_VERSION: u8 = 1;
pub const RECOVERY_HEADER_WORDS: usize = 7;

const MAGIC: u128 = 0x4653;
const CHECKSUM_BITS: u32 = 17;
const CHECKSUM_MASK: u128 = (1u128 << CHECKSUM_BITS) - 1;
const FLAG_PASSPHRASE_REQUIRED: u8 = 1;
const FINGERPRINT_DOMAIN: &[u8] = b"ForgeSworn recovery fingerprint v1\0";
const CHECKSUM_DOMAIN: &[u8] = b"ForgeSworn recovery words v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoveryKind {
    NsecTreeMnemonicV1 = 1,
    RawNsecV1 = 2,
    NsecTreeNsecV1 = 3,
}

impl RecoveryKind {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::NsecTreeMnemonicV1),
            2 => Some(Self::RawNsecV1),
            3 => Some(Self::NsecTreeNsecV1),
            _ => None,
        }
    }
}

pub struct DecodedRecoveryWords {
    pub version: u8,
    pub kind: RecoveryKind,
    pub passphrase_required: bool,
    pub fingerprint: [u8; 4],
    /// Secret entropy. It is scrubbed automatically when this value drops.
    pub payload: Zeroizing<Vec<u8>>,
}

pub struct RestoredRecoveryWords {
    pub secret: Zeroizing<[u8; 32]>,
    pub mode: MasterMode,
    pub version: u8,
    pub fingerprint: [u8; 4],
}

fn fingerprint(secret: &[u8; 32]) -> Result<[u8; 4], String> {
    let public = crate::derive::public_key_xonly(secret).map_err(ToString::to_string)?;
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update(public);
    let mut digest = hasher.finalize();
    let out = [digest[0], digest[1], digest[2], digest[3]];
    digest.zeroize();
    Ok(out)
}

fn recovery_checksum(kind: RecoveryKind, flags: u8, fingerprint: &[u8; 4], payload: &[u8]) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update([RECOVERY_WORDS_VERSION, kind as u8, flags]);
    hasher.update(fingerprint);
    hasher.update(payload);
    let mut digest = hasher.finalize();
    let out = (((digest[0] as u32) << 9) | ((digest[1] as u32) << 1) | ((digest[2] as u32) >> 7))
        & 0x1ffff;
    digest.zeroize();
    out
}

fn validate_payload(kind: RecoveryKind, payload: &[u8]) -> Result<(), String> {
    match kind {
        RecoveryKind::NsecTreeMnemonicV1 if matches!(payload.len(), 16 | 20 | 24 | 28 | 32) => {
            Ok(())
        }
        RecoveryKind::NsecTreeMnemonicV1 => {
            Err("invalid mnemonic recovery payload length".to_string())
        }
        _ if payload.len() == 32 => Ok(()),
        _ => Err("nsec recovery payload must contain 32 bytes".to_string()),
    }
}

fn encode(
    kind: RecoveryKind,
    payload_words: &str,
    passphrase_required: bool,
    derived_secret: &[u8; 32],
) -> Result<Zeroizing<String>, String> {
    let mnemonic = Mnemonic::parse_normalized(payload_words)
        .map_err(|_| "invalid BIP-39 recovery payload".to_string())?;
    let (entropy, entropy_len) = mnemonic.to_entropy_array();
    let payload = &entropy[..entropy_len];
    validate_payload(kind, payload)?;
    let fp = fingerprint(derived_secret)?;
    let flags = if passphrase_required {
        FLAG_PASSPHRASE_REQUIRED
    } else {
        0
    };
    if kind != RecoveryKind::NsecTreeMnemonicV1 && flags != 0 {
        return Err("passphrase flag is only valid for mnemonic recovery".to_string());
    }

    let mut packed = MAGIC;
    packed = (packed << 4) | RECOVERY_WORDS_VERSION as u128;
    packed = (packed << 4) | kind as u128;
    packed = (packed << 4) | flags as u128;
    packed = (packed << 32) | u32::from_be_bytes(fp) as u128;
    packed = (packed << CHECKSUM_BITS) | recovery_checksum(kind, flags, &fp, payload) as u128;

    let list = Language::English.word_list();
    let mut out = Zeroizing::new(String::new());
    for word_index in 0..RECOVERY_HEADER_WORDS {
        let shift = (RECOVERY_HEADER_WORDS - 1 - word_index) * 11;
        let index = ((packed >> shift) & 0x7ff) as usize;
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(list[index]);
    }
    out.push(' ');
    out.push_str(&mnemonic.to_string());
    Ok(out)
}

pub fn create_mnemonic_recovery_words(
    mnemonic: &str,
    passphrase: &str,
) -> Result<Zeroizing<String>, String> {
    let root = Zeroizing::new(crate::mnemonic::derive_root_secret(mnemonic, passphrase)?);
    encode(
        RecoveryKind::NsecTreeMnemonicV1,
        mnemonic,
        !passphrase.is_empty(),
        &root,
    )
}

/// Encode a mnemonic when its already-derived root is available. This avoids a
/// second PBKDF2/BIP-32 walk during on-device generation. Callers must pass the
/// root produced by this mnemonic and passphrase policy; the public
/// fingerprint deliberately makes any mismatch fail during recovery.
pub fn create_mnemonic_recovery_words_for_root(
    mnemonic: &str,
    passphrase_required: bool,
    derived_root: &[u8; 32],
) -> Result<Zeroizing<String>, String> {
    encode(
        RecoveryKind::NsecTreeMnemonicV1,
        mnemonic,
        passphrase_required,
        derived_root,
    )
}

pub fn create_nsec_recovery_words(
    nsec: &[u8; 32],
    derive: bool,
) -> Result<Zeroizing<String>, String> {
    // Both nsec kinds assert that the payload is a valid Nostr secret scalar,
    // even when it is subsequently used as the nsec-tree HMAC key.
    crate::derive::public_key_xonly(nsec).map_err(ToString::to_string)?;
    let mnemonic = Mnemonic::from_entropy(nsec)
        .map_err(|_| "could not encode nsec recovery payload".to_string())?;
    if derive {
        let root = crate::derive::nsec_to_tree_root(nsec).map_err(ToString::to_string)?;
        encode(
            RecoveryKind::NsecTreeNsecV1,
            &mnemonic.to_string(),
            false,
            &root,
        )
    } else {
        encode(RecoveryKind::RawNsecV1, &mnemonic.to_string(), false, nsec)
    }
}

pub fn decode_recovery_words(words: &str) -> Result<DecodedRecoveryWords, String> {
    let canonical = Zeroizing::new(words.trim().to_ascii_lowercase());
    let parts: Vec<&str> = canonical.split_whitespace().collect();
    if parts.len() <= RECOVERY_HEADER_WORDS {
        return Err("not ForgeSworn recovery words (missing typed header or payload)".to_string());
    }

    let language = Language::English;
    let mut packed = 0u128;
    for word in &parts[..RECOVERY_HEADER_WORDS] {
        let index = language
            .find_word(word)
            .ok_or_else(|| format!("unknown recovery word: {word}"))?;
        packed = (packed << 11) | index as u128;
    }

    let expected_checksum = (packed & CHECKSUM_MASK) as u32;
    packed >>= CHECKSUM_BITS;
    let fp = (packed as u32).to_be_bytes();
    packed >>= 32;
    let flags = (packed & 0xf) as u8;
    packed >>= 4;
    let kind_code = (packed & 0xf) as u8;
    packed >>= 4;
    let version = (packed & 0xf) as u8;
    packed >>= 4;

    if packed != MAGIC {
        return Err("not ForgeSworn recovery words (bad magic)".to_string());
    }
    if version != RECOVERY_WORDS_VERSION {
        return Err(format!(
            "unsupported ForgeSworn recovery words version: {version}"
        ));
    }
    if flags & !FLAG_PASSPHRASE_REQUIRED != 0 {
        return Err("unsupported ForgeSworn recovery flags".to_string());
    }
    let kind = RecoveryKind::from_u8(kind_code)
        .ok_or_else(|| format!("unsupported ForgeSworn recovery kind: {kind_code}"))?;
    if kind != RecoveryKind::NsecTreeMnemonicV1 && flags != 0 {
        return Err("passphrase flag is only valid for mnemonic recovery".to_string());
    }

    let payload_words = Zeroizing::new(parts[RECOVERY_HEADER_WORDS..].join(" "));
    let mnemonic = Mnemonic::parse_normalized(&payload_words)
        .map_err(|_| "ForgeSworn recovery payload has an invalid BIP-39 checksum".to_string())?;
    let (entropy, entropy_len) = mnemonic.to_entropy_array();
    let payload = Zeroizing::new(entropy[..entropy_len].to_vec());
    validate_payload(kind, &payload)?;
    if recovery_checksum(kind, flags, &fp, &payload) != expected_checksum {
        return Err("ForgeSworn recovery checksum mismatch".to_string());
    }

    Ok(DecodedRecoveryWords {
        version,
        kind,
        passphrase_required: flags & FLAG_PASSPHRASE_REQUIRED != 0,
        fingerprint: fp,
        payload,
    })
}

pub fn restore_recovery_words(
    words: &str,
    passphrase: &str,
) -> Result<RestoredRecoveryWords, String> {
    let decoded = decode_recovery_words(words)?;
    if decoded.passphrase_required && passphrase.is_empty() {
        return Err("recovery passphrase required".to_string());
    }
    if !decoded.passphrase_required && !passphrase.is_empty() {
        return Err("these recovery words do not use a passphrase".to_string());
    }

    let (secret, mode) = match decoded.kind {
        RecoveryKind::NsecTreeMnemonicV1 => {
            let mnemonic = Mnemonic::from_entropy(&decoded.payload)
                .map_err(|_| "invalid mnemonic recovery payload".to_string())?;
            (
                Zeroizing::new(crate::mnemonic::derive_root_secret(
                    &mnemonic.to_string(),
                    passphrase,
                )?),
                MasterMode::TreeMnemonic,
            )
        }
        RecoveryKind::RawNsecV1 => {
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&decoded.payload);
            (Zeroizing::new(secret), MasterMode::Bunker)
        }
        RecoveryKind::NsecTreeNsecV1 => {
            let mut nsec = Zeroizing::new([0u8; 32]);
            nsec.copy_from_slice(&decoded.payload);
            crate::derive::public_key_xonly(&nsec).map_err(ToString::to_string)?;
            (
                crate::derive::nsec_to_tree_root(&nsec).map_err(ToString::to_string)?,
                MasterMode::TreeNsec,
            )
        }
    };

    if fingerprint(&secret)? != decoded.fingerprint {
        return Err("recovery fingerprint mismatch: check the words and passphrase".to_string());
    }
    Ok(RestoredRecoveryWords {
        secret,
        mode,
        version: decoded.version,
        fingerprint: decoded.fingerprint,
    })
}
