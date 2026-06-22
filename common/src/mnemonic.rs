//! On-device recovery-phrase generation.
//!
//! Lets the ESP signer create its OWN master seed and show the 12-word recovery
//! phrase on its own screen — so the phrase is generated and displayed only on
//! the device, never in the browser. The browser just asks the device to
//! generate; only the resulting public npub comes back.
//!
//! The entropy → BIP-39 mnemonic → BIP-32 (`m/44'/1237'/727'/0'/0'`) → tree-root
//! derivation mirrors the provision CLI's `derive_root_secret` exactly (same
//! `bip39`/`bip32` crates and path), verified against the shared test vector
//! below. That means a phrase generated on-device recovers through the existing
//! "Tree (mnemonic)" import path and any standard BIP-39 tool.

use zeroize::Zeroizing;

/// BIP-32 derivation path — MUST match sapwood `provision.ts` MNEMONIC_PATH and
/// the provision CLI, or a written-down phrase won't recover the same key.
const MNEMONIC_PATH: &str = "m/44'/1237'/727'/0'/0'";

/// Derive the 32-byte nsec-tree root secret from a BIP-39 mnemonic (+ optional
/// passphrase). Identical to the provision CLI's derivation.
pub fn derive_root_secret(mnemonic: &str, passphrase: &str) -> Result<[u8; 32], String> {
    let parsed: bip39::Mnemonic = mnemonic.parse().map_err(|_| "invalid mnemonic".to_string())?;
    let seed = Zeroizing::new(parsed.to_seed(passphrase));

    let master = bip32::XPrv::new(*seed).map_err(|e| format!("BIP-32 master key failed: {e}"))?;
    let path: bip32::DerivationPath =
        MNEMONIC_PATH.parse().map_err(|e| format!("invalid derivation path: {e}"))?;
    let child = path
        .iter()
        .try_fold(master, |key, child_num| key.derive_child(child_num))
        .map_err(|e| format!("BIP-32 derivation failed: {e}"))?;

    Ok(child.to_bytes())
}

/// Generate a fresh 12-word mnemonic from 16 bytes of entropy (128 bits) and
/// derive its tree-root secret. Returns `(phrase_to_display, root_secret)`.
/// The caller supplies entropy from the hardware RNG and zeroizes the root after
/// storing it; the phrase is shown on the OLED and never leaves the device.
pub fn generate(entropy: &[u8; 16]) -> Result<(String, [u8; 32]), String> {
    let m = bip39::Mnemonic::from_entropy(entropy)
        .map_err(|_| "could not build mnemonic from entropy".to_string())?;
    let phrase = m.to_string();
    let root = derive_root_secret(&phrase, "")?;
    Ok((phrase, root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::hex_encode;

    // The canonical all-zero BIP-39 vector, shared with the provision CLI's
    // `test_mnemonic_derivation`. If this drifts, on-device-generated phrases
    // stop recovering through the browser's tree-mnemonic import.
    const ZERO_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const ZERO_ROOT_HEX: &str = "cc92d213b5eccd19eb85c12c2cf6fd168f27c2cc347c51a7c4c62ac67795fc65";

    #[test]
    fn derive_matches_shared_vector() {
        let root = derive_root_secret(ZERO_PHRASE, "").unwrap();
        assert_eq!(hex_encode(&root), ZERO_ROOT_HEX);
    }

    #[test]
    fn generate_from_zero_entropy_matches_vector() {
        let (phrase, root) = generate(&[0u8; 16]).unwrap();
        assert_eq!(phrase, ZERO_PHRASE);
        assert_eq!(hex_encode(&root), ZERO_ROOT_HEX);
    }

    #[test]
    fn generate_produces_twelve_words() {
        let (phrase, _) = generate(&[0x42u8; 16]).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);
    }

    #[test]
    fn different_entropy_gives_different_root() {
        let (_, a) = generate(&[0x01u8; 16]).unwrap();
        let (_, b) = generate(&[0x02u8; 16]).unwrap();
        assert_ne!(a, b);
    }
}
