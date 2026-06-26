//! On-device recovery-phrase generation.
//!
//! Lets the ESP signer create its OWN master seed and show the 12-word recovery
//! phrase on its own screen — so the phrase is generated and displayed only on
//! the device, never in the browser. The browser just asks the device to
//! generate; only the resulting public npub comes back.
//!
//! The entropy → BIP-39 mnemonic → BIP-32 (`m/44'/1237'/727'/0'/0'`) → tree-root
//! derivation produces the same key as the provision CLI and sapwood (verified
//! against the shared test vector below), so a phrase generated on-device
//! recovers through the existing "Tree (mnemonic)" import and any standard tool.
//! BIP-39 (wordlist + PBKDF2 seed) comes from the `bip39` crate; the BIP-32
//! step is hand-rolled on the firmware's existing `secp256k1` so we don't pull
//! `k256` + a second `secp256k1` (which overflowed the 2 MB OTA slot).
#[allow(unused_imports)]
use alloc::{format, string::{String, ToString}, vec, vec::Vec};


use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

/// Hardened child indices of `m/44'/1237'/727'/0'/0'` — MUST match sapwood
/// `provision.ts` MNEMONIC_PATH and the provision CLI, or a written-down phrase
/// won't recover the same key.
const PATH: [u32; 5] = [44, 1237, 727, 0, 0];
const HARDENED: u32 = 0x8000_0000;

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Derive the 32-byte nsec-tree root secret from a BIP-39 mnemonic (+ optional
/// passphrase) via BIP-39 seed and an all-hardened BIP-32 path.
pub fn derive_root_secret(mnemonic: &str, passphrase: &str) -> Result<[u8; 32], String> {
    // The `_normalized` variants skip bip39's NFKD path — and the huge
    // unicode-normalization tables it would pull in (they overflow the lx106's
    // DRAM by ~118 KB). BIP-39 English words are ASCII and heartwood always uses
    // an empty passphrase, so NFKD is a no-op and the derived key is byte-identical
    // (verified by the frozen vector test below, under both curve backends).
    let parsed = bip39::Mnemonic::parse_normalized(mnemonic).map_err(|_| "invalid mnemonic".to_string())?;
    let seed = Zeroizing::new(parsed.to_seed_normalized(passphrase)); // PBKDF2-HMAC-SHA512, 64 bytes

    // BIP-32 master: HMAC-SHA512("Bitcoin seed", seed) → key || chain code.
    let i = Zeroizing::new(hmac_sha512(b"Bitcoin seed", seed.as_ref()));
    let mut key: [u8; 32] = i[0..32].try_into().unwrap();
    let mut chain: [u8; 32] = i[32..64].try_into().unwrap();

    // All indices are hardened: I = HMAC-SHA512(chain, 0x00 || key || index_be);
    // child_key = (parse256(I_L) + key) mod n; child_chain = I_R.
    for raw in PATH {
        let index = raw | HARDENED;
        let mut data = [0u8; 37];
        data[1..33].copy_from_slice(&key);
        data[33..37].copy_from_slice(&index.to_be_bytes());
        let i = Zeroizing::new(hmac_sha512(&chain, &data));

        let il: [u8; 32] = i[0..32].try_into().unwrap();
        // (parse256(I_L) + key) mod n, via whichever curve backend is active —
        // byte-identical to the secp256k1 path the WiFi firmware uses.
        key = crate::derive::backend::tweak_add(&key, &il).map_err(|e| e.to_string())?;
        chain.copy_from_slice(&i[32..64]);
    }

    Ok(key)
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
