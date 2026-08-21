// common/src/note_seal.rs
//
// At-rest sealing for bearer-note record blobs — the note-locker half of the
// P5/vault at-rest design. A note blob (note_store's `HWNB` record, which
// embeds the raw k1) is sealed under a 32-byte **note key** that is random,
// generated on-device at enable time, wrapped by `seed_cipher::encrypt_seed`
// into the locker's `nk` blob under the same PIN/vault secret as the seeds,
// unwrapped once at unlock, and retained in RAM for the boot. Notes are
// therefore sealed exactly when the seeds are sealed, at the cost of one
// extra PBKDF2 run per unlock — and with no lifetime coupling to any master
// (docs/plans/2026-08-18-note-locker-goal.md, open question 5, option (a)).
//
// Construction: the exact `seed_cipher` shape (encrypt-then-MAC, the same
// shape NIP-44 v2 uses) minus the KDF — the note key is full-entropy random,
// so there is nothing to stretch and no salt to store:
//   enc_key = key[0..]          (the 32-byte note key, used directly)
//   mac_key = HMAC-SHA256(key, "heartwood-note-seal-mac")   (domain-split)
//   ct      = ChaCha20(enc_key, nonce) XOR plaintext        (variable length)
//   tag     = HMAC-SHA256(mac_key, nonce || ct)             (32 bytes)
//   blob    = magic "HWNS" || version(1) || nonce(12) || ct || tag(32)
//
// The magic makes sealed and plaintext records self-identifying on flash, so
// a loader can tell "sealed, come back with the key" from "corrupt" — the
// distinction that keeps a locked boot from mis-reporting held notes as
// damage. Same honest limitation as seed_cipher: with the PIN path the
// wrapping key is PIN-derived and offline-enumerable; the vault-key path is
// full-entropy.

use alloc::vec::Vec;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 32;
/// magic(4) + version(1) + nonce + tag — everything but the ciphertext.
pub const OVERHEAD: usize = 4 + 1 + NONCE_LEN + TAG_LEN;

const SEALED_MAGIC: [u8; 4] = *b"HWNS";
const SEALED_VERSION: u8 = 1;
const MAC_DOMAIN: &[u8] = b"heartwood-note-seal-mac";

#[derive(Debug, PartialEq, Eq)]
pub enum NoteSealError {
    /// Too short to be a sealed blob, or not one at all.
    BadLength,
    /// The MAC did not verify — wrong key or a tampered blob.
    WrongKeyOrTampered,
}

/// Whether a stored blob is a sealed record (as opposed to a plaintext
/// `HWNB` record or garbage). Deliberately checks only the prefix: a sealed
/// blob that is also truncated should still be *reported* as sealed, not as
/// an unknown format — the notes behind it are intact-or-not independently
/// of what this boot can prove.
pub fn is_sealed(blob: &[u8]) -> bool {
    blob.len() >= 5 && blob[0..4] == SEALED_MAGIC && blob[4] == SEALED_VERSION
}

fn mac_key(key: &[u8; KEY_LEN]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(MAC_DOMAIN);
    mac.finalize().into_bytes().into()
}

/// Seal a plaintext record blob. `nonce` must be random and fresh per seal
/// (caller supplies it so this stays deterministic and host-testable; the
/// device draws it from `fill_random`).
pub fn seal(key: &[u8; KEY_LEN], plain: &[u8], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut ct = plain.to_vec();
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.apply_keystream(&mut ct);

    let mut mk = mac_key(key);
    let mut mac = HmacSha256::new_from_slice(&mk).expect("HMAC accepts any key length");
    mac.update(nonce);
    mac.update(&ct);
    let tag = mac.finalize().into_bytes();
    mk.zeroize();

    let mut blob = Vec::with_capacity(OVERHEAD + plain.len());
    blob.extend_from_slice(&SEALED_MAGIC);
    blob.push(SEALED_VERSION);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ct);
    blob.extend_from_slice(&tag);
    blob
}

/// Open a sealed blob. Wrong key or any tampering fails the constant-time
/// MAC check — never garbage plaintext. The caller zeroises the returned
/// plaintext after use (it embeds the note secret).
pub fn open(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>, NoteSealError> {
    if blob.len() < OVERHEAD || !is_sealed(blob) {
        return Err(NoteSealError::BadLength);
    }
    let nonce: &[u8; NONCE_LEN] = blob[5..5 + NONCE_LEN].try_into().expect("length checked");
    let ct = &blob[5 + NONCE_LEN..blob.len() - TAG_LEN];
    let tag = &blob[blob.len() - TAG_LEN..];

    let mut mk = mac_key(key);
    let mut mac = HmacSha256::new_from_slice(&mk).expect("HMAC accepts any key length");
    mac.update(nonce);
    mac.update(ct);
    let verified = mac.verify_slice(tag);
    mk.zeroize();
    if verified.is_err() {
        return Err(NoteSealError::WrongKeyOrTampered);
    }

    let mut plain = ct.to_vec();
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.apply_keystream(&mut plain);
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    fn key(fill: u8) -> [u8; KEY_LEN] {
        [fill; KEY_LEN]
    }

    #[test]
    fn round_trips_at_every_interesting_length() {
        let nonce = [9u8; NONCE_LEN];
        for len in [0usize, 1, 31, 32, 33, 422, 600] {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let blob = seal(&key(1), &plain, &nonce);
            assert_eq!(blob.len(), OVERHEAD + len);
            assert!(is_sealed(&blob));
            assert_eq!(open(&key(1), &blob).unwrap(), plain, "len {len}");
        }
    }

    #[test]
    fn every_flipped_byte_is_rejected() {
        let nonce = [7u8; NONCE_LEN];
        let plain = b"HWNB-pretend-record-with-a-secret-inside".to_vec();
        let blob = seal(&key(2), &plain, &nonce);
        for i in 0..blob.len() {
            let mut bad = blob.clone();
            bad[i] ^= 0x01;
            let result = open(&key(2), &bad);
            assert!(result.is_err(), "flipped byte {i} still opened");
        }
    }

    #[test]
    fn wrong_key_is_rejected_not_garbage() {
        let nonce = [3u8; NONCE_LEN];
        let blob = seal(&key(4), b"money", &nonce);
        assert_eq!(open(&key(5), &blob), Err(NoteSealError::WrongKeyOrTampered));
    }

    #[test]
    fn truncated_and_foreign_blobs_are_bad_length() {
        let nonce = [1u8; NONCE_LEN];
        let blob = seal(&key(6), b"x", &nonce);
        for cut in 0..OVERHEAD {
            assert_eq!(open(&key(6), &blob[..cut]), Err(NoteSealError::BadLength));
        }
        // A plaintext HWNB record is not sealed and must not be treated as one.
        assert!(!is_sealed(b"HWNB\x01whatever"));
        assert_eq!(open(&key(6), b"HWNB\x01whatever"), Err(NoteSealError::BadLength));
    }

    #[test]
    fn truncated_sealed_blob_still_identifies_as_sealed() {
        // A torn write can shorten a sealed blob; the loader must still say
        // "sealed" (intact notes behind a key) rather than "unknown format".
        let nonce = [2u8; NONCE_LEN];
        let blob = seal(&key(8), b"record", &nonce);
        assert!(is_sealed(&blob[..8]));
    }

    #[test]
    fn distinct_nonces_give_distinct_ciphertexts() {
        let plain = b"same plaintext".to_vec();
        let a = seal(&key(9), &plain, &[1u8; NONCE_LEN]);
        let b = seal(&key(9), &plain, &[2u8; NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn wraps_a_note_record_end_to_end() {
        // The real payload shape: an encoded note_store record.
        use crate::note_store::{encode_note, decode_note, Note, NoteState, SECRET_LEN};
        use alloc::string::ToString;
        let note = Note {
            id: "a1b2c3d4".to_string(),
            secret: [0x5a; SECRET_LEN],
            state: NoteState::Confirmed,
            amount_msat: 21_000,
            host: "mint.example/w".to_string(),
            label: "float".to_string(),
            sig: alloc::string::String::new(),
            parent_ids: vec![],
            created_at: 1,
            updated_at: 2,
        };
        let plain = encode_note(&note).unwrap();
        let sealed = seal(&key(7), &plain, &[4u8; NONCE_LEN]);
        let mut opened = open(&key(7), &sealed).unwrap();
        let back = decode_note(&opened).unwrap();
        assert_eq!(back.secret, note.secret);
        opened.zeroize();
    }
}
