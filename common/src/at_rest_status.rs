// common/src/at_rest_status.rs
//
// Read-only summary for FIRMWARE_INFO and the relay `get_status` reply: how
// the board's seeds are protected at rest, and how many phones can unlock it
// (plan item G2: "Add an at-rest field ... so Sapwood's mode chooser stops
// inferring"). Before this, Sapwood guessed the mode from side effects it
// happened to witness this session (`inferUnlockMode` in
// sapwood/src/lib/phone-unlock.ts) — an enrolled phone proves encryption is
// on, but nothing told it PIN from vault, or "no encryption" from "I haven't
// looked yet".
//
// Deliberately narrow: a mode and a count, nothing that could identify a
// phone. See `heartwood_common::data_key::PhoneRecord` for what stays off
// this surface (ids, labels, hints never appear here).

use crate::data_key::PhoneSet;

/// How the board's seeds are protected at rest. The wire spelling
/// (`AtRestMode::wire`) is the JSON value FIRMWARE_INFO and get_status carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtRestMode {
    /// Every seed is plaintext in NVS.
    None,
    /// Sealed under a human PIN, entered at every boot (P5).
    Pin,
    /// Sealed under a host-held vault key (heartwoodd or Sapwood delivers it
    /// on reboot; unattended reboot).
    Vault,
}

impl AtRestMode {
    /// The wire spelling used by both FIRMWARE_INFO and get_status.
    pub const fn wire(self) -> &'static str {
        match self {
            AtRestMode::None => "none",
            AtRestMode::Pin => "pin",
            AtRestMode::Vault => "vault",
        }
    }
}

/// Which secret currently wraps the data key, once at-rest encryption is on.
///
/// The wrapped data key (`dk_sec`) is deliberately opaque about what wrapped
/// it — the same shape whether the secret was 4-8 PIN digits or a 32-byte
/// vault key (see `data_key::write_secret_wrap`) — so nothing already on
/// flash says which one is in force. Firmware persists this alongside the
/// wrapper it describes (`firmware/src/pin.rs`, written by
/// `enable_encryption`/`disable_encryption`, the same write that sets or
/// clears the wrapper). It carries no cryptographic weight: a wrong or
/// missing value only mislabels the mode a manager shows, never what unlocks
/// the board.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretKind {
    Pin,
    Vault,
}

/// Derive the at-rest mode purely from durable state: whether any seed is
/// sealed, and — if so — which secret the marker says wrapped it.
///
/// `kind` is `None` on a plaintext board (irrelevant there) and also on a
/// board that was encrypted by firmware older than the marker. The fallback
/// for that case is [`AtRestMode::Pin`], the more conservative label: it does
/// not claim a host or Sapwood can unlock the board unattended when that
/// might not be true. The marker is written the next time the secret is
/// (re)set, which corrects a mislabelled legacy board.
pub fn derive_mode(encrypted: bool, kind: Option<SecretKind>) -> AtRestMode {
    if !encrypted {
        return AtRestMode::None;
    }
    match kind {
        Some(SecretKind::Vault) => AtRestMode::Vault,
        Some(SecretKind::Pin) | None => AtRestMode::Pin,
    }
}

/// How many phones are enrolled to unlock this board, from the raw `dk_ph`
/// blob (or its absence). Firmware reads this while locked too — phone
/// records are stored unsealed for exactly that reason (see
/// [`crate::data_key::PhoneRecord`]) — so the count needs no secret and no
/// unlock. An unreadable or corrupt blob counts as zero rather than failing
/// the whole status response, the same way an absent blob does.
pub fn phone_count_from_blob(blob: Option<&[u8]>) -> usize {
    blob.and_then(PhoneSet::decode)
        .map(|set| set.records().len())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_when_not_encrypted_whatever_the_marker() {
        assert_eq!(derive_mode(false, None), AtRestMode::None);
        assert_eq!(derive_mode(false, Some(SecretKind::Pin)), AtRestMode::None);
        assert_eq!(derive_mode(false, Some(SecretKind::Vault)), AtRestMode::None);
    }

    #[test]
    fn pin_marker_reports_pin() {
        assert_eq!(derive_mode(true, Some(SecretKind::Pin)), AtRestMode::Pin);
    }

    #[test]
    fn vault_marker_reports_vault() {
        assert_eq!(derive_mode(true, Some(SecretKind::Vault)), AtRestMode::Vault);
    }

    #[test]
    fn encrypted_with_no_marker_falls_back_to_pin() {
        // A board encrypted before this marker existed. Conservative default:
        // never claim unattended (vault) recovery that might not be true.
        assert_eq!(derive_mode(true, None), AtRestMode::Pin);
    }

    #[test]
    fn wire_spellings_match_the_plan() {
        assert_eq!(AtRestMode::None.wire(), "none");
        assert_eq!(AtRestMode::Pin.wire(), "pin");
        assert_eq!(AtRestMode::Vault.wire(), "vault");
    }

    #[test]
    fn phone_count_absent_blob_is_zero() {
        assert_eq!(phone_count_from_blob(None), 0);
    }

    #[test]
    fn phone_count_corrupt_blob_is_zero() {
        assert_eq!(phone_count_from_blob(Some(b"not a phone set")), 0);
    }

    #[test]
    fn phone_count_empty_set_is_zero() {
        let set = PhoneSet::default();
        let encoded = set.encode();
        assert_eq!(phone_count_from_blob(Some(&encoded)), 0);
    }

    #[test]
    fn phone_count_matches_several_enrolled() {
        let dk = [7u8; crate::data_key::DK_LEN];
        let mut set = PhoneSet::default();
        for i in 0..3u32 {
            let slot_secret = [i as u8 + 1; crate::data_key::SLOT_SECRET_LEN];
            let nonce = [i as u8; crate::data_key::NONCE_LEN];
            set.enrol(i, "phone", &slot_secret, &dk, &nonce)
                .expect("enrol under the cap");
        }
        let encoded = set.encode();
        assert_eq!(phone_count_from_blob(Some(&encoded)), 3);
    }

    #[test]
    fn phone_count_after_revoke_drops_by_one() {
        let dk = [9u8; crate::data_key::DK_LEN];
        let mut set = PhoneSet::default();
        for i in 0..2u32 {
            let slot_secret = [i as u8 + 1; crate::data_key::SLOT_SECRET_LEN];
            let nonce = [i as u8; crate::data_key::NONCE_LEN];
            set.enrol(i, "phone", &slot_secret, &dk, &nonce)
                .expect("enrol under the cap");
        }
        set.revoke(0).expect("id 0 is enrolled");
        let encoded = set.encode();
        assert_eq!(phone_count_from_blob(Some(&encoded)), 1);
    }
}
