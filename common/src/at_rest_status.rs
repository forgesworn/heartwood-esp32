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

use crate::data_key::{PhoneSet, SecretKind};

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
    /// Sealed, but which secret sealed it is not known — the marker is
    /// missing or its digest no longer matches the wrapper on flash (see
    /// `data_key::secret_kind_from_marker`). Never "pin": labelling an
    /// unattended-vault board as PIN-protected is the dangerous wrong guess —
    /// only a PIN_UNLOCK guess counts towards the 5-failure wipe, so it
    /// invites typed guesses into a counter a vault board was never meant to
    /// arm. "Encrypted" is the honest answer instead.
    Encrypted,
}

impl AtRestMode {
    /// The wire spelling used by both FIRMWARE_INFO and get_status.
    pub const fn wire(self) -> &'static str {
        match self {
            AtRestMode::None => "none",
            AtRestMode::Pin => "pin",
            AtRestMode::Vault => "vault",
            AtRestMode::Encrypted => "encrypted",
        }
    }
}

/// Derive the at-rest mode purely from durable state: whether any seed is
/// sealed, and — if so — what [`data_key::secret_kind_from_marker`] (or
/// [`data_key::read_secret_kind`]) resolved the marker to. `kind` is `None`
/// both for a plaintext board (irrelevant there) and for a sealed board whose
/// marker is missing, malformed, or stale — both collapse to
/// [`AtRestMode::Encrypted`], never a guessed label.
pub fn derive_mode(encrypted: bool, kind: Option<SecretKind>) -> AtRestMode {
    if !encrypted {
        return AtRestMode::None;
    }
    match kind {
        Some(SecretKind::Pin) => AtRestMode::Pin,
        Some(SecretKind::Vault) => AtRestMode::Vault,
        None => AtRestMode::Encrypted,
    }
}

/// How many phones are enrolled to unlock this board, from the raw `dk_ph`
/// blob (or its absence). Firmware reads this while locked too — phone
/// records are stored unsealed for exactly that reason (see
/// [`crate::data_key::PhoneRecord`]) — so the count needs no secret and no
/// unlock.
///
/// `None` (JSON `null`) only for a *present* blob that fails to parse —
/// [`crate::data_key::load_phones`]'s rule that damage is never mistaken for
/// zero phones, carried over to the count. An absent blob (never enrolled, or
/// cleanly cleared) is `Some(0)`, the honest zero.
pub fn phone_count_from_blob(blob: Option<&[u8]>) -> Option<usize> {
    match blob {
        None => Some(0),
        Some(bytes) => PhoneSet::count(bytes),
    }
}

/// Reconcile the phone count with the mode. Once at-rest is "none" there is
/// no data key left for a phone record to wrap, so a `dk_ph` blob found
/// alongside it is orphaned, not a phone that can unlock anything — for
/// example, removing a board's last identity drops its seeds but not `dk_ph`
/// (`provision.rs`, `masters.rs`), or a board disabled encryption on firmware
/// older than that cleanup. Reporting the honest position ("no encryption, no
/// phone can unlock anything") beats surfacing stale bookkeeping, so `mode ==
/// None` always reports zero — even over a damaged blob, since a mode of
/// "none" makes the blob's contents moot either way.
pub fn phone_count_for_mode(mode: AtRestMode, raw: Option<usize>) -> Option<usize> {
    if mode == AtRestMode::None {
        Some(0)
    } else {
        raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_key::{DK_LEN, NONCE_LEN, SLOT_SECRET_LEN};

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
    fn encrypted_with_no_resolved_marker_reports_encrypted_never_pin() {
        // A missing, malformed or stale-digest marker (see
        // `data_key::secret_kind_from_marker`) must never be reported as
        // "pin": only a PIN_UNLOCK guess counts towards the 5-failure wipe,
        // so mislabelling a vault board as "pin" invites typed guesses into a
        // counter it was never meant to arm.
        assert_eq!(derive_mode(true, None), AtRestMode::Encrypted);
    }

    #[test]
    fn wire_spellings_match_the_plan() {
        assert_eq!(AtRestMode::None.wire(), "none");
        assert_eq!(AtRestMode::Pin.wire(), "pin");
        assert_eq!(AtRestMode::Vault.wire(), "vault");
        assert_eq!(AtRestMode::Encrypted.wire(), "encrypted");
    }

    #[test]
    fn phone_count_absent_blob_is_zero() {
        assert_eq!(phone_count_from_blob(None), Some(0));
    }

    #[test]
    fn phone_count_corrupt_blob_is_null_not_zero() {
        assert_eq!(phone_count_from_blob(Some(b"not a phone set")), None);
    }

    #[test]
    fn phone_count_empty_set_is_zero() {
        let set = PhoneSet::default();
        let encoded = set.encode();
        assert_eq!(phone_count_from_blob(Some(&encoded)), Some(0));
    }

    #[test]
    fn phone_count_matches_several_enrolled() {
        let dk = [7u8; DK_LEN];
        let mut set = PhoneSet::default();
        for i in 0..3u32 {
            let slot_secret = [i as u8 + 1; SLOT_SECRET_LEN];
            let nonce = [i as u8; NONCE_LEN];
            set.enrol(i, "phone", &slot_secret, &dk, &nonce)
                .expect("enrol under the cap");
        }
        let encoded = set.encode();
        assert_eq!(phone_count_from_blob(Some(&encoded)), Some(3));
    }

    #[test]
    fn phone_count_after_revoke_drops_by_one() {
        let dk = [9u8; DK_LEN];
        let mut set = PhoneSet::default();
        for i in 0..2u32 {
            let slot_secret = [i as u8 + 1; SLOT_SECRET_LEN];
            let nonce = [i as u8; NONCE_LEN];
            set.enrol(i, "phone", &slot_secret, &dk, &nonce)
                .expect("enrol under the cap");
        }
        set.revoke(0).expect("id 0 is enrolled");
        let encoded = set.encode();
        assert_eq!(phone_count_from_blob(Some(&encoded)), Some(1));
    }

    #[test]
    fn none_mode_always_reports_zero_phones_even_over_a_leftover_or_damaged_blob() {
        // Removing the last identity leaves `dk_ph` behind (provision.rs,
        // masters.rs); once at-rest is "none" that blob is orphaned
        // bookkeeping, not a live phone. The override applies even if the
        // leftover blob happens to be unreadable.
        assert_eq!(phone_count_for_mode(AtRestMode::None, Some(5)), Some(0));
        assert_eq!(phone_count_for_mode(AtRestMode::None, None), Some(0));
        assert_eq!(phone_count_for_mode(AtRestMode::None, Some(0)), Some(0));
    }

    #[test]
    fn other_modes_pass_the_raw_count_through_unchanged() {
        for mode in [AtRestMode::Pin, AtRestMode::Vault, AtRestMode::Encrypted] {
            assert_eq!(phone_count_for_mode(mode, Some(2)), Some(2));
            assert_eq!(phone_count_for_mode(mode, Some(0)), Some(0));
            assert_eq!(phone_count_for_mode(mode, None), None, "{mode:?} must not paper over damage");
        }
    }
}
