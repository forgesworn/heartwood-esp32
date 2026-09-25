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

/// Everything FIRMWARE_INFO and get_status report about at-rest state,
/// resolved in one place from raw NVS reads instead of three call sites each
/// composing `derive_mode`/`phone_count_from_blob`/`phone_count_for_mode`
/// themselves. Pure — every input is bytes or a length the caller already
/// read — so it is host-testable without an `EspNvs`.
///
/// - `encrypted`: `masters::encryption_at_rest_active`'s result.
/// - `wrap`, `marker`: the raw `dk_sec` / `at_rest_kind` blobs, if present.
/// - `phone_blob_len`: `dk_ph`'s `blob_len()` — `None` only when the key is
///   absent. A read failure when inspecting the key is the caller's to turn
///   into "damaged" (a length outside anything valid, e.g. `usize::MAX`),
///   never into `None`/absent, which this treats as an honest zero phones.
/// - `phone_blob`: the bytes actually read back for `dk_ph`. A length that
///   disagrees with `phone_blob_len` (oversized beyond the format ceiling, or
///   a short read) is treated as damage, exactly like a blob that fails to
///   parse — see the size cases in the tests below.
pub fn resolve(
    encrypted: bool,
    wrap: Option<&[u8]>,
    marker: Option<&[u8]>,
    phone_blob_len: Option<usize>,
    phone_blob: Option<&[u8]>,
) -> (AtRestMode, Option<usize>) {
    let mode = derive_mode(encrypted, crate::data_key::secret_kind_from_marker(wrap, marker));
    let raw_phones = match phone_blob_len {
        None => Some(0),
        Some(len) if len > crate::data_key::MAX_PHONES_BLOB_LEN => None,
        Some(len) => match phone_blob {
            Some(bytes) if bytes.len() == len => phone_count_from_blob(Some(bytes)),
            _ => None,
        },
    };
    (mode, phone_count_for_mode(mode, raw_phones))
}

/// Keys in the reduced status reply a per-identity delegate receives
/// (`dispatch_mgmt`'s `get_status` arm, `firmware/src/relay.rs`). Kept here,
/// not just typed out in `relay.rs`, so the fallback-is-a-subset test below
/// cannot silently drift from what the firmware actually sends — the
/// property the closed heap-pressure leak depended on.
pub const DELEGATE_STATUS_KEYS: &[&str] = &[
    "master_npub_hex",
    "mode",
    "capabilities",
    "slots",
    "client_storage_ready",
    "version",
    "board",
];

/// Keys in the same delegate's reply when the board is too low on heap to
/// answer in full (`minimal_status_json`'s `!is_device_op` branch,
/// `firmware/src/relay.rs`). `truncated` is the one key here that is not in
/// [`DELEGATE_STATUS_KEYS`]: a structural "this reply was cut down" marker
/// present on every low-heap reply, device or delegate, that names no data —
/// not a fact about the owner's board. Every other key here must already be
/// one the delegate's normal reply carries; see the subset test.
pub const DELEGATE_STATUS_FALLBACK_KEYS: &[&str] = &[
    "master_npub_hex",
    "mode",
    "version",
    "board",
    "truncated",
];

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

    fn phone_set_bytes(count: u32) -> Vec<u8> {
        let dk = [1u8; DK_LEN];
        let mut set = PhoneSet::default();
        for i in 0..count {
            let slot_secret = [i as u8 + 1; SLOT_SECRET_LEN];
            let nonce = [i as u8; NONCE_LEN];
            set.enrol(i, "phone", &slot_secret, &dk, &nonce).unwrap();
        }
        set.encode()
    }

    #[test]
    fn resolve_none_mode_and_no_phones() {
        assert_eq!(resolve(false, None, None, None, None), (AtRestMode::None, Some(0)));
        // A wrapper/marker present alongside `encrypted: false` is
        // inconsistent state, but "none" still wins — no seed is sealed.
        assert_eq!(
            resolve(false, Some(b"x"), Some(b"y"), Some(9), Some(b"garbage!!")),
            (AtRestMode::None, Some(0))
        );
    }

    #[test]
    fn resolve_vault_mode_with_phones() {
        let bytes = phone_set_bytes(2);
        let wrap = [0u8; crate::data_key::SECRET_WRAP_LEN];
        let marker = crate::data_key::encode_secret_kind_marker(
            crate::data_key::SecretKind::Vault,
            &wrap,
        );
        assert_eq!(
            resolve(true, Some(&wrap), Some(&marker), Some(bytes.len()), Some(&bytes)),
            (AtRestMode::Vault, Some(2))
        );
    }

    #[test]
    fn resolve_encrypted_mode_when_the_marker_is_absent() {
        let wrap = [0u8; crate::data_key::SECRET_WRAP_LEN];
        assert_eq!(
            resolve(true, Some(&wrap), None, None, None),
            (AtRestMode::Encrypted, Some(0))
        );
    }

    #[test]
    fn resolve_phone_count_null_over_an_oversized_blob() {
        let wrap = [0u8; crate::data_key::SECRET_WRAP_LEN];
        let marker = crate::data_key::encode_secret_kind_marker(
            crate::data_key::SecretKind::Pin,
            &wrap,
        );
        let huge = vec![0u8; crate::data_key::MAX_PHONES_BLOB_LEN + 1];
        let (mode, count) = resolve(
            true,
            Some(&wrap),
            Some(&marker),
            Some(huge.len()),
            Some(&huge),
        );
        assert_eq!(mode, AtRestMode::Pin);
        assert_eq!(count, None, "an oversized blob must read as damage, not a count");
    }

    #[test]
    fn resolve_phone_count_null_over_a_length_mismatch() {
        let wrap = [0u8; crate::data_key::SECRET_WRAP_LEN];
        let marker = crate::data_key::encode_secret_kind_marker(
            crate::data_key::SecretKind::Pin,
            &wrap,
        );
        // `blob_len` said 50, but only 10 bytes actually came back — a short
        // or torn read must not be graded against the wrong length.
        let short = vec![0u8; 10];
        let (_, count) = resolve(true, Some(&wrap), Some(&marker), Some(50), Some(&short));
        assert_eq!(count, None);
    }

    #[test]
    fn resolve_phone_count_null_over_a_zero_length_blob() {
        let wrap = [0u8; crate::data_key::SECRET_WRAP_LEN];
        let marker = crate::data_key::encode_secret_kind_marker(
            crate::data_key::SecretKind::Pin,
            &wrap,
        );
        // A stored zero-length `dk_ph` cannot happen through `save_phones`
        // (it removes the key instead), so this is already damage: shorter
        // than the format's own header.
        let (_, count) = resolve(true, Some(&wrap), Some(&marker), Some(0), Some(&[]));
        assert_eq!(count, None);
    }

    #[test]
    fn the_delegate_fallback_never_carries_a_key_the_normal_reply_does_not() {
        for key in DELEGATE_STATUS_FALLBACK_KEYS {
            assert!(
                *key == "truncated" || DELEGATE_STATUS_KEYS.contains(key),
                "{key} is new in the fallback and not in the delegate's normal reply"
            );
        }
    }
}
