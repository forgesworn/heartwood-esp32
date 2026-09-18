// common/src/backup.rs
//
// Backup payload types shared between firmware and heartwoodd.
// The backup JSON is the plaintext inside the encrypted envelope.
#[allow(unused_imports)]
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use serde::{Deserialize, Serialize};

use crate::note_store::{NoteMeta, NoteStore};
use crate::policy::ConnectSlot;

/// How many inventory entries a backup may carry. The locker's own ceiling
/// (`note_store::MAX_NOTES`) is 16, so this is not a truncation in practice.
/// It is the same number written down on the wire side so a hostile or
/// corrupt file cannot make a reader allocate without bound.
pub const MAX_NOTE_INVENTORY: usize = 16;

/// A non-spendable record of one bearer note the locker held when the backup
/// was taken.
///
/// This exists because of the asymmetry at the heart of the note locker: a
/// seed is a key and copies safely, but a bearer note IS its secret, so a
/// restored copy of one is a double spend. Notes therefore stay out of
/// backups as money. What goes in is this: enough to make a dead board a
/// legible, provable loss: what existed, how much, at which mint, in what
/// state, and nothing with which to move a satoshi.
///
/// `commitment` (`note_store::note_commitment_hex`) is the identifier the
/// issuing mint already files the note under. For an ordinary note that is
/// `sha256(k1)`; for a note paid to one of this device's own keys it is that
/// key's x-only public key, which is what the mint recovers from a spend.
/// `key_index` being non-null is what distinguishes the second case from the
/// first. It is deliberately not called `secret_hash`: for half the notes
/// here it is not a hash of anything, and a name that says otherwise invites
/// a reader to check it the wrong way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteInventoryEntry {
    /// Note id: 8 lowercase hex characters.
    pub id: String,
    /// 64 lowercase hex characters. A commitment, never a preimage.
    pub commitment: String,
    /// `pending` | `confirmed` | `spent`.
    pub state: String,
    pub amount_msat: u64,
    /// The note's withdraw endpoint, path and all. At most 64 bytes.
    pub host: String,
    /// Where on this identity's LUD-25 address branch the note's key sits,
    /// for a note paid to a key; `None` for a note behind a hash.
    pub key_index: Option<u32>,
    pub created_at: u32,
    pub updated_at: u32,
}

impl NoteInventoryEntry {
    /// Build one entry from a note's metadata and its public commitment, as
    /// [`NoteStore::commitments`] pairs them. There is deliberately no
    /// constructor that takes a secret.
    pub fn new(meta: &NoteMeta, commitment: &str) -> Self {
        NoteInventoryEntry {
            id: meta.id.clone(),
            commitment: commitment.to_string(),
            state: meta.state.as_str().to_string(),
            amount_msat: meta.amount_msat,
            host: meta.host.clone(),
            key_index: meta.key.as_ref().map(|k| k.index),
            created_at: meta.created_at,
            updated_at: meta.updated_at,
        }
    }

    /// Shape check, matching the reader's (Sapwood's `isNoteInventory`).
    /// Used on the import side so a malformed inventory is reported rather
    /// than quietly believed. It is never acted on either way.
    pub fn well_formed(&self) -> bool {
        fn lower_hex(s: &str, len: usize) -> bool {
            s.len() == len
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        lower_hex(&self.id, 8)
            && lower_hex(&self.commitment, 64)
            && matches!(self.state.as_str(), "pending" | "confirmed" | "spent")
            && self.host.len() <= crate::note_store::MAX_HOST_LEN
            // The reader is JavaScript and parses these as doubles. An amount
            // above 2^53-1 is unreachable on any real mint (it is nine million
            // bitcoin) but it would not survive the trip, so it is malformed
            // here rather than a silent difference of opinion there.
            && self.amount_msat <= MAX_SAFE_INTEGER
            && u64::from(self.created_at) <= MAX_SAFE_INTEGER
            && u64::from(self.updated_at) <= MAX_SAFE_INTEGER
    }
}

/// `Number.MAX_SAFE_INTEGER`. The backup's reader is JavaScript.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Build the inventory a backup carries, from the locker.
///
/// Takes the store by shared reference and can therefore change nothing.
/// Only notes this boot can actually read appear: a record still sealed
/// under a key the device has not been given is not in the store, and
/// inventing a line for it would be exactly the dishonesty this feature
/// exists to remove. Entries that could not survive the reader's own shape
/// check are dropped rather than emitted, so one impossible note cannot make
/// a whole backup file unparseable.
pub fn build_note_inventory(store: &NoteStore) -> Vec<NoteInventoryEntry> {
    store
        .commitments()
        .iter()
        .map(|(meta, commitment)| NoteInventoryEntry::new(meta, commitment))
        .filter(|entry| entry.well_formed())
        .take(MAX_NOTE_INVENTORY)
        .collect()
}

/// A carried inventory as the import side sees it.
///
/// A backup's job is to restore identities and pairings. The inventory is a
/// record of something that is already gone, so it must never be able to stop
/// that job: a file written by a future firmware, or corrupted in storage,
/// still has to give an owner their app slots back. Hence the second variant,
/// and hence [`BackupPayload`]'s deserialiser accepting anything at all here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteInventory {
    /// Entries this firmware understands. Well-formedness is a separate
    /// question, reported by [`InventoryReport::malformed`].
    Entries(Vec<NoteInventoryEntry>),
    /// Something was in the field and it was not a list of entries this
    /// firmware can read. Kept as a fact rather than an error: the restore
    /// carries on, and the operator is told the inventory was ignored.
    Unreadable,
}

impl NoteInventory {
    pub fn entries(&self) -> &[NoteInventoryEntry] {
        match self {
            NoteInventory::Entries(entries) => entries,
            NoteInventory::Unreadable => &[],
        }
    }
}

impl Serialize for NoteInventory {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            NoteInventory::Entries(entries) => entries.serialize(s),
            // Never produced by an export. A payload re-serialised after an
            // import (heartwoodd relays one) drops a field it could not read
            // rather than passing on a shape it does not understand.
            NoteInventory::Unreadable => s.serialize_none(),
        }
    }
}

impl<'de> Deserialize<'de> for NoteInventory {
    /// Read the field as free-form JSON first, then try to make entries of
    /// it. Only the first step can fail, and it fails only where the whole
    /// document was already malformed, so a `note_inventory` this firmware
    /// does not understand costs the inventory and nothing else.
    ///
    /// Deliberately not `#[serde(untagged)]`, which would do the same job:
    /// untagged pulls in serde's own self-describing buffer type and its
    /// `Deserialize` impl, and measured on the Heltec release image that is
    /// about 5 KB of a slot with a few tens of KB spare. `serde_json::Value`
    /// is already linked into this firmware many times over (it is how every
    /// note command arrives), so routing through it is free.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = serde_json::Value::deserialize(d)?;
        Ok(match serde_json::from_value::<Vec<NoteInventoryEntry>>(raw) {
            Ok(entries) => NoteInventory::Entries(entries),
            Err(_) => NoteInventory::Unreadable,
        })
    }
}

/// What a restore may do with a carried inventory: look at it, and nothing
/// else.
///
/// This function takes no store, no storage and no secret, and returns
/// counts. That is the whole of the no-resurrection rule, stated as a
/// signature rather than as a convention: there is no path from a backup
/// file to a note, because nothing on the import side is handed anything it
/// could write a note with. A restored inventory line is a record of
/// something that was lost, and a lost bearer note stays lost. The
/// alternative is a second board believing in money the first one already
/// spent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InventoryReport {
    /// Entries carried in the file.
    pub entries: usize,
    /// Of those, how many failed the shape check.
    pub malformed: usize,
    /// True when the file carried more entries than any locker could hold.
    pub over_cap: bool,
    /// The field was present but in no shape this firmware reads, so it was
    /// ignored whole. The restore is unaffected either way.
    pub unreadable_field: bool,
    /// Notes the EXPORTING board could not read, as that board counted them
    /// (`note_inventory_unreadable`). Not a fault in this file: it is how
    /// many notes the inventory is known to be missing.
    pub unreadable_notes: u32,
}

/// Inspect (and thereby discard) the inventory on an imported backup.
pub fn inspect_imported_inventory(payload: &BackupPayload) -> InventoryReport {
    let mut report = InventoryReport {
        unreadable_notes: payload.note_inventory_unreadable,
        ..InventoryReport::default()
    };
    match payload.note_inventory.as_ref() {
        None => report,
        Some(NoteInventory::Unreadable) => {
            report.unreadable_field = true;
            report
        }
        Some(NoteInventory::Entries(entries)) => {
            report.entries = entries.len();
            report.malformed = entries.iter().filter(|e| !e.well_formed()).count();
            report.over_cap = entries.len() > MAX_NOTE_INVENTORY;
            report
        }
    }
}

/// A master's metadata and connection slots for backup purposes.
/// Does NOT contain the master secret -- only enough to match
/// against a re-provisioned master by pubkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMaster {
    pub slot: u8,
    pub label: String,
    /// Provisioning mode (0=Bunker, 1=TreeMnemonic, 2=TreeNsec).
    pub mode: u8,
    /// 0 for direct/raw keys; 1 for the frozen nsec-tree v1 derivation.
    /// Missing on historical backup JSON and therefore defaults to unknown/0.
    #[serde(default)]
    pub derivation_version: u8,
    /// Hex-encoded x-only public key (64 chars).
    pub pubkey: String,
    pub connection_slots: Vec<ConnectSlot>,
}

/// The complete backup payload (plaintext, before encryption).
///
/// SECURITY: this struct contains the bridge secret in plaintext. Callers
/// MUST encrypt it (the Argon2id + XChaCha20-Poly1305 backup envelope) before
/// serialising — nothing in the type system enforces encrypt-before-serialise,
/// so every new consumer is responsible for upholding it. It must only exist
/// in memory or inside an encrypted backup envelope. Never serialise to disk,
/// logs, or the wire without encrypting first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPayload {
    /// Unix timestamp (seconds) when the backup was created.
    pub created_at: u64,
    /// Hex-encoded SHA-256 of the bridge secret -- non-secret device fingerprint.
    pub device_id: String,
    pub masters: Vec<BackupMaster>,
    /// Hex-encoded bridge secret (64 chars). Included so the Pi-ESP32 link
    /// can be restored without re-pairing. Encrypted at rest in the backup envelope.
    pub bridge_secret: String,
    /// A non-spendable record of the bearer notes held when the backup was
    /// taken (#86). Notes themselves are NOT here and never will be: this
    /// says what was lost, it cannot restore it. See [`NoteInventoryEntry`].
    ///
    /// `None` on backups written before the field existed, and on a Soft-mode
    /// backup, which has no locker. Hence `Option` rather than an empty
    /// vector, which would claim "this device held no notes".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note_inventory: Option<NoteInventory>,
    /// How many notes the exporting board held but could NOT read, and so
    /// could not inventory: records still sealed under an at-rest key that
    /// boot was never given, or a locker whose index would not load.
    ///
    /// This travels in the FILE and not only in a log, because otherwise an
    /// export taken on a locked board carries an empty inventory that is
    /// byte-identical to one taken on an empty locker. The whole point of
    /// #86 is that a loss is legible, and "I cannot see N of them" is a
    /// different statement from "there were none". Zero is omitted, so the
    /// common case adds nothing to the file.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub note_inventory_unreadable: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ConnectSlot;

    fn sample_slot(index: u8, label: &str) -> ConnectSlot {
        ConnectSlot {
            slot_index: index,
            label: label.to_string(),
            secret: "ab".repeat(32),
            current_pubkey: Some("cc".repeat(32)),
            allowed_methods: vec!["sign_event".to_string(), "get_public_key".to_string()],
            allowed_kinds: vec![1, 7],
            auto_approve: true,
            signing_approved: true,
            strict_permissions: false,
            authorized_pubkeys: vec![],
            escalate: false,
            petition_on_deny: false,
            audit_child_wrap: false,
            guardian_notice_wrap: false,
            bound_identity: None,
            approved_identities: String::new(),
            was_bound: false,
        }
    }

    #[test]
    fn serde_roundtrip() {
        let payload = BackupPayload {
            created_at: 1_700_000_000,
            device_id: "dd".repeat(32),
            bridge_secret: "ee".repeat(32),
            note_inventory: None,
            note_inventory_unreadable: 0,
            masters: vec![BackupMaster {
                slot: 0,
                label: "Personal".to_string(),
                mode: 1,
                derivation_version: 1,
                pubkey: "ff".repeat(32),
                connection_slots: vec![sample_slot(0, "nostrudel desktop")],
            }],
        };

        let json = serde_json::to_string(&payload).unwrap();
        let decoded: BackupPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.created_at, 1_700_000_000);
        assert_eq!(decoded.device_id, "dd".repeat(32));
        assert_eq!(decoded.bridge_secret, "ee".repeat(32));
        assert_eq!(decoded.masters.len(), 1);

        let master = &decoded.masters[0];
        assert_eq!(master.slot, 0);
        assert_eq!(master.label, "Personal");
        assert_eq!(master.mode, 1);
        assert_eq!(master.derivation_version, 1);
        assert_eq!(master.pubkey, "ff".repeat(32));
        assert_eq!(master.connection_slots.len(), 1);
        assert_eq!(master.connection_slots[0].label, "nostrudel desktop");
        assert_eq!(master.connection_slots[0].slot_index, 0);
    }

    #[test]
    fn historical_backup_without_derivation_version_defaults_to_zero() {
        let json = r#"{
            "created_at": 1700000000,
            "device_id": "legacy-device",
            "masters": [{
                "slot": 0,
                "label": "Legacy",
                "mode": 1,
                "pubkey": "legacy-pubkey",
                "connection_slots": []
            }],
            "bridge_secret": "legacy-bridge-secret"
        }"#;

        let decoded: BackupPayload = serde_json::from_str(json).unwrap();

        assert_eq!(decoded.masters[0].derivation_version, 0);
    }

    #[test]
    fn empty_masters_roundtrip() {
        let payload = BackupPayload {
            created_at: 1_600_000_000,
            device_id: "aa".repeat(32),
            bridge_secret: "bb".repeat(32),
            note_inventory: None,
            note_inventory_unreadable: 0,
            masters: vec![],
        };

        let json = serde_json::to_string(&payload).unwrap();
        let decoded: BackupPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.created_at, 1_600_000_000);
        assert!(decoded.masters.is_empty());
    }

    #[test]
    fn multiple_masters_multiple_slots() {
        let payload = BackupPayload {
            created_at: 1_750_000_000,
            device_id: "11".repeat(32),
            bridge_secret: "22".repeat(32),
            note_inventory: None,
            note_inventory_unreadable: 0,
            masters: vec![
                BackupMaster {
                    slot: 0,
                    label: "Work".to_string(),
                    mode: 2,
                    derivation_version: 1,
                    pubkey: "33".repeat(32),
                    connection_slots: vec![
                        sample_slot(0, "Bark browser"),
                        sample_slot(1, "nostrudel desktop"),
                    ],
                },
                BackupMaster {
                    slot: 1,
                    label: "Personal".to_string(),
                    mode: 0,
                    derivation_version: 0,
                    pubkey: "44".repeat(32),
                    connection_slots: vec![],
                },
            ],
        };

        let json = serde_json::to_string(&payload).unwrap();
        let decoded: BackupPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.masters.len(), 2);

        let work = &decoded.masters[0];
        assert_eq!(work.label, "Work");
        assert_eq!(work.mode, 2);
        assert_eq!(work.connection_slots.len(), 2);
        assert_eq!(work.connection_slots[0].label, "Bark browser");
        assert_eq!(work.connection_slots[1].label, "nostrudel desktop");

        let personal = &decoded.masters[1];
        assert_eq!(personal.label, "Personal");
        assert_eq!(personal.mode, 0);
        assert!(personal.connection_slots.is_empty());
    }

    // ---- note inventory (#86) ----
    //
    // The wire shape here is a contract with Sapwood's `isNoteInventory`
    // (src/lib/backup.ts). These tests pin the JSON exactly as that parser
    // reads it, so a drift on this side fails here rather than at a restore.

    fn sample_entry() -> NoteInventoryEntry {
        NoteInventoryEntry {
            id: "a1b2c3d4".to_string(),
            commitment: "11".repeat(32),
            state: "confirmed".to_string(),
            amount_msat: 21_000,
            host: "mint.example/w".to_string(),
            key_index: None,
            created_at: 100,
            updated_at: 100,
        }
    }

    fn payload_with(inventory: Option<Vec<NoteInventoryEntry>>) -> BackupPayload {
        payload_full(inventory, 0)
    }

    fn payload_full(
        inventory: Option<Vec<NoteInventoryEntry>>,
        unreadable: u32,
    ) -> BackupPayload {
        BackupPayload {
            created_at: 1,
            device_id: "dd".repeat(32),
            bridge_secret: "ee".repeat(32),
            masters: vec![sample_master()],
            note_inventory: inventory.map(NoteInventory::Entries),
            note_inventory_unreadable: unreadable,
        }
    }

    fn sample_master() -> BackupMaster {
        BackupMaster {
            slot: 0,
            label: "Personal".to_string(),
            mode: 1,
            derivation_version: 1,
            pubkey: "ff".repeat(32),
            connection_slots: vec![sample_slot(0, "nostrudel desktop")],
        }
    }

    #[test]
    fn inventory_serialises_in_the_shape_the_reader_checks() {
        let payload = payload_with(Some(vec![sample_entry()]));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&payload).unwrap()).unwrap();
        let entry = &json["note_inventory"][0];

        assert_eq!(entry["id"], "a1b2c3d4");
        assert_eq!(entry["commitment"], "11".repeat(32));
        assert_eq!(entry["state"], "confirmed");
        assert_eq!(entry["amount_msat"], 21_000);
        assert_eq!(entry["host"], "mint.example/w");
        // null, not absent: the reader distinguishes "no key" from a key at
        // index 0, and `undefined` would fail its `key_index === null` arm.
        assert!(entry["key_index"].is_null());
        assert_eq!(entry["created_at"], 100);
        assert_eq!(entry["updated_at"], 100);
        assert_eq!(entry.as_object().unwrap().len(), 8, "no extra fields");
    }

    #[test]
    fn a_key_note_carries_its_index_and_a_pubkey_commitment() {
        let entry = NoteInventoryEntry {
            key_index: Some(7),
            commitment: "5d".repeat(32),
            ..sample_entry()
        };
        assert!(entry.well_formed());
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&entry).unwrap()).unwrap();
        assert_eq!(json["key_index"], 7);
        assert_eq!(json["commitment"], "5d".repeat(32));
    }

    #[test]
    fn a_locker_with_no_notes_still_says_so() {
        let payload = payload_with(Some(vec![]));
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"note_inventory\":[]"));
        let decoded: BackupPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.note_inventory, Some(NoteInventory::Entries(vec![])));
    }

    #[test]
    fn a_backup_with_no_locker_omits_the_field_entirely() {
        // Soft mode, and every backup written before #86. An absent field is
        // "this backup makes no claim about notes", which is not the same
        // statement as "this device held none".
        let json = serde_json::to_string(&payload_with(None)).unwrap();
        assert!(!json.contains("note_inventory"));
    }

    #[test]
    fn historical_backup_without_an_inventory_parses_unchanged() {
        let json = r#"{
            "created_at": 1700000000,
            "device_id": "legacy-device",
            "masters": [],
            "bridge_secret": "legacy-bridge-secret"
        }"#;
        let decoded: BackupPayload = serde_json::from_str(json).unwrap();
        assert!(decoded.note_inventory.is_none());
        assert_eq!(decoded.bridge_secret, "legacy-bridge-secret");
    }

    #[test]
    fn firmware_that_predates_the_field_still_reads_a_new_backup() {
        // The old struct, field for field, with no `note_inventory` and no
        // `deny_unknown_fields`, which is precisely why this works, and why
        // this test exists to stop anyone adding one.
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct OldPayload {
            created_at: u64,
            device_id: String,
            masters: Vec<BackupMaster>,
            bridge_secret: String,
        }

        let json = serde_json::to_string(&payload_with(Some(vec![sample_entry()]))).unwrap();
        let old: OldPayload = serde_json::from_str(&json).expect("unknown field tolerated");
        assert_eq!(old.bridge_secret, "ee".repeat(32));
    }

    #[test]
    fn shape_check_matches_the_readers_rules() {
        assert!(sample_entry().well_formed());

        let bad = |f: fn(&mut NoteInventoryEntry)| {
            let mut e = sample_entry();
            f(&mut e);
            assert!(!e.well_formed(), "should be rejected");
        };

        bad(|e| e.id = "A1B2C3D4".to_string()); // uppercase
        bad(|e| e.id = "a1b2c3d".to_string()); // seven
        bad(|e| e.commitment = "not-a-hash".to_string());
        bad(|e| e.commitment = "11".repeat(31));
        bad(|e| e.state = "melted".to_string());
        bad(|e| e.host = "x".repeat(65));
        bad(|e| e.amount_msat = u64::MAX);
    }

    #[test]
    fn an_import_only_ever_counts_an_inventory() {
        let mut entries = vec![sample_entry(); 3];
        entries[1].state = "wibble".to_string();
        let report = inspect_imported_inventory(&payload_with(Some(entries)));
        assert_eq!(report.entries, 3);
        assert_eq!(report.malformed, 1);
        assert!(!report.over_cap);

        let over = inspect_imported_inventory(&payload_with(Some(vec![
            sample_entry();
            MAX_NOTE_INVENTORY + 1
        ])));
        assert!(over.over_cap);

        assert_eq!(
            inspect_imported_inventory(&payload_with(None)),
            InventoryReport::default()
        );
    }

    // ---- a locked board must not export a lie ----

    #[test]
    fn an_export_that_could_not_read_every_note_says_so_in_the_file() {
        // The case this exists for: a board locked at rest, where every
        // record is sealed and the locker reads none of them. Without the
        // count, this file is byte-identical to one taken on an empty
        // locker, and the owner is told a loss is nil when it is unknown.
        let locked = payload_full(Some(vec![]), 4);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&locked).unwrap()).unwrap();
        assert_eq!(json["note_inventory"].as_array().unwrap().len(), 0);
        assert_eq!(json["note_inventory_unreadable"], 4);

        let empty = payload_full(Some(vec![]), 0);
        let empty_json = serde_json::to_string(&empty).unwrap();
        assert!(!empty_json.contains("note_inventory_unreadable"), "zero is omitted");

        // And the two are distinguishable after a round trip, which is the
        // whole claim.
        let locked_back: BackupPayload =
            serde_json::from_str(&serde_json::to_string(&locked).unwrap()).unwrap();
        let empty_back: BackupPayload = serde_json::from_str(&empty_json).unwrap();
        assert_eq!(locked_back.note_inventory_unreadable, 4);
        assert_eq!(empty_back.note_inventory_unreadable, 0);
        assert_eq!(
            locked_back.note_inventory.as_ref().map(NoteInventory::entries),
            empty_back.note_inventory.as_ref().map(NoteInventory::entries),
            "the inventories are identical; only the count tells them apart"
        );
    }

    #[test]
    fn a_partly_readable_locker_reports_both_halves() {
        let partial = payload_full(Some(vec![sample_entry()]), 2);
        let report = inspect_imported_inventory(&partial);
        assert_eq!(report.entries, 1);
        assert_eq!(report.unreadable_notes, 2);
        assert!(!report.unreadable_field);
    }

    #[test]
    fn a_historical_backup_reads_the_count_as_zero() {
        let json = r#"{
            "created_at": 1,
            "device_id": "legacy",
            "masters": [],
            "bridge_secret": "legacy"
        }"#;
        let decoded: BackupPayload = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.note_inventory_unreadable, 0);
        assert!(decoded.note_inventory.is_none());
    }

    // ---- an inventory must never cost an owner their pairings ----

    /// Every shape a `note_inventory` has no business being, including one a
    /// future firmware might legitimately write.
    #[cfg(test)]
    const HOSTILE_INVENTORIES: &[&str] = &[
        "42",
        "\"a string\"",
        "null",
        "{\"not\":\"a list\"}",
        "[1,2,3]",
        "[{\"id\":42}]",
        // An entry missing required fields.
        "[{\"id\":\"a1b2c3d4\"}]",
        // Nested, and far larger than any locker could hold.
        "[[[[[1]]]]]",
        // An entry written against the pre-release field name. The inventory
        // is a record, not a restore, so an unrecognised entry shape costs
        // nothing but the record: it is ignored, and the slots still come
        // back.
        "[{\"id\":\"a1b2c3d4\",\"secret_hash\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"state\":\"spent\",\"amount_msat\":1,\"host\":\"m\",\"key_index\":null,\"created_at\":1,\"updated_at\":1}]",
    ];

    #[test]
    fn a_garbage_inventory_still_restores_masters_and_slots() {
        for hostile in HOSTILE_INVENTORIES {
            let json = format!(
                r#"{{"created_at":1,"device_id":"dd","bridge_secret":"ee",
                     "masters":[{{"slot":0,"label":"Personal","mode":1,
                       "derivation_version":1,"pubkey":"ff","connection_slots":[]}}],
                     "note_inventory":{hostile}}}"#
            );
            let decoded: BackupPayload = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("inventory {hostile} blocked the restore: {e}"));

            // The part that matters survived, untouched and still strict.
            assert_eq!(decoded.masters.len(), 1);
            assert_eq!(decoded.masters[0].label, "Personal");
            assert_eq!(decoded.bridge_secret, "ee");

            // And not one of these shapes yields an entry: each is either
            // absent or declared unreadable. Never an error, never acted on.
            let report = inspect_imported_inventory(&decoded);
            assert_eq!(report.entries, 0, "inventory {hostile} produced entries");
            assert!(
                decoded
                    .note_inventory
                    .as_ref()
                    .map(NoteInventory::entries)
                    .unwrap_or(&[])
                    .is_empty()
            );
        }
    }

    #[test]
    fn an_oversized_inventory_does_not_block_a_restore_either() {
        let entry = serde_json::to_string(&sample_entry()).unwrap();
        let huge: Vec<String> = (0..200).map(|_| entry.clone()).collect();
        let json = format!(
            r#"{{"created_at":1,"device_id":"dd","bridge_secret":"ee",
                 "masters":[{{"slot":0,"label":"Personal","mode":1,
                   "derivation_version":1,"pubkey":"ff","connection_slots":[]}}],
                 "note_inventory":[{}]}}"#,
            huge.join(",")
        );
        let decoded: BackupPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.masters.len(), 1);
        let report = inspect_imported_inventory(&decoded);
        assert!(report.over_cap);
        assert_eq!(report.entries, 200);
    }

    #[test]
    fn a_future_entry_field_parses_rather_than_reading_as_unreadable() {
        // Forward compatibility in the other direction: this firmware must
        // read tomorrow's entries, not throw the whole inventory away.
        let json = r#"{"created_at":1,"device_id":"dd","bridge_secret":"ee","masters":[],
             "note_inventory":[{"id":"a1b2c3d4",
               "commitment":"1111111111111111111111111111111111111111111111111111111111111111",
               "state":"spent","amount_msat":1,"host":"m","key_index":null,
               "created_at":1,"updated_at":1,"future_field":{"deep":[1,2,3]}}]}"#;
        let decoded: BackupPayload = serde_json::from_str(json).unwrap();
        let report = inspect_imported_inventory(&decoded);
        assert!(!report.unreadable_field);
        assert_eq!(report.entries, 1);
        assert_eq!(report.malformed, 0);
    }

    #[test]
    fn a_wholly_unreadable_inventory_is_reported_as_such() {
        let json = r#"{"created_at":1,"device_id":"dd","bridge_secret":"ee",
                       "masters":[],"note_inventory":"nonsense"}"#;
        let decoded: BackupPayload = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.note_inventory, Some(NoteInventory::Unreadable));
        let report = inspect_imported_inventory(&decoded);
        assert!(report.unreadable_field);
        assert_eq!(report.entries, 0);
        // Re-serialising drops what it could not read rather than passing on
        // a shape it does not understand.
        let out = serde_json::to_string(&decoded).unwrap();
        assert!(out.contains("\"note_inventory\":null"));
    }
}
