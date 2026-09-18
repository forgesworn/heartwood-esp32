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
/// (`note_store::MAX_NOTES`) is 16, so this is not a truncation in practice —
/// it is the same number written down on the wire side so a hostile or
/// corrupt file cannot make a reader allocate without bound.
pub const MAX_NOTE_INVENTORY: usize = 16;

/// A non-spendable record of one bearer note the locker held when the backup
/// was taken.
///
/// This exists because of the asymmetry at the heart of the note locker: a
/// seed is a key and copies safely, but a bearer note IS its secret, so a
/// restored copy of one is a double spend. Notes therefore stay out of
/// backups as money. What goes in is this: enough to make a dead board a
/// legible, provable loss — what existed, how much, at which mint, in what
/// state — and nothing with which to move a satoshi.
///
/// `secret_hash` is the note's PUBLIC commitment
/// (`note_store::note_commitment_hex`): the identifier the issuing mint
/// already files the note under. For an ordinary note that is `sha256(k1)`;
/// for a note paid to one of this device's own keys it is that key's x-only
/// public key, which is what the mint recovers from a spend. `key_index`
/// being non-null is what distinguishes the second case from the first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteInventoryEntry {
    /// Note id: 8 lowercase hex characters.
    pub id: String,
    /// 64 lowercase hex characters. A commitment, never a preimage.
    pub secret_hash: String,
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
            secret_hash: commitment.to_string(),
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
    /// than quietly believed — it is never acted on either way.
    pub fn well_formed(&self) -> bool {
        fn lower_hex(s: &str, len: usize) -> bool {
            s.len() == len
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        lower_hex(&self.id, 8)
            && lower_hex(&self.secret_hash, 64)
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

/// What a restore may do with a carried inventory: look at it, and nothing
/// else.
///
/// This function takes no store, no storage and no secret, and returns
/// counts. That is the whole of the no-resurrection rule, stated as a
/// signature rather than as a convention: there is no path from a backup
/// file to a note, because nothing on the import side is handed anything it
/// could write a note with. A restored inventory line is a record of
/// something that was lost, and a lost bearer note stays lost — the
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
}

/// Inspect (and thereby discard) the inventory on an imported backup.
pub fn inspect_imported_inventory(payload: &BackupPayload) -> InventoryReport {
    let Some(inventory) = payload.note_inventory.as_ref() else {
        return InventoryReport::default();
    };
    InventoryReport {
        entries: inventory.len(),
        malformed: inventory.iter().filter(|e| !e.well_formed()).count(),
        over_cap: inventory.len() > MAX_NOTE_INVENTORY,
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
    /// backup, which has no locker — hence `Option` rather than an empty
    /// vector, which would claim "this device held no notes".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note_inventory: Option<Vec<NoteInventoryEntry>>,
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
            secret_hash: "11".repeat(32),
            state: "confirmed".to_string(),
            amount_msat: 21_000,
            host: "mint.example/w".to_string(),
            key_index: None,
            created_at: 100,
            updated_at: 100,
        }
    }

    fn payload_with(inventory: Option<Vec<NoteInventoryEntry>>) -> BackupPayload {
        BackupPayload {
            created_at: 1,
            device_id: "dd".repeat(32),
            bridge_secret: "ee".repeat(32),
            masters: vec![],
            note_inventory: inventory,
        }
    }

    #[test]
    fn inventory_serialises_in_the_shape_the_reader_checks() {
        let payload = payload_with(Some(vec![sample_entry()]));
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&payload).unwrap()).unwrap();
        let entry = &json["note_inventory"][0];

        assert_eq!(entry["id"], "a1b2c3d4");
        assert_eq!(entry["secret_hash"], "11".repeat(32));
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
            secret_hash: "5d".repeat(32),
            ..sample_entry()
        };
        assert!(entry.well_formed());
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&entry).unwrap()).unwrap();
        assert_eq!(json["key_index"], 7);
        assert_eq!(json["secret_hash"], "5d".repeat(32));
    }

    #[test]
    fn a_locker_with_no_notes_still_says_so() {
        let payload = payload_with(Some(vec![]));
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"note_inventory\":[]"));
        let decoded: BackupPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.note_inventory, Some(vec![]));
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
        // `deny_unknown_fields` — which is precisely why this works, and why
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
        bad(|e| e.secret_hash = "not-a-hash".to_string());
        bad(|e| e.secret_hash = "11".repeat(31));
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
}
