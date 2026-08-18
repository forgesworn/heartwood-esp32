//! Bearer-note locker: NVS persistence and the USB frame handler.
//!
//! The lifecycle model and wire protocol live host-tested in
//! `heartwood_common::{note_store, note_cmd}`; this module wires them to the
//! board — an NVS namespace of its own for the blobs, `fill_random` for
//! secrets, and the shared approval loop for every gated command. See
//! docs/plans/2026-08-18-note-locker-goal.md.
//!
//! The `hw_notes` namespace is deliberately NOT part of backup export: a
//! bearer note restored onto two boards is a double-spend waiting to happen,
//! so notes are unrecoverable by design (backup.rs reads only the seed and
//! slot keys it always has; nothing to exclude, but the rule is recorded
//! here where the data lives).
//!
//! At-rest sealing status: v1 stores note blobs as the seeds are stored
//! without a PIN — plaintext, physical-possession model. The sealing pass
//! (notes ride the PIN/vault key like the seeds do) is the remaining half of
//! phase 2 and needs the retained-key design decided; the `NoteStorage`
//! boundary here is where that seal wraps when it lands.

use esp_idf_svc::nvs::{EspNvs, EspNvsPartition, NvsDefault};

use heartwood_common::note_cmd::{self, Approval, GatedCmd, NoteCmdContext};
use heartwood_common::note_store::{
    NoteMeta, NoteStorage, NoteStore, StorageError, ID_LEN, MAX_NOTES,
};
use heartwood_common::types::{FRAME_TYPE_NACK, FRAME_TYPE_NOTE_RESP};

use crate::protocol;
use crate::serial::SerialPort;

/// Own namespace on the shared NVS partition — the locker's churn (a few
/// writes per human-paced spend) stays legible in nvs_stats and is trivially
/// excludable from anything that walks the `heartwood` namespace.
const NAMESPACE: &str = "hw_notes";
const INDEX_KEY: &str = "idx";

/// A note blob is ~120 B for typical hosts/labels; the encoded ceiling with
/// every field maxed is under 600. One page of index is 16 ids × 8 bytes.
const NOTE_BUF: usize = 640;
const INDEX_BUF: usize = MAX_NOTES * ID_LEN;

/// NVS-backed [`NoteStorage`]. The index is the concatenation of 8-byte ids —
/// fixed-width, so a torn length is detectable as "not a multiple of 8", the
/// same integrity trick lnurl-vault's index uses.
pub struct NoteNvs {
    nvs: EspNvs<NvsDefault>,
    /// Set on any failed write/delete so `get_info` can stop reporting a
    /// storage that is refusing writes as "ok" — the per-command error is
    /// storage_full either way, and this field is what lets the wallet tell
    /// "at cap, delete something" from "storage is failing, deleting cannot
    /// help".
    failed: bool,
}

impl NoteStorage for NoteNvs {
    fn load_index(&mut self) -> Result<Option<alloc_vec::Vec<String>>, StorageError> {
        let mut buf = [0u8; INDEX_BUF];
        match self.nvs.get_blob(INDEX_KEY, &mut buf) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => {
                if bytes.len() % ID_LEN != 0 {
                    log::error!(
                        "[notes] index blob is {} bytes, not a multiple of {ID_LEN}; treating as unreadable",
                        bytes.len()
                    );
                    return Err(StorageError);
                }
                let mut ids = alloc_vec::Vec::new();
                for chunk in bytes.chunks(ID_LEN) {
                    match core::str::from_utf8(chunk) {
                        Ok(s) => ids.push(s.to_string()),
                        Err(_) => return Err(StorageError),
                    }
                }
                Ok(Some(ids))
            }
            Err(e) => {
                log::error!("[notes] index read failed: {e}");
                Err(StorageError)
            }
        }
    }

    fn save_index(&mut self, ids: &[String]) -> Result<(), StorageError> {
        let mut blob = alloc_vec::Vec::with_capacity(ids.len() * ID_LEN);
        for id in ids {
            blob.extend_from_slice(id.as_bytes());
        }
        self.nvs.set_blob(INDEX_KEY, &blob).map_err(|e| {
            log::error!("[notes] index write failed: {e}");
            self.failed = true;
            StorageError
        })
    }

    fn load_note(&mut self, id: &str) -> Result<Option<alloc_vec::Vec<u8>>, StorageError> {
        let mut buf = [0u8; NOTE_BUF];
        let result = match self.nvs.get_blob(id, &mut buf) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => Ok(Some(bytes.to_vec())),
            Err(e) => {
                log::error!("[notes] read {id} failed: {e}");
                Err(StorageError)
            }
        };
        // The raw blob embeds the secret; scrub the stack copy.
        use zeroize::Zeroize;
        buf.zeroize();
        result
    }

    fn save_note(&mut self, id: &str, blob: &[u8]) -> Result<(), StorageError> {
        self.nvs.set_blob(id, blob).map_err(|e| {
            log::error!("[notes] write {id} failed: {e}");
            self.failed = true;
            StorageError
        })
    }

    fn delete_note(&mut self, id: &str) -> Result<(), StorageError> {
        self.nvs.remove(id).map(|_| ()).map_err(|e| {
            log::error!("[notes] delete {id} failed: {e}");
            self.failed = true;
            StorageError
        })
    }
}

// The common crate is no_std/alloc; keep the type paths uniform here.
mod alloc_vec {
    pub use std::vec::Vec;
}
use std::string::{String, ToString};

/// Storage stand-in for a boot where the namespace itself would not open:
/// reads say "nothing here", writes fail. Paired with
/// `NoteStore::storage_unavailable`, it keeps the fail-closed semantics
/// without a special store mode — and without making a broken locker take
/// the signer down with it.
struct NullStorage;

impl NoteStorage for NullStorage {
    fn load_index(&mut self) -> Result<Option<alloc_vec::Vec<String>>, StorageError> {
        Err(StorageError)
    }
    fn save_index(&mut self, _ids: &[String]) -> Result<(), StorageError> {
        Err(StorageError)
    }
    fn load_note(&mut self, _id: &str) -> Result<Option<alloc_vec::Vec<u8>>, StorageError> {
        Err(StorageError)
    }
    fn save_note(&mut self, _id: &str, _blob: &[u8]) -> Result<(), StorageError> {
        Err(StorageError)
    }
    fn delete_note(&mut self, _id: &str) -> Result<(), StorageError> {
        Err(StorageError)
    }
}

/// Concrete storage so `storage_state()` can inspect the runtime failure
/// flag — a `Box<dyn NoteStorage>` would hide it.
enum Storage {
    Nvs(NoteNvs),
    Null(NullStorage),
}

impl NoteStorage for Storage {
    fn load_index(&mut self) -> Result<Option<alloc_vec::Vec<String>>, StorageError> {
        match self {
            Storage::Nvs(s) => s.load_index(),
            Storage::Null(s) => s.load_index(),
        }
    }
    fn save_index(&mut self, ids: &[String]) -> Result<(), StorageError> {
        match self {
            Storage::Nvs(s) => s.save_index(ids),
            Storage::Null(s) => s.save_index(ids),
        }
    }
    fn load_note(&mut self, id: &str) -> Result<Option<alloc_vec::Vec<u8>>, StorageError> {
        match self {
            Storage::Nvs(s) => s.load_note(id),
            Storage::Null(s) => s.load_note(id),
        }
    }
    fn save_note(&mut self, id: &str, blob: &[u8]) -> Result<(), StorageError> {
        match self {
            Storage::Nvs(s) => s.save_note(id, blob),
            Storage::Null(s) => s.save_note(id, blob),
        }
    }
    fn delete_note(&mut self, id: &str) -> Result<(), StorageError> {
        match self {
            Storage::Nvs(s) => s.delete_note(id),
            Storage::Null(s) => s.delete_note(id),
        }
    }
}

/// The locker as main.rs owns it: store + storage + the boot-time diagnosis
/// `storage_state()` folds runtime failures into.
pub struct Notes {
    pub store: NoteStore,
    storage: Storage,
    boot_state: &'static str,
}

impl Notes {
    /// The `storage` string `get_info` reports, computed per call so a write
    /// that failed after boot shows up: boot diagnosis first, then the
    /// vault-protocol "full" (out of free pages is the realistic runtime
    /// failure on a shared NVS partition, and "delete notes" genuinely is
    /// the wrong advice the state exists to prevent).
    fn storage_state(&self) -> &'static str {
        match &self.storage {
            Storage::Null(_) => "unavailable",
            Storage::Nvs(nvs) => {
                if self.boot_state != "ok" {
                    self.boot_state
                } else if nvs.failed {
                    "full"
                } else {
                    "ok"
                }
            }
        }
    }
}

/// Bring the locker up. Never erases anything on any failure — a boot that
/// cannot read its notes reports that and refuses creation (the model fails
/// closed), and recovery is a reboot, never a wipe.
pub fn init(partition: EspNvsPartition<NvsDefault>) -> Notes {
    let nvs = match EspNvs::new(partition, NAMESPACE, true) {
        Ok(nvs) => nvs,
        Err(e) => {
            // The signer must not die for its sidecar: run with a locker
            // that reports "unavailable" and refuses everything mutating.
            log::error!("[notes] namespace init failed: {e}");
            return Notes {
                store: NoteStore::storage_unavailable(MAX_NOTES),
                storage: Storage::Null(NullStorage),
                boot_state: "unavailable",
            };
        }
    };
    let mut storage = NoteNvs { nvs, failed: false };
    let outcome = NoteStore::load(&mut storage, MAX_NOTES);
    let boot_state = if !outcome.store.index_known() {
        log::error!("[notes] index unreadable this boot — refusing note creation");
        "index_unreadable"
    } else {
        if !outcome.skipped.is_empty() {
            // The blobs stay on flash; counts are not statements about how
            // many notes exist. Loud, because this is someone's money.
            log::error!(
                "[notes] {} note blob(s) unreadable: {:?}",
                outcome.skipped.len(),
                outcome.skipped
            );
        }
        let (count, pending) = outcome.store.counts();
        log::info!("[notes] loaded {count} note(s), {pending} pending");
        "ok"
    };
    Notes { store: outcome.store, storage: Storage::Nvs(storage), boot_state }
}

/// Seconds since boot — informational timestamps only, never authoritative
/// (the mint's state is). The USB tier has no wall clock to lie with.
fn now_secs() -> u32 {
    (unsafe { esp_idf_svc::sys::esp_timer_get_time() } / 1_000_000) as u32
}

/// One line of card text for the approval loop: what is being decided, in
/// units the owner thinks in.
fn card_title(kind: GatedCmd, meta: &NoteMeta) -> String {
    let sats = meta.amount_msat / 1000;
    let action = match kind {
        GatedCmd::ExportSecret => "Release",
        GatedCmd::MarkSpent => "Spend",
        GatedCmd::Discard => "Discard",
        GatedCmd::Rename => "Rename",
        GatedCmd::Delete => "Delete",
    };
    if sats > 0 {
        format!("{action} note?\n{sats} sats @ {}", meta.host)
    } else {
        format!("{action} note?\n{}", meta.id)
    }
}

/// Handle one `FRAME_TYPE_NOTE_CMD` (0x70) frame: JSON command in the
/// payload, JSON response in a 0x71 frame. Every gated command runs the
/// shared 30 s hold-to-approve loop with the note's own amount and host on
/// screen — approval never overrides the lifecycle rules, and a state error
/// answers before the owner is ever prompted.
pub fn handle_note_cmd_frame(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    notes: &mut Notes,
    display: &mut crate::oled::Display<'_>,
    buttons: &crate::button::Buttons<'_>,
) {
    let Ok(msg) = core::str::from_utf8(payload) else {
        protocol::write_frame(usb, FRAME_TYPE_NACK, b"payload not utf-8");
        return;
    };

    let mut rng = |buf: &mut [u8]| crate::fill_random(buf);
    let mut approve = |kind: GatedCmd, meta: &NoteMeta| -> Approval {
        let title = card_title(kind, meta);
        let result = crate::approval::run_approval_loop(display, buttons, 30, |d, remaining| {
            crate::oled::show_change_approval(d, &title, remaining, 30);
        });
        match result {
            crate::approval::ApprovalResult::Approved => Approval::Approved,
            crate::approval::ApprovalResult::Denied => Approval::Declined,
            crate::approval::ApprovalResult::TimedOut => Approval::TimedOut,
        }
    };

    // Read the state before ctx takes its mutable borrows of `notes`. A
    // write failing inside THIS dispatch shows in the next get_info, which
    // is when the wallet re-reads it anyway.
    let storage_state = notes.storage_state();
    let mut ctx = NoteCmdContext {
        store: &mut notes.store,
        storage: &mut notes.storage,
        rng: &mut rng,
        approve: &mut approve,
        now: now_secs(),
        fw_version: env!("CARGO_PKG_VERSION"),
        board: crate::board::BOARD,
        storage_state,
    };
    let response = note_cmd::handle_note_cmd(&mut ctx, msg);
    let mut bytes = serde_json::to_vec(&response)
        .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"bad_request\"}".to_vec());
    protocol::write_frame(usb, FRAME_TYPE_NOTE_RESP, &bytes);
    // An export response carries a plaintext k1; scrub the buffer we own.
    // (The serde Value's own strings are beyond reach — noted, not hidden.)
    use zeroize::Zeroize;
    bytes.zeroize();
}

/// The locked-boot subset: `get_info` answers truthfully (counts and storage
/// state expose no secret and let the wallet say "locked device" instead of
/// "broken device"); every other command NACKs with a reason. This is the
/// exception the frame-type comment in types.rs documents.
pub fn handle_note_cmd_frame_locked(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    notes: &mut Notes,
) {
    let is_get_info = core::str::from_utf8(payload)
        .ok()
        .and_then(|msg| serde_json::from_str::<serde_json::Value>(msg).ok())
        .map(|cmd| cmd.get("cmd").and_then(|v| v.as_str()) == Some("get_info"))
        .unwrap_or(false);
    if !is_get_info {
        protocol::write_frame(usb, FRAME_TYPE_NACK, b"locked");
        return;
    }
    let (note_count, pending_count) = notes.store.counts();
    let response = serde_json::json!({
        "ok": true,
        "fw_version": env!("CARGO_PKG_VERSION"),
        "board": crate::board::BOARD,
        "storage": notes.storage_state(),
        "note_count": note_count,
        "pending_count": pending_count,
    });
    let bytes = serde_json::to_vec(&response)
        .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"bad_request\"}".to_vec());
    protocol::write_frame(usb, FRAME_TYPE_NOTE_RESP, &bytes);
}
