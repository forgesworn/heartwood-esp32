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
//! At-rest sealing: note blobs ride the PIN/vault secret exactly like the
//! seeds do. A random 32-byte **note key** is wrapped by
//! `seed_cipher::encrypt_seed` into this namespace's `nk` blob under the
//! same secret, unwrapped once at unlock (one extra PBKDF2 run), and
//! retained in RAM for the boot; each record blob is sealed under it via
//! `note_seal` at the `NoteStorage` boundary, verify-after-seal before every
//! write. `sync_sealed` makes the sealed state converge with the seeds'
//! at-rest state from any torn intermediate (enable, disable, PIN change,
//! or pre-locker firmware), and NOTHING here ever deletes a blob it cannot
//! read. At-rest changes are refused in WiFi-standalone mode while notes
//! are held (`any_held`), because this sync machinery only runs on the USB
//! path.

use esp_idf_svc::nvs::{EspNvs, EspNvsPartition, NvsDefault};

use heartwood_common::note_cmd::{self, Approval, GatedCmd, NoteCmdContext};
use heartwood_common::note_seal;
use heartwood_common::note_store::{
    NoteMeta, NoteStorage, NoteStore, StorageError, ID_LEN, MAX_NOTES,
};
use heartwood_common::seed_cipher;
use heartwood_common::types::{FRAME_TYPE_NACK, FRAME_TYPE_NOTE_RESP};
use zeroize::Zeroize;

use crate::protocol;
use crate::serial::SerialPort;

/// Own namespace on the shared NVS partition — the locker's churn (a few
/// writes per human-paced spend) stays legible in nvs_stats and is trivially
/// excludable from anything that walks the `heartwood` namespace.
const NAMESPACE: &str = "hw_notes";
const INDEX_KEY: &str = "idx";
/// The wrapped note key: `seed_cipher::encrypt_seed(secret, note_key)`.
const NK_KEY: &str = "nk";

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
    /// The unwrapped note key, retained in RAM for the boot. `Some` exactly
    /// when at-rest is on and this boot has unlocked (or enabled it): saves
    /// seal, loads open. `None`: records pass through plaintext, and sealed
    /// blobs are held aside in `sealed_pending` rather than decoded.
    key: Option<[u8; note_seal::KEY_LEN]>,
    /// Ids whose blobs are sealed and unreadable this boot (no key yet).
    /// The notes behind them are intact; they are counted, never deleted,
    /// and re-loaded after `sync_sealed` supplies the key.
    sealed_pending: alloc_vec::Vec<String>,
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
        // A sealed blob can be larger than the plaintext record by the seal
        // overhead; size the stack buffer for both.
        let mut buf = [0u8; NOTE_BUF + note_seal::OVERHEAD];
        let result = match self.nvs.get_blob(id, &mut buf) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) if note_seal::is_sealed(bytes) => match &self.key {
                Some(key) => match note_seal::open(key, bytes) {
                    Ok(plain) => Ok(Some(plain)),
                    Err(_) => {
                        // Wrong key or tampered — refuse the record; the
                        // bytes stay on flash untouched.
                        log::error!("[notes] {id}: sealed blob did not open under this boot's key");
                        Err(StorageError)
                    }
                },
                None => {
                    // Intact but unreadable until unlock. Held aside, not
                    // reported as damage.
                    if !self.sealed_pending.iter().any(|s| s == id) {
                        self.sealed_pending.push(id.to_string());
                    }
                    Err(StorageError)
                }
            },
            Ok(Some(bytes)) => Ok(Some(bytes.to_vec())),
            Err(e) => {
                log::error!("[notes] read {id} failed: {e}");
                Err(StorageError)
            }
        };
        // The raw blob embeds the secret; scrub the stack copy.
        buf.zeroize();
        result
    }

    fn save_note(&mut self, id: &str, blob: &[u8]) -> Result<(), StorageError> {
        let stored: alloc_vec::Vec<u8>;
        let to_write: &[u8] = match &self.key {
            Some(key) => {
                let mut nonce = [0u8; note_seal::NONCE_LEN];
                crate::fill_random(&mut nonce);
                stored = note_seal::seal(key, blob, &nonce);
                // VERIFY-AFTER-SEAL before anything touches flash: a blob
                // that cannot decrypt back to the record must never replace
                // one that could (the seed path's rule, applied to money).
                match note_seal::open(key, &stored) {
                    Ok(mut back) if back == blob => back.zeroize(),
                    _ => {
                        log::error!("[notes] {id}: seal verification failed — refusing to write");
                        self.failed = true;
                        return Err(StorageError);
                    }
                }
                &stored
            }
            None => blob,
        };
        self.nvs.set_blob(id, to_write).map_err(|e| {
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

/// The one shared locker instance. Two surfaces reach it — the USB frame
/// handler on the main loop and the `heartwood_note_*` NIP-46 arms on the
/// relay loop — the exact two-consumers problem lnurl-vault solves with
/// `vault_lock.c`; here the Mutex is the arbitration. Only one surface is
/// ever live per boot (USB mode has no relay loop; WiFi mode NACKs the USB
/// note frames), so contention is structural belt-and-braces, not a hot
/// path.
static LOCKER: std::sync::Mutex<Option<Notes>> = std::sync::Mutex::new(None);

/// Run `f` with the locker. Panics if `init` has not run — it is called
/// unconditionally at boot, before either serving surface exists.
pub fn with_locker<R>(f: impl FnOnce(&mut Notes) -> R) -> R {
    let mut guard = LOCKER.lock().expect("note locker poisoned");
    f(guard.as_mut().expect("note locker used before init"))
}

/// The locker: store + storage + the boot-time diagnosis `storage_state()`
/// folds runtime failures into.
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

/// Bring the locker up and install it as THE locker. Never erases anything
/// on any failure — a boot that cannot read its notes reports that and
/// refuses creation (the model fails closed), and recovery is a reboot,
/// never a wipe.
pub fn init(partition: EspNvsPartition<NvsDefault>) {
    let notes = build(partition);
    NOTES_HELD.store(notes.any_held(), core::sync::atomic::Ordering::Relaxed);
    *LOCKER.lock().expect("note locker poisoned") = Some(notes);
}

fn build(partition: EspNvsPartition<NvsDefault>) -> Notes {
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
    let mut storage = NoteNvs {
        nvs,
        failed: false,
        key: None,
        sealed_pending: alloc_vec::Vec::new(),
    };
    let outcome = NoteStore::load(&mut storage, MAX_NOTES);
    let boot_state = if !outcome.store.index_known() {
        log::error!("[notes] index unreadable this boot — refusing note creation");
        "index_unreadable"
    } else {
        let sealed = storage.sealed_pending.len();
        if sealed > 0 {
            log::info!("[notes] {sealed} sealed note(s) awaiting unlock");
        }
        // `skipped` includes the sealed-pending ids (they refused to load);
        // anything beyond those is genuine damage. The blobs stay on flash
        // either way; counts are not statements about how many notes exist.
        // Loud, because this is someone's money.
        let damaged = outcome
            .skipped
            .iter()
            .filter(|id| !storage.sealed_pending.contains(id))
            .count();
        if damaged > 0 {
            log::error!("[notes] {damaged} note blob(s) unreadable (not merely sealed) — left on flash");
        }
        let (count, pending) = outcome.store.counts();
        log::info!("[notes] loaded {count} note(s), {pending} pending");
        "ok"
    };
    Notes { store: outcome.store, storage: Storage::Nvs(storage), boot_state }
}

/// Whether the device holds any notes (loaded or sealed), for code with no
/// locker in scope — the WiFi-standalone tier consults this before allowing
/// an at-rest change it could not sync notes through. Set at init and
/// re-stored after every note command (USB frame or relay method), so it
/// stays fresh in both modes.
static NOTES_HELD: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn any_notes_held() -> bool {
    NOTES_HELD.load(core::sync::atomic::Ordering::Relaxed)
}

impl Notes {
    fn any_held(&self) -> bool {
        let (count, _) = self.store.counts();
        count > 0 || self.sealed_count() > 0
    }

    /// Sealed records awaiting a key this boot. Included in `get_info`'s
    /// counts — they are held value, not damage.
    pub fn sealed_count(&self) -> usize {
        match &self.storage {
            Storage::Nvs(nvs) => nvs.sealed_pending.len(),
            Storage::Null(_) => 0,
        }
    }
}

/// Make the locker's sealed state converge with the seeds' at-rest state,
/// given the freshly proven unlock secret (PIN digits or 32-byte vault key
/// — the same bytes the seed path used). Called after a successful unlock
/// on a locked boot, and after an at-rest enable or PIN/vault-key change on
/// an unlocked one. Converges from every torn intermediate:
///
///  - `nk` present, key not yet in RAM: unwrap it (one PBKDF2 run), reload
///    the store so sealed records decode, then re-seal any plaintext
///    stragglers a torn enable left behind.
///  - `nk` present, key already in RAM (PIN/vault-key change): re-wrap the
///    SAME note key under the new secret — the sealed records stay valid.
///  - `nk` absent: first enable, self-heal after a torn one, or an at-rest
///    state inherited from pre-locker firmware: mint a note key, wrap it,
///    verify the wrap decrypts, then seal every plaintext record.
///
/// An `nk` that will not decrypt under this secret is reported loudly and
/// left alone — the sealed notes behind it stay on flash for the secret
/// that can open them. Never deletes anything it cannot read.
pub fn sync_sealed(secret: &[u8]) {
    with_locker(|notes| sync_sealed_inner(notes, secret))
}

fn sync_sealed_inner(notes: &mut Notes, secret: &[u8]) {
    {
        let Storage::Nvs(nvs) = &mut notes.storage else {
            return; // unavailable locker: nothing to seal, nothing to lose
        };

        // 1. Establish the note key in RAM. Every seed_cipher call below is
        // a 100k-round PBKDF2 (~26 s on the S3 at opt-z) — feed the task
        // watchdog before each one, exactly as pin.rs does per locked slot,
        // or the 60 s watchdog fires mid-derivation (bench-caught 2026-08-18:
        // two task-wdt reboots inside the verify decrypt).
        if nvs.key.is_none() {
            let mut buf = [0u8; seed_cipher::BLOB_LEN];
            let nk = nvs.nvs.get_blob(NK_KEY, &mut buf);
            match nk {
                Ok(Some(blob)) => match {
                    // Yield so IDLE0 runs between KDF stretches (its
                    // watchdog aborts after 60 s of unbroken compute —
                    // bench-caught 2026-08-18), then feed our own.
                    esp_idf_hal::delay::FreeRtos::delay_ms(20);
                    crate::wdt::feed(); // PBKDF2: nk unwrap
                    seed_cipher::decrypt_seed(secret, blob)
                } {
                    Ok(key) => nvs.key = Some(key),
                    Err(_) => {
                        log::error!(
                            "[notes] nk does not decrypt under this secret — {} sealed note(s) stay sealed",
                            nvs.sealed_pending.len()
                        );
                        return;
                    }
                },
                Ok(None) => {
                    // First enable or self-heal: mint and wrap a fresh key.
                    let mut key = [0u8; note_seal::KEY_LEN];
                    crate::fill_random(&mut key);
                    let mut salt = [0u8; seed_cipher::SALT_LEN];
                    let mut nonce = [0u8; seed_cipher::NONCE_LEN];
                    crate::fill_random(&mut salt);
                    crate::fill_random(&mut nonce);
                    esp_idf_hal::delay::FreeRtos::delay_ms(20); // yield for IDLE0
                    crate::wdt::feed(); // PBKDF2: nk wrap
                    let blob = seed_cipher::encrypt_seed(secret, &key, &salt, &nonce);
                    // VERIFY-AFTER-ENCRYPT: the wrap must decrypt back before
                    // it is trusted as the key's only persistence.
                    esp_idf_hal::delay::FreeRtos::delay_ms(20); // yield for IDLE0
                    crate::wdt::feed(); // PBKDF2: wrap verification
                    if seed_cipher::decrypt_seed(secret, &blob) != Ok(key) {
                        log::error!("[notes] nk wrap failed verification — notes stay plaintext");
                        key.zeroize();
                        return;
                    }
                    if let Err(e) = nvs.nvs.set_blob(NK_KEY, &blob) {
                        log::error!("[notes] nk write failed: {e} — notes stay plaintext");
                        key.zeroize();
                        return;
                    }
                    nvs.key = Some(key);
                }
                Err(e) => {
                    log::error!("[notes] nk read failed: {e} — leaving sealed state untouched");
                    return;
                }
            }
        } else {
            // Key already in RAM: the secret changed — re-wrap the same key
            // so every sealed record stays valid under the new secret.
            let key = nvs.key.expect("checked is_some");
            let mut salt = [0u8; seed_cipher::SALT_LEN];
            let mut nonce = [0u8; seed_cipher::NONCE_LEN];
            crate::fill_random(&mut salt);
            crate::fill_random(&mut nonce);
            esp_idf_hal::delay::FreeRtos::delay_ms(20); // yield for IDLE0
            crate::wdt::feed(); // PBKDF2: nk re-wrap
            let blob = seed_cipher::encrypt_seed(secret, &key, &salt, &nonce);
            esp_idf_hal::delay::FreeRtos::delay_ms(20); // yield for IDLE0
            crate::wdt::feed(); // PBKDF2: re-wrap verification
            if seed_cipher::decrypt_seed(secret, &blob) != Ok(key) {
                log::error!("[notes] nk re-wrap failed verification — old wrap kept");
                return;
            }
            if let Err(e) = nvs.nvs.set_blob(NK_KEY, &blob) {
                log::error!("[notes] nk re-wrap write failed: {e} — old wrap kept");
                return;
            }
        }
    }

    // 2. Reload so previously sealed records decode under the key.
    let had_sealed = notes.sealed_count() > 0;
    if had_sealed {
        if let Storage::Nvs(nvs) = &mut notes.storage {
            nvs.sealed_pending.clear();
        }
        let outcome = NoteStore::load(&mut notes.storage, MAX_NOTES);
        if !outcome.skipped.is_empty() {
            log::error!(
                "[notes] {} note blob(s) still unreadable after unlock",
                outcome.skipped.len()
            );
        }
        notes.store = outcome.store;
    }

    // 3. Seal any plaintext stragglers (first enable, or a torn earlier one).
    if let Err(e) = notes.store.rewrite_all(&mut notes.storage) {
        log::error!("[notes] sealing pass incomplete ({e:?}) — will converge next sync");
    }
    let (count, _) = notes.store.counts();
    NOTES_HELD.store(notes.any_held(), core::sync::atomic::Ordering::Relaxed);
    log::info!("[notes] sealed state in sync ({count} note(s) under the note key)");
}

/// Turn at-rest off for the locker: rewrite every record plaintext, then
/// drop `nk` and the in-RAM key. Refusal, not destruction, when sealed
/// records exist with no key. Order matters: records go plaintext BEFORE
/// `nk` is removed, so a reset between the two leaves an orphan `nk`
/// (harmless — overwritten by the next enable) rather than sealed records
/// with no wrap.
pub fn disable_sealing() {
    with_locker(disable_sealing_inner)
}

fn disable_sealing_inner(notes: &mut Notes) {
    if notes.sealed_count() > 0 {
        log::error!("[notes] at-rest disabled while sealed notes have no key — they stay sealed on flash");
        return;
    }
    {
        let Storage::Nvs(nvs) = &mut notes.storage else { return };
        if nvs.key.is_none() {
            return; // never sealed — nothing to do
        }
        if let Some(mut k) = nvs.key.take() {
            k.zeroize();
        }
    }
    if let Err(e) = notes.store.rewrite_all(&mut notes.storage) {
        log::error!("[notes] plaintext rewrite incomplete ({e:?}) — rerun by toggling at-rest");
        return;
    }
    if let Storage::Nvs(nvs) = &mut notes.storage {
        if let Err(e) = nvs.nvs.remove(NK_KEY) {
            log::error!("[notes] nk remove failed: {e} (orphan wrap, harmless)");
        }
    }
    log::info!("[notes] notes now plaintext at rest");
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
    display: &mut crate::oled::Display<'_>,
    buttons: &crate::button::Buttons<'_>,
) {
    with_locker(|notes| handle_note_cmd_frame_inner(usb, payload, notes, display, buttons))
}

fn handle_note_cmd_frame_inner(
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
    bytes.zeroize();
    NOTES_HELD.store(notes.any_held(), core::sync::atomic::Ordering::Relaxed);
}

/// The locked-boot subset: `get_info` answers truthfully (counts and storage
/// state expose no secret and let the wallet say "locked device" instead of
/// "broken device"); every other command NACKs with a reason. This is the
/// exception the frame-type comment in types.rs documents.
pub fn handle_note_cmd_frame_locked(usb: &mut SerialPort<'_>, payload: &[u8]) {
    with_locker(|notes| handle_note_cmd_frame_locked_inner(usb, payload, notes))
}

fn handle_note_cmd_frame_locked_inner(
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
    // Sealed records are held value awaiting the key, not damage: counted.
    // (pending_count only covers decodable records — a sealed note's state
    // is inside the ciphertext, and a locked boot cannot know it.)
    let (note_count, pending_count) = notes.store.counts();
    let response = serde_json::json!({
        "ok": true,
        "fw_version": env!("CARGO_PKG_VERSION"),
        "board": crate::board::BOARD,
        "storage": notes.storage_state(),
        "note_count": note_count + notes.sealed_count(),
        "pending_count": pending_count,
    });
    let bytes = serde_json::to_vec(&response)
        .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"bad_request\"}".to_vec());
    protocol::write_frame(usb, FRAME_TYPE_NOTE_RESP, &bytes);
}

/// Run one already-approved note command for the NIP-46 relay path and
/// return the raw response object. The physical approval for gated methods
/// happens in nip46_handler's pre-dispatch gate (pinned ButtonRequired, so
/// no slot policy can silence it) BEFORE this runs — by the time we are
/// here, either the method needs no button or the hold has completed. The
/// lifecycle rules still apply: approval never overrides them.
pub fn run_note_cmd_approved(msg: &str) -> serde_json::Value {
    with_locker(|notes| {
        let mut rng = |buf: &mut [u8]| crate::fill_random(buf);
        let mut approve = |_kind: GatedCmd, _meta: &NoteMeta| Approval::Approved;
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
        NOTES_HELD.store(notes.any_held(), core::sync::atomic::Ordering::Relaxed);
        response
    })
}
