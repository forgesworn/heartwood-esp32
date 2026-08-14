// firmware/src/personas.rs
//
// Persisted persona registry, packed layout.
//
// Personas live in chunked NVS blobs (`pc{c}`, 16 entries each) with a single
// `pcnt` count key — heartwood_common::persona_pack defines the byte format
// and the migration/removal journals, and host tests there cover the exact
// models replayed here after a power cut. The legacy five-keys-per-entry
// layout (`p{n}_ms|ix|pk|pp|nm` + `persona_count`) is migrated once at boot
// (`migrate_if_needed`); the legacy entry ops remain because a master-removal
// journal written by pre-packed firmware may still need resuming against the
// old layout after an OTA, before the migration has run.
//
// Authority rule: the presence of `pcnt` means the packed layout is
// authoritative; until then the legacy keys are. Every multi-key transaction
// persists a durable cursor before and after each idempotent step, in the
// same style as masters.rs.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use heartwood_common::persona_pack::{
    chunk_index, chunk_offset, decode_chunk, encode_chunk, MigrationJournal, MigrationPhase,
    PackedPersona, PersonaRemovalJournal, PersonaRemovalPhase, CHUNK_CAPACITY, MAX_NAME_LEN,
    MIGRATION_JOURNAL_LEN, PERSONA_REMOVAL_JOURNAL_LEN,
};

/// Labels are cosmetic; clamp to the stored 64-byte bound at a character
/// boundary. (The legacy layout read names into a 64-byte buffer and silently
/// dropped anything longer — clamping is kinder than erroring, and the
/// derivation purpose is never clamped.)
fn clamp_label(name: &str) -> &str {
    if name.len() <= MAX_NAME_LEN {
        return name;
    }
    let mut end = MAX_NAME_LEN;
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    &name[..end]
}

/// Maximum number of personas the device can hold. The bound is NVS bytes,
/// not entry indices: the T-Display's 24 KB partition takes 64 packed
/// personas with policy headroom to spare; the Heltec's 16 KB stays at 32.
#[cfg(feature = "tdisplay")]
pub const MAX_PERSONAS: u8 = 64;
#[cfg(not(feature = "tdisplay"))]
pub const MAX_PERSONAS: u8 = 32;

const COUNT_KEY: &str = "pcnt";
const LEGACY_COUNT_KEY: &str = "persona_count";
const MIGRATION_JOURNAL_KEY: &str = "pmig_jnl";
const REMOVAL_JOURNAL_KEY: &str = "prm_jnl";

/// Worst-case encoded chunk: 6-byte header, 16 maximum-length entries, CRC.
const MAX_CHUNK_LEN: usize = 6 + CHUNK_CAPACITY * 231 + 4;

/// A persisted persona (no secret — re-derived from the owning master on use).
pub struct LoadedPersona {
    pub master_slot: u8,
    pub purpose: String,
    pub index: u32,
    pub name: Option<String>,
    pub pubkey: [u8; 32],
}

fn to_loaded(p: PackedPersona) -> LoadedPersona {
    LoadedPersona {
        master_slot: p.master_slot,
        purpose: p.purpose,
        index: p.index,
        name: p.name,
        pubkey: p.pubkey,
    }
}

// ---------------------------------------------------------------------------
// Small storage helpers (same read-back-verify style as masters.rs).
// ---------------------------------------------------------------------------

fn blob_present(nvs: &EspNvs<NvsDefault>, key: &str) -> Result<bool, &'static str> {
    match nvs.blob_len(key) {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(_) => Err("failed to inspect persona state"),
    }
}

fn read_blob_bounded(
    nvs: &EspNvs<NvsDefault>,
    key: &str,
    bound: usize,
) -> Result<Option<Vec<u8>>, &'static str> {
    let len = match nvs.blob_len(key) {
        Ok(Some(len)) if len <= bound => len,
        Ok(Some(_)) => return Err("persona state exceeds size bound"),
        Ok(None) => return Ok(None),
        Err(_) => return Err("failed to inspect persona state"),
    };
    let mut value = vec![0u8; core::cmp::max(len, 1)];
    match nvs.get_blob(key, &mut value) {
        Ok(Some(bytes)) if bytes.len() == len => Ok(Some(bytes.to_vec())),
        _ => Err("failed to read persona state"),
    }
}

fn clear_blob(nvs: &mut EspNvs<NvsDefault>, key: &str) -> Result<(), &'static str> {
    nvs.remove(key)
        .map_err(|_| "failed to clear persona state")?;
    match nvs.blob_len(key) {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err("cleared persona state still present"),
        Err(_) => Err("failed to verify cleared persona state"),
    }
}

// ---------------------------------------------------------------------------
// Format detection and counts.
// ---------------------------------------------------------------------------

/// Whether the packed layout is authoritative (`pcnt` present).
pub fn packed_format(nvs: &EspNvs<NvsDefault>) -> Result<bool, &'static str> {
    blob_present(nvs, COUNT_KEY)
}

fn read_count_key(nvs: &EspNvs<NvsDefault>, key: &str) -> u8 {
    let mut buf = [0u8; 1];
    match nvs.get_blob(key, &mut buf) {
        Ok(Some(b)) if b.len() == 1 => buf[0],
        _ => 0,
    }
}

/// Read the persona count from whichever layout is authoritative.
pub fn read_count(nvs: &EspNvs<NvsDefault>) -> u8 {
    match packed_format(nvs) {
        Ok(true) => read_count_key(nvs, COUNT_KEY),
        _ => read_count_key(nvs, LEGACY_COUNT_KEY),
    }
}

/// Strict count read for transactional paths (master removal, persona
/// removal): storage errors and out-of-range values are errors, absence is 0.
pub fn read_count_strict(nvs: &EspNvs<NvsDefault>) -> Result<u8, &'static str> {
    let key = if packed_format(nvs)? {
        COUNT_KEY
    } else {
        LEGACY_COUNT_KEY
    };
    let mut buf = [0u8; 1];
    match nvs.get_blob(key, &mut buf) {
        Ok(Some(bytes)) if bytes.len() == 1 && bytes[0] <= MAX_PERSONAS => Ok(bytes[0]),
        Ok(Some(_)) => Err("invalid persona count"),
        Ok(None) => Ok(0),
        Err(_) => Err("failed to read persona count"),
    }
}

/// Write the registry count to whichever layout is authoritative, with
/// read-back verification. Used by the master-removal transaction.
pub(crate) fn write_registry_count(
    nvs: &mut EspNvs<NvsDefault>,
    count: u8,
) -> Result<(), &'static str> {
    let key = if packed_format(nvs)? {
        COUNT_KEY
    } else {
        LEGACY_COUNT_KEY
    };
    nvs.set_blob(key, &[count])
        .map_err(|_| "failed to write persona count")?;
    if read_count_strict(nvs)? == count {
        Ok(())
    } else {
        Err("persona count verification failed")
    }
}

fn write_packed_count(nvs: &mut EspNvs<NvsDefault>, count: u8) -> Result<(), &'static str> {
    nvs.set_blob(COUNT_KEY, &[count])
        .map_err(|_| "failed to write persona count")?;
    if read_count_key(nvs, COUNT_KEY) == count {
        Ok(())
    } else {
        Err("persona count verification failed")
    }
}

// ---------------------------------------------------------------------------
// Packed chunk I/O.
// ---------------------------------------------------------------------------

fn chunk_key(chunk: u8) -> String {
    format!("pc{chunk}")
}

/// Read one chunk; an absent key is an empty chunk, a corrupt one an error.
fn read_chunk(nvs: &EspNvs<NvsDefault>, chunk: u8) -> Result<Vec<PackedPersona>, &'static str> {
    match read_blob_bounded(nvs, &chunk_key(chunk), MAX_CHUNK_LEN)? {
        Some(bytes) => decode_chunk(&bytes).ok_or("corrupt persona chunk"),
        None => Ok(Vec::new()),
    }
}

/// Encode and write one chunk, verifying the stored bytes decode back to the
/// same entries. An NVS blob write is copy-on-write, so a power cut mid-write
/// leaves the previous value — never a torn one.
fn write_chunk(
    nvs: &mut EspNvs<NvsDefault>,
    chunk: u8,
    entries: &[PackedPersona],
) -> Result<(), &'static str> {
    let encoded = encode_chunk(entries)?;
    nvs.set_blob(&chunk_key(chunk), &encoded)
        .map_err(|_| "failed to write persona chunk")?;
    let stored = read_blob_bounded(nvs, &chunk_key(chunk), MAX_CHUNK_LEN)?
        .ok_or("persona chunk missing after write")?;
    if stored == encoded {
        Ok(())
    } else {
        Err("persona chunk verification failed")
    }
}

/// Read one entry (strict — for transactional paths).
fn read_entry(nvs: &EspNvs<NvsDefault>, entry: u8) -> Result<PackedPersona, &'static str> {
    let entries = read_chunk(nvs, chunk_index(entry))?;
    entries
        .get(chunk_offset(entry))
        .cloned()
        .ok_or("persona entry missing")
}

/// Write one entry in place via a chunk read-modify-write.
fn write_entry(
    nvs: &mut EspNvs<NvsDefault>,
    entry: u8,
    value: PackedPersona,
) -> Result<(), &'static str> {
    let chunk = chunk_index(entry);
    let mut entries = read_chunk(nvs, chunk)?;
    let offset = chunk_offset(entry);
    if offset >= entries.len() {
        return Err("persona entry missing");
    }
    entries[offset] = value;
    write_chunk(nvs, chunk, &entries)
}

// ---------------------------------------------------------------------------
// Public registry API.
// ---------------------------------------------------------------------------

/// Load all personas from NVS into memory. A corrupt chunk is skipped with an
/// error log (its personas stop being served until re-derived); this mirrors
/// the per-entry skip the legacy loader did.
pub fn load_all(nvs: &EspNvs<NvsDefault>) -> Vec<LoadedPersona> {
    match packed_format(nvs) {
        Ok(true) => {}
        Ok(false) => return legacy_load_all(nvs),
        Err(e) => {
            log::error!("Persona registry unreadable: {e}");
            return Vec::new();
        }
    }
    let count = read_count_key(nvs, COUNT_KEY) as usize;
    let mut out = Vec::with_capacity(count);
    let mut chunk = 0u8;
    while (chunk as usize) * CHUNK_CAPACITY < count {
        let span = core::cmp::min(count - (chunk as usize) * CHUNK_CAPACITY, CHUNK_CAPACITY);
        match read_chunk(nvs, chunk) {
            Ok(entries) if entries.len() >= span => {
                out.extend(entries.into_iter().take(span).map(to_loaded));
            }
            Ok(entries) => {
                log::error!(
                    "Persona chunk {chunk} short ({} of {span} entries) — skipping remainder",
                    entries.len()
                );
                out.extend(entries.into_iter().take(span).map(to_loaded));
            }
            Err(e) => log::error!("Failed to load persona chunk {chunk}: {e}"),
        }
        chunk += 1;
    }
    out
}

/// Whether a pubkey is already in the in-memory registry.
pub fn contains_pubkey(personas: &[LoadedPersona], pubkey: &[u8; 32]) -> bool {
    personas.iter().any(|p| &p.pubkey == pubkey)
}

/// Find a persona by x-only public key (32 bytes).
pub fn find_by_pubkey(personas: &[LoadedPersona], pubkey: &[u8; 32]) -> Option<usize> {
    personas.iter().position(|p| &p.pubkey == pubkey)
}

/// Whether the registry (and the NVS partition behind it) can take another
/// persona. `Err` carries the actionable refusal — the "storage full" NACK
/// text the design doc requires — so callers can pre-check before deriving.
pub fn capacity_check(nvs: &EspNvs<NvsDefault>) -> Result<(), &'static str> {
    if read_count(nvs) >= MAX_PERSONAS {
        return Err("identity storage full: this device holds its maximum number of personas — remove an unused one first");
    }
    if !crate::nvs_stats::persona_write_allowed() {
        return Err("identity storage full: not enough flash headroom left — remove an unused persona or app pairing first");
    }
    Ok(())
}

/// Persist a new persona. The caller is responsible for checking the
/// in-memory registry first (`contains_pubkey`) so the same identity isn't
/// stored twice. Refuses cleanly (never mid-write) when the registry or the
/// partition is full.
pub fn add(
    nvs: &mut EspNvs<NvsDefault>,
    master_slot: u8,
    purpose: &str,
    index: u32,
    name: Option<&str>,
    pubkey: &[u8; 32],
) -> Result<(), &'static str> {
    resume_pending_removal(nvs)?;
    capacity_check(nvs)?;

    if !packed_format(nvs)? {
        // First persona on a fresh (or freshly-wiped) device adopts the packed
        // layout directly; a legacy registry has already been migrated at boot.
        if read_count_key(nvs, LEGACY_COUNT_KEY) != 0 {
            return Err("persona registry migration has not run");
        }
        write_packed_count(nvs, 0)?;
    }

    let count = read_count_key(nvs, COUNT_KEY);
    let chunk = chunk_index(count);
    let mut entries = read_chunk(nvs, chunk)?;
    // Entries at or beyond the count are stale leftovers from an interrupted
    // add (chunk written, count not yet); drop them before appending.
    entries.truncate(chunk_offset(count));
    entries.push(PackedPersona {
        master_slot,
        index,
        pubkey: *pubkey,
        purpose: purpose.to_string(),
        name: name.map(|n| clamp_label(n).to_string()),
    });
    write_chunk(nvs, chunk, &entries)?;
    write_packed_count(nvs, count + 1)?;
    log::info!("Stored persona entry {count}: purpose={purpose} index={index}");
    Ok(())
}

/// Rename (or clear the name of) a persona. Single-chunk read-modify-write;
/// the chunk write is atomic, so no journal is needed.
pub fn rename_by_pubkey(
    nvs: &mut EspNvs<NvsDefault>,
    pubkey: &[u8; 32],
    name: Option<&str>,
) -> Result<bool, &'static str> {
    resume_pending_removal(nvs)?;
    if !packed_format(nvs)? {
        return Err("persona registry migration has not run");
    }
    let count = read_count_key(nvs, COUNT_KEY);
    for entry in 0..count {
        let current = read_entry(nvs, entry)?;
        if &current.pubkey == pubkey {
            let mut updated = current;
            updated.name = name.map(|n| clamp_label(n).to_string());
            write_entry(nvs, entry, updated)?;
            return Ok(true);
        }
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// Single-persona removal (journal-protected).
// ---------------------------------------------------------------------------

/// Remove a persona by pubkey. Returns Ok(false) if no such persona exists.
/// The multi-chunk shift is journal-protected: a power cut resumes at boot
/// (`resume_pending_removal`) before anything loads.
pub fn remove_by_pubkey(
    nvs: &mut EspNvs<NvsDefault>,
    pubkey: &[u8; 32],
) -> Result<bool, &'static str> {
    resume_pending_removal(nvs)?;
    if !packed_format(nvs)? {
        return Err("persona registry migration has not run");
    }
    let count = read_count_strict(nvs)?;
    let mut target = None;
    for entry in 0..count {
        if &read_entry(nvs, entry)?.pubkey == pubkey {
            target = Some(entry);
            break;
        }
    }
    let Some(target) = target else {
        return Ok(false);
    };
    let journal = PersonaRemovalJournal::new(target, count).ok_or("persona index out of range")?;
    persist_removal_journal(nvs, &journal)?;
    resume_pending_removal(nvs)?;
    Ok(true)
}

/// Resume (or complete) an interrupted persona removal. Runs at boot after
/// the master-removal resume and the layout migration, and defensively at the
/// top of every mutating registry call.
pub fn resume_pending_removal(nvs: &mut EspNvs<NvsDefault>) -> Result<(), &'static str> {
    let Some(mut journal) = read_removal_journal(nvs)? else {
        return Ok(());
    };
    loop {
        match journal.phase {
            PersonaRemovalPhase::ShiftEntries => {
                if journal.cursor + 1 < journal.original_count {
                    let source = read_entry(nvs, journal.cursor + 1)?;
                    write_entry(nvs, journal.cursor, source)?;
                    journal.cursor += 1;
                    persist_removal_journal(nvs, &journal)?;
                } else {
                    journal.phase = PersonaRemovalPhase::Truncate;
                    persist_removal_journal(nvs, &journal)?;
                }
            }
            PersonaRemovalPhase::Truncate => {
                let last = journal.original_count - 1;
                let chunk = chunk_index(last);
                let mut entries = read_chunk(nvs, chunk)?;
                if entries.len() > chunk_offset(last) {
                    entries.truncate(chunk_offset(last));
                    write_chunk(nvs, chunk, &entries)?;
                }
                journal.phase = PersonaRemovalPhase::CommitCount;
                persist_removal_journal(nvs, &journal)?;
            }
            PersonaRemovalPhase::CommitCount => {
                write_packed_count(nvs, journal.original_count - 1)?;
                journal.phase = PersonaRemovalPhase::Complete;
                persist_removal_journal(nvs, &journal)?;
            }
            PersonaRemovalPhase::Complete => {
                clear_blob(nvs, REMOVAL_JOURNAL_KEY)?;
                log::info!("Removed persona entry {}", journal.target);
                return Ok(());
            }
        }
    }
}

fn read_removal_journal(
    nvs: &EspNvs<NvsDefault>,
) -> Result<Option<PersonaRemovalJournal>, &'static str> {
    let mut buf = [0u8; PERSONA_REMOVAL_JOURNAL_LEN];
    match nvs.get_blob(REMOVAL_JOURNAL_KEY, &mut buf) {
        Ok(Some(bytes)) => PersonaRemovalJournal::decode(bytes)
            .map(Some)
            .ok_or("invalid persona-removal journal"),
        Ok(None) => Ok(None),
        Err(_) => Err("failed to read persona-removal journal"),
    }
}

fn persist_removal_journal(
    nvs: &mut EspNvs<NvsDefault>,
    journal: &PersonaRemovalJournal,
) -> Result<(), &'static str> {
    let encoded = journal.encode();
    nvs.set_blob(REMOVAL_JOURNAL_KEY, &encoded)
        .map_err(|_| "failed to write persona-removal journal")?;
    match read_removal_journal(nvs)? {
        Some(stored) if stored == *journal => Ok(()),
        _ => Err("persona-removal journal verification failed"),
    }
}

// ---------------------------------------------------------------------------
// One-time layout migration (legacy five-key entries → packed chunks).
// ---------------------------------------------------------------------------

/// Migrate the legacy registry to the packed layout if needed. Runs at boot
/// after the master-removal resume (which may still operate on the legacy
/// layout) and before anything loads personas. Journal-protected; the legacy
/// keys stay authoritative until the packed count key commits.
pub fn migrate_if_needed(nvs: &mut EspNvs<NvsDefault>) -> Result<(), &'static str> {
    if let Some(journal) = read_migration_journal(nvs)? {
        return resume_migration(nvs, journal);
    }
    if packed_format(nvs)? {
        // Defensive: a legacy count key alongside the packed layout should be
        // impossible (the journal covers every cut), but sweep it if seen.
        if blob_present(nvs, LEGACY_COUNT_KEY)? {
            log::warn!("Legacy persona count found beside packed registry — sweeping");
            let journal = MigrationJournal {
                phase: MigrationPhase::DeleteOldEntries,
                delete_cursor: 0,
                original_count: legacy_max_entries(),
            };
            persist_migration_journal(nvs, &journal)?;
            return resume_migration(nvs, journal);
        }
        return Ok(());
    }
    let legacy_count = read_count_key(nvs, LEGACY_COUNT_KEY);
    if legacy_count == 0 {
        // Fresh device (or an empty legacy registry): nothing to migrate; the
        // first `add` adopts the packed layout.
        return Ok(());
    }
    log::info!("Migrating {legacy_count} persona(s) to the packed registry layout");
    let journal = MigrationJournal::new(legacy_count);
    persist_migration_journal(nvs, &journal)?;
    resume_migration(nvs, journal)
}

/// The most legacy entries any earlier firmware could have written.
fn legacy_max_entries() -> u8 {
    32
}

fn resume_migration(
    nvs: &mut EspNvs<NvsDefault>,
    mut journal: MigrationJournal,
) -> Result<(), &'static str> {
    loop {
        match journal.phase {
            MigrationPhase::WriteChunks => {
                // Recomputed wholesale from the (untouched) legacy keys, so a
                // repeat after a power cut writes the same bytes again. An
                // unreadable legacy entry is skipped with a log, exactly as
                // the legacy loader served it.
                let entries = read_legacy_entries(nvs, journal.original_count);
                let mut chunk = 0u8;
                while (chunk as usize) * CHUNK_CAPACITY < entries.len() || chunk == 0 {
                    let start = (chunk as usize) * CHUNK_CAPACITY;
                    let end = core::cmp::min(entries.len(), start + CHUNK_CAPACITY);
                    write_chunk(nvs, chunk, &entries[start..end])?;
                    chunk += 1;
                }
                journal.phase = MigrationPhase::CommitFormat;
                persist_migration_journal(nvs, &journal)?;
            }
            MigrationPhase::CommitFormat => {
                // The commit point: `pcnt` existing flips authority to the
                // packed layout. The count is recomputed from the legacy keys,
                // which are still intact, so this too repeats identically.
                let migrated = read_legacy_entries(nvs, journal.original_count).len() as u8;
                write_packed_count(nvs, migrated)?;
                journal.phase = MigrationPhase::DeleteOldEntries;
                persist_migration_journal(nvs, &journal)?;
            }
            MigrationPhase::DeleteOldEntries => {
                if journal.delete_cursor < journal.original_count {
                    let n = journal.delete_cursor;
                    for suffix in ["ms", "ix", "pk", "pp", "nm"] {
                        clear_blob(nvs, &legacy_key(n, suffix))?;
                    }
                    journal.delete_cursor += 1;
                    persist_migration_journal(nvs, &journal)?;
                } else {
                    journal.phase = MigrationPhase::DeleteOldCount;
                    persist_migration_journal(nvs, &journal)?;
                }
            }
            MigrationPhase::DeleteOldCount => {
                clear_blob(nvs, LEGACY_COUNT_KEY)?;
                journal.phase = MigrationPhase::Complete;
                persist_migration_journal(nvs, &journal)?;
            }
            MigrationPhase::Complete => {
                clear_blob(nvs, MIGRATION_JOURNAL_KEY)?;
                log::info!("Persona registry migration complete");
                return Ok(());
            }
        }
    }
}

fn read_migration_journal(
    nvs: &EspNvs<NvsDefault>,
) -> Result<Option<MigrationJournal>, &'static str> {
    let mut buf = [0u8; MIGRATION_JOURNAL_LEN];
    match nvs.get_blob(MIGRATION_JOURNAL_KEY, &mut buf) {
        Ok(Some(bytes)) => MigrationJournal::decode(bytes)
            .map(Some)
            .ok_or("invalid persona-migration journal"),
        Ok(None) => Ok(None),
        Err(_) => Err("failed to read persona-migration journal"),
    }
}

fn persist_migration_journal(
    nvs: &mut EspNvs<NvsDefault>,
    journal: &MigrationJournal,
) -> Result<(), &'static str> {
    let encoded = journal.encode();
    nvs.set_blob(MIGRATION_JOURNAL_KEY, &encoded)
        .map_err(|_| "failed to write persona-migration journal")?;
    match read_migration_journal(nvs)? {
        Some(stored) if stored == *journal => Ok(()),
        _ => Err("persona-migration journal verification failed"),
    }
}

// ---------------------------------------------------------------------------
// Entry-level ops for the master-removal transaction (layout-dispatching).
// masters.rs calls these; the journal semantics there are unchanged.
// ---------------------------------------------------------------------------

/// Read entry `n`'s owning master slot.
pub(crate) fn entry_owner(nvs: &EspNvs<NvsDefault>, entry: u8) -> Result<u8, &'static str> {
    if packed_format(nvs)? {
        Ok(read_entry(nvs, entry)?.master_slot)
    } else {
        let mut buf = [0u8; 1];
        match nvs.get_blob(&legacy_key(entry, "ms"), &mut buf) {
            Ok(Some(bytes)) if bytes.len() == 1 => Ok(bytes[0]),
            _ => Err("failed to read persona master slot"),
        }
    }
}

/// Copy entry `source` over entry `destination` with a remapped owner. When
/// `source == destination` only the owner byte changes; the journal's
/// in-flight owner field makes the repeat idempotent (see masters.rs).
pub(crate) fn copy_entry_with_owner(
    nvs: &mut EspNvs<NvsDefault>,
    source: u8,
    destination: u8,
    mapped_owner: u8,
) -> Result<(), &'static str> {
    if packed_format(nvs)? {
        let mut value = read_entry(nvs, source)?;
        value.master_slot = mapped_owner;
        write_entry(nvs, destination, value)?;
        if read_entry(nvs, destination)?.master_slot != mapped_owner {
            return Err("remapped persona owner verification failed");
        }
        Ok(())
    } else {
        legacy_copy_entry(nvs, source, destination, mapped_owner)
    }
}

/// Clear entry `n` as part of the ascending tail sweep. Packed layout: the
/// chunk is truncated at the entry's offset (everything after it in the chunk
/// is also tail, so over-truncating is harmless and idempotent).
pub(crate) fn clear_entry_tail(nvs: &mut EspNvs<NvsDefault>, entry: u8) -> Result<(), &'static str> {
    if packed_format(nvs)? {
        let chunk = chunk_index(entry);
        let mut entries = read_chunk(nvs, chunk)?;
        if entries.len() > chunk_offset(entry) {
            entries.truncate(chunk_offset(entry));
            write_chunk(nvs, chunk, &entries)?;
        }
        Ok(())
    } else {
        for suffix in ["ms", "ix", "pk", "pp", "nm"] {
            clear_blob(nvs, &legacy_key(entry, suffix))?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Legacy layout internals.
// ---------------------------------------------------------------------------

fn legacy_key(entry: u8, suffix: &str) -> String {
    format!("p{entry}_{suffix}")
}

fn legacy_load_all(nvs: &EspNvs<NvsDefault>) -> Vec<LoadedPersona> {
    let count = read_count_key(nvs, LEGACY_COUNT_KEY);
    let mut out = Vec::with_capacity(count as usize);
    for n in 0..count {
        match legacy_load_one(nvs, n) {
            Some(p) => out.push(to_loaded(p)),
            None => log::warn!("Failed to load persona entry {n}"),
        }
    }
    out
}

fn read_legacy_entries(nvs: &EspNvs<NvsDefault>, count: u8) -> Vec<PackedPersona> {
    let mut out = Vec::with_capacity(count as usize);
    for n in 0..count {
        match legacy_load_one(nvs, n) {
            Some(p) => out.push(p),
            None => log::warn!("Skipping unreadable persona entry {n} during migration"),
        }
    }
    out
}

fn legacy_load_one(nvs: &EspNvs<NvsDefault>, n: u8) -> Option<PackedPersona> {
    let mut ms = [0u8; 1];
    match nvs.get_blob(&legacy_key(n, "ms"), &mut ms) {
        Ok(Some(b)) if b.len() == 1 => {}
        _ => return None,
    }

    let mut ix = [0u8; 4];
    match nvs.get_blob(&legacy_key(n, "ix"), &mut ix) {
        Ok(Some(b)) if b.len() == 4 => {}
        _ => return None,
    }

    let mut pubkey = [0u8; 32];
    match nvs.get_blob(&legacy_key(n, "pk"), &mut pubkey) {
        Ok(Some(b)) if b.len() == 32 => {}
        _ => return None,
    }

    let mut purpose_buf = [0u8; 128];
    let purpose = match nvs.get_blob(&legacy_key(n, "pp"), &mut purpose_buf) {
        Ok(Some(b)) if !b.is_empty() => String::from_utf8_lossy(b).to_string(),
        _ => return None,
    };

    let mut name_buf = [0u8; 64];
    let name = match nvs.get_blob(&legacy_key(n, "nm"), &mut name_buf) {
        Ok(Some(b)) if !b.is_empty() => Some(String::from_utf8_lossy(b).to_string()),
        _ => None,
    };

    Some(PackedPersona {
        master_slot: ms[0],
        index: u32::from_be_bytes(ix),
        pubkey,
        purpose,
        name,
    })
}

fn legacy_copy_entry(
    nvs: &mut EspNvs<NvsDefault>,
    source: u8,
    destination: u8,
    mapped_owner: u8,
) -> Result<(), &'static str> {
    for suffix in ["ix", "pk", "pp"] {
        let value = read_blob_bounded(nvs, &legacy_key(source, suffix), 256)?
            .ok_or("required persona state missing")?;
        nvs.set_blob(&legacy_key(destination, suffix), &value)
            .map_err(|_| "failed to shift persona state")?;
        if read_blob_bounded(nvs, &legacy_key(destination, suffix), 256)?.as_deref()
            != Some(value.as_slice())
        {
            return Err("shifted persona state verification failed");
        }
    }
    match read_blob_bounded(nvs, &legacy_key(source, "nm"), 256)? {
        Some(value) => {
            nvs.set_blob(&legacy_key(destination, "nm"), &value)
                .map_err(|_| "failed to shift persona state")?;
            if read_blob_bounded(nvs, &legacy_key(destination, "nm"), 256)?.as_deref()
                != Some(value.as_slice())
            {
                return Err("shifted persona state verification failed");
            }
        }
        None => clear_blob(nvs, &legacy_key(destination, "nm"))?,
    }
    nvs.set_blob(&legacy_key(destination, "ms"), &[mapped_owner])
        .map_err(|_| "failed to write remapped persona owner")?;
    if entry_owner(nvs, destination)? != mapped_owner {
        return Err("remapped persona owner verification failed");
    }
    Ok(())
}
