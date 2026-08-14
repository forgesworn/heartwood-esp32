//! Packed persona registry codec and its transaction journals.
//!
//! Personas are stored as chunked NVS blobs (16 entries per chunk) instead of
//! five NVS keys per entry. ESP-IDF NVS charges one entry-table slot per key
//! plus one per 32 bytes of blob data, so the five-key layout costs roughly
//! 350 bytes of entry table per persona, where one packed chunk amortises the
//! per-key overhead across 16 personas (about 85 bytes each for typical
//! purpose/name lengths). Chunking also bounds each copy-on-write rewrite: a
//! change to entry `n` rewrites only chunk `n / 16`.
//!
//! This module is platform-independent so host tests cover the exact byte
//! format and the resumable migration/removal models used on-device, in the
//! same way `persistent_state` covers master removal.

/// Entries per packed chunk. A change to one entry rewrites one chunk, so this
/// bounds the copy-on-write cost (about 1.5 KB worst case with maximum-length
/// purposes and names).
pub const CHUNK_CAPACITY: usize = 16;

/// Upper bound on chunks (64 personas on the largest board / 16 per chunk).
pub const MAX_CHUNKS: u8 = 4;

/// Maximum purpose length in bytes (matches the legacy per-key read buffer).
pub const MAX_PURPOSE_LEN: usize = 128;

/// Maximum name length in bytes (matches the legacy per-key read buffer).
pub const MAX_NAME_LEN: usize = 64;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

const CHUNK_MAGIC: [u8; 4] = *b"HWPC";
const CHUNK_VERSION: u8 = 1;

/// A persona as stored in a packed chunk. No secret — the signing key is
/// re-derived from the owning master on use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedPersona {
    pub master_slot: u8,
    pub index: u32,
    pub pubkey: [u8; 32],
    pub purpose: String,
    pub name: Option<String>,
}

/// Which chunk an entry index lives in.
pub fn chunk_index(entry: u8) -> u8 {
    entry / CHUNK_CAPACITY as u8
}

/// An entry's offset within its chunk.
pub fn chunk_offset(entry: u8) -> usize {
    (entry as usize) % CHUNK_CAPACITY
}

/// Encode one chunk. Fails if the entry count exceeds the chunk capacity or
/// any field exceeds its length bound.
pub fn encode_chunk(entries: &[PackedPersona]) -> Result<Vec<u8>, &'static str> {
    if entries.len() > CHUNK_CAPACITY {
        return Err("too many entries for one chunk");
    }
    let mut out = Vec::with_capacity(16 + entries.len() * 96);
    out.extend_from_slice(&CHUNK_MAGIC);
    out.push(CHUNK_VERSION);
    out.push(entries.len() as u8);
    for p in entries {
        let purpose = p.purpose.as_bytes();
        if purpose.is_empty() || purpose.len() > MAX_PURPOSE_LEN {
            return Err("persona purpose length out of range");
        }
        let name = p.name.as_deref().unwrap_or("").as_bytes();
        if name.len() > MAX_NAME_LEN {
            return Err("persona name too long");
        }
        out.push(p.master_slot);
        out.extend_from_slice(&p.index.to_be_bytes());
        out.extend_from_slice(&p.pubkey);
        out.push(purpose.len() as u8);
        out.extend_from_slice(purpose);
        out.push(name.len() as u8);
        out.extend_from_slice(name);
    }
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&out);
    out.extend_from_slice(&hasher.finalize().to_le_bytes());
    Ok(out)
}

/// Decode one chunk. Strict: bad magic/version, short reads, out-of-range
/// lengths, trailing bytes, or a CRC mismatch all reject the chunk.
pub fn decode_chunk(bytes: &[u8]) -> Option<Vec<PackedPersona>> {
    if bytes.len() < 10 || bytes[0..4] != CHUNK_MAGIC || bytes[4] != CHUNK_VERSION {
        return None;
    }
    let (body, crc) = bytes.split_at(bytes.len() - 4);
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(body);
    if crc != hasher.finalize().to_le_bytes() {
        return None;
    }
    let count = body[5] as usize;
    if count > CHUNK_CAPACITY {
        return None;
    }
    let mut entries = Vec::with_capacity(count);
    let mut at = 6usize;
    for _ in 0..count {
        let master_slot = *body.get(at)?;
        at += 1;
        let index = u32::from_be_bytes(body.get(at..at + 4)?.try_into().ok()?);
        at += 4;
        let pubkey: [u8; 32] = body.get(at..at + 32)?.try_into().ok()?;
        at += 32;
        let purpose_len = *body.get(at)? as usize;
        at += 1;
        if purpose_len == 0 || purpose_len > MAX_PURPOSE_LEN {
            return None;
        }
        let purpose = core::str::from_utf8(body.get(at..at + purpose_len)?)
            .ok()?
            .to_string();
        at += purpose_len;
        let name_len = *body.get(at)? as usize;
        at += 1;
        if name_len > MAX_NAME_LEN {
            return None;
        }
        let name = if name_len == 0 {
            None
        } else {
            Some(
                core::str::from_utf8(body.get(at..at + name_len)?)
                    .ok()?
                    .to_string(),
            )
        };
        at += name_len;
        entries.push(PackedPersona {
            master_slot,
            index,
            pubkey,
            purpose,
            name,
        });
    }
    if at != body.len() {
        return None;
    }
    Some(entries)
}

// ---------------------------------------------------------------------------
// Migration journal: legacy five-key layout → packed chunks.
// ---------------------------------------------------------------------------

/// Fixed journal encoding (`HWPM`, version, fields, CRC32).
pub const MIGRATION_JOURNAL_LEN: usize = 12;
const MIGRATION_MAGIC: [u8; 4] = *b"HWPM";
const MIGRATION_VERSION: u8 = 1;

/// Durable phase of the one-time layout migration.
///
/// `WriteChunks` recomputes every chunk from the (untouched) legacy keys on
/// each attempt, so it needs no cursor: repeating it after a power cut writes
/// the same bytes again. The legacy keys stay authoritative until
/// `CommitFormat` writes the packed count key, which is the single commit
/// point; the deletion phases afterwards are idempotent sweeps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MigrationPhase {
    WriteChunks = 0,
    CommitFormat = 1,
    DeleteOldEntries = 2,
    DeleteOldCount = 3,
    Complete = 4,
}

impl MigrationPhase {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::WriteChunks),
            1 => Some(Self::CommitFormat),
            2 => Some(Self::DeleteOldEntries),
            3 => Some(Self::DeleteOldCount),
            4 => Some(Self::Complete),
            _ => None,
        }
    }
}

/// Cursor persisted after every idempotent migration step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationJournal {
    pub phase: MigrationPhase,
    /// Legacy entry index for the `DeleteOldEntries` sweep.
    pub delete_cursor: u8,
    /// Legacy persona count at migration start (bounds the deletion sweep).
    pub original_count: u8,
}

impl MigrationJournal {
    pub fn new(original_count: u8) -> Self {
        Self {
            phase: MigrationPhase::WriteChunks,
            delete_cursor: 0,
            original_count,
        }
    }

    pub fn encode(self) -> [u8; MIGRATION_JOURNAL_LEN] {
        let mut encoded = [
            MIGRATION_MAGIC[0],
            MIGRATION_MAGIC[1],
            MIGRATION_MAGIC[2],
            MIGRATION_MAGIC[3],
            MIGRATION_VERSION,
            self.phase as u8,
            self.delete_cursor,
            self.original_count,
            0,
            0,
            0,
            0,
        ];
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&encoded[..8]);
        encoded[8..12].copy_from_slice(&hasher.finalize().to_le_bytes());
        encoded
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != MIGRATION_JOURNAL_LEN
            || bytes[0..4] != MIGRATION_MAGIC
            || bytes[4] != MIGRATION_VERSION
        {
            return None;
        }
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&bytes[..8]);
        if bytes[8..12] != hasher.finalize().to_le_bytes() {
            return None;
        }
        let journal = Self {
            phase: MigrationPhase::from_u8(bytes[5])?,
            delete_cursor: bytes[6],
            original_count: bytes[7],
        };
        if journal.delete_cursor > journal.original_count {
            return None;
        }
        Some(journal)
    }
}

// ---------------------------------------------------------------------------
// Persona-removal journal: drop one entry, shift the tail down, commit count.
// ---------------------------------------------------------------------------

/// Fixed journal encoding (`HWPR`, version, fields, CRC32).
pub const PERSONA_REMOVAL_JOURNAL_LEN: usize = 13;
const PERSONA_REMOVAL_MAGIC: [u8; 4] = *b"HWPR";
const PERSONA_REMOVAL_VERSION: u8 = 1;

/// Durable phase of a single-persona removal.
///
/// `ShiftEntries` performs `entry[cursor] = entry[cursor + 1]` ascending from
/// the target: the source entry is untouched by its own shift step, so
/// repeating a step after a power cut writes the same destination bytes
/// again. `Truncate` drops the now-duplicated final entry from its chunk, and
/// `CommitCount` is the single authority flip.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PersonaRemovalPhase {
    ShiftEntries = 0,
    Truncate = 1,
    CommitCount = 2,
    Complete = 3,
}

impl PersonaRemovalPhase {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::ShiftEntries),
            1 => Some(Self::Truncate),
            2 => Some(Self::CommitCount),
            3 => Some(Self::Complete),
            _ => None,
        }
    }
}

/// Cursor persisted after every idempotent removal step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersonaRemovalJournal {
    pub target: u8,
    pub original_count: u8,
    pub phase: PersonaRemovalPhase,
    pub cursor: u8,
}

impl PersonaRemovalJournal {
    pub fn new(target: u8, count: u8) -> Option<Self> {
        if count == 0 || target >= count {
            return None;
        }
        Some(Self {
            target,
            original_count: count,
            phase: PersonaRemovalPhase::ShiftEntries,
            cursor: target,
        })
    }

    pub fn encode(self) -> [u8; PERSONA_REMOVAL_JOURNAL_LEN] {
        let mut encoded = [
            PERSONA_REMOVAL_MAGIC[0],
            PERSONA_REMOVAL_MAGIC[1],
            PERSONA_REMOVAL_MAGIC[2],
            PERSONA_REMOVAL_MAGIC[3],
            PERSONA_REMOVAL_VERSION,
            self.target,
            self.original_count,
            self.phase as u8,
            self.cursor,
            0,
            0,
            0,
            0,
        ];
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&encoded[..9]);
        encoded[9..13].copy_from_slice(&hasher.finalize().to_le_bytes());
        encoded
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PERSONA_REMOVAL_JOURNAL_LEN
            || bytes[0..4] != PERSONA_REMOVAL_MAGIC
            || bytes[4] != PERSONA_REMOVAL_VERSION
        {
            return None;
        }
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&bytes[..9]);
        if bytes[9..13] != hasher.finalize().to_le_bytes() {
            return None;
        }
        let journal = Self {
            target: bytes[5],
            original_count: bytes[6],
            phase: PersonaRemovalPhase::from_u8(bytes[7])?,
            cursor: bytes[8],
        };
        if journal.original_count == 0
            || journal.target >= journal.original_count
            || journal.cursor < journal.target
            || journal.cursor >= journal.original_count
        {
            return None;
        }
        Some(journal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn persona(tag: u8) -> PackedPersona {
        PackedPersona {
            master_slot: tag % 4,
            index: tag as u32,
            pubkey: [tag; 32],
            purpose: format!("nostr:persona:test-{tag}"),
            name: if tag.is_multiple_of(2) {
                Some(format!("Name {tag}"))
            } else {
                None
            },
        }
    }

    #[test]
    fn chunk_round_trip() {
        for n in [0usize, 1, 2, CHUNK_CAPACITY] {
            let entries: Vec<PackedPersona> = (0..n as u8).map(persona).collect();
            let encoded = encode_chunk(&entries).unwrap();
            assert_eq!(decode_chunk(&encoded), Some(entries));
        }
    }

    #[test]
    fn chunk_rejects_oversize_and_bad_fields() {
        let too_many: Vec<PackedPersona> = (0..(CHUNK_CAPACITY + 1) as u8).map(persona).collect();
        assert!(encode_chunk(&too_many).is_err());

        let mut long_purpose = persona(1);
        long_purpose.purpose = "x".repeat(MAX_PURPOSE_LEN + 1);
        assert!(encode_chunk(&[long_purpose]).is_err());

        let mut empty_purpose = persona(1);
        empty_purpose.purpose = String::new();
        assert!(encode_chunk(&[empty_purpose]).is_err());

        let mut long_name = persona(1);
        long_name.name = Some("x".repeat(MAX_NAME_LEN + 1));
        assert!(encode_chunk(&[long_name]).is_err());
    }

    #[test]
    fn chunk_rejects_corruption() {
        let encoded = encode_chunk(&[persona(1), persona(2)]).unwrap();
        // CRC flip.
        let mut corrupt = encoded.clone();
        *corrupt.last_mut().unwrap() ^= 0xff;
        assert_eq!(decode_chunk(&corrupt), None);
        // Body flip.
        let mut corrupt = encoded.clone();
        corrupt[7] ^= 0xff;
        assert_eq!(decode_chunk(&corrupt), None);
        // Truncation and trailing garbage.
        assert_eq!(decode_chunk(&encoded[..encoded.len() - 1]), None);
        let mut trailing = encoded.clone();
        trailing.insert(encoded.len() - 4, 0);
        assert_eq!(decode_chunk(&trailing), None);
        // Bad magic / version.
        let mut bad = encoded.clone();
        bad[0] ^= 0xff;
        assert_eq!(decode_chunk(&bad), None);
        let mut bad = encoded;
        bad[4] = 99;
        assert_eq!(decode_chunk(&bad), None);
    }

    /// Frozen byte fixture. This is the on-flash format — if this test fails,
    /// the change breaks every device that has already migrated. Do not
    /// regenerate silently; bump CHUNK_VERSION and write a migration instead.
    #[test]
    fn chunk_format_is_frozen() {
        let entries = vec![
            PackedPersona {
                master_slot: 0,
                index: 0,
                pubkey: [0x11; 32],
                purpose: "nostr:persona:natural-person".to_string(),
                name: None,
            },
            PackedPersona {
                master_slot: 2,
                index: 7,
                pubkey: [0xab; 32],
                purpose: "nostr:persona:dependant-1-np".to_string(),
                name: Some("Tom".to_string()),
            },
        ];
        let encoded = encode_chunk(&entries).unwrap();
        let hex: String = encoded.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "48575043010200000000001111111111111111111111111111111111111111\
             1111111111111111111111111c6e6f7374723a706572736f6e613a6e617475\
             72616c2d706572736f6e000200000007ababababababababababababababab\
             ababababababababababababababababab1c6e6f7374723a706572736f6e61\
             3a646570656e64616e742d312d6e7003546f6dbb3f00e9"
                .replace(char::is_whitespace, "")
        );
        assert_eq!(decode_chunk(&encoded), Some(entries));
    }

    #[test]
    fn migration_journal_round_trip_and_validation() {
        let journal = MigrationJournal::new(9);
        assert_eq!(MigrationJournal::decode(&journal.encode()), Some(journal));
        let mut malformed = journal.encode();
        malformed[5] = 99;
        assert_eq!(MigrationJournal::decode(&malformed), None);
        let mut cursor_beyond_count = MigrationJournal::new(3);
        cursor_beyond_count.delete_cursor = 4;
        assert_eq!(
            MigrationJournal::decode(&cursor_beyond_count.encode()),
            None
        );
    }

    #[test]
    fn removal_journal_round_trip_and_validation() {
        let journal = PersonaRemovalJournal::new(1, 4).unwrap();
        assert_eq!(
            PersonaRemovalJournal::decode(&journal.encode()),
            Some(journal)
        );
        assert!(PersonaRemovalJournal::new(0, 0).is_none());
        assert!(PersonaRemovalJournal::new(4, 4).is_none());
        let mut malformed = journal.encode();
        malformed[7] = 99;
        assert_eq!(PersonaRemovalJournal::decode(&malformed), None);
    }

    // ------------------------------------------------------------------
    // Entry-level removal model, mirroring persistent_state's cut tests.
    // The firmware performs each step as a chunk read-modify-write; the
    // chunk write is atomic (NVS copy-on-write), so the entry-level model
    // is exactly what a device replays after a power cut.
    // ------------------------------------------------------------------

    fn removal_step(entries: &mut [u8], count: &mut u8, journal: &mut PersonaRemovalJournal) {
        match journal.phase {
            PersonaRemovalPhase::ShiftEntries => {
                if journal.cursor + 1 < journal.original_count {
                    let src = (journal.cursor + 1) as usize;
                    let dst = journal.cursor as usize;
                    entries[dst] = entries[src];
                    journal.cursor += 1;
                } else {
                    journal.phase = PersonaRemovalPhase::Truncate;
                }
            }
            PersonaRemovalPhase::Truncate => {
                let last = (journal.original_count - 1) as usize;
                entries[last] = 0xee; // cleared marker
                journal.phase = PersonaRemovalPhase::CommitCount;
            }
            PersonaRemovalPhase::CommitCount => {
                *count = journal.original_count - 1;
                journal.phase = PersonaRemovalPhase::Complete;
            }
            PersonaRemovalPhase::Complete => {}
        }
    }

    fn removed(target: u8) -> (Vec<u8>, u8) {
        let mut entries = vec![10, 11, 12, 13];
        let mut count = 4u8;
        let mut journal = PersonaRemovalJournal::new(target, 4).unwrap();
        while journal.phase != PersonaRemovalPhase::Complete {
            removal_step(&mut entries, &mut count, &mut journal);
        }
        (entries, count)
    }

    #[test]
    fn removal_model_first_middle_and_last() {
        assert_eq!(removed(0), (vec![11, 12, 13, 0xee], 3));
        assert_eq!(removed(1), (vec![10, 12, 13, 0xee], 3));
        assert_eq!(removed(3), (vec![10, 11, 12, 0xee], 3));
    }

    #[test]
    fn removal_model_survives_a_cut_after_any_step() {
        let expected = removed(1);
        for cut_after in 0..8 {
            let mut entries = vec![10, 11, 12, 13];
            let mut count = 4u8;
            let mut journal = PersonaRemovalJournal::new(1, 4).unwrap();
            for _ in 0..cut_after {
                if journal.phase == PersonaRemovalPhase::Complete {
                    break;
                }
                removal_step(&mut entries, &mut count, &mut journal);
            }
            // Simulate a cut after the step's data write but before its
            // journal write: run once on a throwaway cursor, resume with the
            // durable pre-step cursor, and repeat the action.
            if journal.phase != PersonaRemovalPhase::Complete {
                let durable = journal;
                removal_step(&mut entries, &mut count, &mut journal);
                journal = durable;
            }
            while journal.phase != PersonaRemovalPhase::Complete {
                removal_step(&mut entries, &mut count, &mut journal);
            }
            assert_eq!((entries, count), expected.clone(), "cut after {cut_after}");
        }
    }
}
