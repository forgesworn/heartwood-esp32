//! NVS entry budget: how much room a blob replace needs, when a replace that
//! does not fit may fall back to erasing first, and when a write that grows
//! the store is allowed at all.
//!
//! The firmware replaces a blob with a lone `nvs_set_blob`, which writes the
//! new copy in full before it erases the old one, so a power cut leaves one
//! of them (`firmware/src/nvs.rs`). The price is room: both copies hold
//! entries at once. This module decides, from `nvs_get_stats`'s
//! `available_entries` (free entries minus the page NVS keeps back for
//! garbage collection), whether that room exists.
//!
//! It must decide BEFORE ESP-IDF tries. In ESP-IDF v5.3.2 a multi-page blob
//! write that runs out of room cleans up by erasing chunk `ii` of each page it
//! used, not chunk `chunkStart + ii`
//! (`components/nvs_flash/src/nvs_storage.cpp:363-368`; still so in the
//! 6.0.1 tree). Every second replace of a key is written at the version-1
//! offset, so that cleanup can erase a chunk of the OLD copy, which the next
//! read then drops as incomplete (`:619-624`), and leaves the new chunks live;
//! a later retry that succeeds then carries those strays, and boot drops its
//! index for a chunk-count mismatch (`:98-114`). So a replace that might not
//! fit is refused here, and ESP-IDF is never asked.
//!
//! Pure and host-tested; the firmware supplies the numbers.

/// Bytes per NVS entry.
pub const ENTRY_SIZE: usize = 32;
/// Entries per 4 KiB page (`Page::ENTRY_COUNT`).
pub const PAGE_ENTRIES: usize = 126;
/// Largest blob chunk one page holds (`Page::CHUNK_MAX_SIZE`).
pub const CHUNK_MAX: usize = ENTRY_SIZE * (PAGE_ENTRIES - 1);
/// A blob's first chunk moves to a fresh page rather than start in less
/// tailroom than this (`CHUNK_MAX_SIZE / 10`), abandoning the rest of the page.
pub const FIRST_CHUNK_MIN: usize = CHUNK_MAX / 10;

use alloc::format;
use alloc::string::String;

fn div_ceil(n: usize, d: usize) -> usize {
    n.div_ceil(d)
}

/// An upper bound on the entries `nvs_set_blob` consumes writing `len` bytes
/// as a new copy (the old copy is still held while it does):
///
/// - data: one entry per 32 bytes, plus one per chunk for its partial tail;
/// - one header entry per chunk, where a blob spans at most
///   `ceil(len / CHUNK_MAX) + 1` pages because it may start part-way through
///   one;
/// - one blob index entry;
/// - the tail of the current page, abandoned when the first chunk would start
///   in less than `min(len, FIRST_CHUNK_MIN)` bytes of tailroom.
pub fn blob_entries(len: usize) -> usize {
    let chunks = div_ceil(len, CHUNK_MAX) + 1;
    div_ceil(len, ENTRY_SIZE) + 2 * chunks + 1 + div_ceil(len.min(FIRST_CHUNK_MIN), ENTRY_SIZE)
}

/// A lower bound on the entries a stored blob of `len` bytes occupies: its
/// data, at least one chunk header and its index. What erasing it certainly
/// frees.
pub fn stored_entries_min(len: usize) -> usize {
    div_ceil(len, ENTRY_SIZE) + 2
}

/// Room kept for the small keys that must never fall back to erasing first
/// (the data-key wrapper, a sealed seed, the note key, the PIN wipe counter,
/// a management challenge): one rewrite of the largest of them at a time,
/// since each old copy is erased before the next write starts.
pub const SMALL_WRITE_MAX: usize = 128;

/// Entries kept back for [`SMALL_WRITE_MAX`].
pub fn small_write_reserve() -> usize {
    blob_entries(SMALL_WRITE_MAX)
}

/// What a replace that does not fit in place may do instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fallback {
    /// Refuse. The old value stays; the caller reports storage full.
    Never,
    /// On a revocation only, and only when the new value is no larger, erase
    /// the key and then write. A cut between the two leaves the key absent,
    /// which for these keys means less authority, never more: no pairings
    /// for that identity, or no unlock phones. Failing the write instead
    /// would leave the party being revoked authorised.
    EraseFirstOnRevoke,
}

/// The per-key fallback policy. Everything not listed is [`Fallback::Never`]:
/// losing `dk_sec`, a sealed seed, `nk` or a note record loses keys or value,
/// losing `pin_attempts` or a management challenge resets a counter an
/// attacker is up against, and losing a journal abandons a transaction
/// half done.
pub fn fallback_for(key: &str) -> Fallback {
    // `connslots_N`: one master's pairing table. `dk_ph`: the unlock phones
    // (`data_key::PHONES_KEY`, spelt out because that module is feature-gated).
    if key == "dk_ph" || key.strip_prefix("connslots_").is_some_and(|n| !n.is_empty()) {
        Fallback::EraseFirstOnRevoke
    } else {
        Fallback::Never
    }
}

/// Master slots a board can hold (`masters::MAX_MASTERS`).
pub const MAX_MASTER_SLOTS: u8 = 8;

/// The blobs that are rewritten in place and must stay rewritable: every
/// master's pairing table, the unlock phones and the persona chunks. The
/// growth gate keeps room for the largest of them.
pub fn hot_keys() -> impl Iterator<Item = String> {
    (0..MAX_MASTER_SLOTS)
        .map(|slot| format!("connslots_{slot}"))
        .chain(core::iter::once(String::from("dk_ph")))
        .chain((0..crate::persona_pack::MAX_CHUNKS).map(|chunk| format!("pc{chunk}")))
}

/// How to carry out one replace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    /// `nvs_set_blob` alone: old or new after a cut.
    Direct,
    /// `nvs_erase_key`, then `nvs_set_blob`: old, new or absent after a cut.
    EraseFirst,
    /// Do not write. The old value stays.
    Refuse,
}

/// Plan a replace of `key` (currently `old_len` bytes, or absent) with
/// `new_len` bytes, given `available` entries. `revoking` is the caller's
/// statement that the write only removes authority; it matters only for a key
/// whose policy allows it.
pub fn plan_replace(
    key: &str,
    available: usize,
    old_len: Option<usize>,
    new_len: usize,
    revoking: bool,
) -> Plan {
    let need = blob_entries(new_len);
    if need <= available {
        return Plan::Direct;
    }
    match (fallback_for(key), old_len) {
        (Fallback::EraseFirstOnRevoke, Some(old))
            if revoking && new_len <= old && need <= available + stored_entries_min(old) =>
        {
            Plan::EraseFirst
        }
        _ => Plan::Refuse,
    }
}

/// Whether a write that grows the store (a new pairing, a persona, an unlock
/// phone, an avatar) may go ahead: it must fit, and afterwards there must
/// still be room to rewrite the largest hot blob in place, plus the small-key
/// reserve. `old_len` is the growing key's current size (its old copy is
/// freed once the write completes); `largest_hot` is the largest of the blobs
/// that are rewritten in place (the pairing tables, `dk_ph`, the persona
/// chunks). Keeping this true is what keeps a later revocation a direct,
/// cut-safe replace; the erase-first fallback is for boards already past it.
pub fn growth_allowed(available: usize, old_len: Option<usize>, new_len: usize, largest_hot: usize) -> bool {
    let need = blob_entries(new_len);
    if need > available {
        return false;
    }
    let after = available - need + old_len.map_or(0, stored_entries_min);
    after >= blob_entries(largest_hot.max(new_len)) + small_write_reserve()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entry_bound_covers_every_part_of_a_write() {
        // One byte: data 1, two chunk headers, index 1, one abandoned entry.
        assert_eq!(blob_entries(1), 1 + 4 + 1 + 1);
        assert_eq!(blob_entries(0), 2 + 1);
        // A 6 KB pairing table spans at most three pages.
        assert_eq!(blob_entries(6000), 188 + 6 + 1 + 13);
        // Always at least what the blob occupies once stored.
        for len in [0, 1, 31, 32, 33, 399, 400, 4000, 4001, 8000, 16_000] {
            assert!(blob_entries(len) >= stored_entries_min(len), "len {len}");
        }
    }

    #[test]
    fn only_pairing_tables_and_phone_records_may_fall_back() {
        for key in ["connslots_0", "connslots_7", "dk_ph"] {
            assert_eq!(fallback_for(key), Fallback::EraseFirstOnRevoke, "{key}");
        }
        for key in [
            "dk_sec",
            "m0_seed_enc",
            "master_0_secret",
            "nk",
            "idx",
            "pin_attempts",
            "mgmt_nonce",
            "mgmt_0123abcd",
            "at_rest_kind",
            "rm_journal",
            "pc0",
            "net_trial",
            "connslots_",
            "connslots",
            "master_0_conn",
        ] {
            assert_eq!(fallback_for(key), Fallback::Never, "{key}");
        }
    }

    #[test]
    fn every_hot_key_but_the_persona_chunks_may_fall_back_on_revoke() {
        let keys: Vec<String> = hot_keys().collect();
        assert_eq!(keys.len(), 8 + 1 + crate::persona_pack::MAX_CHUNKS as usize);
        for key in &keys {
            let expect = if key.starts_with("pc") { Fallback::Never } else { Fallback::EraseFirstOnRevoke };
            assert_eq!(fallback_for(key), expect, "{key}");
        }
    }

    #[test]
    fn a_replace_that_fits_is_direct_whatever_the_key() {
        let need = blob_entries(500);
        assert_eq!(plan_replace("dk_sec", need, Some(92), 500, false), Plan::Direct);
        assert_eq!(plan_replace("connslots_0", need, Some(600), 500, true), Plan::Direct);
    }

    #[test]
    fn a_revocation_that_does_not_fit_erases_first_only_where_allowed() {
        let old = 6000;
        let new = 5400;
        let available = 17; // the bench V4's measured headroom
        assert_eq!(plan_replace("connslots_2", available, Some(old), new, true), Plan::EraseFirst);
        assert_eq!(plan_replace("dk_ph", available, Some(2166), 2031, true), Plan::EraseFirst);
        // Not a revocation, not a fallback key, growing, or absent: refused.
        assert_eq!(plan_replace("connslots_2", available, Some(old), new, false), Plan::Refuse);
        assert_eq!(plan_replace("pc0", available, Some(old), new, true), Plan::Refuse);
        assert_eq!(plan_replace("connslots_2", available, Some(old), old + 1, true), Plan::Refuse);
        assert_eq!(plan_replace("connslots_2", available, None, new, true), Plan::Refuse);
        // Even erasing the old copy would not make room: refused.
        assert_eq!(plan_replace("connslots_2", 0, Some(40), 40, true), Plan::Refuse);
    }

    #[test]
    fn growth_keeps_room_to_rewrite_the_largest_hot_blob_in_place() {
        let table = 6000;
        let grown = table + 700;
        // Exactly enough: the grown table fits, and afterwards a rewrite of it
        // (now the largest hot blob) still fits in place.
        let mut available = blob_entries(grown) + blob_entries(grown) + small_write_reserve()
            - stored_entries_min(table);
        assert!(growth_allowed(available, Some(table), grown, table));
        let after = available - blob_entries(grown) + stored_entries_min(table);
        assert_eq!(plan_replace("connslots_0", after, Some(grown), table, false), Plan::Direct);
        available -= 1;
        assert!(!growth_allowed(available, Some(table), grown, table));
        // A small growth is still refused while a larger hot blob would lose
        // its in-place rewrite.
        assert!(!growth_allowed(200, Some(100), 300, 6000));
        assert!(growth_allowed(500, Some(100), 300, 6000));
    }

    /// Every firmware blob write goes through `nvs::ReplaceBlob`. esp-idf-svc's
    /// `set_blob` and `set_str` erase the key before writing, and
    /// `EspKeyValueStorage::set_raw` removes it first; the raw ESP-IDF calls
    /// belong to `nvs.rs` alone, where the budget is checked first. Comments
    /// are skipped, so the reasons can still be written down.
    #[test]
    fn firmware_writes_blobs_only_through_the_budgeted_helper() {
        use std::path::Path;
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../firmware/src");
        let mut files = Vec::new();
        let mut dirs = vec![src.clone()];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("firmware/src is readable") {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    files.push(path);
                }
            }
        }
        assert!(files.len() > 20, "found the firmware sources ({} files)", files.len());
        let mut hits = Vec::new();
        for path in &files {
            let text = std::fs::read_to_string(path).unwrap();
            let is_helper = path.ends_with("nvs.rs") && path.parent() == Some(src.as_path());
            for (n, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                let mut banned = vec![".set_blob(", ".set_str(", ".set_raw("];
                if !is_helper {
                    banned.extend(["nvs_set_blob(", "nvs_set_str(", "nvs_erase_key("]);
                }
                for pattern in banned {
                    if code.contains(pattern) {
                        hits.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                    }
                }
            }
        }
        assert!(hits.is_empty(), "blob writes outside nvs::ReplaceBlob:\n{}", hits.join("\n"));
    }
}
