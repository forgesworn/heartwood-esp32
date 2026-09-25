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
//! fit is either refused here (secrets and small critical keys, which stay
//! small enough to fit) or written after erasing the old copy (everything
//! else, as every write was before), and ESP-IDF is never asked to write a
//! second copy it has no room for.
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

/// Room kept for the small keys that never fall back to erasing first (the
/// data-key wrapper, a sealed seed, the note key, a management challenge):
/// one rewrite of the largest of them at a time, since each old copy is
/// erased before the next write starts.
pub const SMALL_WRITE_MAX: usize = 128;

/// Entries kept back for [`SMALL_WRITE_MAX`].
pub fn small_write_reserve() -> usize {
    blob_entries(SMALL_WRITE_MAX)
}

/// What a replace that does not fit beside the old copy does instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fallback {
    /// Refuse, before ESP-IDF is asked. The old value stays and the caller
    /// reports storage full. For secrets and the small keys whose absence
    /// loses keys or resets a replay boundary.
    Never,
    /// Erase the key, then write. A cut in between leaves it absent, which is
    /// what every write did before this firmware; with the key absent the
    /// write starts at version offset 0, where ESP-IDF's failure cleanup
    /// erases the right chunks.
    EraseFirst,
}

/// The per-key policy for the `heartwood` namespace. The note locker's
/// namespace never falls back whatever the key, and says so at its call sites.
pub fn fallback_for(key: &str) -> Fallback {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let seed_enc = key
        .strip_prefix('m')
        .and_then(|k| k.strip_suffix("_seed_enc"))
        .is_some_and(digits);
    let seed_plain = key
        .strip_prefix("master_")
        .and_then(|k| k.strip_suffix("_secret"))
        .is_some_and(digits);
    let never = matches!(key, "dk_sec" | "at_rest_kind" | "root_secret" | "pin_attempts")
        || key.starts_with("mgmt_")
        || seed_enc
        || seed_plain;
    if never {
        Fallback::Never
    } else {
        Fallback::EraseFirst
    }
}

/// Master slots a board can hold (`masters::MAX_MASTERS`).
pub const MAX_MASTER_SLOTS: u8 = 8;

/// The blobs most often rewritten in place: every master's pairing table,
/// the unlock phones and the persona chunks. The growth gate keeps room for
/// the largest of them.
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

/// Plan a replace of a key (currently `old_len` bytes, or absent) with
/// `new_len` bytes, given `available` entries.
///
/// A first write is always attempted: with no old copy the write starts at
/// version offset 0, so a failure part-way is cleaned up correctly and costs
/// nothing. A replace that fits beside the old copy is written in place.
/// Otherwise `fallback` decides.
pub fn plan_replace(fallback: Fallback, available: usize, old_len: Option<usize>, new_len: usize) -> Plan {
    if old_len.is_none() || blob_entries(new_len) <= available {
        return Plan::Direct;
    }
    match fallback {
        Fallback::Never => Plan::Refuse,
        Fallback::EraseFirst => Plan::EraseFirst,
    }
}

/// Whether a write that grows the store (a new pairing, a persona, an unlock
/// phone, an avatar) may go ahead: it must fit, and afterwards there must
/// still be room to rewrite the largest hot blob in place, plus the small-key
/// reserve. `old_len` is the growing key's current size (its old copy is
/// freed once the write completes); `largest_hot` is the largest of the blobs
/// that are rewritten in place (the pairing tables, `dk_ph`, the persona
/// chunks). Headroom hygiene, not a guarantee: other writes are not gated,
/// so a board can still end up where a large replace erases first.
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
    fn only_secrets_and_small_critical_keys_refuse() {
        for key in [
            "dk_sec",
            "at_rest_kind",
            "root_secret",
            "pin_attempts",
            "m0_seed_enc",
            "m7_seed_enc",
            "master_0_secret",
            "master_7_secret",
            "mgmt_nonce",
            "mgmt_0123abcd",
        ] {
            assert_eq!(fallback_for(key), Fallback::Never, "{key}");
        }
        for key in [
            "connslots_0",
            "dk_ph",
            "pc0",
            "pcnt",
            "rm_journal",
            "net_config",
            "net_trial",
            "net_last",
            "ph_relays",
            "pinned_rly",
            "imav0",
            "master_0_label",
            "master_0_conn",
            "m0_seed_encx",
            "mx_seed_enc",
            "master__secret",
        ] {
            assert_eq!(fallback_for(key), Fallback::EraseFirst, "{key}");
        }
    }

    #[test]
    fn hot_keys_cover_every_pairing_table_the_phones_and_the_persona_chunks() {
        let keys: Vec<String> = hot_keys().collect();
        assert_eq!(keys.len(), 8 + 1 + crate::persona_pack::MAX_CHUNKS as usize);
        assert!(keys.iter().all(|k| fallback_for(k) == Fallback::EraseFirst));
    }

    #[test]
    fn a_replace_that_fits_or_a_first_write_is_direct_whatever_the_key() {
        let need = blob_entries(500);
        for fallback in [Fallback::Never, Fallback::EraseFirst] {
            assert_eq!(plan_replace(fallback, need, Some(92), 500), Plan::Direct);
            assert_eq!(plan_replace(fallback, 0, None, 500), Plan::Direct);
        }
    }

    #[test]
    fn a_replace_that_does_not_fit_erases_first_unless_the_key_forbids_it() {
        // The bench V4's measured headroom, far short of a second table.
        let available = 17;
        assert_eq!(plan_replace(Fallback::EraseFirst, available, Some(6000), 6000), Plan::EraseFirst);
        assert_eq!(plan_replace(Fallback::EraseFirst, available, Some(6000), 6700), Plan::EraseFirst);
        assert_eq!(plan_replace(Fallback::Never, available, Some(6000), 5400), Plan::Refuse);
        // A secret wrapper still fits in place at that headroom.
        assert_eq!(plan_replace(Fallback::Never, available, Some(101), 101), Plan::Direct);
    }

    #[test]
    fn at_the_bench_headroom_every_never_fallback_value_still_fits() {
        // dk_sec and the sealed seeds are at most 101 bytes, at_rest_kind 9,
        // a management challenge record at most 64.
        for len in [101, 82, 9, 32, 64] {
            assert!(blob_entries(len) <= 17, "{len} bytes need {}", blob_entries(len));
        }
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
        assert_eq!(plan_replace(Fallback::EraseFirst, after, Some(grown), table), Plan::Direct);
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
