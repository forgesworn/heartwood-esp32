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
use alloc::vec::Vec;

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
///
/// Never: the data-key wrapper, the sealed and plaintext seeds and the at-rest
/// marker (losing them loses keys), `bridge_secret` (without it the USB
/// bridge-authentication gate is open), `rzrec_N` (a lost receipt reopens its
/// nonce), and `net_config` / `net_trial` (a lost config brings a WiFi board
/// up in USB mode, stranding a remote one; a refused network change is safe).
/// The management challenges fall back: an absent one is minted afresh, and a
/// replayed request still fails as stale.
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
    let receipts = key.strip_prefix("rzrec_").is_some_and(digits);
    let never = matches!(
        key,
        "dk_sec" | "at_rest_kind" | "root_secret" | "pin_attempts" | "bridge_secret" | "net_config" | "net_trial"
    ) || receipts
        || seed_enc
        || seed_plain;
    if never {
        Fallback::Never
    } else {
        Fallback::EraseFirst
    }
}

/// Whether a blob of `len` bytes is always written as one chunk: its first
/// chunk moves to a fresh page rather than split in less tailroom than
/// `min(len, FIRST_CHUNK_MIN)`, so up to [`FIRST_CHUNK_MIN`] bytes never split.
pub fn single_chunk(len: usize) -> bool {
    len <= FIRST_CHUNK_MIN
}

/// Keys whose multi-chunk write failed this boot. ESP-IDF v5.3.2's failure
/// cleanup erases chunks through the page pointer it recorded as it wrote
/// each one (`nvs_storage.cpp:326-333`, `:363-368`); garbage collection
/// during the same write can move such a page, so a chunk can survive as a
/// live stray. Rewriting the key in the same boot writes the same chunk
/// indices again, and boot then drops the index for a chunk-count mismatch
/// (`:98-114`). So a key that failed that way is not written again until a
/// restart has run the orphan cleanup. A single-chunk write is unaffected: a
/// page move for it happens before its one chunk is written, or inside a
/// `requestNewPage` that then succeeded, after which only a flash error can
/// fail the index write.
#[derive(Default, Debug)]
pub struct FailedWrites {
    keys: Vec<String>,
}

impl FailedWrites {
    pub const fn new() -> Self {
        FailedWrites { keys: Vec::new() }
    }

    /// Whether `key` must not be written again this boot.
    pub fn blocks(&self, key: &str) -> bool {
        self.keys.iter().any(|k| k == key)
    }

    /// Note a failed write of `len` bytes to `key`. True if an immediate
    /// retry is safe (a single-chunk value); otherwise the key is blocked.
    pub fn record(&mut self, key: &str, len: usize) -> bool {
        if single_chunk(len) {
            return true;
        }
        if !self.blocks(key) {
            self.keys.push(String::from(key));
        }
        false
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

/// The cached identity pictures, one per master slot (`imav<slot>`, written
/// by the firmware's `identity_meta.rs`). A display nicety Sapwood can send
/// again, so the one thing dropped to make room for a pairing, a persona or a
/// phone; the names beside them (`iman<slot>`) stay.
pub fn avatar_keys() -> impl Iterator<Item = String> {
    (0..MAX_MASTER_SLOTS).map(|slot| format!("imav{slot}"))
}

/// Entries dropping every cached avatar can be counted on to free: each at
/// its fewest entries (`nvs_room::min_blob_entries`). `blob_len` answers a
/// key's stored length, `None` if absent or unreadable.
pub fn avatar_reclaim(blob_len: impl Fn(&str) -> Option<usize>) -> usize {
    avatar_keys()
        .filter_map(|key| blob_len(&key))
        .map(crate::nvs_room::min_blob_entries)
        .sum()
}

/// Drop every cached avatar through `remove` (true if a key was there and
/// went). How many went.
pub fn evict_avatars(mut remove: impl FnMut(&str) -> bool) -> usize {
    avatar_keys().filter(|key| remove(key)).count()
}

/// What a replace leaves behind, worst first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    /// Erased first, then the new copy did not fit either: the key is gone.
    Lost,
    /// Not written: refused, or a first write with no room. The old value
    /// (if any) stays.
    NoRoom,
    /// Written after erasing the old copy: a cut in between leaves it absent.
    AfterErase,
    /// Written beside the old copy: a cut leaves the old or the new.
    InPlace,
}

/// How a replace planned by [`plan_replace`] ends, judged by the same
/// bounds: the new copy needs [`blob_entries`], an erased old copy frees at
/// least [`stored_entries_min`].
pub fn replace_outcome(fallback: Fallback, available: usize, old_len: Option<usize>, new_len: usize) -> Outcome {
    let need = blob_entries(new_len);
    match plan_replace(fallback, available, old_len, new_len) {
        Plan::Direct if need <= available => Outcome::InPlace,
        Plan::Direct | Plan::Refuse => Outcome::NoRoom,
        Plan::EraseFirst if need <= available + old_len.map_or(0, stored_entries_min) => Outcome::AfterErase,
        Plan::EraseFirst => Outcome::Lost,
    }
}

/// Whether to drop the cached avatars (`reclaim` entries, [`avatar_reclaim`])
/// before a replace: only when that changes how it ends. A write that does
/// not fit then fits, a replace that would erase first then goes in place
/// (or one refused in place is then written), or an erase-first rewrite that
/// would lose the key then lands. When the avatars would not change the
/// outcome they stay: a table that erases first either way gains nothing
/// from their loss.
pub fn evict_for_replace(
    fallback: Fallback,
    available: usize,
    reclaim: usize,
    old_len: Option<usize>,
    new_len: usize,
) -> bool {
    reclaim > 0
        && replace_outcome(fallback, available.saturating_add(reclaim), old_len, new_len)
            > replace_outcome(fallback, available, old_len, new_len)
}

/// Whether to drop the cached avatars before a growth [`growth_allowed`]
/// refuses: only when, with their `reclaim` entries back, it would pass.
/// Otherwise the growth is refused and the avatars stay.
pub fn evict_for_growth(
    available: usize,
    reclaim: usize,
    old_len: Option<usize>,
    new_len: usize,
    largest_hot: usize,
) -> bool {
    reclaim > 0
        && !growth_allowed(available, old_len, new_len, largest_hot)
        && growth_allowed(available.saturating_add(reclaim), old_len, new_len, largest_hot)
}

/// [`growth_allowed`], counting the cached avatars as room: what a check made
/// before the card asks, since the write after the press drops them first
/// when that is what lets it through ([`evict_for_growth`]).
pub fn growth_allowed_with_reclaim(
    available: usize,
    reclaim: usize,
    old_len: Option<usize>,
    new_len: usize,
    largest_hot: usize,
) -> bool {
    growth_allowed(available.saturating_add(reclaim), old_len, new_len, largest_hot)
}

/// Whether an avatar of `new_len` bytes may be stored over one of `old_len`
/// (an avatar replace may erase first: the old picture is a cache), given
/// `available` entries, `reclaim` entries of avatars stored now (this key's
/// old copy included, as [`avatar_reclaim`] counts it) and the lengths of the
/// hot blobs stored (`hot_keys`).
///
/// It must fit and leave the small-key reserve. And it must never be what a
/// later rewrite of a hot blob at its present size drops at once, so for
/// every hot blob:
///
/// - erased and rewritten, it still fits with the reserve to spare (so
///   [`evict_for_replace`] never finds the rewrite would lose the key);
/// - if it could be rewritten in place with every avatar gone, it still can
///   with this one stored, with the reserve to spare (so the eviction never
///   finds the avatar is what stands between it and an in-place write).
///
/// A hot blob that cannot be rewritten in place even with no avatar at all
/// erases first either way, so a picture costs it nothing. A rewrite that
/// shrinks a hot blob (a revocation) may still drop the picture, when that
/// is what lets the smaller copy go in place. Not
/// [`growth_allowed`], which would insist on room to rewrite that blob in
/// place and so refuses every picture on a board whose largest pairing table
/// is already past it.
pub fn avatar_allowed(
    available: usize,
    reclaim: usize,
    old_len: Option<usize>,
    new_len: usize,
    hot: &[usize],
) -> bool {
    let room = available.saturating_add(old_len.map_or(0, stored_entries_min));
    let need = blob_entries(new_len);
    if need > room {
        return false;
    }
    let after = room - need;
    let reserve = small_write_reserve();
    if after < reserve {
        return false;
    }
    let bare = available.saturating_add(reclaim);
    hot.iter().all(|&len| {
        let rewrite = blob_entries(len);
        let erased_fits = after + stored_entries_min(len) >= rewrite + reserve;
        let in_place_kept = rewrite > bare || after >= rewrite + reserve;
        erased_fits && in_place_kept
    })
}

/// How many of `steps`, growths written one after another (each a hot
/// blob's current length, or `None`, and its new length), [`growth_allowed`]
/// lets through in turn, stopping at the first refusal: the gate each write
/// would meet, judged before any of them. Each step that passes is taken as
/// written: it uses [`blob_entries`] of its new length and frees
/// [`stored_entries_min`] of its old one, the bounds the gate already uses,
/// so a real write leaves at least the room this assumes, and its new length
/// joins the hot blobs the later steps must keep room to rewrite.
pub fn growth_run(
    mut available: usize,
    mut largest_hot: usize,
    steps: impl IntoIterator<Item = (Option<usize>, usize)>,
) -> usize {
    let mut passed = 0;
    for (old_len, new_len) in steps {
        if !growth_allowed(available, old_len, new_len, largest_hot) {
            break;
        }
        available = available - blob_entries(new_len) + old_len.map_or(0, stored_entries_min);
        largest_hot = largest_hot.max(new_len);
        passed += 1;
    }
    passed
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
            "bridge_secret",
            "net_config",
            "net_trial",
            "rzrec_0",
            "rzrec_7",
            "m0_seed_enc",
            "m7_seed_enc",
            "master_0_secret",
            "master_7_secret",
        ] {
            assert_eq!(fallback_for(key), Fallback::Never, "{key}");
        }
        for key in [
            "connslots_0",
            "dk_ph",
            "pc0",
            "pcnt",
            "rm_journal",
            "mgmt_nonce",
            "mgmt_0123abcd",
            "net_last",
            "rzrec_",
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
    fn only_a_value_that_always_fits_one_chunk_may_be_retried() {
        assert!(single_chunk(0) && single_chunk(FIRST_CHUNK_MIN));
        assert!(!single_chunk(FIRST_CHUNK_MIN + 1));
        let mut failed = FailedWrites::new();
        assert!(failed.record("dk_ph", 300), "one chunk: retry now");
        assert!(!failed.blocks("dk_ph"));
        assert!(!failed.record("connslots_0", 3000), "several chunks: no retry");
        assert!(failed.blocks("connslots_0"));
        assert!(!failed.record("connslots_0", 3000));
        assert!(!failed.blocks("connslots_1"));
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

    #[test]
    fn a_run_of_growths_is_judged_as_if_each_earlier_one_was_written() {
        // One step is exactly the gate.
        for available in [150, 200, 250, 300, 400] {
            assert_eq!(
                growth_run(available, 2000, [(Some(1000), 1150)]),
                usize::from(growth_allowed(available, Some(1000), 1150, 2000)),
                "{available}"
            );
        }
        // The least room in which each of two 150-byte growths of a chunk
        // would pass on its own, judged against today's board.
        let available = (100..1000)
            .find(|&a| growth_allowed(a, Some(1150), 1300, 2000))
            .unwrap();
        assert!(growth_allowed(available, Some(1000), 1150, 2000), "the first alone passes too");
        // But after the first is written, the second does not.
        assert_eq!(growth_run(available, 2000, [(Some(1000), 1150), (Some(1150), 1300)]), 1);
        // With room for both, both pass; a refusal stops the run.
        assert_eq!(growth_run(available + 200, 2000, [(Some(1000), 1150), (Some(1150), 1300)]), 2);
        assert_eq!(growth_run(0, 2000, [(Some(1000), 1150), (None, 100)]), 0);
        // A step that grows past the largest hot blob raises what later
        // steps must keep room for.
        let big = growth_run(10_000, 0, [(None, 9000), (None, 100)]);
        let small = growth_run(10_000, 0, [(None, 100), (None, 100)]);
        assert!(big <= small);
    }

    // The owner's T-Display on beta.38: a 6-page (756-entry) partition with
    // 176 entries available, one master and six pairings. The 6-slot table is
    // modelled (bound, signing slots with grants, about 880 bytes each, as
    // the host harness builds it), not read from the board, so the board's
    // own table may differ; what the figures below rest on is that it is too
    // large to rewrite beside itself in 176 entries (4,993 bytes or more).
    const BOARD_AVAILABLE: usize = 176;
    const TABLE_6: usize = 5280;
    const TABLE_7: usize = 6160;
    /// A 48x48 picture as stored from now on: 4 header bytes, one a pixel.
    const AVATAR_48: usize = 4 + 48 * 48;
    const AVATAR_64: usize = 4 + 64 * 64;
    /// The same pictures as beta.38 stored them: 2 size bytes, Rgb565.
    const LEGACY_48: usize = 2 + 48 * 48 * 2;
    const LEGACY_64: usize = 2 + 64 * 64 * 2;

    #[test]
    fn the_board_figures() {
        assert_eq!(blob_entries(TABLE_6), 165 + 6 + 1 + 13);
        assert_eq!(stored_entries_min(TABLE_6), 167);
        assert_eq!(blob_entries(TABLE_7), 193 + 6 + 1 + 13);
        assert_eq!(blob_entries(AVATAR_48), 73 + 4 + 1 + 13);
        assert_eq!(crate::nvs_room::min_blob_entries(AVATAR_48), 75);
        assert_eq!(blob_entries(AVATAR_64), 129 + 6 + 1 + 13);
        assert_eq!(crate::nvs_room::min_blob_entries(AVATAR_64), 132);
        assert_eq!(blob_entries(LEGACY_48), 145 + 6 + 1 + 13);
        assert_eq!(blob_entries(LEGACY_64), 257 + 8 + 1 + 13);
        // The table cannot be rewritten in place (185 > 176), so every
        // rewrite of it erases first, avatar or not.
        assert_eq!(plan_replace(Fallback::EraseFirst, BOARD_AVAILABLE, Some(TABLE_6), TABLE_6), Plan::EraseFirst);
        // And the growth gate, which keeps room to rewrite it in place
        // (185 + 13 = 198 after the write), refuses every growth at all.
        for len in [1, 100, AVATAR_48, TABLE_6 + 1] {
            assert!(!growth_allowed(BOARD_AVAILABLE, None, len, TABLE_6), "{len}");
        }
    }

    #[test]
    fn a_48px_one_byte_picture_is_accepted_on_the_board() {
        // 91 entries at most, 85 left: the table still rewrites after its
        // erase (85 + 167 >= 185 + 13), and it could not go in place even
        // with no picture (185 > 176).
        assert!(avatar_allowed(BOARD_AVAILABLE, 0, None, AVATAR_48, &[TABLE_6]));
        // Replacing one: its old copy is freed.
        let with = BOARD_AVAILABLE - crate::nvs_room::min_blob_entries(AVATAR_48);
        assert!(avatar_allowed(with, 75, Some(AVATAR_48), AVATAR_48, &[TABLE_6]));
        // Over a legacy Rgb565 one.
        let legacy = BOARD_AVAILABLE - crate::nvs_room::min_blob_entries(LEGACY_48);
        assert!(avatar_allowed(legacy, crate::nvs_room::min_blob_entries(LEGACY_48), Some(LEGACY_48), AVATAR_48, &[TABLE_6]));
    }

    #[test]
    fn a_64px_picture_and_a_two_byte_48px_one_do_not_fit_the_board() {
        // 64px, one byte a pixel: 149 entries, 27 left. The table's
        // erase-first rewrite needs 185 + 13 = 198 of 27 + 167 = 194: four
        // short.
        assert!(!avatar_allowed(BOARD_AVAILABLE, 0, None, AVATAR_64, &[TABLE_6]));
        // 48px as beta.38 stored it: 165 entries, 11 left, under the reserve.
        assert!(!avatar_allowed(BOARD_AVAILABLE, 0, None, LEGACY_48, &[TABLE_6]));
        assert!(!avatar_allowed(BOARD_AVAILABLE, 0, None, LEGACY_64, &[TABLE_6]));
        // Four more entries and 64px fits.
        assert!(avatar_allowed(BOARD_AVAILABLE + 4, 0, None, AVATAR_64, &[TABLE_6]));
    }

    #[test]
    fn where_the_table_could_go_in_place_the_picture_must_not_take_that() {
        // 300 available: the table rewrites in place (185 <= 300). A 64px
        // picture would leave 151, short of 185 + 13, so it is refused; a
        // 48px one leaves 209 and is not.
        assert!(!avatar_allowed(300, 0, None, AVATAR_64, &[TABLE_6]));
        assert!(avatar_allowed(300, 0, None, AVATAR_48, &[TABLE_6]));
        // Every hot blob is judged, not only the largest: a small one that
        // goes in place keeps doing so.
        // At 140 the table erases first either way; a 1500-byte blob (65
        // entries) goes in place without the picture and would not with it.
        assert!(avatar_allowed(140, 0, None, AVATAR_48, &[TABLE_6]));
        assert!(!avatar_allowed(140, 0, None, AVATAR_48, &[TABLE_6, 1500]));
        assert!(avatar_allowed(140, 0, None, AVATAR_48, &[TABLE_6, 300]));
        // No hot blob: fit and the reserve.
        assert!(avatar_allowed(blob_entries(AVATAR_48) + small_write_reserve(), 0, None, AVATAR_48, &[]));
        assert!(!avatar_allowed(blob_entries(AVATAR_48) + small_write_reserve() - 1, 0, None, AVATAR_48, &[]));
    }

    #[test]
    fn a_six_pairing_save_keeps_the_picture() {
        // With a 48px picture stored the board has 176 - 91 = 85 entries at
        // worst, 176 - 75 = 101 at best; dropping the picture brings back 75.
        // The table erases first with it (185 > 85) and without it
        // (185 > 160 or 176): the drop changes nothing, so it is not made.
        for available in [85, 101] {
            assert_eq!(replace_outcome(Fallback::EraseFirst, available, Some(TABLE_6), TABLE_6), Outcome::AfterErase);
            assert!(!evict_for_replace(Fallback::EraseFirst, available, 75, Some(TABLE_6), TABLE_6));
            // In place only (a legacy credential still to clear): refused
            // with the picture or without.
            assert!(!evict_for_replace(Fallback::Never, available, 75, Some(TABLE_6), TABLE_6));
        }
    }

    #[test]
    fn the_seventh_pairing_is_refused_with_or_without_a_picture() {
        // A seventh pairing grows the table to about 6160 bytes: 213 entries
        // for the new copy alone, beyond 176 before anything else is asked.
        assert!(!growth_allowed(BOARD_AVAILABLE, Some(TABLE_6), TABLE_7, TABLE_6));
        // With a 48px picture stored, dropping it brings back 75 entries, to
        // 160 or 176: still short, so the picture stays.
        for available in [85, 101] {
            assert!(!evict_for_growth(available, 75, Some(TABLE_6), TABLE_7, TABLE_6));
            assert!(!growth_allowed_with_reclaim(available, 75, Some(TABLE_6), TABLE_7, TABLE_6));
        }
        // The growth gate wants 213 for the copy and 213 + 13 after it, less
        // the 167 the old copy frees: 272 entries available.
        let least = (0..1000).find(|&a| growth_allowed(a, Some(TABLE_6), TABLE_7, TABLE_6)).unwrap();
        assert_eq!(least, 213 + 213 + 13 - 167);
    }

    #[test]
    fn the_pictures_go_only_when_that_changes_how_a_write_ends() {
        // A first write with no room fits once they go.
        assert_eq!(replace_outcome(Fallback::EraseFirst, 20, None, 877), Outcome::NoRoom);
        assert!(evict_for_replace(Fallback::EraseFirst, 20, 300, None, 877));
        assert!(!evict_for_replace(Fallback::EraseFirst, 20, 10, None, 877));
        // Erase-first becomes in place.
        assert!(evict_for_replace(Fallback::EraseFirst, 100, 90, Some(TABLE_6), TABLE_6));
        // Refused in place becomes in place.
        assert!(evict_for_replace(Fallback::Never, 100, 90, Some(TABLE_6), TABLE_6));
        // An erase-first rewrite that would lose the key lands instead.
        assert_eq!(replace_outcome(Fallback::EraseFirst, 10, Some(TABLE_6), TABLE_7), Outcome::Lost);
        assert!(evict_for_replace(Fallback::EraseFirst, 10, 40, Some(TABLE_6), TABLE_7));
        // Nothing to drop, or already in place: no.
        assert!(!evict_for_replace(Fallback::EraseFirst, 20, 0, None, 877));
        assert!(!evict_for_replace(Fallback::EraseFirst, 400, 90, Some(TABLE_6), TABLE_6));
        // A growth: only when it then passes.
        let least = (0..1000).find(|&a| growth_allowed(a, Some(1000), 1150, 2000)).unwrap();
        assert!(evict_for_growth(least - 10, 10, Some(1000), 1150, 2000));
        assert!(!evict_for_growth(least - 10, 9, Some(1000), 1150, 2000));
        assert!(!evict_for_growth(least, 10, Some(1000), 1150, 2000), "already passes");
        assert!(growth_allowed_with_reclaim(least - 10, 10, Some(1000), 1150, 2000));
    }

    #[test]
    fn an_accepted_picture_is_not_dropped_by_a_same_size_rewrite() {
        // Whatever the board, a picture `avatar_allowed` lets in leaves a
        // board where rewriting any hot blob at its size does not call for
        // the drop. A rewrite that shrinks it may (a revocation, below). The board after the write has between `blob_entries` and
        // `min_blob_entries` fewer entries; the drop counts the latter.
        for available in (0..500).step_by(3) {
            for hot in [0, 300, 1500, 3000, TABLE_6, TABLE_7, 8000] {
                for new in [AVATAR_48, AVATAR_64, LEGACY_48] {
                    if !avatar_allowed(available, 0, None, new, &[hot]) {
                        continue;
                    }
                    let min = crate::nvs_room::min_blob_entries(new);
                    for after in (available - blob_entries(new))..=(available - min) {
                        for fallback in [Fallback::EraseFirst, Fallback::Never] {
                            assert!(
                                !evict_for_replace(fallback, after, min, Some(hot), hot),
                                "available {available}, hot {hot}, picture {new}, after {after}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_picture_fits_beside_a_table_that_cannot_go_in_place() {
        // The 48px acceptance at 176 rests on the table being too large to
        // rewrite in place even with no picture: 4,993 bytes or more. The
        // board's real `connslots_0` length is not known here; the model's
        // 5,280 is 288 bytes over.
        assert_eq!(blob_entries(4992), BOARD_AVAILABLE);
        assert!(!avatar_allowed(BOARD_AVAILABLE, 0, None, AVATAR_48, &[4992]));
        assert!(avatar_allowed(BOARD_AVAILABLE, 0, None, AVATAR_48, &[4993]));
        // Hold the rest of the board fixed instead (343 entries besides the
        // modelled table) and let the table's length change, as revoking
        // pairings does: a 48px picture is refused from 3,489 to 5,120
        // bytes (about four to five pairings), where the table goes in place
        // only without it, and again from 7,009, where its erased rewrite no
        // longer fits beside the picture. 64px fits only up to 2,560 bytes
        // and at 5,121 to 5,152.
        let base = BOARD_AVAILABLE + stored_entries_min(TABLE_6);
        let accepted = |picture: usize, table: usize| {
            avatar_allowed(base - stored_entries_min(table), 0, None, picture, &[table])
        };
        let edges = |picture: usize| {
            let mut edges = Vec::new();
            let mut last = true;
            for table in 1..9000 {
                let now = accepted(picture, table);
                if now != last {
                    edges.push(table);
                    last = now;
                }
            }
            edges
        };
        assert_eq!(edges(AVATAR_48), [3489, 5121, 7009]);
        assert_eq!(edges(AVATAR_64), [2561, 5121, 5153]);
    }

    #[test]
    fn the_avatar_keys_and_their_room() {
        let keys: Vec<String> = avatar_keys().collect();
        assert_eq!(keys, ["imav0", "imav1", "imav2", "imav3", "imav4", "imav5", "imav6", "imav7"]);
        assert!(keys.iter().all(|k| fallback_for(k) == Fallback::EraseFirst));
        // 40 bytes: 2 data + 1 chunk header + 1 index; 5000 bytes: 157 + 2 + 1.
        let stored = |key: &str| match key {
            "imav0" => Some(40),
            "imav7" => Some(5000),
            _ => None,
        };
        assert_eq!(avatar_reclaim(stored), (2 + 1 + 1) + (157 + 2 + 1));
        assert_eq!(avatar_reclaim(|_| None), 0);
        let mut removed = Vec::new();
        let gone = evict_avatars(|key| {
            removed.push(String::from(key));
            stored(key).is_some()
        });
        assert_eq!(gone, 2);
        assert_eq!(removed.len(), 8, "every slot's key is tried");
    }

    /// Every firmware blob write goes through `nvs::ReplaceBlob`. esp-idf-svc's
    /// `set_blob` and `set_str` erase the key before writing, and
    /// `EspKeyValueStorage::set_raw` removes it first; the raw ESP-IDF calls
    /// belong to `nvs.rs` alone, where the budget is checked first. Both call
    /// forms are caught: `nvs.set_blob(..)` and `EspNvs::set_blob(&nvs, ..)`.
    /// Comments are skipped, so the reasons can still be written down.
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
        // The allocation journal writes fixed-width records through its own raw
        // handle, never erasing first, but outside the entry budget. That is
        // tolerable only while it is dormant (no runtime caller), and it opens
        // its namespace on the default `nvs` partition, which the signer's keys
        // share. The exemption lapses the moment the writer stops declaring
        // itself dormant, or the moment any other file reaches into the writer
        // module (a `writer::` path, or a `use` of it), whatever its header
        // says: put its writes under the budget before waking it.
        let journal = |path: &Path| {
            path.ends_with("allocation_journal_writer.rs") || path.ends_with("allocation_journal_write_nvs.rs")
        };
        let header = std::fs::read_to_string(src.join("allocation_journal_writer.rs"))
            .is_ok_and(|t| t.starts_with("//! Dormant, private durable controller."));
        let mut wakers = Vec::new();
        for path in files.iter().filter(|p| !journal(p)) {
            let text = std::fs::read_to_string(path).unwrap();
            for (n, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if names_writer_module(code) {
                    wakers.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                }
            }
        }
        let dormant = header && wakers.is_empty();
        let mut hits = Vec::new();
        for path in &files {
            if dormant && path.ends_with("allocation_journal_write_nvs.rs") {
                continue;
            }
            let text = std::fs::read_to_string(path).unwrap();
            let is_helper = path.ends_with("nvs.rs") && path.parent() == Some(src.as_path());
            for (n, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                let mut banned = vec![
                    ".set_blob(", ".set_str(", ".set_raw(", "::set_blob(", "::set_str(", "::set_raw(",
                ];
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
        assert!(
            hits.is_empty(),
            "blob writes outside nvs::ReplaceBlob:\n{}\nfiles reaching into the dormant journal writer:\n{}",
            hits.join("\n"),
            wakers.join("\n")
        );
    }

    /// Whether `code` names the allocation journal's `writer` module as a
    /// path segment (`writer::x`, `super::writer`, `use writer`), as opposed
    /// to declaring it (`mod writer;`) or an unrelated `writer` word
    /// (`a.writer()`, `to_writer(`, `writer_seed`).
    fn names_writer_module(code: &str) -> bool {
        let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
        code.match_indices("writer").any(|(at, _)| {
            let before = &code[..at];
            let after = &code[at + "writer".len()..];
            if before.chars().next_back().is_some_and(word) || after.chars().next().is_some_and(word) {
                return false;
            }
            after.starts_with("::") || before.ends_with("::") || before.trim_end().ends_with("use")
        })
    }

    #[test]
    fn the_journal_writer_scan_tells_a_path_from_a_declaration() {
        assert!(names_writer_module("    writer::Controller::open(handle)"));
        assert!(names_writer_module("use super::writer;"));
        assert!(names_writer_module("pub use writer as journal_writer;"));
        assert!(names_writer_module("let _ = self::writer::reset();"));
        assert!(!names_writer_module("mod writer;"));
        assert!(!names_writer_module("if a.writer() == a.witness() {"));
        assert!(!names_writer_module("serde_json::to_writer(&mut bytes, value)"));
        assert!(!names_writer_module("let writer_seed = key(self.root, &[]);"));
    }
}
