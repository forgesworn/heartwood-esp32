//! How many NVS entries a blob write needs, and whether the partition has
//! them, before anything is shown to the owner.
//!
//! The arithmetic follows ESP-IDF v5.3.2's `nvs_flash` (the version the
//! firmware builds against, `firmware/.embuild/espressif/esp-idf/v5.3.2`):
//!
//! - A page holds [`PAGE_ENTRIES`] entries of [`ENTRY_SIZE`] bytes
//!   (`nvs_page.hpp`: `ENTRY_COUNT = 126`), and one chunk of a blob holds at
//!   most [`CHUNK_MAX_SIZE`] bytes (`CHUNK_MAX_SIZE = ENTRY_SIZE *
//!   (ENTRY_COUNT - 1)`, 4000 bytes: a page less the chunk's own header).
//! - `Storage::writeMultiPageBlob` (`nvs_storage.cpp`) splits a blob into
//!   chunks, one per page. Each chunk is a `BLOB_DATA` item: one header entry
//!   plus one entry per 32 bytes of data (`Page::getVarDataTailroom` skips
//!   one entry for that header). Every chunk but the last fills its page's
//!   tailroom, a whole number of entries, so the data entries total
//!   `ceil(len / 32)`. One `BLOB_IDX` entry closes the blob.
//! - The chunk count depends on where the free entries are. On fresh pages a
//!   blob takes `ceil(len / 4000)` chunks, plus one when the first goes into
//!   the tail of the page being written. On a nearly full partition the free
//!   entries are scattered: once the free-page list is down to the reserved
//!   page, each new page is a garbage-collected victim whose tailroom is far
//!   under 4000 bytes, so a blob can take a chunk on every page it touches.
//!   The estimate assumes the worse of the two: `max(ceil(len / 4000) + 1,
//!   min(pages, ceil(len / 32)))` chunk headers, where `pages` is the
//!   partition's page count (a chunk holds at least one data entry, and in
//!   practice one write puts at most one chunk on a page). That is a strong
//!   heuristic, not a ceiling: a garbage collection inside the write can pick
//!   as its victim a full page holding an earlier chunk of the same write and
//!   continue on the page it copied into. The true ceiling is one header per
//!   data entry; the case is very unlikely and is not charged.
//! - A first chunk that does not fit a tailroom under `CHUNK_MAX_SIZE / 10`
//!   (400 bytes, 13 entries) skips that page, and those entries stay empty
//!   but unusable until garbage collection. The skip happens only when the
//!   data does not fit the tailroom, so it strands at most `ceil(len / 32)`
//!   entries and at most [`FIRST_CHUNK_SKIP_SLACK`]: every blob write adds
//!   [`first_chunk_skip_slack`] for it. Those entries still count as free in
//!   the stats until a garbage collection reclaims them, so the slack is a
//!   buffer for that delay rather than an exact cost, and a skip can repeat
//!   on later pages before the "not improving" guard ends the write.
//! - `Storage::writeItem` writes the new blob under the other chunk version
//!   before it erases the old one (`eraseMultiPageBlob` after
//!   `writeMultiPageBlob`), so the old blob's entries are still counted as
//!   used while the new one is written.
//! - `PageManager::fillStats` (`nvs_pagemanager.cpp`) counts a page's erased
//!   and empty entries alike as free, and reports `available_entries` as
//!   `free_entries - ENTRY_COUNT`: one page is always kept free so garbage
//!   collection (`PageManager::requestNewPage`) has somewhere to copy a
//!   page's live items. That page is never available to a write.
//!
//! The estimate errs high: a rare refusal on a nearly full board is the
//! accepted cost, a failed write after the owner's hold is the bug. It is
//! still not exact (`writeMultiPageBlob`'s "not improving" guard can refuse
//! a write that would fit in total). The write and its read-back stay the
//! authority; this check only makes a failed write after the hold rare.

/// Bytes per NVS entry (`nvs_page.hpp`: `ENTRY_SIZE`).
pub const ENTRY_SIZE: usize = 32;

/// Entries per NVS page (`nvs_page.hpp`: `ENTRY_COUNT`).
pub const PAGE_ENTRIES: usize = 126;

/// The most data one blob chunk holds (`nvs_page.hpp`: `CHUNK_MAX_SIZE`).
pub const CHUNK_MAX_SIZE: usize = ENTRY_SIZE * (PAGE_ENTRIES - 1);

/// The most entries a write can lose to `writeMultiPageBlob`'s first-chunk
/// rule: a tailroom under `CHUNK_MAX_SIZE / 10` (400 bytes) is skipped, which
/// leaves up to 13 entries of that page empty.
pub const FIRST_CHUNK_SKIP_SLACK: usize = (CHUNK_MAX_SIZE / 10).div_ceil(ENTRY_SIZE);

/// Entries one write of `len` bytes may lose to the first-chunk rule. The
/// rule skips a page only when the data does not fit its tailroom, so it
/// strands at most `ceil(len / 32)` entries, and at most
/// [`FIRST_CHUNK_SKIP_SLACK`]. A blob of one data entry strands at most the
/// page's last entry, which the extra chunk header [`blob_entries`] charges
/// it already absorbs (4 against a real 3): 0 here. Keep the two in step: if
/// `blob_entries` stops over-charging, return 1 for those. An empty blob is
/// not over-charged and may strand 1.
pub fn first_chunk_skip_slack(len: usize) -> usize {
    match len.div_ceil(ENTRY_SIZE) {
        0 => 1,
        1 => 0,
        data => data.min(FIRST_CHUNK_SKIP_SLACK),
    }
}

/// Entries a new blob of `len` bytes takes on a partition of `pages` pages:
/// its data entries, a chunk header per chunk (the worse of the fresh-page
/// layout and one chunk on every page the write could touch; see the module
/// doc), and the blob index.
pub fn blob_entries(len: usize, pages: usize) -> usize {
    let data = len.div_ceil(ENTRY_SIZE);
    let chunk_headers = (len.div_ceil(CHUNK_MAX_SIZE) + 1).max(pages.min(data));
    data + chunk_headers + 1
}

/// Entries one blob write may need at its peak: [`blob_entries`] plus what
/// a skipped first page may strand ([`first_chunk_skip_slack`]).
pub fn blob_write_entries(len: usize, pages: usize) -> usize {
    blob_entries(len, pages) + first_chunk_skip_slack(len)
}

/// Entries a REPLACE of a blob with `len` bytes is charged before the card:
/// the stricter of [`blob_write_entries`] and the bound
/// `nvs::ReplaceBlob` plans the write against
/// ([`crate::nvs_budget::blob_entries`]). The two model the same write in
/// different ways and each is the higher somewhere (the budget for small
/// blobs, and by 2 entries for a 4,001 to 8,000 byte blob on a 4-page
/// partition), so a check against this one cannot pass where the write
/// would find no room for a second copy and erase first.
pub fn replace_peak(len: usize, pages: usize) -> usize {
    blob_write_entries(len, pages).max(crate::nvs_budget::blob_entries(len))
}

/// The fewest entries a stored blob of `len` bytes can hold: its data
/// entries, one chunk header per 4000 bytes and the index. What erasing it
/// (or evicting it) can be counted on to free; a blob written across more
/// pages frees more, which only makes the estimate safer.
pub fn min_blob_entries(len: usize) -> usize {
    len.div_ceil(ENTRY_SIZE) + len.div_ceil(CHUNK_MAX_SIZE) + 1
}

/// Entries a write may use: `free_entries` (as `nvs_get_stats` reports it)
/// less the page ESP-IDF keeps free for garbage collection, the
/// `available_entries` of `fillStats`.
pub fn available_entries(free_entries: usize) -> usize {
    free_entries.saturating_sub(PAGE_ENTRIES)
}

/// The partition's room as the firmware reads it before a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvsRoom {
    /// `nvs_stats_t::free_entries` for the default partition.
    pub free_entries: usize,
    /// `nvs_stats_t::total_entries` for the default partition: its page
    /// count times [`PAGE_ENTRIES`].
    pub total_entries: usize,
    /// Entries the writer would free itself before a second try (the cached
    /// avatars `persist_slots` drops when a slot write does not fit).
    pub reclaimable_entries: usize,
}

impl NvsRoom {
    /// The partition's page count, the most chunks one blob write can take.
    pub fn pages(&self) -> usize {
        self.total_entries / PAGE_ENTRIES
    }

    /// Whether `needed` entries can be written with no reclaim: only
    /// `free_entries`, less the reserved page.
    pub fn fits_without_reclaim(&self, needed: usize) -> bool {
        needed <= available_entries(self.free_entries)
    }

    /// Whether `needed` entries can be written while every existing blob,
    /// the one being replaced included, still holds its entries.
    pub fn fits(&self, needed: usize) -> bool {
        needed <= available_entries(self.free_entries.saturating_add(self.reclaimable_entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bench T-Display's partition: 756 entries, 6 pages.
    const BENCH_TOTAL: usize = 756;

    #[test]
    fn a_blob_takes_its_data_entries_its_chunk_headers_and_an_index() {
        assert_eq!(CHUNK_MAX_SIZE, 4000);
        assert_eq!(FIRST_CHUNK_SKIP_SLACK, 13, "400 bytes, rounded up to whole entries");
        // On a one-page partition the fresh-page layout is the worse case:
        // an empty blob is still a chunk and an index.
        assert_eq!(blob_entries(0, 1), 2);
        assert_eq!(blob_entries(1, 1), 1 + 2 + 1);
        assert_eq!(blob_entries(32, 1), 1 + 2 + 1);
        assert_eq!(blob_entries(33, 1), 2 + 2 + 1);
        assert_eq!(blob_entries(4000, 1), 125 + 2 + 1);
        assert_eq!(blob_entries(4001, 1), 126 + 3 + 1);
        assert_eq!(blob_entries(8000, 1), 250 + 3 + 1);
        // On the bench's 6 pages a blob of 6 or more data entries may take
        // a chunk header on every page.
        assert_eq!(blob_entries(1, 6), 1 + 2 + 1);
        assert_eq!(blob_entries(96, 6), 3 + 3 + 1);
        assert_eq!(blob_entries(2900, 6), 91 + 6 + 1);
        assert_eq!(blob_entries(8000, 6), 250 + 6 + 1);
        assert_eq!(blob_write_entries(2900, 6), 91 + 6 + 1 + 13);
        // A skip strands no more entries than the data would have taken.
        assert_eq!(first_chunk_skip_slack(0), 1);
        assert_eq!(first_chunk_skip_slack(1), 0);
        assert_eq!(first_chunk_skip_slack(32), 0);
        assert_eq!(first_chunk_skip_slack(33), 2);
        assert_eq!(first_chunk_skip_slack(158), 5);
        assert_eq!(first_chunk_skip_slack(416), 13);
        assert_eq!(first_chunk_skip_slack(417), 13);
        assert_eq!(first_chunk_skip_slack(5 * 1024), 13);
        assert_eq!(blob_write_entries(1, 6), 1 + 2 + 1);
        assert_eq!(blob_write_entries(200, 6), 7 + 6 + 1 + 7);
        // What a stored blob is counted on to free: no phantom chunk.
        assert_eq!(min_blob_entries(0), 1);
        assert_eq!(min_blob_entries(40), 2 + 1 + 1);
        assert_eq!(min_blob_entries(8000), 250 + 2 + 1);
        assert_eq!(min_blob_entries(8192), 256 + 3 + 1);
    }

    #[test]
    fn a_replace_is_charged_at_least_what_the_write_is_planned_against() {
        for pages in [1, 4, 6, 16] {
            for len in (0..=64 * 1024).step_by(7) {
                let peak = replace_peak(len, pages);
                assert!(peak >= blob_write_entries(len, pages), "{len} on {pages}");
                assert!(peak >= crate::nvs_budget::blob_entries(len), "{len} on {pages}");
            }
        }
        // A 16 KB partition (4 pages): this estimate alone was 2 short of
        // the plan for a 4,001 to 8,000 byte table.
        for len in [4001, 5120, 8000] {
            assert_eq!(blob_write_entries(len, 4) + 2, crate::nvs_budget::blob_entries(len));
            assert_eq!(replace_peak(len, 4), crate::nvs_budget::blob_entries(len));
        }
        // Where this estimate is the higher it stands: 2.9 KB on 6 pages.
        assert_eq!(replace_peak(2900, 6), 111);
        // The 1-byte count blob: 7, not 4.
        assert_eq!(replace_peak(1, 6), crate::nvs_budget::blob_entries(1));
        assert_eq!(replace_peak(1, 6), 7);
    }

    #[test]
    fn one_page_is_kept_back_for_garbage_collection() {
        assert_eq!(available_entries(756), 630);
        assert_eq!(available_entries(126), 0);
        assert_eq!(available_entries(100), 0);
        let room = NvsRoom { free_entries: 140, total_entries: BENCH_TOTAL, reclaimable_entries: 260 };
        assert_eq!(room.pages(), 6);
        assert!(room.fits_without_reclaim(14));
        assert!(!room.fits_without_reclaim(15));
        assert!(room.fits(274));
        assert!(!room.fits(275));
    }

    #[test]
    fn the_bench_partition_refuses_a_5_kb_table_until_slots_are_revoked() {
        // Orange T-Display, 2026-10-19: 756 entries in all, 129 free, a
        // 5-slot table over 5 KB. `persist_slots` failed after the hold.
        let tight = NvsRoom { free_entries: 129, total_entries: BENCH_TOTAL, reclaimable_entries: 0 };
        assert!(!tight.fits(blob_write_entries(5 * 1024, tight.pages())));
        // Not even a small table fits beside the reserved page: a plain
        // CONNSLOT_CREATE failed on the same board.
        assert!(!tight.fits(blob_write_entries(200, tight.pages())));
        // After three slots were revoked: 225 free (99 available), the same
        // bundle saved. Two of the five ~1 KB slots were left, about 2 KB:
        // 64 data + 6 headers + 1 index + 13 = 84.
        let freed = NvsRoom { free_entries: 225, total_entries: BENCH_TOTAL, reclaimable_entries: 0 };
        assert!(freed.fits(blob_write_entries(2048, freed.pages())));
        assert!(!freed.fits(blob_write_entries(5 * 1024, freed.pages())));
        // The edge there: 79 data entries + 6 + 1 + 13 = 99. A table over
        // 2528 bytes no longer fits at 225 free.
        assert!(freed.fits(blob_write_entries(2528, freed.pages())));
        assert!(!freed.fits(blob_write_entries(2529, freed.pages())));
        // Cached avatars the writer would drop count towards the room.
        let with_avatars = NvsRoom { free_entries: 129, total_entries: BENCH_TOTAL, reclaimable_entries: 200 };
        assert!(with_avatars.fits(blob_write_entries(5 * 1024, with_avatars.pages())));
    }

    #[test]
    fn a_fragmented_partition_is_charged_a_chunk_header_per_page() {
        // Review S3: a 6-page partition with 99 available entries spread over
        // five pages and a ~2.9 KB table. The fresh-page count (91 data +
        // 2 headers + 1 index = 94) fitted; the blob can span 5 pages (97)
        // and lose a skipped first page's tail besides. Now 91 + 6 + 1 + 13.
        let room = NvsRoom { free_entries: 99 + PAGE_ENTRIES, total_entries: BENCH_TOTAL, reclaimable_entries: 0 };
        assert_eq!(blob_write_entries(2900, room.pages()), 111);
        assert!(!room.fits(blob_write_entries(2900, room.pages())));
        // With comfortable room the same table still fits.
        let roomy = NvsRoom { free_entries: 400, total_entries: BENCH_TOTAL, reclaimable_entries: 0 };
        assert!(roomy.fits(blob_write_entries(2900, roomy.pages())));
    }
}
