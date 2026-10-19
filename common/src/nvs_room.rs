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
//!   `ceil(len / 32)`. The first chunk may go into the tail of the page
//!   being written, so a blob takes at most `ceil(len / 4000) + 1` chunks.
//!   One `BLOB_IDX` entry closes the blob.
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
//! The estimate is not exact: free entries scattered over many pages cost a
//! chunk header each, and `persist_slots` also drops cached avatars before a
//! second try. The write and its read-back stay the authority; this check
//! only makes a failed write after the owner's hold rare.

/// Bytes per NVS entry (`nvs_page.hpp`: `ENTRY_SIZE`).
pub const ENTRY_SIZE: usize = 32;

/// Entries per NVS page (`nvs_page.hpp`: `ENTRY_COUNT`).
pub const PAGE_ENTRIES: usize = 126;

/// The most data one blob chunk holds (`nvs_page.hpp`: `CHUNK_MAX_SIZE`).
pub const CHUNK_MAX_SIZE: usize = ENTRY_SIZE * (PAGE_ENTRIES - 1);

/// Entries a new blob of `len` bytes takes: its data entries, one chunk
/// header per chunk (the page-sized chunks plus a first chunk in the tail of
/// the current page), and the blob index.
pub fn blob_entries(len: usize) -> usize {
    let data = len.div_ceil(ENTRY_SIZE);
    let chunk_headers = len.div_ceil(CHUNK_MAX_SIZE) + 1;
    data + chunk_headers + 1
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
    /// Entries the writer would free itself before a second try (the cached
    /// avatars `persist_slots` drops when a slot write does not fit).
    pub reclaimable_entries: usize,
}

impl NvsRoom {
    /// Whether `needed` entries can be written while every existing blob,
    /// the one being replaced included, still holds its entries.
    pub fn fits(&self, needed: usize) -> bool {
        needed <= available_entries(self.free_entries.saturating_add(self.reclaimable_entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blob_takes_its_data_entries_its_chunk_headers_and_an_index() {
        assert_eq!(CHUNK_MAX_SIZE, 4000);
        // An empty blob is still a chunk and an index.
        assert_eq!(blob_entries(0), 2);
        assert_eq!(blob_entries(1), 1 + 2 + 1);
        assert_eq!(blob_entries(32), 1 + 2 + 1);
        assert_eq!(blob_entries(33), 2 + 2 + 1);
        assert_eq!(blob_entries(4000), 125 + 2 + 1);
        assert_eq!(blob_entries(4001), 126 + 3 + 1);
        assert_eq!(blob_entries(8000), 250 + 3 + 1);
    }

    #[test]
    fn one_page_is_kept_back_for_garbage_collection() {
        assert_eq!(available_entries(756), 630);
        assert_eq!(available_entries(126), 0);
        assert_eq!(available_entries(100), 0);
    }

    #[test]
    fn the_bench_partition_refuses_a_5_kb_table_until_slots_are_revoked() {
        // Orange T-Display, 2026-10-19: 756 entries in all, 129 free, a
        // 5-slot table over 5 KB. `persist_slots` failed after the hold.
        let tight = NvsRoom { free_entries: 129, reclaimable_entries: 0 };
        assert!(!tight.fits(blob_entries(5 * 1024)));
        // Not even a small table fits beside the reserved page: a plain
        // CONNSLOT_CREATE failed on the same board.
        assert!(!tight.fits(blob_entries(200)));
        // After three slots were revoked: 225 free, the same bundle saved.
        let freed = NvsRoom { free_entries: 225, reclaimable_entries: 0 };
        assert!(freed.fits(blob_entries(2560)));
        assert!(!freed.fits(blob_entries(5 * 1024)));
        // Exactly at the edge.
        let edge = NvsRoom { free_entries: PAGE_ENTRIES + blob_entries(2560), reclaimable_entries: 0 };
        assert!(edge.fits(blob_entries(2560)));
        assert!(!edge.fits(blob_entries(2560) + 1));
        // Cached avatars the writer would drop count towards the room.
        let with_avatars = NvsRoom { free_entries: 129, reclaimable_entries: 200 };
        assert!(with_avatars.fits(blob_entries(5 * 1024)));
    }
}
