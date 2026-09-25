//! Zero what NVS has deleted but not yet erased.
//!
//! ESP-IDF NVS (v5.3.2, the version the firmware builds against) deletes or
//! replaces a value by flipping two state bits per 32-byte entry in the page's
//! state bitmap (`Page::eraseEntryAndSpan`, `alterEntryState`,
//! `alterEntryRangeState`: `components/nvs_flash/src/nvs_page.cpp:371-438`,
//! `:788-834`). The entry's own bytes stay on flash until garbage collection
//! erases the whole sector, which happens only when free pages run low. So a
//! flash dump can hold a plaintext seed written before sealing, a revoked
//! phone's record, a replaced wrapper.
//!
//! This module finds, in a raw image of the NVS partition, the entries whose
//! bitmap state is ERASED and whose bytes are not already zero, and
//! [`scrub`] programs each of them to zero in place. NOR flash programming
//! only clears bits, so this needs no sector erase; NVS itself reprograms
//! already-programmed words the same way (the bitmap word,
//! `nvs_page.cpp:788-804`, and the page state word, `:836-846`).
//!
//! What it touches, and why NVS cannot notice:
//!
//! - Only the 32 data bytes of ERASED entries, on pages whose header is
//!   ACTIVE or FULL, whose header CRC matches and whose format version is
//!   `0xfe`. Never a page header, never the bitmap, never an EMPTY, WRITTEN or
//!   ILLEGAL entry. NVS keeps no copy of entry data in RAM, only the bitmap,
//!   hash list and counters, and none of those change.
//! - NVS never reads an ERASED entry's data: load skips them on ACTIVE pages
//!   (`nvs_page.cpp:624-627`) and reads only WRITTEN ones on FULL and
//!   FREEING pages (`:712-719`); lookups skip anything not WRITTEN (`:898-906`);
//!   garbage collection copies only WRITTEN entries (`:481-490`).
//! - One load step reads entries by position rather than by state: on an
//!   ACTIVE page, starting at the first EMPTY entry, it marks each following
//!   entry ERASED while that entry's first word is not `0xffffffff` (a
//!   half-written entry, `:559-608`). Zeroing an ERASED entry in that run
//!   whose first word was `0xffffffff` would lengthen it. So on an ACTIVE page
//!   an ERASED entry after the first EMPTY one is left alone (counted in
//!   [`ScrubReport::left`]). A normal page has none: NVS writes in order.
//! - An ERASED entry inside the span of a live (WRITTEN, header-consistent)
//!   variable-length item is left alone too. Load erases such an item because
//!   its span is not all WRITTEN (`:665-683`, `:744-757`), so its data is
//!   never read either way; leaving it costs nothing and needs no argument.
//!
//! A page this module cannot fully parse (FREEING, CORRUPT, an unknown state
//! word, a bad header CRC, another format version, an uninitialised header
//! over non-blank bytes) is skipped whole and reported, never guessed at.
//!
//! Power cuts: every write programs zeros into one entry NVS already ignores.
//! A cut at any point, including mid-program, leaves NVS reading exactly what
//! it read before; the next pass finishes the job. Already-zero entries are
//! skipped, so a pass over a clean partition writes nothing.
//!
//! Pure and host-tested; the firmware supplies the flash reads and writes
//! (`firmware/src/nvs_scrub.rs`).

use alloc::vec::Vec;

/// One NVS page is one flash sector (`Page::SEC_SIZE`).
pub const PAGE_SIZE: usize = 4096;
/// Bytes per entry (`Page::ENTRY_SIZE`).
pub const ENTRY_SIZE: usize = 32;
/// Entries per page (`Page::ENTRY_COUNT`).
pub const ENTRY_COUNT: usize = 126;
/// The state bitmap: two bits per entry after the 32-byte header
/// (`Page::ENTRY_TABLE_OFFSET`).
pub const BITMAP_OFFSET: usize = 32;
/// The first entry (`Page::ENTRY_DATA_OFFSET`).
pub const DATA_OFFSET: usize = 64;
/// The page format this firmware's NVS writes (`Page::NVS_VERSION`).
pub const NVS_VERSION: u8 = 0xfe;

/// Page state words (`Page::PageState`, `nvs_page.hpp:52-72`).
pub const PAGE_UNINITIALIZED: u32 = 0xffff_ffff;
pub const PAGE_ACTIVE: u32 = 0xffff_fffe;
pub const PAGE_FULL: u32 = 0xffff_fffc;
pub const PAGE_FREEING: u32 = 0xffff_fff8;
pub const PAGE_CORRUPT: u32 = 0xffff_fff0;

/// NVS item types (`nvs_handle.hpp:27-41`, `nvs.h:103-113`).
const TYPE_SZ: u8 = 0x21;
const TYPE_BLOB: u8 = 0x41;
const TYPE_BLOB_DATA: u8 = 0x42;
const TYPE_BLOB_IDX: u8 = 0x48;
const PRIMITIVE_TYPES: [u8; 8] = [0x01, 0x11, 0x02, 0x12, 0x04, 0x14, 0x08, 0x18];
const CHUNK_ANY: u8 = 0xff;

/// An entry's two state bits (`Page::EntryState`, `nvs_page.hpp:169-175`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryState {
    /// `0b11`: never written since the sector was erased.
    Empty,
    /// `0b10`: holds live data.
    Written,
    /// `0b00`: deleted; the bytes stay until the sector is erased.
    Erased,
    /// `0b01`: only possible if the flash is inconsistent.
    Illegal,
}

/// Why a page was skipped whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// The page could not be read, or was not a full sector.
    Unreadable,
    /// Header says uninitialised, but the page is not all `0xff`. NVS loads
    /// such a page as CORRUPT (`nvs_page.cpp:41-65`).
    NotBlank,
    /// Header CRC does not match; NVS loads it as CORRUPT (`:66-67`).
    BadHeaderCrc,
    /// Mid garbage collection. NVS finishes or restarts the copy at load
    /// (`nvs_pagemanager.cpp:92-125`), so none should exist once it runs.
    Freeing,
    /// Marked corrupt; NVS keeps it until it needs a free page.
    Corrupt,
    /// A state word NVS does not define; NVS treats it as CORRUPT (`:88-90`).
    UnknownState,
    /// A format version other than the one this firmware writes.
    OtherVersion,
    /// The page header changed between planning and writing (the sector was
    /// collected, or its state moved on), so the rest of it was left for the
    /// next pass. Counted in `pages_skipped` like the others.
    Changed,
}

/// What to do with one page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PageKind {
    /// Erased sector, never initialised: nothing on it.
    Blank,
    /// ACTIVE or FULL and fully parsed.
    Scrub,
    /// Left whole; see the reason.
    Skip(SkipReason),
}

/// The decision for one page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PagePlan {
    pub kind: PageKind,
    /// Entries to program to zero: ERASED, safe to touch, not already zero.
    /// Ascending.
    pub zero: Vec<u8>,
    /// ERASED entries already all zero.
    pub already_clean: u32,
    /// ERASED or ILLEGAL entries deliberately left (see the module docs).
    pub left: u32,
}

impl PagePlan {
    fn empty(kind: PageKind) -> Self {
        Self { kind, zero: Vec::new(), already_clean: 0, left: 0 }
    }
}

/// What a pass did. `complete()` means every ERASED entry on the partition
/// is now zero, as far as the pass could see.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScrubReport {
    /// Entries programmed to zero and read back as zero.
    pub zeroed: u32,
    /// ERASED entries that were already zero (no write).
    pub already_clean: u32,
    /// ERASED or ILLEGAL entries deliberately left on parsed pages.
    pub left: u32,
    /// Pages skipped whole (unreadable, unparsed), plus pages whose header
    /// changed part-way through the pass.
    pub pages_skipped: u32,
    /// Writes that failed or did not read back as zero.
    pub failed: u32,
}

impl ScrubReport {
    /// Nothing skipped, nothing left, nothing failed.
    pub fn complete(&self) -> bool {
        self.pages_skipped == 0 && self.left == 0 && self.failed == 0
    }

    /// A pass that could not run at all over a partition of `pages` pages
    /// (no partition, no buffer): every page counts as skipped.
    pub fn not_run(pages: u32) -> Self {
        Self { pages_skipped: pages.max(1), ..Self::default() }
    }

    /// The owner-facing summary on the wire: entries zeroed, pages skipped,
    /// and whether the pass was complete.
    #[cfg(feature = "nip46")]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "zeroed": self.zeroed,
            "pages_skipped": self.pages_skipped,
            "complete": self.complete(),
        })
    }
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// `esp_rom_crc32_le(init, ..)`: zlib's CRC-32 continued from `init`, the
/// convention ESP-IDF's own parser checks against (`nvs_parser.py:102`,
/// `zlib.crc32(data, 0xFFFFFFFF)`). crc32fast's initial state has the same
/// meaning.
fn crc32_le(init: u32, parts: &[&[u8]]) -> u32 {
    let mut hasher = crc32fast::Hasher::new_with_initial(init);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize()
}

/// The header CRC: over the sequence number, version and reserved bytes,
/// never the state word (`Page::Header::calculateCrc32`, `nvs_page.cpp:17-22`).
fn header_crc(page: &[u8]) -> u32 {
    crc32_le(0xffff_ffff, &[&page[4..28]])
}

/// The page state word.
pub fn page_state(page: &[u8]) -> u32 {
    read_u32(page, 0)
}

/// Entry `index`'s state from the bitmap: little-endian, two bits per entry
/// (`CompressedEnumTable<EntryState, 2, 126>`). `page` needs only the header
/// and bitmap (its first [`DATA_OFFSET`] bytes).
pub fn entry_state(page: &[u8], index: usize) -> EntryState {
    let byte = page[BITMAP_OFFSET + index / 4];
    match (byte >> ((index % 4) * 2)) & 0b11 {
        0b11 => EntryState::Empty,
        0b10 => EntryState::Written,
        0b00 => EntryState::Erased,
        _ => EntryState::Illegal,
    }
}

/// Offset of entry `index` within its page.
pub fn entry_offset(index: usize) -> usize {
    DATA_OFFSET + index * ENTRY_SIZE
}

fn entry(page: &[u8], index: usize) -> &[u8] {
    let at = entry_offset(index);
    &page[at..at + ENTRY_SIZE]
}

fn is_variable_length(datatype: u8) -> bool {
    matches!(datatype, TYPE_SZ | TYPE_BLOB | TYPE_BLOB_DATA)
}

/// The item header's span if it passes `Item::checkHeaderConsistency`
/// (`nvs_types.cpp:43-150`), which NVS applies before trusting any header.
fn consistent_span(e: &[u8], index: usize) -> Option<usize> {
    let crc = crc32_le(0xffff_ffff, &[&e[0..4], &e[8..32]]);
    if read_u32(e, 4) != crc {
        return None;
    }
    let (datatype, span, chunk) = (e[1], e[2] as usize, e[3]);
    if PRIMITIVE_TYPES.contains(&datatype) {
        return (span == 1).then_some(1);
    }
    match datatype {
        TYPE_BLOB_IDX => {
            let max = (u8::MAX as u32 / 2) * (ENTRY_COUNT as u32 - 1) * ENTRY_SIZE as u32;
            (span == 1 && chunk == CHUNK_ANY && read_u32(e, 24) <= max).then_some(1)
        }
        TYPE_SZ | TYPE_BLOB | TYPE_BLOB_DATA => {
            if datatype == TYPE_BLOB_DATA && chunk == CHUNK_ANY {
                return None;
            }
            let size = u16::from_le_bytes([e[24], e[25]]) as usize;
            if size > (ENTRY_COUNT - index - 1) * ENTRY_SIZE || span > ENTRY_COUNT - index {
                return None;
            }
            (span == size.div_ceil(ENTRY_SIZE) + 1).then_some(span)
        }
        _ => None,
    }
}

/// Entries inside the span of a WRITTEN, header-consistent variable-length
/// item, walking the page as NVS's load does (a consistent header's span is
/// skipped; anything else advances one entry).
fn inside_live_spans(page: &[u8]) -> [bool; ENTRY_COUNT] {
    let mut inside = [false; ENTRY_COUNT];
    let mut i = 0;
    while i < ENTRY_COUNT {
        if entry_state(page, i) == EntryState::Written {
            let e = entry(page, i);
            if let Some(span) = consistent_span(e, i) {
                if is_variable_length(e[1]) {
                    for flag in inside.iter_mut().take(i + span).skip(i + 1) {
                        *flag = true;
                    }
                }
                i += span;
                continue;
            }
        }
        i += 1;
    }
    inside
}

/// Decide what to zero on one page. `page` is the whole sector.
pub fn plan_page(page: &[u8]) -> PagePlan {
    if page.len() != PAGE_SIZE {
        return PagePlan::empty(PageKind::Skip(SkipReason::Unreadable));
    }
    let state = page_state(page);
    if state == PAGE_UNINITIALIZED {
        return if page.iter().all(|&b| b == 0xff) {
            PagePlan::empty(PageKind::Blank)
        } else {
            PagePlan::empty(PageKind::Skip(SkipReason::NotBlank))
        };
    }
    if read_u32(page, 28) != header_crc(page) {
        return PagePlan::empty(PageKind::Skip(SkipReason::BadHeaderCrc));
    }
    match state {
        PAGE_ACTIVE | PAGE_FULL => {}
        PAGE_FREEING => return PagePlan::empty(PageKind::Skip(SkipReason::Freeing)),
        PAGE_CORRUPT => return PagePlan::empty(PageKind::Skip(SkipReason::Corrupt)),
        _ => return PagePlan::empty(PageKind::Skip(SkipReason::UnknownState)),
    }
    if page[8] != NVS_VERSION {
        return PagePlan::empty(PageKind::Skip(SkipReason::OtherVersion));
    }

    // Only an ACTIVE page is scanned by position at load (module docs).
    let first_empty = if state == PAGE_ACTIVE {
        (0..ENTRY_COUNT).find(|&i| entry_state(page, i) == EntryState::Empty)
    } else {
        None
    };
    let inside = inside_live_spans(page);

    let mut plan = PagePlan::empty(PageKind::Scrub);
    for (i, &inside_live) in inside.iter().enumerate() {
        match entry_state(page, i) {
            EntryState::Erased => {
                if first_empty.is_some_and(|fe| i > fe) || inside_live {
                    plan.left += 1;
                } else if entry(page, i).iter().all(|&b| b == 0) {
                    plan.already_clean += 1;
                } else {
                    plan.zero.push(i as u8);
                }
            }
            EntryState::Illegal => plan.left += 1,
            EntryState::Empty | EntryState::Written => {}
        }
    }
    plan
}

/// Whether entry `index` may still be zeroed. Compares only the 32-byte page
/// header (state word, sequence number, version, CRC) with the one planned
/// against, plus the target entry's own two state bits; the rest of the
/// bitmap is not compared. `now` is a fresh read of the page's first
/// [`DATA_OFFSET`] bytes.
///
/// That suffices because ERASED (`0b00`) is terminal: state bits only ever
/// go from 1 to 0, so an ERASED entry stays ERASED until its sector is
/// erased, and NVS never reads an ERASED entry's data. The only way the
/// planned entry could come to hold live data is a sector erase and reuse,
/// which rewrites the header: the erase leaves it all `0xff`, and NVS then
/// initialises it with the next, strictly higher sequence number
/// (`PageManager::activatePage`, `nvs_pagemanager.cpp:198-215`, and
/// `Page::initialize`, `nvs_page.cpp:767-786`). A page that only moved from
/// ACTIVE to FULL or FREEING also fails the check, which merely leaves it
/// for the next pass. It is a backstop, not a lock: a writer between this
/// read and the write would not be seen, which is why nothing else may
/// write NVS during a pass (`firmware/src/nvs_scrub.rs`).
pub fn still_erased(planned: &[u8], now: &[u8], index: usize) -> bool {
    now.len() >= DATA_OFFSET
        && now[..BITMAP_OFFSET] == planned[..BITMAP_OFFSET]
        && entry_state(now, index) == EntryState::Erased
}

/// Raw access to the NVS partition, by offset from its start.
pub trait Flash {
    type Error;
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), Self::Error>;
    /// Program `data` at `offset`. NOR semantics: bits only go from 1 to 0.
    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), Self::Error>;
}

/// One pass over a partition of `size` bytes. `page` is a caller-owned
/// buffer of [`PAGE_SIZE`] bytes (so the firmware decides where it lives).
///
/// Per page: read it, plan it, then for each entry re-read the page header
/// and bitmap, program the entry to zero only if [`still_erased`] holds (the
/// header is unchanged and that entry is still ERASED), and read it back.
/// The first failed check stops that page for this pass.
pub fn scrub<F: Flash>(flash: &mut F, size: usize, page: &mut [u8]) -> ScrubReport {
    let mut report = ScrubReport::default();
    if page.len() != PAGE_SIZE {
        return ScrubReport::not_run((size / PAGE_SIZE) as u32);
    }
    let zero = [0u8; ENTRY_SIZE];
    for base in (0..size / PAGE_SIZE).map(|p| p * PAGE_SIZE) {
        if flash.read(base, page).is_err() {
            report.pages_skipped += 1;
            continue;
        }
        let plan = plan_page(page);
        report.already_clean += plan.already_clean;
        report.left += plan.left;
        if let PageKind::Skip(_) = plan.kind {
            report.pages_skipped += 1;
            continue;
        }
        for (done, &index) in plan.zero.iter().enumerate() {
            let index = index as usize;
            let mut head = [0u8; DATA_OFFSET];
            if flash.read(base, &mut head).is_err() || !still_erased(page, &head, index) {
                report.left += (plan.zero.len() - done) as u32;
                report.pages_skipped += 1;
                break;
            }
            let at = base + entry_offset(index);
            if flash.write(at, &zero).is_err() {
                report.failed += 1;
                continue;
            }
            let mut back = [0xffu8; ENTRY_SIZE];
            if flash.read(at, &mut back).is_ok() && back == zero {
                report.zeroed += 1;
            } else {
                report.failed += 1;
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // -----------------------------------------------------------------
    // A model of what ESP-IDF v5.3.2 reads at load. It follows
    // Page::load / mLoadEntryTable (nvs_page.cpp:24-94, :526-765) over a
    // byte image and returns everything load reads or decides: each page's
    // resulting in-RAM states, its next free entry, and every live item
    // with its header and data. If zeroing an entry changed any byte load
    // reads, this output would change.
    // -----------------------------------------------------------------

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct LivePage {
        page: usize,
        state: u32,
        states: Vec<EntryState>,
        next_free: Option<usize>,
        items: Vec<(usize, Vec<u8>, Vec<u8>)>,
    }

    fn set_model_state(states: &mut [EntryState], from: usize, span: usize) {
        for s in states.iter_mut().take((from + span).min(ENTRY_COUNT)).skip(from) {
            *s = EntryState::Erased;
        }
    }

    fn item_data(page: &[u8], index: usize) -> Vec<u8> {
        let e = entry(page, index);
        if !is_variable_length(e[1]) {
            return e[24..32].to_vec();
        }
        let size = u16::from_le_bytes([e[24], e[25]]) as usize;
        let from = entry_offset(index + 1);
        page[from..from + size].to_vec()
    }

    fn load_page(page_no: usize, page: &[u8]) -> Option<LivePage> {
        let state = page_state(page);
        if state == PAGE_UNINITIALIZED || read_u32(page, 28) != header_crc(page) {
            return None;
        }
        if !matches!(state, PAGE_ACTIVE | PAGE_FULL | PAGE_FREEING) {
            return None;
        }
        let mut states: Vec<EntryState> = (0..ENTRY_COUNT).map(|i| entry_state(page, i)).collect();
        let mut live: Vec<(usize, Vec<u8>, Vec<u8>)> = Vec::new();
        let mut next_free = None;
        if state == PAGE_ACTIVE {
            let mut nf = (0..ENTRY_COUNT).find(|&i| states[i] == EntryState::Empty).unwrap_or(usize::MAX);
            while nf < ENTRY_COUNT {
                if read_u32(entry(page, nf), 0) != 0xffff_ffff {
                    states[nf] = EntryState::Erased;
                    nf += 1;
                } else {
                    break;
                }
            }
            next_free = Some(nf);
            let end = nf.min(ENTRY_COUNT);
            let mut i = 0;
            while i < end {
                let mut span = 1;
                match states[i] {
                    EntryState::Erased => {
                        i += 1;
                        continue;
                    }
                    EntryState::Illegal => {
                        states[i] = EntryState::Erased;
                        i += 1;
                        continue;
                    }
                    _ => {}
                }
                let e = entry(page, i);
                let Some(s) = consistent_span(e, i) else {
                    states[i] = EntryState::Erased;
                    i += 1;
                    continue;
                };
                if is_variable_length(e[1]) {
                    span = s;
                    if (i..i + span).any(|j| states[j] != EntryState::Written) {
                        set_model_state(&mut states, i, span);
                        i += span;
                        continue;
                    }
                }
                live.push((i, e.to_vec(), item_data(page, i)));
                i += span;
            }
        } else {
            let mut i = 0;
            while i < ENTRY_COUNT {
                if states[i] != EntryState::Written {
                    i += 1;
                    continue;
                }
                let e = entry(page, i);
                let Some(span) = consistent_span(e, i) else {
                    states[i] = EntryState::Erased;
                    i += 1;
                    continue;
                };
                if is_variable_length(e[1]) && (i + 1..i + span).any(|j| states[j] != EntryState::Written) {
                    set_model_state(&mut states, i, span);
                } else {
                    live.push((i, e.to_vec(), item_data(page, i)));
                }
                i += span;
            }
        }
        Some(LivePage { page: page_no, state, states, next_free, items: live })
    }

    fn load(image: &[u8]) -> Vec<LivePage> {
        image
            .chunks(PAGE_SIZE)
            .enumerate()
            .filter_map(|(n, page)| load_page(n, page))
            .collect()
    }

    /// Live `(namespace index, key, value)` triples, for readable asserts.
    fn live_values(image: &[u8]) -> Vec<(u8, String, Vec<u8>)> {
        let mut out = Vec::new();
        for page in load(image) {
            for (_, header, data) in page.items {
                let key_len = header[8..24].iter().position(|&b| b == 0).unwrap_or(16);
                let key = String::from_utf8_lossy(&header[8..8 + key_len]).into_owned();
                out.push((header[0], key, data));
            }
        }
        out
    }

    // -----------------------------------------------------------------
    // A synthetic NVS writer: lays items out as Page::writeItem does
    // (nvs_page.cpp:150-248), erases as eraseEntryAndSpan does, and only
    // ever clears bits.
    // -----------------------------------------------------------------

    struct Image(Vec<u8>);

    fn program(dst: &mut [u8], src: &[u8]) {
        for (d, s) in dst.iter_mut().zip(src) {
            *d &= *s;
        }
    }

    impl Image {
        fn blank(pages: usize) -> Self {
            Image(vec![0xff; pages * PAGE_SIZE])
        }

        fn page(&self, p: usize) -> &[u8] {
            &self.0[p * PAGE_SIZE..(p + 1) * PAGE_SIZE]
        }

        fn init(&mut self, p: usize, seq: u32, version: u8) {
            let mut header = [0xffu8; 32];
            header[0..4].copy_from_slice(&PAGE_ACTIVE.to_le_bytes());
            header[4..8].copy_from_slice(&seq.to_le_bytes());
            header[8] = version;
            let crc = header_crc(&header);
            header[28..32].copy_from_slice(&crc.to_le_bytes());
            program(&mut self.0[p * PAGE_SIZE..p * PAGE_SIZE + 32], &header);
        }

        fn set_page_state(&mut self, p: usize, state: u32) {
            let at = p * PAGE_SIZE;
            self.0[at..at + 4].copy_from_slice(&state.to_le_bytes());
        }

        fn set_state(&mut self, p: usize, index: usize, state: EntryState) {
            let bits = match state {
                EntryState::Empty => 0b11,
                EntryState::Written => 0b10,
                EntryState::Erased => 0b00,
                EntryState::Illegal => 0b01,
            };
            let at = p * PAGE_SIZE + BITMAP_OFFSET + index / 4;
            let shift = (index % 4) * 2;
            let byte = (self.0[at] & !(0b11 << shift)) | (bits << shift);
            assert_eq!(byte & self.0[at], byte, "a state change may only clear bits");
            self.0[at] = byte;
        }

        fn header(ns: u8, datatype: u8, span: u8, key: &str, chunk: u8, data: [u8; 8]) -> [u8; 32] {
            let mut e = [0xffu8; 32];
            e[0] = ns;
            e[1] = datatype;
            e[2] = span;
            e[3] = chunk;
            e[8..24].fill(0xff);
            e[8..8 + key.len()].copy_from_slice(key.as_bytes());
            e[8 + key.len()] = 0;
            e[24..32].copy_from_slice(&data);
            let crc = crc32_le(0xffff_ffff, &[&e[0..4], &e[8..32]]);
            e[4..8].copy_from_slice(&crc.to_le_bytes());
            e
        }

        /// A one-entry integer item at `index`.
        fn put_u32(&mut self, p: usize, index: usize, ns: u8, key: &str, value: u32) {
            let mut data = [0xffu8; 8];
            data[..4].copy_from_slice(&value.to_le_bytes());
            let e = Self::header(ns, 0x04, 1, key, CHUNK_ANY, data);
            let at = p * PAGE_SIZE + entry_offset(index);
            program(&mut self.0[at..at + 32], &e);
            self.set_state(p, index, EntryState::Written);
        }

        /// A blob chunk (`BLOB_DATA`) at `index`; returns its span.
        fn put_blob(&mut self, p: usize, index: usize, ns: u8, key: &str, chunk: u8, value: &[u8]) -> usize {
            let span = value.len().div_ceil(32) + 1;
            let mut data = [0xffu8; 8];
            data[0..2].copy_from_slice(&(value.len() as u16).to_le_bytes());
            data[4..8].copy_from_slice(&crc32_le(0xffff_ffff, &[value]).to_le_bytes());
            let e = Self::header(ns, TYPE_BLOB_DATA, span as u8, key, chunk, data);
            let at = p * PAGE_SIZE + entry_offset(index);
            program(&mut self.0[at..at + 32], &e);
            let mut body = vec![0xffu8; (span - 1) * 32];
            body[..value.len()].copy_from_slice(value);
            program(&mut self.0[at + 32..at + 32 + body.len()], &body);
            for i in index..index + span {
                self.set_state(p, i, EntryState::Written);
            }
            span
        }

        fn erase(&mut self, p: usize, index: usize, span: usize) {
            for i in index..index + span {
                self.set_state(p, i, EntryState::Erased);
            }
        }
    }

    /// Distinct, never-zero test values per seed (xorshift32).
    fn bytes(seed: u8, len: usize) -> Vec<u8> {
        let mut x = (seed as u32).wrapping_mul(0x9e37_79b9) | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x as u8) | 1
            })
            .collect()
    }

    /// A dirty four-page partition: a FULL page and an ACTIVE page, each with
    /// written, erased and empty entries including multi-entry blobs, and a
    /// blank page (the one NVS keeps free).
    fn dirty_partition() -> Image {
        let mut img = Image::blank(4);
        // Page 0: FULL, old versions erased beside live ones.
        img.init(0, 7, NVS_VERSION);
        let mut i = 0;
        img.put_u32(0, i, 0, "heartwood", 1); // namespace entry
        i += 1;
        let s = img.put_blob(0, i, 1, "master_0_secret", 0, &bytes(3, 32));
        img.erase(0, i, s); // plaintext seed, deleted at sealing
        i += s;
        let s = img.put_blob(0, i, 1, "m0_seed_enc", 0, &bytes(9, 101));
        i += s;
        let s = img.put_blob(0, i, 1, "dk_ph", 0, &bytes(21, 300));
        img.erase(0, i, s); // a phone set before a revoke
        i += s;
        let s = img.put_blob(0, i, 1, "dk_ph", 0, &bytes(33, 200));
        i += s;
        img.put_u32(0, i, 1, "lk_boots", 4);
        img.erase(0, i, 1);
        i += 1;
        img.put_u32(0, i, 1, "lk_boots", 5);
        i += 1;
        let s = img.put_blob(0, i, 1, "net_config", 0, &bytes(50, 700));
        i += s;
        assert!(i < ENTRY_COUNT);
        img.set_page_state(0, PAGE_FULL);
        // Page 1: ACTIVE, erased and written entries then EMPTY tail.
        img.init(1, 8, NVS_VERSION);
        let mut i = 0;
        let s = img.put_blob(1, i, 1, "dk_sec", 0, &bytes(70, 90));
        img.erase(1, i, s);
        i += s;
        let s = img.put_blob(1, i, 1, "dk_sec", 0, &bytes(71, 90));
        i += s;
        img.put_u32(1, i, 1, "pin_fails", 0);
        img.erase(1, i, 1);
        i += 1;
        let s = img.put_blob(1, i, 2, "nk", 0, &bytes(90, 82));
        let _ = s;
        // Page 2: blank. Page 3: a second FULL page holding one big erased blob.
        img.init(3, 3, NVS_VERSION);
        let s = img.put_blob(3, 0, 2, "idx", 0, &bytes(120, 3000));
        img.erase(3, 0, s);
        img.set_page_state(3, PAGE_FULL);
        img
    }

    struct Ram<'a> {
        image: &'a mut [u8],
        writes: usize,
    }

    impl Flash for Ram<'_> {
        type Error = ();
        fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), ()> {
            buf.copy_from_slice(&self.image[offset..offset + buf.len()]);
            Ok(())
        }
        fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), ()> {
            self.writes += 1;
            program(&mut self.image[offset..offset + data.len()], data);
            Ok(())
        }
    }

    fn run(image: &mut [u8]) -> (ScrubReport, usize) {
        let size = image.len();
        let mut flash = Ram { image, writes: 0 };
        let mut page = vec![0u8; PAGE_SIZE];
        let report = scrub(&mut flash, size, &mut page);
        (report, flash.writes)
    }

    /// Every byte that differs between two images, as (offset, before, after).
    fn diff(a: &[u8], b: &[u8]) -> Vec<(usize, u8, u8)> {
        a.iter().zip(b).enumerate().filter(|(_, (x, y))| x != y).map(|(i, (x, y))| (i, *x, *y)).collect()
    }

    /// Byte ranges of every ERASED entry on the parsed pages of `image`.
    fn erased_ranges(image: &[u8]) -> Vec<core::ops::Range<usize>> {
        let mut out = Vec::new();
        for (p, page) in image.chunks(PAGE_SIZE).enumerate() {
            if plan_page(page).kind != PageKind::Scrub {
                continue;
            }
            for i in 0..ENTRY_COUNT {
                if entry_state(page, i) == EntryState::Erased {
                    let at = p * PAGE_SIZE + entry_offset(i);
                    out.push(at..at + ENTRY_SIZE);
                }
            }
        }
        out
    }

    // -----------------------------------------------------------------
    // Against ESP-IDF's own output
    // -----------------------------------------------------------------

    /// Generated by ESP-IDF v5.3.2's nvs_partition_gen.py from the CSV beside
    /// it (`nvs_partition_gen.py generate nvs-idf-v5.3.2-generated.csv <out>
    /// 0x4000`, the release NVS size; `.nvs` because the repo ignores
    /// `*.bin`). nvs_tool.py reads it as page 0 FULL, page 1 ACTIVE, pages 2
    /// and 3 empty, header CRCs OK.
    const IDF_IMAGE: &[u8] = include_bytes!("../tests/fixtures/nvs-idf-v5.3.2-generated.nvs");

    #[test]
    fn reads_the_layout_esp_idf_writes() {
        assert_eq!(IDF_IMAGE.len(), 4 * PAGE_SIZE);
        let kinds: Vec<_> = IDF_IMAGE.chunks(PAGE_SIZE).map(|p| plan_page(p).kind).collect();
        assert_eq!(kinds, [PageKind::Scrub, PageKind::Scrub, PageKind::Blank, PageKind::Blank]);
        assert_eq!(page_state(&IDF_IMAGE[..PAGE_SIZE]), PAGE_FULL);
        assert_eq!(page_state(&IDF_IMAGE[PAGE_SIZE..]), PAGE_ACTIVE);
        // Every written header passes the consistency check: our CRC and
        // header rules agree with the generator's.
        let loaded = load(IDF_IMAGE);
        for page in &loaded {
            for (i, s) in page.states.iter().enumerate() {
                assert_ne!(*s, EntryState::Erased, "page {} entry {i} dropped at load", page.page);
            }
        }
        let values = live_values(IDF_IMAGE);
        let find = |key: &str| values.iter().find(|(_, k, _)| k == key).map(|(_, _, v)| v.clone());
        assert_eq!(find("boots").unwrap()[..4], 305_419_896u32.to_le_bytes());
        assert_eq!(find("pin_fails").unwrap()[0], 3);
        assert_eq!(find("label").unwrap(), b"bench board\0");
        assert_eq!(find("cnt").unwrap()[..4], (-7i32).to_le_bytes());
        let m0: Vec<u8> = (0..32).collect();
        assert_eq!(find("m0_seed_enc").unwrap(), m0);
        // idx is 4500 bytes over two pages: two BLOB_DATA chunks and one
        // BLOB_IDX, all live.
        let idx_chunks: Vec<_> = values.iter().filter(|(_, k, _)| k == "idx").collect();
        assert_eq!(idx_chunks.len(), 3);
        let data_len: usize = idx_chunks.iter().map(|(_, _, v)| v.len()).filter(|&l| l > 8).sum();
        assert_eq!(data_len, 4500);
    }

    #[test]
    fn a_fresh_esp_idf_image_needs_nothing() {
        let mut image = IDF_IMAGE.to_vec();
        let (report, writes) = run(&mut image);
        assert_eq!(writes, 0);
        assert_eq!(report, ScrubReport::default());
        assert!(report.complete());
        assert_eq!(image, IDF_IMAGE);
    }

    #[test]
    fn zeroes_what_is_erased_in_an_esp_idf_image_and_nothing_else() {
        let mut image = IDF_IMAGE.to_vec();
        // Erase dk_sec and m0_seed_enc as eraseEntryAndSpan would: find each
        // live header and flip its whole span to ERASED.
        for key in ["dk_sec", "m0_seed_enc", "pin_fails"] {
            let page = &image[..PAGE_SIZE];
            let (index, span) = (0..ENTRY_COUNT)
                .find_map(|i| {
                    let e = entry(page, i);
                    let named = e[8..8 + key.len()] == *key.as_bytes() && e[8 + key.len()] == 0;
                    (entry_state(page, i) == EntryState::Written && named && e[1] != TYPE_BLOB_IDX)
                        .then(|| (i, consistent_span(e, i).unwrap()))
                })
                .unwrap();
            let mut img = Image(image);
            img.erase(0, index, span);
            image = img.0;
        }
        let before = image.clone();
        let live_before = load(&before);
        let (report, writes) = run(&mut image);
        // dk_sec: 101 bytes = 1 + 4 entries; m0_seed_enc: 1 + 1; pin_fails: 1.
        assert_eq!(report.zeroed, 8);
        assert_eq!(writes, 8);
        assert!(report.complete());
        let ranges = erased_ranges(&before);
        for (at, _, after) in diff(&before, &image) {
            assert_eq!(after, 0);
            assert!(ranges.iter().any(|r| r.contains(&at)), "byte {at} outside an erased entry");
        }
        for r in ranges {
            assert!(image[r].iter().all(|&b| b == 0));
        }
        assert_eq!(load(&image), live_before);
    }

    // -----------------------------------------------------------------
    // Synthetic pages
    // -----------------------------------------------------------------

    #[test]
    fn plans_exactly_the_erased_entries_of_a_mixed_page() {
        let img = dirty_partition();
        let plan = plan_page(img.page(1));
        assert_eq!(plan.kind, PageKind::Scrub);
        // dk_sec (90 bytes: 1 + 3 entries) at 0..4 erased, the live copy at
        // 4..8, pin_fails at 8 erased, nk at 9..13 live, EMPTY from 13.
        assert_eq!(plan.zero, [0, 1, 2, 3, 8]);
        assert_eq!((plan.already_clean, plan.left), (0, 0));
        let plan = plan_page(img.page(3));
        assert_eq!(plan.zero, (0..=94).collect::<Vec<u8>>(), "3000 bytes: 1 + 94 entries");
    }

    #[test]
    fn touches_no_header_bitmap_empty_or_written_byte() {
        let mut img = dirty_partition();
        let before = img.0.clone();
        let (report, _) = run(&mut img.0);
        assert!(report.complete(), "{report:?}");
        let ranges = erased_ranges(&before);
        let changed = diff(&before, &img.0);
        assert!(!changed.is_empty());
        for (at, _, after) in changed {
            assert_eq!(after, 0);
            assert!(ranges.iter().any(|r| r.contains(&at)), "byte {at} outside an erased entry");
        }
        for r in &ranges {
            assert!(img.0[r.clone()].iter().all(|&b| b == 0));
        }
        assert_eq!(load(&img.0), load(&before));
        // The residue is gone: no erased entry still holds a byte of the
        // deleted plaintext seed or the revoked phone set.
        for secret in [bytes(3, 32), bytes(21, 300)] {
            assert!(!img.0.windows(16).any(|w| w == &secret[..16]));
        }
    }

    #[test]
    fn skips_every_page_state_it_cannot_parse() {
        let dirty = |state: u32| {
            let mut img = Image::blank(1);
            img.init(0, 1, NVS_VERSION);
            let s = img.put_blob(0, 0, 1, "gone", 0, &bytes(5, 64));
            img.erase(0, 0, s);
            img.put_u32(0, s, 1, "kept", 9);
            img.set_page_state(0, state);
            img
        };
        assert_eq!(plan_page(dirty(PAGE_ACTIVE).page(0)).zero, [0, 1, 2]);
        assert_eq!(plan_page(dirty(PAGE_FULL).page(0)).zero, [0, 1, 2]);
        let cases = [
            (PAGE_FREEING, SkipReason::Freeing),
            (PAGE_CORRUPT, SkipReason::Corrupt),
            (0, SkipReason::UnknownState),
            (0xffff_fffd, SkipReason::UnknownState),
            (0x1234_5678, SkipReason::UnknownState),
        ];
        for (state, reason) in cases {
            let mut img = dirty(state);
            assert_eq!(plan_page(img.page(0)).kind, PageKind::Skip(reason), "{state:#x}");
            let before = img.0.clone();
            let (report, writes) = run(&mut img.0);
            assert_eq!((writes, report.pages_skipped), (0, 1));
            assert!(!report.complete());
            assert_eq!(img.0, before);
        }

        // A broken header CRC.
        let mut img = dirty(PAGE_ACTIVE);
        img.0[5] ^= 0x01;
        assert_eq!(plan_page(img.page(0)).kind, PageKind::Skip(SkipReason::BadHeaderCrc));
        // Another format version (0xff is the pre-multipage-blob format).
        let mut img = Image::blank(1);
        img.init(0, 1, 0xff);
        let s = img.put_blob(0, 0, 1, "gone", 0, &bytes(5, 64));
        img.erase(0, 0, s);
        assert_eq!(plan_page(img.page(0)).kind, PageKind::Skip(SkipReason::OtherVersion));
        // An uninitialised header: blank, or not blank underneath.
        let mut img = Image::blank(1);
        assert_eq!(plan_page(img.page(0)).kind, PageKind::Blank);
        img.0[PAGE_SIZE - 1] = 0x7f;
        assert_eq!(plan_page(img.page(0)).kind, PageKind::Skip(SkipReason::NotBlank));
        // A short read.
        assert_eq!(plan_page(&[0xff; 100]).kind, PageKind::Skip(SkipReason::Unreadable));
    }

    #[test]
    fn leaves_erased_entries_past_the_first_empty_one_on_an_active_page() {
        // Entry 0 written, 1 EMPTY, 2 ERASED with a first word of
        // 0xffffffff. Load's half-written scan starts at 1 and stops there
        // (its first word is 0xffffffff), so next_free is 1.
        let mut img = Image::blank(1);
        img.init(0, 1, NVS_VERSION);
        img.put_u32(0, 0, 1, "kept", 1);
        let at = entry_offset(2);
        program(&mut img.0[at + 4..at + 32], &[0x5a; 28]);
        img.set_state(0, 2, EntryState::Erased);
        let plan = plan_page(img.page(0));
        assert_eq!(plan.zero, Vec::<u8>::new());
        assert_eq!(plan.left, 1);
        let (report, writes) = run(&mut img.0);
        assert_eq!(writes, 0);
        assert!(!report.complete());

        // Why: zeroing it would not change what load does here (entry 1
        // still stops the scan), but put the EMPTY-with-data case in front
        // of it and it would. Entry 1 half-written (first word set, state
        // still EMPTY), entry 2 ERASED with a 0xffffffff first word: load
        // marks 1 erased, stops at 2, next_free = 2. Zeroed, entry 2's first
        // word would stop being 0xffffffff and next_free would become 3.
        let mut img = Image::blank(1);
        img.init(0, 1, NVS_VERSION);
        img.put_u32(0, 0, 1, "kept", 1);
        program(&mut img.0[entry_offset(1)..entry_offset(1) + 4], &[0x01, 0x04, 0x01, 0xff]);
        program(&mut img.0[at + 4..at + 32], &[0x5a; 28]);
        img.set_state(0, 2, EntryState::Erased);
        assert_eq!(load(&img.0)[0].next_free, Some(2));
        let mut zeroed = img.0.clone();
        zeroed[at..at + 32].fill(0);
        assert_eq!(load(&zeroed)[0].next_free, Some(3), "the rule is load-bearing");
        let before = img.0.clone();
        run(&mut img.0);
        assert_eq!(img.0, before);

        // A FULL page is never scanned by position, so there it is zeroed.
        img.set_page_state(0, PAGE_FULL);
        assert_eq!(plan_page(img.page(0)).zero, [2]);
    }

    #[test]
    fn leaves_erased_entries_inside_a_live_item_span() {
        // A torn erase: header still WRITTEN, the tail of its span ERASED.
        // Load drops the whole item (nvs_page.cpp:665-683); the scrub leaves
        // the tail for the pass after NVS has marked the whole span.
        let mut img = Image::blank(1);
        img.init(0, 1, NVS_VERSION);
        let span = img.put_blob(0, 0, 1, "torn", 0, &bytes(1, 96));
        img.set_state(0, 3, EntryState::Erased);
        img.set_page_state(0, PAGE_FULL);
        let plan = plan_page(img.page(0));
        assert_eq!(span, 4);
        assert_eq!((plan.zero.len(), plan.left), (0, 1));
    }

    #[test]
    fn counts_illegal_entries_as_left() {
        // Data programmed, then the bitmap caught at 0b01, which NVS never
        // writes; only an inconsistent flash shows it.
        let mut img = Image::blank(1);
        img.init(0, 1, NVS_VERSION);
        let e = Image::header(1, 0x04, 1, "odd", CHUNK_ANY, [1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        program(&mut img.0[entry_offset(0)..entry_offset(1)], &e);
        img.set_state(0, 0, EntryState::Illegal);
        img.set_page_state(0, PAGE_FULL);
        let plan = plan_page(img.page(0));
        assert_eq!((plan.zero.len(), plan.left), (0, 1));
    }

    #[test]
    fn a_second_pass_writes_nothing() {
        let mut img = dirty_partition();
        let (first, writes) = run(&mut img.0);
        assert!(writes > 0);
        assert_eq!(first.zeroed as usize, writes);
        let after_first = img.0.clone();
        let (second, writes) = run(&mut img.0);
        assert_eq!(writes, 0);
        assert_eq!(second.zeroed, 0);
        assert_eq!(second.already_clean, first.zeroed);
        assert!(second.complete());
        assert_eq!(img.0, after_first);
    }

    #[test]
    fn an_already_zero_erased_entry_costs_no_write() {
        let mut img = Image::blank(1);
        img.init(0, 1, NVS_VERSION);
        img.put_u32(0, 0, 1, "a", 1);
        img.put_u32(0, 1, 1, "b", 2);
        img.erase(0, 0, 2);
        let at = entry_offset(0);
        img.0[at..at + 32].fill(0);
        let plan = plan_page(img.page(0));
        assert_eq!((plan.zero.clone(), plan.already_clean), (vec![1], 1));
        let (report, writes) = run(&mut img.0);
        assert_eq!((report.zeroed, report.already_clean, writes), (1, 1, 1));
    }

    // -----------------------------------------------------------------
    // Power cuts
    // -----------------------------------------------------------------

    #[derive(Clone, Copy, Debug)]
    enum Cut {
        /// The cut write programs nothing.
        Nothing,
        /// The first half of its bytes land.
        Half,
        /// A scattered subset of its bits lands.
        Bits,
    }

    /// Flash that loses power on write number `after` (counting from 0):
    /// that write lands partly, and every access after it fails.
    struct CutFlash<'a> {
        image: &'a mut [u8],
        after: usize,
        cut: Cut,
        writes: usize,
        dead: bool,
    }

    impl Flash for CutFlash<'_> {
        type Error = ();
        fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), ()> {
            if self.dead {
                return Err(());
            }
            buf.copy_from_slice(&self.image[offset..offset + buf.len()]);
            Ok(())
        }
        fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), ()> {
            if self.dead {
                return Err(());
            }
            let dst = &mut self.image[offset..offset + data.len()];
            if self.writes == self.after {
                self.dead = true;
                match self.cut {
                    Cut::Nothing => {}
                    Cut::Half => program(&mut dst[..data.len() / 2], &data[..data.len() / 2]),
                    Cut::Bits => {
                        for (i, (d, s)) in dst.iter_mut().zip(data).enumerate() {
                            let mask = 0x5a_u8.rotate_left(i as u32 % 8);
                            *d &= *s | mask;
                        }
                    }
                }
                return Err(());
            }
            self.writes += 1;
            program(dst, data);
            Ok(())
        }
    }

    fn cut_sweep(original: &[u8]) {
        let live = load(original);
        let mut full = original.to_vec();
        let (_, total) = run(&mut full);
        assert!(total > 0);
        for after in 0..=total {
            for cut in [Cut::Nothing, Cut::Half, Cut::Bits] {
                let mut image = original.to_vec();
                let mut flash = CutFlash { image: &mut image, after, cut, writes: 0, dead: false };
                let mut page = vec![0u8; PAGE_SIZE];
                scrub(&mut flash, original.len(), &mut page);
                assert_eq!(load(&image), live, "cut before write {after} ({cut:?}) changed what NVS loads");
                // Nothing but erased entries moved, and only towards zero.
                let ranges = erased_ranges(original);
                for (at, before, now) in diff(original, &image) {
                    assert_eq!(now & before, now);
                    assert!(ranges.iter().any(|r| r.contains(&at)));
                }
                // The next boot's pass finishes the job exactly.
                let (report, _) = run(&mut image);
                assert!(report.complete(), "resume after cut {after} ({cut:?}): {report:?}");
                assert_eq!(image, full, "resume after cut {after} ({cut:?}) did not converge");
                let (_, again) = run(&mut image);
                assert_eq!(again, 0);
            }
        }
    }

    #[test]
    fn survives_a_power_cut_at_every_write() {
        cut_sweep(&dirty_partition().0);
    }

    #[test]
    fn survives_a_power_cut_at_every_write_over_an_esp_idf_image() {
        let mut img = Image(IDF_IMAGE.to_vec());
        // Erase the whole multi-page idx blob (both chunks and its index) as
        // eraseMultiPageBlob would, plus nk.
        for p in 0..2 {
            let page = img.page(p).to_vec();
            let mut i = 0;
            while i < ENTRY_COUNT {
                let e = entry(&page, i);
                let span = consistent_span(e, i).filter(|_| entry_state(&page, i) == EntryState::Written);
                match span {
                    Some(span) => {
                        if e[8..12] == *b"idx\0" || e[8..11] == *b"nk\0" {
                            img.erase(p, i, span);
                        }
                        i += span;
                    }
                    None => i += 1,
                }
            }
        }
        let plan: usize = img.0.chunks(PAGE_SIZE).map(|p| plan_page(p).zero.len()).sum();
        // idx: chunks of 105 and 38 entries and a one-entry index; nk: 5 + 1
        // (as nvs_tool.py lists the image).
        assert_eq!(plan, 150);
        cut_sweep(&img.0);
    }

    // -----------------------------------------------------------------
    // Another writer, and failing flash
    // -----------------------------------------------------------------

    /// Flash where the page is collected and reused between the scrub's
    /// plan read and its first recheck, as a concurrent NVS writer might.
    struct Racing<'a> {
        image: &'a mut [u8],
        reads: usize,
        reuse: Vec<u8>,
        writes: usize,
    }

    impl Flash for Racing<'_> {
        type Error = ();
        fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), ()> {
            self.reads += 1;
            if self.reads == 2 {
                self.image[..PAGE_SIZE].copy_from_slice(&self.reuse);
            }
            buf.copy_from_slice(&self.image[offset..offset + buf.len()]);
            Ok(())
        }
        fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), ()> {
            self.writes += 1;
            program(&mut self.image[offset..offset + data.len()], data);
            Ok(())
        }
    }

    #[test]
    fn stops_on_a_page_that_changed_under_it() {
        let mut dirty = Image::blank(1);
        dirty.init(0, 1, NVS_VERSION);
        dirty.put_u32(0, 0, 1, "old", 1);
        dirty.erase(0, 0, 1);
        dirty.put_u32(0, 1, 1, "old", 2);
        // The same sector after collection: new sequence number, a live
        // item at entry 0.
        let mut reused = Image::blank(1);
        reused.init(0, 2, NVS_VERSION);
        reused.put_u32(0, 0, 1, "new", 3);
        let mut image = dirty.0.clone();
        let mut flash = Racing { image: &mut image, reads: 0, reuse: reused.0.clone(), writes: 0 };
        let mut page = vec![0u8; PAGE_SIZE];
        let report = scrub(&mut flash, PAGE_SIZE, &mut page);
        assert_eq!(flash.writes, 0);
        assert_eq!(image, reused.0);
        assert_eq!((report.pages_skipped, report.left), (1, 1));
        assert!(!report.complete());
    }

    #[test]
    fn still_erased_wants_the_same_header_and_an_erased_entry() {
        let img = dirty_partition();
        let page = img.page(1).to_vec();
        assert!(still_erased(&page, &page[..DATA_OFFSET], 0));
        assert!(!still_erased(&page, &page[..DATA_OFFSET], 4), "written");
        assert!(!still_erased(&page, &page[..DATA_OFFSET], 20), "empty");
        let mut moved = page.clone();
        moved[4] ^= 1; // another sequence number
        assert!(!still_erased(&page, &moved[..DATA_OFFSET], 0));
        let mut full = page.clone();
        full[0..4].copy_from_slice(&PAGE_FULL.to_le_bytes());
        assert!(!still_erased(&page, &full[..DATA_OFFSET], 0));
        assert!(!still_erased(&page, &page[..10], 0));
    }

    struct Broken<'a> {
        image: &'a mut [u8],
        fail_writes: bool,
        fail_reads_of: Option<usize>,
    }

    impl Flash for Broken<'_> {
        type Error = ();
        fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), ()> {
            if self.fail_reads_of == Some(offset / PAGE_SIZE) && buf.len() == PAGE_SIZE {
                return Err(());
            }
            buf.copy_from_slice(&self.image[offset..offset + buf.len()]);
            Ok(())
        }
        fn write(&mut self, _: usize, _: &[u8]) -> Result<(), ()> {
            // Either an error, or an "OK" that programmed nothing.
            if self.fail_writes { Err(()) } else { Ok(()) }
        }
    }

    #[test]
    fn reports_writes_that_fail_or_do_not_read_back() {
        let original = dirty_partition().0;
        let expected: u32 = original.chunks(PAGE_SIZE).map(|p| plan_page(p).zero.len() as u32).sum();
        for fail_writes in [true, false] {
            let mut image = original.clone();
            let mut flash = Broken { image: &mut image, fail_writes, fail_reads_of: None };
            let mut page = vec![0u8; PAGE_SIZE];
            let report = scrub(&mut flash, original.len(), &mut page);
            assert_eq!((report.zeroed, report.failed), (0, expected));
            assert!(!report.complete());
            assert_eq!(image, original);
        }
    }

    #[test]
    fn an_unreadable_page_is_skipped_and_the_rest_scrubbed() {
        let original = dirty_partition().0;
        let mut image = original.clone();
        let mut flash = Broken { image: &mut image, fail_writes: false, fail_reads_of: Some(0) };
        let mut page = vec![0u8; PAGE_SIZE];
        let report = scrub(&mut flash, original.len(), &mut page);
        assert_eq!(report.pages_skipped, 1);
        assert_eq!(report.zeroed, 0, "Broken programs nothing, so only failures");
        assert!(report.failed > 0);
    }

    #[test]
    fn a_wrong_sized_buffer_runs_nothing() {
        let mut image = dirty_partition().0;
        let before = image.clone();
        let size = image.len();
        let mut flash = Ram { image: &mut image, writes: 0 };
        let report = scrub(&mut flash, size, &mut [0u8; 100]);
        assert_eq!(report, ScrubReport::not_run(4));
        assert!(!report.complete());
        assert_eq!(image, before);
        assert_eq!(ScrubReport::not_run(0).pages_skipped, 1);
    }

    #[test]
    fn a_partition_tail_shorter_than_a_page_is_ignored() {
        let mut image = dirty_partition().0;
        image.extend_from_slice(&[0x00; 100]);
        let (report, _) = run(&mut image);
        assert!(report.complete());
        assert!(image[4 * PAGE_SIZE..].iter().all(|&b| b == 0));
    }

    #[cfg(feature = "nip46")]
    #[test]
    fn the_wire_summary_is_three_fields() {
        let report = ScrubReport { zeroed: 12, already_clean: 3, left: 0, pages_skipped: 0, failed: 0 };
        assert_eq!(
            report.to_json(),
            serde_json::json!({ "zeroed": 12, "pages_skipped": 0, "complete": true })
        );
        let report = ScrubReport { left: 1, ..report };
        assert_eq!(report.to_json()["complete"], false);
        let report = ScrubReport { failed: 2, ..ScrubReport::default() };
        assert_eq!(report.to_json(), serde_json::json!({ "zeroed": 0, "pages_skipped": 0, "complete": false }));
    }
}
