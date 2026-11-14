//! Duplicate-key counting for the NVS diagnostics in `get_status` and
//! FIRMWARE_INFO (`nvs_stats::read_diag` in the firmware is the caller).
//!
//! ESP-IDF v5.3.2's entry iterator (`Storage::nextEntry`, `nvs_storage.cpp`)
//! skips `BLOB_IDX` entries and every `BLOB_DATA` chunk whose chunk index is
//! not 0 or 0x80, so a healthy blob is returned exactly once, typed
//! `NVS_TYPE_BLOB`. A second entry for the same (namespace, key) means two
//! first chunks are on flash, for example the orphan a failed multi-page
//! write leaves (`writeMultiPageBlob`'s cleanup erases chunk indexes from 0,
//! while the chunks were written from the blob's chunk start). That is
//! direct evidence of an orphan. The converse does not hold: an orphan that
//! is a later chunk, or the only first chunk for a key, is invisible here.
//!
//! The counter keeps 64-bit hashes, never names, in one fixed-capacity
//! buffer, and says "unknown" (`None`) rather than a low number when it runs
//! out of room.

use alloc::vec::Vec;

/// Most (namespace, key) hashes held at once. A blob first chunk costs at
/// least three entries (data header, one data entry, index) and the default
/// partition has 756, so 252 is the physical ceiling and 256 can never be
/// exceeded by a healthy table (2 KB of heap, taken once with
/// `try_reserve_exact`). A walk that somehow meets more reports unknown.
pub const KEY_CAPACITY: usize = 256;

/// FNV-1a over `namespace`, a separator byte that no ASCII name contains,
/// then `key`. Diagnostic only: it never leaves RAM and is not a security
/// primitive, so a collision (about 2^-64 per pair) can only miscount.
pub fn entry_hash(namespace: &[u8], key: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for &b in namespace.iter().chain(&[0xff]).chain(key) {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// Counts the (namespace, key) pairs returned more than once.
pub struct DupCounter {
    hashes: Vec<u64>,
    overflowed: bool,
}

impl DupCounter {
    /// `None` when the one fixed allocation cannot be made.
    pub fn new() -> Option<Self> {
        let mut hashes = Vec::new();
        hashes.try_reserve_exact(KEY_CAPACITY).ok()?;
        Some(Self { hashes, overflowed: false })
    }

    /// Record one iterator entry. Never allocates; past the capacity it only
    /// remembers that the answer is incomplete.
    pub fn push(&mut self, hash: u64) {
        if self.hashes.len() == KEY_CAPACITY {
            self.overflowed = true;
        } else {
            self.hashes.push(hash);
        }
    }

    /// Number of distinct pairs seen more than once (a pair seen three
    /// times counts once). `None` if the capacity was exceeded.
    pub fn finish(mut self) -> Option<usize> {
        if self.overflowed {
            return None;
        }
        self.hashes.sort_unstable();
        let mut dups = 0;
        let mut run = 1usize;
        for pair in self.hashes.windows(2) {
            if pair[0] == pair[1] {
                run += 1;
                if run == 2 {
                    dups += 1;
                }
            } else {
                run = 1;
            }
        }
        Some(dups)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(pairs: &[(&str, &str)]) -> Option<usize> {
        let mut c = DupCounter::new().unwrap();
        for (ns, key) in pairs {
            c.push(entry_hash(ns.as_bytes(), key.as_bytes()));
        }
        c.finish()
    }

    #[test]
    fn empty_and_distinct_keys_count_zero() {
        assert_eq!(count(&[]), Some(0));
        assert_eq!(count(&[("heartwood", "pc0"), ("heartwood", "pc1"), ("hw_notes", "idx")]), Some(0));
    }

    #[test]
    fn the_same_key_twice_in_one_namespace_counts_once() {
        assert_eq!(count(&[("heartwood", "pc0"), ("hw_notes", "idx"), ("heartwood", "pc0")]), Some(1));
    }

    #[test]
    fn three_copies_of_one_key_still_count_one_key() {
        assert_eq!(count(&[("a", "k"), ("a", "k"), ("a", "k")]), Some(1));
    }

    #[test]
    fn two_duplicated_keys_count_two() {
        assert_eq!(count(&[("a", "k"), ("a", "j"), ("a", "k"), ("a", "j"), ("a", "m")]), Some(2));
    }

    #[test]
    fn the_same_key_in_two_namespaces_is_not_a_duplicate() {
        assert_eq!(count(&[("heartwood", "policy"), ("hw_notes", "policy")]), Some(0));
    }

    #[test]
    fn the_namespace_and_key_boundary_is_part_of_the_hash() {
        // "ab" + "c" and "a" + "bc" must not collide.
        assert_ne!(entry_hash(b"ab", b"c"), entry_hash(b"a", b"bc"));
        assert_eq!(count(&[("ab", "c"), ("a", "bc")]), Some(0));
    }

    #[test]
    fn filling_the_buffer_exactly_is_still_an_answer() {
        let mut c = DupCounter::new().unwrap();
        for i in 0..KEY_CAPACITY as u64 {
            c.push(i);
        }
        assert_eq!(c.finish(), Some(0));
    }

    #[test]
    fn overflow_is_unknown_not_a_low_count() {
        let mut c = DupCounter::new().unwrap();
        for i in 0..=KEY_CAPACITY as u64 {
            c.push(i);
        }
        assert_eq!(c.finish(), None);
        // Even when the duplicate is inside the part that was kept.
        let mut c = DupCounter::new().unwrap();
        c.push(7);
        c.push(7);
        for i in 0..KEY_CAPACITY as u64 {
            c.push(1000 + i);
        }
        assert_eq!(c.finish(), None);
    }
}
