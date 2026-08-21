//! Which bearer-note gift wraps the owner has already decided on, and how far
//! back to ask a relay for the ones they have not.
//!
//! A kind-1059 is a regular event: relays keep it. A subscription with
//! `limit:0` therefore hears only what lands while the socket is up, and a
//! note sent to a powered-down device is never asked for by anyone -- the
//! wallet cannot open a wrap sealed to the device's key. So the device asks
//! for stored wraps at connect and after every settled card, and this ledger
//! is what keeps that from re-offering the same note forever.
//!
//! Two rules keep it honest against a stranger, who can address a wrap to
//! any public npub:
//!
//! - Only an owner's decision (a hold or a decline) is written here. Junk
//!   wraps and lapsed cards stay in RAM, so a flood cannot wear the flash or
//!   crowd a real note out of the persisted ring.
//! - The catch-up window is anchored on the lower of the last decision and
//!   the device's own sense of now, less the NIP-59 backdate. A wrap with a forged future timestamp cannot
//!   push the window ahead of notes that have not been seen yet.

use alloc::vec::Vec;

use crate::hex::hex_decode;

/// Decided wraps remembered across reboots. Human-paced writes, so 32 is
/// weeks of traffic for one device, and the relay window below bounds what
/// an older entry could ever be needed for.
pub const RING_LEN: usize = 32;
/// Half an event id: 128 bits, no accidental collision, half the blob.
pub const ID_PREFIX_LEN: usize = 16;
/// NIP-59 lets a sender jitter a wrap's `created_at` this far into the past.
pub const WRAP_BACKDATE_SECS: u64 = 2 * 24 * 60 * 60;
/// Stored wraps fetched per catch-up. Bounds the replay a flood can cause;
/// the relay hands back the newest first.
pub const CATCH_UP_LIMIT: u32 = 16;

const VERSION: u8 = 1;
const HEADER_LEN: usize = 1 + 8;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WrapLedger {
    /// `created_at` of the newest wrap the owner decided on; 0 until then.
    mark: u64,
    /// Decided wrap id prefixes, oldest first.
    ring: Vec<[u8; ID_PREFIX_LEN]>,
}

impl WrapLedger {
    pub const fn new() -> Self {
        Self {
            mark: 0,
            ring: Vec::new(),
        }
    }

    pub fn mark(&self) -> u64 {
        self.mark
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    /// Has the owner already decided on this wrap?
    pub fn decided(&self, id_hex: &str) -> bool {
        match prefix_of(id_hex) {
            Some(p) => self.ring.iter().any(|e| *e == p),
            None => false,
        }
    }

    /// Record an owner's decision on a wrap stamped `created_at`. Returns
    /// false (and changes nothing) for an id that is not hex, or one already
    /// recorded.
    pub fn decide(&mut self, id_hex: &str, created_at: u64) -> bool {
        let Some(p) = prefix_of(id_hex) else {
            return false;
        };
        if self.ring.iter().any(|e| *e == p) {
            return false;
        }
        if self.ring.len() >= RING_LEN {
            self.ring.remove(0);
        }
        self.ring.push(p);
        if created_at > self.mark {
            self.mark = created_at;
        }
        true
    }

    /// The `since` for a catch-up REQ, or `None` for "no lower bound" when
    /// nothing has been decided yet -- a first catch-up must reach back as
    /// far as the relay will (bounded by [`CATCH_UP_LIMIT`]), because the
    /// device has no idea how long it sat in a drawer.
    ///
    /// `wall_now` is the device's clock estimate, 0 when it has none yet.
    /// The anchor is the lower of the two readings, so a forged-future
    /// decision is overridden by an honest clock after the next reboot and a
    /// forged-future clock is overridden by the honest mark.
    pub fn since(&self, wall_now: u64) -> Option<u64> {
        if self.mark == 0 {
            return None;
        }
        let anchor = if wall_now == 0 {
            self.mark
        } else {
            self.mark.min(wall_now)
        };
        Some(anchor.saturating_sub(WRAP_BACKDATE_SECS))
    }

    /// `version | mark LE u64 | prefixes...`
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.ring.len() * ID_PREFIX_LEN);
        out.push(VERSION);
        out.extend_from_slice(&self.mark.to_le_bytes());
        for p in &self.ring {
            out.extend_from_slice(p);
        }
        out
    }

    /// A blob of another version, or with a torn tail, is refused rather
    /// than half-read: the cost of a refused ledger is one round of
    /// re-offered cards, the cost of a misread one is a skipped note.
    pub fn decode(blob: &[u8]) -> Option<Self> {
        if blob.len() < HEADER_LEN || blob[0] != VERSION {
            return None;
        }
        let body = &blob[HEADER_LEN..];
        if body.len() % ID_PREFIX_LEN != 0 || body.len() / ID_PREFIX_LEN > RING_LEN {
            return None;
        }
        let mut mark_bytes = [0u8; 8];
        mark_bytes.copy_from_slice(&blob[1..HEADER_LEN]);
        let ring = body
            .chunks_exact(ID_PREFIX_LEN)
            .map(|c| {
                let mut p = [0u8; ID_PREFIX_LEN];
                p.copy_from_slice(c);
                p
            })
            .collect();
        Some(Self {
            mark: u64::from_le_bytes(mark_bytes),
            ring,
        })
    }
}

fn prefix_of(id_hex: &str) -> Option<[u8; ID_PREFIX_LEN]> {
    if id_hex.len() < ID_PREFIX_LEN * 2 {
        return None;
    }
    let bytes = hex_decode(&id_hex[..ID_PREFIX_LEN * 2]).ok()?;
    let mut p = [0u8; ID_PREFIX_LEN];
    p.copy_from_slice(&bytes);
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    /// Distinct in the prefix the ledger keys on, as a real sha256 id is.
    fn id(n: u32) -> alloc::string::String {
        format!("{n:08x}{:056x}", 0)
    }

    #[test]
    fn a_decision_is_remembered_and_moves_the_mark() {
        let mut l = WrapLedger::new();
        assert!(!l.decided(&id(1)));
        assert!(l.decide(&id(1), 1_000));
        assert!(l.decided(&id(1)));
        assert_eq!(l.mark(), 1_000);
        assert!(!l.decide(&id(1), 2_000), "a repeat is not a new decision");
        assert_eq!(l.mark(), 1_000, "and does not move the mark");
    }

    #[test]
    fn the_mark_never_moves_backwards() {
        let mut l = WrapLedger::new();
        l.decide(&id(1), 5_000);
        l.decide(&id(2), 4_000);
        assert_eq!(l.mark(), 5_000);
    }

    #[test]
    fn the_ring_evicts_the_oldest_decision() {
        let mut l = WrapLedger::new();
        for n in 0..(RING_LEN as u32 + 3) {
            l.decide(&id(n), 100 + u64::from(n));
        }
        assert_eq!(l.len(), RING_LEN);
        assert!(!l.decided(&id(0)));
        assert!(!l.decided(&id(2)));
        assert!(l.decided(&id(3)));
        assert!(l.decided(&id(RING_LEN as u32 + 2)));
    }

    #[test]
    fn no_decision_means_no_lower_bound() {
        let l = WrapLedger::new();
        assert_eq!(l.since(0), None);
        assert_eq!(l.since(1_700_000_000), None, "an honest clock alone must not narrow a first catch-up");
    }

    #[test]
    fn since_reaches_back_the_nip59_backdate_from_the_mark() {
        let mut l = WrapLedger::new();
        l.decide(&id(1), 1_700_000_000);
        assert_eq!(l.since(0), Some(1_700_000_000 - WRAP_BACKDATE_SECS));
    }

    #[test]
    fn a_forged_future_decision_is_capped_by_the_clock() {
        let mut l = WrapLedger::new();
        l.decide(&id(1), 1_900_000_000);
        assert_eq!(l.since(1_700_000_000), Some(1_700_000_000 - WRAP_BACKDATE_SECS));
    }

    #[test]
    fn a_forged_future_clock_is_capped_by_the_mark() {
        let mut l = WrapLedger::new();
        l.decide(&id(1), 1_700_000_000);
        assert_eq!(l.since(1_900_000_000), Some(1_700_000_000 - WRAP_BACKDATE_SECS));
    }

    #[test]
    fn since_saturates_at_zero() {
        let mut l = WrapLedger::new();
        l.decide(&id(1), 10);
        assert_eq!(l.since(0), Some(0));
    }

    #[test]
    fn encode_decode_round_trips() {
        let mut l = WrapLedger::new();
        l.decide(&id(7), 1_700_000_001);
        l.decide(&id(9), 1_700_000_009);
        let blob = l.encode();
        assert_eq!(blob.len(), HEADER_LEN + 2 * ID_PREFIX_LEN);
        assert_eq!(WrapLedger::decode(&blob), Some(l));
    }

    #[test]
    fn decode_refuses_a_torn_or_foreign_blob() {
        let mut l = WrapLedger::new();
        l.decide(&id(7), 1_700_000_001);
        let blob = l.encode();
        assert_eq!(WrapLedger::decode(&blob[..blob.len() - 1]), None, "torn tail");
        let mut wrong = blob.clone();
        wrong[0] = VERSION + 1;
        assert_eq!(WrapLedger::decode(&wrong), None, "other version");
        assert_eq!(WrapLedger::decode(&[]), None, "empty");
        let mut oversize = WrapLedger::new().encode();
        oversize.extend(core::iter::repeat(0u8).take((RING_LEN + 1) * ID_PREFIX_LEN));
        assert_eq!(WrapLedger::decode(&oversize), None, "more entries than the ring holds");
    }

    #[test]
    fn a_non_hex_id_is_neither_decided_nor_recordable() {
        let mut l = WrapLedger::new();
        assert!(!l.decide("not-hex", 1));
        assert!(!l.decided("not-hex"));
        assert!(!l.decide("abcd", 1), "too short");
        assert!(l.is_empty());
    }
}
