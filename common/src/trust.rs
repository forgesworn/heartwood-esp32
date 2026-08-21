//! Senders whose bearer-note gift wraps the device stores without a hold.
//!
//! The hold on a RECEIVE card protects a slot, not money: accepting a note
//! costs nothing but room in the letterbox, and the hold exists so a
//! stranger cannot fill it. A note from a known public mint's Nostr key (a
//! zap paid out as a note, see docs/bearer-notes-over-nostr.md) is not a
//! stranger, and a zap should not need a human. So the owner trusts the
//! mint's key once, with a hold, and every wrap that key seals afterwards
//! is stored on arrival with a three-second toast.
//!
//! Trust is on the SEAL signer, which NIP-59 authenticates; the wrap's
//! throwaway key says nothing. A trusted sender still cannot overfill the
//! letterbox: the received cap applies before trust is consulted.

use alloc::vec::Vec;

/// Bounded because it is one NVS blob and one line of `get_info`. Eight
/// mints is more than anyone has.
pub const MAX_TRUSTED: usize = 8;

const VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrustList {
    keys: Vec<[u8; 32]>,
}

impl TrustList {
    pub const fn new() -> Self {
        Self { keys: Vec::new() }
    }

    pub fn contains(&self, pubkey: &[u8; 32]) -> bool {
        self.keys.iter().any(|k| k == pubkey)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.keys.iter()
    }

    /// `Ok(true)` added, `Ok(false)` already there, `Err` full.
    pub fn add(&mut self, pubkey: [u8; 32]) -> Result<bool, &'static str> {
        if self.contains(&pubkey) {
            return Ok(false);
        }
        if self.keys.len() >= MAX_TRUSTED {
            return Err("trust list full");
        }
        self.keys.push(pubkey);
        Ok(true)
    }

    /// True if it was there.
    pub fn remove(&mut self, pubkey: &[u8; 32]) -> bool {
        let before = self.keys.len();
        self.keys.retain(|k| k != pubkey);
        self.keys.len() != before
    }

    /// `version | keys...`
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.keys.len() * 32);
        out.push(VERSION);
        for k in &self.keys {
            out.extend_from_slice(k);
        }
        out
    }

    /// A torn or foreign blob reads as an empty list: the cost is a hold
    /// the owner already knows how to give, never an unasked acceptance.
    pub fn decode(blob: &[u8]) -> Option<Self> {
        if blob.is_empty() || blob[0] != VERSION {
            return None;
        }
        let body = &blob[1..];
        if body.len() % 32 != 0 || body.len() / 32 > MAX_TRUSTED {
            return None;
        }
        let keys = body
            .chunks_exact(32)
            .map(|c| {
                let mut k = [0u8; 32];
                k.copy_from_slice(c);
                k
            })
            .collect();
        Some(Self { keys })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn add_remove_contains() {
        let mut t = TrustList::new();
        assert!(!t.contains(&key(1)));
        assert_eq!(t.add(key(1)), Ok(true));
        assert_eq!(t.add(key(1)), Ok(false), "a repeat is not a change");
        assert!(t.contains(&key(1)));
        assert!(t.remove(&key(1)));
        assert!(!t.remove(&key(1)));
        assert!(t.is_empty());
    }

    #[test]
    fn the_list_is_bounded() {
        let mut t = TrustList::new();
        for n in 0..MAX_TRUSTED as u8 {
            assert_eq!(t.add(key(n)), Ok(true));
        }
        assert_eq!(t.add(key(99)), Err("trust list full"));
        assert_eq!(t.add(key(0)), Ok(false), "an existing key is still recognised when full");
        assert_eq!(t.len(), MAX_TRUSTED);
    }

    #[test]
    fn encode_decode_round_trips_and_refuses_junk() {
        let mut t = TrustList::new();
        t.add(key(7)).unwrap();
        t.add(key(9)).unwrap();
        let blob = t.encode();
        assert_eq!(blob.len(), 1 + 64);
        assert_eq!(TrustList::decode(&blob), Some(t));
        assert_eq!(TrustList::decode(&blob[..blob.len() - 1]), None, "torn");
        assert_eq!(TrustList::decode(&[]), None, "empty");
        assert_eq!(TrustList::decode(&[VERSION + 1]), None, "other version");
        assert_eq!(TrustList::decode(&[VERSION]), Some(TrustList::new()), "a bare version is an empty list");
        let mut oversize = alloc::vec![VERSION];
        oversize.extend(core::iter::repeat(0u8).take((MAX_TRUSTED + 1) * 32));
        assert_eq!(TrustList::decode(&oversize), None, "more than the list holds");
    }
}
