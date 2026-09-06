//! Where a mint's LUD-25 subtree lives, and how far up its ladder we are.
//!
//! [`crate::cash`] is the arithmetic; this is the state. One entry per mint:
//! the `m/139'/d1/d2/d3/d4` domain node that mint's note secrets hang off, and
//! the next index to mint at.
//!
//! ## Why the node is provisioned rather than derived here
//!
//! `m/139'` hangs off the BIP-32 master, and this device does not keep one.
//! `mnemonic::generate` returns the phrase and the `m/44'/1237'/727'/0'/0'`
//! tree root; `provision.rs` stores that 32-byte root and zeroizes the rest,
//! and the phrase only ever exists on the owner's screen. A board provisioned
//! before this has no seed to walk `m/139'` from and never will, so the node
//! has to come from a host that does hold the seed — the same answer
//! `lnurl-vault` reached from having no elliptic curve at all.
//!
//! **What that costs, stated plainly: whoever provisions a node can derive
//! every note secret this device will ever hold at that mint.** One mint's
//! subtree, not the wallet, and the host doing it is the wallet that holds the
//! seed anyway. It is still the reason provisioning is a held-button decision
//! and not a quiet write.
//!
//! ## The counter is not a secret, and is not authoritative
//!
//! `next_index` only says where to look next. An index reveals nothing without
//! the node, and a wallet restoring from seed alone finds notes by scanning a
//! gap rather than by trusting a counter. What it must never do is go
//! BACKWARDS: re-deriving an index already minted at would hand out a secret
//! the mint has already issued a note against, so [`CashRegistry::take_index`]
//! only ever moves forward and the caller persists before the secret is used.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use zeroize::Zeroize;

use crate::cash::{cash_node_from_bytes, cash_node_to_bytes, CashNode, MAX_NOTE_INDEX};
use crate::note_store::MAX_HOST_LEN;

/// Mints this device will derive notes for. Small on purpose: each entry is
/// 64 bytes of bearer material plus a host string, it lives in the same NVS
/// this board already fills with note records, and a locker that talks to
/// eight mints is already an unusual one.
pub const MAX_CASH_MINTS: usize = 8;

const VERSION: u8 = 1;

/// One mint's subtree and our place in it.
pub struct CashMint {
    /// Lowercase, port included where there is one — byte-identical to
    /// `lnurlcash-kit`'s `serverOf`, because a host spelled differently here
    /// is a different tree and every note in it is unfindable from the wallet.
    pub host: String,
    /// `m/139'/d1/d2/d3/d4` for this mint: 32-byte key then 32-byte chain code.
    pub node: CashNode,
    /// The next index to mint at. Never decreases.
    pub next_index: u32,
}

impl core::fmt::Debug for CashMint {
    /// The host and the index only. A node in a log line is every note secret
    /// at that mint.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CashMint")
            .field("host", &self.host)
            .field("next_index", &self.next_index)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
pub struct CashRegistry {
    mints: Vec<CashMint>,
}

impl core::fmt::Debug for CashRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.mints.iter()).finish()
    }
}

/// Why a registry change was refused. Deliberately narrow: the command layer
/// maps each to one wire error, and a caller that cannot tell "full" from
/// "that host is not a host" cannot fix either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CashError {
    /// The host is empty, too long, or not lowercase.
    BadHost,
    /// No more room; forget a mint first.
    Full,
    /// Nothing provisioned for that host.
    Unknown,
    /// This mint's ladder is used up. 2^31 notes at one mint is not a
    /// situation, but a silent wrap would re-issue every secret from zero.
    Exhausted,
}

/// The one spelling rule, applied at the door rather than trusted from the
/// caller, and public so the command layer can apply it BEFORE it puts a host
/// on an approval card. A card for a request that could never succeed teaches
/// the owner to press without reading, and a host that reaches a card without
/// passing here could also be non-ASCII, which the card's byte slicing would
/// panic on.
/// a host that differs by case is a different BIP-32 tree, so
/// `Mint.Example` and `mint.example` would each hold notes the other cannot
/// see. Uppercase is refused rather than folded, because folding it silently
/// would leave the caller believing it provisioned what it typed.
pub fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && host
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b':' | b'_'))
}

impl CashRegistry {
    pub const fn new() -> Self {
        Self { mints: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.mints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mints.is_empty()
    }

    pub fn hosts(&self) -> impl Iterator<Item = (&str, u32)> {
        self.mints
            .iter()
            .map(|m| (m.host.as_str(), m.next_index))
    }

    pub fn get(&self, host: &str) -> Option<&CashMint> {
        self.mints.iter().find(|m| m.host == host)
    }

    /// Provision (or replace) one mint's subtree.
    ///
    /// Replacing is allowed and resets the index to zero, because a node that
    /// changed is a different tree: carrying the old counter over would start
    /// the new ladder partway up and skip notes a restore would then have to
    /// find by luck. The caller is expected to have asked the owner first —
    /// this layer keeps no opinion about approval, the command layer does.
    pub fn provision(&mut self, host: &str, node: CashNode) -> Result<(), CashError> {
        if !valid_host(host) {
            return Err(CashError::BadHost);
        }
        if let Some(existing) = self.mints.iter_mut().find(|m| m.host == host) {
            existing.node = node;
            existing.next_index = 0;
            return Ok(());
        }
        if self.mints.len() >= MAX_CASH_MINTS {
            return Err(CashError::Full);
        }
        self.mints.push(CashMint {
            host: host.to_string(),
            node,
            next_index: 0,
        });
        Ok(())
    }

    /// Drop a mint's subtree. Notes already held under it are untouched: their
    /// secrets are stored, not re-derived, so forgetting the node loses the
    /// ability to mint MORE notes there, never the ability to spend one.
    pub fn forget(&mut self, host: &str) -> bool {
        let before = self.mints.len();
        self.mints.retain(|m| m.host != host);
        self.mints.len() != before
    }

    /// The index to mint at next, consuming it.
    ///
    /// Only ever moves forward. The caller MUST persist the registry before
    /// the secret derived at this index goes anywhere: a counter that survives
    /// a reboot one index behind hands out a secret the mint has already
    /// issued a note against, and both notes then answer to the same `k1`.
    pub fn take_index(&mut self, host: &str) -> Result<u32, CashError> {
        let mint = self
            .mints
            .iter_mut()
            .find(|m| m.host == host)
            .ok_or(CashError::Unknown)?;
        if mint.next_index > MAX_NOTE_INDEX {
            return Err(CashError::Exhausted);
        }
        let index = mint.next_index;
        mint.next_index = index.saturating_add(1);
        Ok(index)
    }

    /// Fold a wallet's own counter in, so a device and the wallet that
    /// provisioned it do not hand out the same index twice.
    ///
    /// Never decreases, for the reason `take_index` gives. A wallet that has
    /// minted further than this device knows raises the floor; one that is
    /// behind changes nothing.
    pub fn raise_index(&mut self, host: &str, at_least: u32) -> Result<u32, CashError> {
        let mint = self
            .mints
            .iter_mut()
            .find(|m| m.host == host)
            .ok_or(CashError::Unknown)?;
        if at_least > mint.next_index {
            mint.next_index = at_least;
        }
        Ok(mint.next_index)
    }

    /// `VERSION || [ host_len:u8 || host || node:64 || next_index:u32be ]*`
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(VERSION);
        for mint in &self.mints {
            out.push(mint.host.len() as u8);
            out.extend_from_slice(mint.host.as_bytes());
            out.extend_from_slice(cash_node_to_bytes(&mint.node).as_ref());
            out.extend_from_slice(&mint.next_index.to_be_bytes());
        }
        out
    }

    /// A torn or foreign blob reads as an empty registry.
    ///
    /// The cost of that is minting at a mint this device can no longer derive
    /// for, which fails loudly at the next `new_secret` and is fixed by
    /// provisioning again. The cost of the other choice — salvaging what
    /// parses — would be a counter read out of a damaged record, and a counter
    /// that came back too low re-issues secrets. Nothing here is worth
    /// guessing at.
    pub fn decode(blob: &[u8]) -> Option<Self> {
        if blob.is_empty() || blob[0] != VERSION {
            return None;
        }
        let mut rest = &blob[1..];
        let mut mints = Vec::new();
        while !rest.is_empty() {
            let host_len = *rest.first()? as usize;
            if host_len == 0 || host_len > MAX_HOST_LEN {
                return None;
            }
            let need = 1 + host_len + 64 + 4;
            if rest.len() < need {
                return None;
            }
            let host = core::str::from_utf8(&rest[1..1 + host_len]).ok()?;
            if !valid_host(host) {
                return None;
            }
            let mut node_bytes = [0u8; 64];
            node_bytes.copy_from_slice(&rest[1 + host_len..1 + host_len + 64]);
            let node = cash_node_from_bytes(&node_bytes);
            node_bytes.zeroize();
            let next_index = u32::from_be_bytes(
                rest[1 + host_len + 64..need].try_into().ok()?,
            );
            if mints.len() >= MAX_CASH_MINTS {
                return None;
            }
            if mints.iter().any(|m: &CashMint| m.host == host) {
                return None;
            }
            mints.push(CashMint {
                host: host.to_string(),
                node,
                next_index,
            });
            rest = &rest[need..];
        }
        Some(Self { mints })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cash::{derive_cash_domain_node, derive_cash_root};

    fn node(host: &str) -> CashNode {
        // the conformance vectors' standard phrase
        let seed = {
            let text = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
                        9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
            let mut out = [0u8; 64];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
            }
            out
        };
        derive_cash_domain_node(&derive_cash_root(&seed).unwrap(), host).unwrap()
    }

    #[test]
    fn provisioning_then_taking_indices_walks_forward() {
        let mut reg = CashRegistry::new();
        reg.provision("mint.example", node("mint.example")).unwrap();
        assert_eq!(reg.take_index("mint.example"), Ok(0));
        assert_eq!(reg.take_index("mint.example"), Ok(1));
        assert_eq!(reg.take_index("mint.example"), Ok(2));
        assert_eq!(reg.get("mint.example").unwrap().next_index, 3);
    }

    #[test]
    fn an_unprovisioned_mint_has_no_index_to_give() {
        let mut reg = CashRegistry::new();
        assert_eq!(reg.take_index("mint.example"), Err(CashError::Unknown));
    }

    #[test]
    fn a_replaced_node_starts_its_ladder_at_zero() {
        // A different node is a different tree. Carrying the counter over
        // would start partway up a ladder with nothing below, and a restore
        // would have to find those notes by luck.
        let mut reg = CashRegistry::new();
        reg.provision("mint.example", node("mint.example")).unwrap();
        reg.take_index("mint.example").unwrap();
        reg.take_index("mint.example").unwrap();
        reg.provision("mint.example", node("other.example")).unwrap();
        assert_eq!(reg.get("mint.example").unwrap().next_index, 0);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn a_counter_never_goes_backwards() {
        let mut reg = CashRegistry::new();
        reg.provision("mint.example", node("mint.example")).unwrap();
        reg.take_index("mint.example").unwrap(); // 0, next is 1
        assert_eq!(reg.raise_index("mint.example", 9), Ok(9));
        assert_eq!(reg.raise_index("mint.example", 3), Ok(9));
        assert_eq!(reg.take_index("mint.example"), Ok(9));
    }

    #[test]
    fn an_exhausted_ladder_refuses_rather_than_wrapping() {
        // 2^31 notes at one mint is not a situation, but a wrap would
        // re-issue every secret from zero against notes that still exist.
        let mut reg = CashRegistry::new();
        reg.provision("mint.example", node("mint.example")).unwrap();
        reg.raise_index("mint.example", MAX_NOTE_INDEX).unwrap();
        assert_eq!(reg.take_index("mint.example"), Ok(MAX_NOTE_INDEX));
        assert_eq!(
            reg.take_index("mint.example"),
            Err(CashError::Exhausted)
        );
    }

    #[test]
    fn a_host_that_is_not_one_is_refused() {
        let mut reg = CashRegistry::new();
        assert_eq!(reg.provision("", node("a")), Err(CashError::BadHost));
        // uppercase is refused rather than folded: a caller that typed it
        // would otherwise believe it provisioned what it typed
        assert_eq!(
            reg.provision("Mint.Example", node("a")),
            Err(CashError::BadHost)
        );
        assert_eq!(
            reg.provision("mint.example/w", node("a")),
            Err(CashError::BadHost)
        );
        let long = "a".repeat(MAX_HOST_LEN + 1);
        assert_eq!(reg.provision(&long, node("a")), Err(CashError::BadHost));
        // and the ones that are hosts go in, port included
        assert!(reg.provision("mint.example", node("mint.example")).is_ok());
        assert!(reg.provision("127.0.0.1:8899", node("127.0.0.1:8899")).is_ok());
    }

    #[test]
    fn the_registry_fills_up_and_says_so() {
        let mut reg = CashRegistry::new();
        for i in 0..MAX_CASH_MINTS {
            let host = alloc::format!("mint{i}.example");
            assert!(reg.provision(&host, node(&host)).is_ok());
        }
        assert_eq!(
            reg.provision("one.too.many", node("one.too.many")),
            Err(CashError::Full)
        );
        // and forgetting one makes room
        assert!(reg.forget("mint0.example"));
        assert!(!reg.forget("mint0.example"));
        assert!(reg.provision("one.too.many", node("one.too.many")).is_ok());
    }

    #[test]
    fn a_registry_survives_the_blob_round_trip() {
        let mut reg = CashRegistry::new();
        reg.provision("mint.example", node("mint.example")).unwrap();
        reg.provision("127.0.0.1:8899", node("127.0.0.1:8899")).unwrap();
        reg.take_index("mint.example").unwrap();
        reg.raise_index("127.0.0.1:8899", 77).unwrap();

        let back = CashRegistry::decode(&reg.encode()).expect("round trip");
        assert_eq!(back.len(), 2);
        assert_eq!(back.get("mint.example").unwrap().next_index, 1);
        assert_eq!(back.get("127.0.0.1:8899").unwrap().next_index, 77);
        assert_eq!(
            back.get("mint.example").unwrap().node.private_key,
            reg.get("mint.example").unwrap().node.private_key
        );
        assert_eq!(
            back.get("mint.example").unwrap().node.chain_code,
            reg.get("mint.example").unwrap().node.chain_code
        );
    }

    #[test]
    fn a_torn_blob_reads_as_empty_rather_than_as_a_guess() {
        // A counter salvaged from a damaged record could come back too low,
        // and a low counter re-issues secrets. Refusing costs a provisioning
        // round trip; guessing costs somebody's note.
        let mut reg = CashRegistry::new();
        reg.provision("mint.example", node("mint.example")).unwrap();
        reg.raise_index("mint.example", 5).unwrap();
        let blob = reg.encode();

        assert!(CashRegistry::decode(&[]).is_none());
        assert!(CashRegistry::decode(&[2]).is_none()); // wrong version
        // From 2: a blob of just the version byte IS a valid empty registry,
        // and reading it as one is the intended answer - "nothing
        // provisioned" fails loudly at the next new_secret. Every cut past
        // that lands mid-entry and must not decode.
        for cut in 2..blob.len() {
            assert!(
                CashRegistry::decode(&blob[..cut]).is_none(),
                "a blob cut at {cut} decoded"
            );
        }
        assert!(CashRegistry::decode(&blob[..1]).expect("bare version").is_empty());
        assert!(CashRegistry::decode(&blob).is_some());
    }

    #[test]
    fn an_empty_registry_round_trips_as_empty() {
        let reg = CashRegistry::new();
        let back = CashRegistry::decode(&reg.encode()).expect("round trip");
        assert!(back.is_empty());
    }

    #[test]
    fn a_blob_naming_one_host_twice_is_refused() {
        // Two entries for one host means two counters, and the one that loses
        // hands out an index the other already used.
        let mut reg = CashRegistry::new();
        reg.provision("mint.example", node("mint.example")).unwrap();
        let one = reg.encode();
        let mut doubled = one.clone();
        doubled.extend_from_slice(&one[1..]);
        assert!(CashRegistry::decode(&doubled).is_none());
    }

    #[test]
    fn forgetting_a_mint_keeps_nothing_and_loses_no_note() {
        // The node only mints MORE notes. Secrets already held are stored,
        // never re-derived, so this is not a way to lose money.
        let mut reg = CashRegistry::new();
        reg.provision("mint.example", node("mint.example")).unwrap();
        assert!(reg.forget("mint.example"));
        assert!(reg.get("mint.example").is_none());
        assert_eq!(reg.take_index("mint.example"), Err(CashError::Unknown));
    }
}
