//! Durable, public receipts for an approved rendezvous-child provision.
//!
//! A future `heartwood_provision_rendezvous` handler must remember enough to
//! refuse a replay after a restart, but must never put the derived scalar,
//! pairing ciphertext or raw pairing nonce in NVS. This module is that small
//! persistence model. The firmware owns its storage transaction and only
//! records a receipt after it has encrypted the child to the approved target.
//!
//! The store is intentionally human-paced: a stranger cannot fill it because
//! recording follows a physical approval. A full ring refuses a new provision
//! rather than silently evicting a still-live nonce and making its replay
//! ambiguous.

use alloc::vec::Vec;

use sha2::{Digest, Sha256};

/// Approved target devices retained per root. A thirty-two entry store covers
/// a person's current devices and a reasonable rotation history without
/// making the signer a general device directory.
pub const MAX_RECEIPTS: usize = 32;

/// We retain 128 bits of a domain-separated nonce digest. The nonce itself is
/// not a secret, but retaining it would make a persisted receipt a reusable
/// pairing input. A collision is negligibly likely and never authorises a
/// provision: it only causes a safe refusal.
pub const NONCE_DIGEST_LEN: usize = 16;

const VERSION: u8 = 1;
const ENTRY_LEN: usize = 32 + 32 + 4 + NONCE_DIGEST_LEN + 8;
const NONCE_DOMAIN: &[u8] = b"heartwood/rendezvous-provision/nonce/v1\0";

/// Public, scalar-free evidence of one completed provision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousProvisionReceipt {
    /// Device whose own key received the encrypted child record.
    pub target_device_pubkey: [u8; 32],
    /// Derived rendezvous child's public half, retained for audit only.
    pub rendezvous_pubkey: [u8; 32],
    /// Root-child rotation index.
    pub index: u32,
    /// Domain-separated digest of the single-use request nonce.
    pub nonce_digest: [u8; NONCE_DIGEST_LEN],
    /// Public expiry copied from the approved request.
    pub expires_at: u64,
}

/// Whether a proposed provisioning request can enter its physical approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionReplay {
    /// No receipt names this nonce.
    Fresh,
    /// The exact public request was already completed. A caller must not make
    /// another ciphertext or raise a second card; the device starts a fresh
    /// pairing ceremony if it lost the first encrypted record.
    Exact,
    /// A nonce is single-use across every target, index and expiry. Reusing it
    /// with even one changed field is an error rather than an opportunity to
    /// broaden an old approval.
    NonceReused,
}

/// Bounded, serialisable receipts for one root identity.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RendezvousProvisionReceipts {
    entries: Vec<RendezvousProvisionReceipt>,
}

impl RendezvousProvisionReceipts {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &RendezvousProvisionReceipt> {
        self.entries.iter()
    }

    /// Check the candidate before a future handler spends an approval.
    pub fn classify(
        &self,
        target_device_pubkey: &[u8; 32],
        index: u32,
        nonce: &str,
        expires_at: u64,
    ) -> ProvisionReplay {
        let nonce_digest = nonce_digest(nonce);
        match self
            .entries
            .iter()
            .find(|entry| entry.nonce_digest == nonce_digest)
        {
            None => ProvisionReplay::Fresh,
            Some(entry)
                if entry.target_device_pubkey == *target_device_pubkey
                    && entry.index == index
                    && entry.expires_at == expires_at =>
            {
                ProvisionReplay::Exact
            }
            Some(_) => ProvisionReplay::NonceReused,
        }
    }

    /// Record a completed provision. The caller must persist the returned
    /// state before replying successfully; an NVS write failure therefore
    /// makes the operation fail rather than leaving a replay window.
    pub fn record(&mut self, receipt: RendezvousProvisionReceipt) -> Result<(), &'static str> {
        match self
            .entries
            .iter()
            .find(|entry| entry.nonce_digest == receipt.nonce_digest)
        {
            Some(entry) if entry == &receipt => {
                return Err("rendezvous provision already recorded")
            }
            Some(_) => return Err("rendezvous provision nonce already used"),
            None => {}
        }
        if self.entries.len() >= MAX_RECEIPTS {
            return Err("rendezvous provision receipt store full");
        }
        self.entries.push(receipt);
        Ok(())
    }

    /// Forget only expired entries. The caller supplies the signer's trusted
    /// wall-clock estimate; no untrusted request timestamp can age a receipt
    /// out. A replay after expiry is useless because the future handler must
    /// separately reject an expired request.
    pub fn discard_expired(&mut self, wall_now: u64) -> usize {
        if wall_now == 0 {
            return 0;
        }
        let before = self.entries.len();
        self.entries.retain(|entry| entry.expires_at > wall_now);
        before - self.entries.len()
    }

    /// `version | target | child | index LE | nonce digest | expiry LE ...`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.entries.len() * ENTRY_LEN);
        out.push(VERSION);
        for entry in &self.entries {
            out.extend_from_slice(&entry.target_device_pubkey);
            out.extend_from_slice(&entry.rendezvous_pubkey);
            out.extend_from_slice(&entry.index.to_le_bytes());
            out.extend_from_slice(&entry.nonce_digest);
            out.extend_from_slice(&entry.expires_at.to_le_bytes());
        }
        out
    }

    /// A torn, foreign or overfull blob is refused rather than partially
    /// recovered. The safe result is a failed provisioning attempt, never an
    /// unrecorded approval.
    pub fn decode(blob: &[u8]) -> Option<Self> {
        if blob.is_empty() || blob[0] != VERSION {
            return None;
        }
        let body = &blob[1..];
        if body.len() % ENTRY_LEN != 0 || body.len() / ENTRY_LEN > MAX_RECEIPTS {
            return None;
        }
        let entries = body
            .chunks_exact(ENTRY_LEN)
            .map(|chunk| {
                let mut target_device_pubkey = [0u8; 32];
                target_device_pubkey.copy_from_slice(&chunk[..32]);
                let mut rendezvous_pubkey = [0u8; 32];
                rendezvous_pubkey.copy_from_slice(&chunk[32..64]);
                let mut index = [0u8; 4];
                index.copy_from_slice(&chunk[64..68]);
                let mut nonce_digest = [0u8; NONCE_DIGEST_LEN];
                nonce_digest.copy_from_slice(&chunk[68..68 + NONCE_DIGEST_LEN]);
                let mut expires_at = [0u8; 8];
                expires_at.copy_from_slice(&chunk[68 + NONCE_DIGEST_LEN..ENTRY_LEN]);
                RendezvousProvisionReceipt {
                    target_device_pubkey,
                    rendezvous_pubkey,
                    index: u32::from_le_bytes(index),
                    nonce_digest,
                    expires_at: u64::from_le_bytes(expires_at),
                }
            })
            .collect();
        Some(Self { entries })
    }
}

/// Digest the nonce without retaining a pairing capability in the receipt.
pub fn nonce_digest(nonce: &str) -> [u8; NONCE_DIGEST_LEN] {
    let mut digest = Sha256::new();
    digest.update(NONCE_DOMAIN);
    digest.update(nonce.as_bytes());
    let full = digest.finalize();
    let mut out = [0u8; NONCE_DIGEST_LEN];
    out.copy_from_slice(&full[..NONCE_DIGEST_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(
        target: u8,
        child: u8,
        index: u32,
        nonce: &str,
        expires_at: u64,
    ) -> RendezvousProvisionReceipt {
        RendezvousProvisionReceipt {
            target_device_pubkey: [target; 32],
            rendezvous_pubkey: [child; 32],
            index,
            nonce_digest: nonce_digest(nonce),
            expires_at,
        }
    }

    #[test]
    fn a_nonce_is_single_use_and_exact_retries_do_not_prompt_again() {
        let mut receipts = RendezvousProvisionReceipts::new();
        let stored = receipt(1, 2, 7, "AAECAwQFBgcICQoLDA0ODw", 1_700_000_100);
        assert_eq!(
            receipts.classify(
                &stored.target_device_pubkey,
                7,
                "AAECAwQFBgcICQoLDA0ODw",
                stored.expires_at
            ),
            ProvisionReplay::Fresh
        );
        receipts.record(stored.clone()).unwrap();
        assert_eq!(
            receipts.classify(
                &stored.target_device_pubkey,
                7,
                "AAECAwQFBgcICQoLDA0ODw",
                stored.expires_at
            ),
            ProvisionReplay::Exact
        );
        assert_eq!(
            receipts.classify(
                &stored.target_device_pubkey,
                8,
                "AAECAwQFBgcICQoLDA0ODw",
                stored.expires_at
            ),
            ProvisionReplay::NonceReused
        );
        assert_eq!(
            receipts.classify(&[3; 32], 7, "AAECAwQFBgcICQoLDA0ODw", stored.expires_at),
            ProvisionReplay::NonceReused
        );
        assert_eq!(
            receipts.classify(
                &stored.target_device_pubkey,
                7,
                "AAECAwQFBgcICQoLDA0ODw",
                stored.expires_at + 1
            ),
            ProvisionReplay::NonceReused
        );
        assert_eq!(
            receipts.record(stored),
            Err("rendezvous provision already recorded")
        );
    }

    #[test]
    fn receipt_has_no_nonce_or_secret_and_round_trips() {
        let mut receipts = RendezvousProvisionReceipts::new();
        receipts
            .record(receipt(1, 2, 7, "AAECAwQFBgcICQoLDA0ODw", 10))
            .unwrap();
        receipts
            .record(receipt(3, 4, 8, "EBAQEBAQEBAQEBAQEBAQEA", 20))
            .unwrap();
        let blob = receipts.encode();
        assert_eq!(blob.len(), 1 + 2 * ENTRY_LEN);
        assert!(!blob
            .windows("AAECAwQFBgcICQoLDA0ODw".len())
            .any(|window| window == b"AAECAwQFBgcICQoLDA0ODw"));
        assert_eq!(RendezvousProvisionReceipts::decode(&blob), Some(receipts));
    }

    #[test]
    fn expiry_is_never_advanced_by_an_untrusted_zero_clock() {
        let mut receipts = RendezvousProvisionReceipts::new();
        receipts
            .record(receipt(1, 2, 7, "AAECAwQFBgcICQoLDA0ODw", 10))
            .unwrap();
        assert_eq!(receipts.discard_expired(0), 0);
        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts.discard_expired(10),
            1,
            "expiry is not live at its timestamp"
        );
        assert!(receipts.is_empty());
    }

    #[test]
    fn full_or_torn_storage_fails_closed() {
        let mut receipts = RendezvousProvisionReceipts::new();
        for index in 0..MAX_RECEIPTS as u32 {
            receipts
                .record(receipt(
                    index as u8,
                    9,
                    index,
                    &alloc::format!("nonce-{index}"),
                    100,
                ))
                .unwrap();
        }
        assert_eq!(
            receipts.record(receipt(99, 9, 99, "nonce-overflow", 100)),
            Err("rendezvous provision receipt store full")
        );
        let blob = receipts.encode();
        assert_eq!(RendezvousProvisionReceipts::decode(&blob), Some(receipts));
        assert_eq!(
            RendezvousProvisionReceipts::decode(&blob[..blob.len() - 1]),
            None
        );
        assert_eq!(RendezvousProvisionReceipts::decode(&[]), None);
        assert_eq!(RendezvousProvisionReceipts::decode(&[VERSION + 1]), None);
    }

    #[test]
    fn nonce_digest_is_domain_separated_and_stable() {
        assert_eq!(nonce_digest("nonce"), nonce_digest("nonce"));
        assert_ne!(nonce_digest("nonce"), nonce_digest("nonce2"));
        assert_ne!(
            nonce_digest("nonce"),
            nonce_digest("heartwood/rendezvous-provision/nonce/v1\0nonce")
        );
    }
}
