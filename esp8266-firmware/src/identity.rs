//! Multi-identity (nsec-tree) state for the tethered signer.
//!
//! The single provisioned master seed is the *account* identity — signed with
//! directly (see `sign_path`, the no-context path). Named **personas** are
//! children derived via the canonical `nostr:persona:<name>` purpose namespace,
//! byte-for-byte identical to signet, the nsec-tree CLI, and the WiFi firmware,
//! because they all go through the same `heartwood_common::derive`.
//!
//! Two pieces of RAM-only state, sized for a tethered signer (a handful of
//! personas, a few client sessions):
//!   * `IdentityCache` — metadata only. The private key is NOT held; signing
//!     re-derives it on demand (`secret_for`), so at most one persona secret is
//!     ever live, and the heap cost per identity is just its strings.
//!   * `Sessions` — a per-client "active identity" pointer for stateful
//!     `heartwood_switch`. Without it a client that switches then sends a bare
//!     `sign_event` would silently be signed as the master, not the persona.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use heartwood_common::derive;
use heartwood_common::types::MasterMode;

/// Cached metadata for one derived identity (no secret material).
pub struct CachedId {
    pub npub: String,
    pub purpose: String,
    pub index: u32,
    pub persona_name: Option<String>,
    pub public_key: [u8; 32],
}

/// The master's derivation tree-root secret, given its mode. Tree modes store
/// the seed AS the tree root; Bunker mode HMACs it (`nsec_to_tree_root`). An
/// unknown mode byte is treated as a tree mode (matches `storage::DEFAULT_MODE`).
pub fn tree_root_secret(master_seed: &[u8; 32], mode: u8) -> Option<[u8; 32]> {
    let is_tree = MasterMode::from_u8(mode).map_or(true, |m| m.is_tree());
    if is_tree {
        Some(*master_seed)
    } else {
        derive::nsec_to_tree_root(master_seed).ok().map(|z| *z)
    }
}

/// Derive the identity at `purpose`/`index`, returning its public key, npub, and
/// (resolved) index — NO secret. The Identity's secret is zeroised on drop here,
/// so this is the path for enumeration and `get_public_key`.
#[inline(never)]
pub fn derive_pubkey_meta(
    master_seed: &[u8; 32],
    mode: u8,
    purpose: &str,
    index: u32,
) -> Option<([u8; 32], String, u32)> {
    let root_secret = tree_root_secret(master_seed, mode)?;
    let root = derive::create_tree_root(&root_secret).ok()?;
    let id = derive::derive(&root, purpose, index).ok()?;
    Some((id.public_key, id.npub.clone(), id.index))
}

/// Derive the (secret, public key) for `purpose`/`index` — the sign path, where
/// the persona secret must be materialised for the instant of signing.
#[inline(never)]
pub fn derive_signing(
    master_seed: &[u8; 32],
    mode: u8,
    purpose: &str,
    index: u32,
) -> Option<([u8; 32], [u8; 32])> {
    let root_secret = tree_root_secret(master_seed, mode)?;
    let root = derive::create_tree_root(&root_secret).ok()?;
    let id = derive::derive(&root, purpose, index).ok()?;
    Some((*id.private_key, id.public_key))
}

pub struct IdentityCache {
    ids: Vec<CachedId>,
}

impl IdentityCache {
    pub fn new() -> Self {
        Self { ids: Vec::new() }
    }

    /// Derive (if not already cached) the identity at `purpose`/`index`, store
    /// its metadata, and return its cache index. Mirrors the WiFi firmware's
    /// `IdentityCache::derive_and_cache`: dedup is by the *requested* purpose +
    /// index, and the *resolved* index (after any invalid-scalar skip) is stored.
    #[inline(never)]
    pub fn derive_and_cache(
        &mut self,
        master_seed: &[u8; 32],
        mode: u8,
        purpose: &str,
        index: u32,
        persona_name: Option<String>,
    ) -> Result<usize, &'static str> {
        if let Some(pos) = self.find(purpose, index) {
            return Ok(pos);
        }
        let (public_key, npub, resolved_index) =
            derive_pubkey_meta(master_seed, mode, purpose, index).ok_or("derivation failed")?;
        self.ids.push(CachedId {
            npub,
            purpose: purpose.to_string(),
            index: resolved_index,
            persona_name,
            public_key,
        });
        Ok(self.ids.len() - 1)
    }

    pub fn find(&self, purpose: &str, index: u32) -> Option<usize> {
        self.ids.iter().position(|i| i.purpose == purpose && i.index == index)
    }

    pub fn find_by_npub(&self, npub: &str) -> Option<usize> {
        self.ids.iter().position(|i| i.npub == npub)
    }

    pub fn find_by_persona(&self, name: &str) -> Option<usize> {
        self.ids.iter().position(|i| i.persona_name.as_deref() == Some(name))
    }

    pub fn get(&self, idx: usize) -> Option<&CachedId> {
        self.ids.get(idx)
    }

    /// JSON array of cached identities (`npub`, `pubkey`, `purpose`, `index`,
    /// optional `personaName`). Never includes secrets. Matches the WiFi
    /// firmware's `IdentityCache::list_json` byte shape.
    pub fn list_json(&self) -> String {
        let entries: Vec<serde_json::Value> = self
            .ids
            .iter()
            .map(|id| {
                let mut obj = serde_json::json!({
                    "npub": id.npub,
                    "pubkey": heartwood_common::hex::hex_encode(&id.public_key),
                    "purpose": id.purpose,
                    "index": id.index,
                });
                if let Some(name) = &id.persona_name {
                    obj["personaName"] = serde_json::json!(name);
                }
                obj
            })
            .collect();
        serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
    }
}

/// Per-client "active identity" pointers for stateful `heartwood_switch`, keyed
/// by the client x-only pubkey.
pub struct Sessions {
    entries: Vec<([u8; 32], Option<usize>)>,
}

impl Sessions {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// The cache index the client last switched to, if any.
    pub fn active(&self, client_pk: &[u8; 32]) -> Option<usize> {
        self.entries.iter().find(|(pk, _)| pk == client_pk).and_then(|(_, a)| *a)
    }

    /// Set (or clear, with `None`) the client's active identity.
    pub fn set(&mut self, client_pk: &[u8; 32], active: Option<usize>) {
        if let Some(e) = self.entries.iter_mut().find(|(pk, _)| pk == client_pk) {
            e.1 = active;
        } else {
            self.entries.push((*client_pk, active));
        }
    }
}
