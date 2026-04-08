// firmware/src/identity_cache.rs
//
// Per-master cache of derived identities for heartwood extensions.
//
// Identities are derived on demand and held in memory for the lifetime of the
// session. Private key material is zeroised when a CachedIdentity is dropped.

use heartwood_common::derive;
use zeroize::Zeroize;

/// A cached derived identity.
pub struct CachedIdentity {
    pub npub: String,
    pub purpose: String,
    pub index: u32,
    pub persona_name: Option<String>,
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl Drop for CachedIdentity {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// Per-master identity cache.
///
/// Keyed by master slot so the frame dispatcher can route heartwood requests to
/// the correct cache when multiple masters are loaded.
pub struct IdentityCache {
    pub master_slot: u8,
    pub identities: Vec<CachedIdentity>,
}

impl IdentityCache {
    pub fn new(master_slot: u8) -> Self {
        Self {
            master_slot,
            identities: Vec::new(),
        }
    }

    /// Derive and cache an identity. Returns the index into the cache.
    ///
    /// If an identity with the same purpose and index is already cached the
    /// existing entry is returned without re-deriving.
    pub fn derive_and_cache(
        &mut self,
        master_secret: &[u8; 32],
        purpose: &str,
        index: u32,
        persona_name: Option<String>,
    ) -> Result<usize, &'static str> {
        if let Some(pos) = self.find(purpose, index) {
            return Ok(pos);
        }

        let root = derive::create_tree_root(master_secret)?;
        let identity = derive::derive(&root, purpose, index)?;

        let cached = CachedIdentity {
            npub: identity.npub.clone(),
            purpose: identity.purpose.clone(),
            index: identity.index,
            persona_name,
            private_key: *identity.private_key,
            public_key: identity.public_key,
        };

        self.identities.push(cached);
        Ok(self.identities.len() - 1)
    }

    /// Find by purpose and index. Returns the position in the cache, or None.
    pub fn find(&self, purpose: &str, index: u32) -> Option<usize> {
        self.identities
            .iter()
            .position(|id| id.purpose == purpose && id.index == index)
    }

    /// Find by npub string. Returns the position in the cache, or None.
    pub fn find_by_npub(&self, npub: &str) -> Option<usize> {
        self.identities.iter().position(|id| id.npub == npub)
    }

    /// Find by persona name. Returns the position in the cache, or None.
    pub fn find_by_persona(&self, name: &str) -> Option<usize> {
        self.identities
            .iter()
            .position(|id| id.persona_name.as_deref() == Some(name))
    }

    /// Serialise all cached identities to a JSON array string.
    ///
    /// Each entry contains `npub`, `purpose`, `index`, and an optional
    /// `personaName` field. Private key material is never included.
    pub fn list_json(&self) -> String {
        let entries: Vec<serde_json::Value> = self
            .identities
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

    /// Scan default purposes and pre-derive identities up to `lookahead` indices.
    ///
    /// Used by `heartwood_recover` to rebuild the cache after a reset or when
    /// switching masters. Invalid scalars are silently skipped — the derive loop
    /// in `derive::derive` already increments the index automatically, so this
    /// will only fail on catastrophic HMAC errors.
    ///
    /// Returns the number of identities newly added to the cache.
    pub fn recover(
        &mut self,
        master_secret: &[u8; 32],
        lookahead: u32,
    ) -> Result<usize, &'static str> {
        let default_purposes = ["messaging", "signing", "social", "commerce"];
        let mut recovered = 0;

        for purpose in &default_purposes {
            for index in 0..lookahead {
                match self.derive_and_cache(master_secret, purpose, index, None) {
                    Ok(_) => recovered += 1,
                    Err(_) => {} // invalid scalar — skip, continue scanning
                }
            }
        }

        Ok(recovered)
    }
}
