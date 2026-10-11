//! Private allocation custody and local journal inspection. No allocation owner,
//! or child-release API. A private dormant writer is construction-gated.
//! Boot checks the crypto backend.
//! It establishes custody of one routed master, not authority to select it.
#![allow(dead_code)]

use crate::{held_data_key::HeldDataKey, master_identity::LoadedMaster};
use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use heartwood_common::{data_key, derive, types::MasterMode};
use zeroize::Zeroizing;

#[path = "allocation_crypto.rs"]
mod crypto;
#[path = "allocation_journal.rs"]
mod journal;
#[path = "allocation_journal_nvs.rs"]
mod journal_nvs;
pub(crate) use journal::{InventoryHold, Report, StoredBlob};

pub(crate) fn crypto_backend_ready() -> bool {
    crypto::backend_ready()
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Hold {
    Storage,
    Metadata,
    Locked,
    Seed,
    Busy,
    Changed,
}

// Not constructible from bytes, cloneable, printable or exportable.
struct NormalizedMasterRootV1(Zeroizing<[u8; 32]>);

/// Exclusive master/NVS borrows and the boot data-key guard last until Drop.
/// Do not call current/remember/forget while held: those legacy APIs lock the
/// same mutex. No callback or await is accepted here.
pub(crate) struct HeldAllocationRoot<'a> {
    nvs: &'a mut EspNvs<NvsDefault>,
    master: &'a mut LoadedMaster,
    data_key: HeldDataKey,
    root: NormalizedMasterRootV1,
    slot: u8,
    mode: MasterMode,
    version: u8,
    issuer: [u8; 32],
}

fn read_exact(nvs: &EspNvs<NvsDefault>, key: &str, out: &mut [u8]) -> Result<(), Hold> {
    let width = out.len();
    if nvs.blob_len(key).map_err(|_| Hold::Storage)? != Some(width) {
        return Err(Hold::Metadata);
    }
    match nvs.get_blob(key, out).map_err(|_| Hold::Storage)? {
        Some(bytes) if bytes.len() == width => Ok(()),
        _ => Err(Hold::Metadata),
    }
}

fn validate(
    nvs: &EspNvs<NvsDefault>,
    master: &LoadedMaster,
    key: &HeldDataKey,
    require_encrypted: bool,
) -> Result<NormalizedMasterRootV1, Hold> {
    if master.locked {
        return Err(Hold::Locked);
    }
    let mut count = [0; 1];
    read_exact(nvs, "master_count", &mut count)?;
    if count[0] == 0 || count[0] > 8 || master.slot >= count[0] {
        return Err(Hold::Metadata);
    }
    if nvs
        .blob_len("rm_journal")
        .map_err(|_| Hold::Storage)?
        .is_some()
    {
        return Err(Hold::Metadata);
    }
    let prefix = format!("master_{}", master.slot);
    let mut mode = [0; 1];
    let mut version = [0; 1];
    let mut issuer = [0; 32];
    read_exact(nvs, &format!("{prefix}_mode"), &mut mode)?;
    read_exact(nvs, &format!("{prefix}_deriv"), &mut version)?;
    read_exact(nvs, &format!("{prefix}_pubkey"), &mut issuer)?;
    let mode = MasterMode::from_u8(mode[0]).ok_or(Hold::Metadata)?;
    if version[0] != mode.derivation_version()
        || mode != master.mode
        || version[0] != master.derivation_version
        || issuer != master.pubkey
    {
        return Err(Hold::Metadata);
    }
    if derive::public_key_xonly(&master.secret).map_err(|_| Hold::Seed)? != issuer {
        return Err(Hold::Seed);
    }

    // Establish exact stored bytes, not just x-only public-key equivalence:
    // scalar k and n-k share an x-only public key but different namespaces.
    let enc_key = data_key::seed_enc_key(master.slot);
    match nvs.blob_len(&enc_key).map_err(|_| Hold::Storage)? {
        Some(_) => {
            // Symmetric board invariant: all counted seeds must authenticate
            // under this held data key and have no plaintext shadow.
            for slot in 0..count[0] {
                let mut blob = [0; data_key::SEALED_LEN];
                read_exact(nvs, &data_key::seed_enc_key(slot), &mut blob)?;
                if nvs
                    .blob_len(&format!("master_{slot}_secret"))
                    .map_err(|_| Hold::Storage)?
                    .is_some()
                    || !key.authenticates_seed(&blob)
                {
                    return Err(Hold::Seed);
                }
                if slot == master.slot && !key.matches_seed(&blob, &master.secret) {
                    return Err(Hold::Seed);
                }
            }
        }
        None => {
            if require_encrypted {
                return Err(Hold::Seed);
            }
            // No downgrade to plaintext on a board with any encrypted slot.
            for slot in 0..count[0] {
                if nvs
                    .blob_len(&data_key::seed_enc_key(slot))
                    .map_err(|_| Hold::Storage)?
                    .is_some()
                {
                    return Err(Hold::Seed);
                }
            }
            let mut stored = Zeroizing::new([0; 32]);
            read_exact(nvs, &format!("{prefix}_secret"), stored.as_mut())?;
            if *stored != master.secret {
                return Err(Hold::Seed);
            }
        }
    }
    let root = if mode.is_tree() {
        Zeroizing::new(master.secret)
    } else {
        derive::nsec_to_tree_root(&master.secret).map_err(|_| Hold::Seed)?
    };
    derive::public_key_xonly(&root).map_err(|_| Hold::Seed)?;
    Ok(NormalizedMasterRootV1(root))
}

impl<'a> HeldAllocationRoot<'a> {
    /// The future physical owner must route its actually selected master here.
    /// This constructor has no browser/serial/relay call site.
    pub(crate) fn hold(
        nvs: &'a mut EspNvs<NvsDefault>,
        master: &'a mut LoadedMaster,
    ) -> Result<Self, Hold> {
        let data_key = HeldDataKey::try_hold().map_err(|_| Hold::Busy)?;
        let root = validate(nvs, master, &data_key, false)?;
        Ok(Self {
            slot: master.slot,
            mode: master.mode,
            version: master.derivation_version,
            issuer: master.pubkey,
            nvs,
            master,
            data_key,
            root,
        })
    }

    pub(crate) fn issuer(&self) -> &[u8; 32] {
        &self.issuer
    }

    /// Local bytes only: no derived-writer or witness signature authority.
    /// The future adapter must open this namespace read-only and enumerate all
    /// keys/errors. This method has no runtime caller and performs no writes.
    pub(crate) fn inspect_journal(
        &self,
        blobs: &[StoredBlob<'_>],
    ) -> Result<Report, InventoryHold> {
        self.recheck().map_err(|_| InventoryHold::Custody)?;
        if !crypto::backend_ready() {
            return Err(InventoryHold::Crypto);
        }
        let result = journal::inspect(&self.root, &self.issuer, blobs);
        self.recheck().map_err(|_| InventoryHold::Custody)?;
        result
    }

    pub(crate) fn journal_namespace(&self) -> Result<String, InventoryHold> {
        self.recheck().map_err(|_| InventoryHold::Custody)?;
        let namespace = journal::namespace(&self.root);
        self.recheck().map_err(|_| InventoryHold::Custody)?;
        Ok(namespace)
    }

    /// Reads only the existing root-derived namespace. Never initializes,
    /// writes, or interprets missing storage as first use. No runtime caller.
    pub(crate) fn inspect_persisted_journal(&self) -> Result<Report, InventoryHold> {
        self.recheck().map_err(|_| InventoryHold::Custody)?;
        if !crypto::backend_ready() {
            return Err(InventoryHold::Crypto);
        }
        let namespace = Zeroizing::new(journal::namespace(&self.root));
        let result = journal_nvs::inspect(self.nvs, &namespace, &self.root, &self.issuer);
        self.recheck().map_err(|_| InventoryHold::Custody)?;
        result
    }

    /// Required again before any future authority decision. A failure is HOLD;
    /// it never reloads/replaces the root or repairs missing metadata.
    pub(crate) fn recheck(&self) -> Result<(), Hold> {
        self.recheck_storage(false)
    }

    /// Writer-only eligibility: legacy plaintext can be inspected but never
    /// authorises persisting a root-encrypted allocation history.
    fn recheck_for_write(&self) -> Result<(), Hold> {
        self.recheck_storage(true)
    }

    fn recheck_storage(&self, require_encrypted: bool) -> Result<(), Hold> {
        if self.master.slot != self.slot
            || self.master.mode != self.mode
            || self.master.derivation_version != self.version
            || self.master.pubkey != self.issuer
        {
            return Err(Hold::Changed);
        }
        let root = validate(self.nvs, self.master, &self.data_key, require_encrypted)?;
        if *root.0 != *self.root.0 {
            return Err(Hold::Changed);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../common/src/allocation_root_host_tests.rs"]
mod tests;
