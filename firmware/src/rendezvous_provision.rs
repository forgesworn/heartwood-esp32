//! NVS transaction for scalar-free rendezvous provision receipts.
//!
//! Receipts follow the master slot whenever identities are shifted or removed
//! (see `masters::slot_keys`). A malformed or unreadable blob is a hard
//! refusal: forgetting a prior physical approval would reopen its nonce.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use heartwood_common::rendezvous_receipts::{RendezvousProvisionReceipts, MAX_RECEIPTS};

const KEY_PREFIX: &str = "rzrec_";
const MAX_BLOB_LEN: usize = 1 + MAX_RECEIPTS * (32 + 32 + 4 + 16 + 8);

pub fn key(master_slot: u8) -> String { format!("{KEY_PREFIX}{master_slot}") }

pub fn load(nvs: &EspNvs<NvsDefault>, master_slot: u8) -> Result<RendezvousProvisionReceipts, &'static str> {
    let key = key(master_slot);
    let len = match nvs.blob_len(&key) {
        Ok(None) => return Ok(RendezvousProvisionReceipts::new()),
        Ok(Some(len)) if len <= MAX_BLOB_LEN => len,
        Ok(Some(_)) => return Err("rendezvous provision receipt storage exceeds bound"),
        Err(_) => return Err("failed to inspect rendezvous provision receipts"),
    };
    let mut blob = vec![0u8; core::cmp::max(len, 1)];
    let bytes = match nvs.get_blob(&key, &mut blob) {
        Ok(Some(bytes)) if bytes.len() == len => bytes,
        _ => return Err("failed to read rendezvous provision receipts"),
    };
    RendezvousProvisionReceipts::decode(bytes).ok_or("malformed rendezvous provision receipt storage")
}

/// Store and read back the exact receipt bytes before a successful NIP-46
/// response is emitted.
pub fn persist(nvs: &mut EspNvs<NvsDefault>, master_slot: u8, receipts: &RendezvousProvisionReceipts) -> Result<(), &'static str> {
    let key = key(master_slot);
    let encoded = receipts.encode();
    if encoded.len() > MAX_BLOB_LEN { return Err("rendezvous provision receipt storage exceeds bound"); }
    nvs.set_blob(&key, &encoded).map_err(|_| "failed to persist rendezvous provision receipt")?;
    let len = nvs.blob_len(&key).map_err(|_| "failed to verify rendezvous provision receipt")?.ok_or("rendezvous provision receipt missing after write")?;
    if len != encoded.len() { return Err("rendezvous provision receipt verification length mismatch"); }
    let mut verify = vec![0u8; core::cmp::max(len, 1)];
    match nvs.get_blob(&key, &mut verify) {
        Ok(Some(stored)) if stored == encoded.as_slice() => Ok(()),
        _ => Err("rendezvous provision receipt verification failed"),
    }
}
