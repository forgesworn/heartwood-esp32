// firmware/src/nvs.rs
//
// NVS storage for root secret. Plaintext NVS, encryption deferred. Also the
// one blob write every module uses ([`ReplaceBlob`]) and the gate on writes
// that grow the store ([`growth_allowed`]).

use std::ffi::CString;

use esp_idf_svc::handle::RawHandle;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use esp_idf_svc::sys::{self, esp, EspError};
use heartwood_common::nvs_budget::{self, Fallback, Plan};

/// Write a blob so a power cut leaves either the old value or the new one.
///
/// esp-idf-svc 0.52.1's `EspNvs::set_blob` calls `nvs_erase_key` before
/// `nvs_set_blob`, so a cut between the two leaves the key with no value at
/// all. `nvs_set_blob` on its own does not need that: ESP-IDF v5.3.2 writes
/// the new data chunks under the other version offset, then the new blob
/// index (components/nvs_flash/src/nvs_storage.cpp:269-372, index at :350),
/// and only then erases the old version (:408-452). Until the new index
/// lands, boot drops the new chunks as orphans (:153-180); once it has, boot
/// drops the older index as a duplicate (nvs_pagemanager.cpp:57-90,
/// nvs_page.cpp:662-705) and then its chunks. A half-written entry is skipped
/// at load (nvs_page.cpp:573-600).
///
/// Every key this firmware writes has only ever been a blob, which this
/// relies on: over a key of another type, `nvs_set_blob` would leave the old
/// item in place beside the new blob. `set_blob`'s pre-erase is what copes
/// with a type change, so do not use it here, and do not name these methods
/// `set_blob` either: the inherent method would win the call.
///
/// The new copy is written while the old one still holds its entries, so a
/// replace needs room for both. Whether there is room is decided here, from
/// `available_entries`, before ESP-IDF is asked (`nvs_budget::plan_replace`):
/// a v5.3.2 blob write that runs out of room part-way, over an existing key,
/// cleans up the wrong chunks and can damage the old copy (see `nvs_budget`).
/// When there is no room, secrets and the small critical keys are refused
/// with ESP_ERR_NVS_NOT_ENOUGH_SPACE and keep their old value; everything
/// else is erased first and then written, as every write was before this
/// firmware. Rewriting a value that is already stored is a no-op.
pub trait ReplaceBlob {
    /// Replace under the key's policy (`nvs_budget::fallback_for`).
    fn replace_blob(&self, key: &str, value: &[u8]) -> Result<(), EspError>;

    /// Replace in place or refuse, whatever the key. For a namespace whose
    /// keys all hold value (the note locker).
    fn replace_blob_in_place(&self, key: &str, value: &[u8]) -> Result<(), EspError>;

    /// Replace, erasing first if there is no room, whatever the key. Only for
    /// a caller whose old value is recoverable elsewhere: a journalled copy
    /// whose source stays intact until the copy has landed.
    fn overwrite_blob(&self, key: &str, value: &[u8]) -> Result<(), EspError>;
}

impl ReplaceBlob for EspNvs<NvsDefault> {
    fn replace_blob(&self, key: &str, value: &[u8]) -> Result<(), EspError> {
        write_blob(self, key, value, nvs_budget::fallback_for(key))
    }

    fn replace_blob_in_place(&self, key: &str, value: &[u8]) -> Result<(), EspError> {
        write_blob(self, key, value, Fallback::Never)
    }

    fn overwrite_blob(&self, key: &str, value: &[u8]) -> Result<(), EspError> {
        write_blob(self, key, value, Fallback::EraseFirst)
    }
}

fn not_enough_space() -> EspError {
    EspError::from_infallible::<{ sys::ESP_ERR_NVS_NOT_ENOUGH_SPACE }>()
}

fn write_blob(nvs: &EspNvs<NvsDefault>, key: &str, value: &[u8], fallback: Fallback) -> Result<(), EspError> {
    let c_key = CString::new(key)
        .map_err(|_| EspError::from_infallible::<{ sys::ESP_ERR_INVALID_ARG }>())?;
    let available = crate::nvs_stats::read()
        .map(|s| s.available_entries)
        .ok_or_else(EspError::from_infallible::<{ sys::ESP_FAIL }>)?;
    let old_len = nvs.blob_len(key)?;
    let plan = nvs_budget::plan_replace(fallback, available, old_len, value.len());
    if plan != Plan::Direct && old_len == Some(value.len()) && stored_equals(nvs, key, value)? {
        return Ok(());
    }
    // SAFETY (every call below): the handle is open for as long as `nvs`
    // lives, the key is a NUL-terminated string that outlives the call, and
    // ESP-IDF copies exactly `value.len()` bytes from `value`.
    let set = || {
        esp!(unsafe {
            sys::nvs_set_blob(nvs.handle(), c_key.as_ptr(), value.as_ptr().cast(), value.len())
        })
    };
    match plan {
        Plan::Direct => set()?,
        Plan::Refuse => {
            log::warn!("nvs: {key} not written: {} bytes need more room than is free", value.len());
            return Err(not_enough_space());
        }
        Plan::EraseFirst => {
            log::warn!("nvs: {key} erased before its rewrite: no room for a second copy");
            esp!(unsafe { sys::nvs_erase_key(nvs.handle(), c_key.as_ptr()) })?;
            // The key is now absent, so the old value is gone whatever
            // happens next. Try the new one twice rather than give up on it:
            // a caller must never be left thinking the old value survived.
            if let Err(e) = set() {
                log::warn!("nvs: {key} rewrite after erase failed ({e}), retrying");
                set()?;
            }
        }
    }
    // A no-op in ESP-IDF v5.3.2 (the write above is already on flash);
    // called as esp-idf-svc does, in case a later version caches.
    esp!(unsafe { sys::nvs_commit(nvs.handle()) })
}

fn stored_equals(nvs: &EspNvs<NvsDefault>, key: &str, value: &[u8]) -> Result<bool, EspError> {
    let mut buf = vec![0u8; value.len().max(1)];
    Ok(matches!(nvs.get_blob(key, &mut buf)?, Some(stored) if stored == value))
}

/// Whether a write that grows `key` to `new_len` bytes (a new pairing, a
/// persona, an unlock phone, an avatar) may go ahead: after it, a rewrite of
/// the largest blob that is replaced in place must still fit in place
/// (`nvs_budget::growth_allowed`). Refuses when the numbers cannot be read.
pub fn growth_allowed(nvs: &EspNvs<NvsDefault>, key: &str, new_len: usize) -> bool {
    let Some(stats) = crate::nvs_stats::read() else {
        return false;
    };
    let Ok(old_len) = nvs.blob_len(key) else {
        return false;
    };
    let largest_hot = nvs_budget::hot_keys()
        .filter_map(|k| nvs.blob_len(&k).ok().flatten())
        .max()
        .unwrap_or(0);
    nvs_budget::growth_allowed(stats.available_entries, old_len, new_len, largest_hot)
}

const NVS_NAMESPACE: &str = "heartwood";
const NVS_KEY: &str = "root_secret";

/// Read the root secret from NVS. Returns None if not provisioned.
pub fn read_root_secret(
    nvs_partition: EspDefaultNvsPartition,
) -> Result<(EspNvs<NvsDefault>, Option<[u8; 32]>), &'static str> {
    let nvs = EspNvs::new(nvs_partition, NVS_NAMESPACE, true)
        .map_err(|_| "failed to open NVS namespace")?;

    let mut buf = [0u8; 32];
    match nvs.get_blob(NVS_KEY, &mut buf) {
        Ok(Some(bytes)) => {
            if bytes.len() == 32 {
                Ok((nvs, Some(buf)))
            } else {
                Ok((nvs, None))
            }
        }
        Ok(None) => Ok((nvs, None)),
        Err(_) => Ok((nvs, None)),
    }
}

/// Write the root secret to NVS.
pub fn write_root_secret(
    nvs: &mut EspNvs<NvsDefault>,
    secret: &[u8; 32],
) -> Result<(), &'static str> {
    nvs.replace_blob(NVS_KEY, secret)
        .map_err(|_| "failed to write root secret to NVS")
}
