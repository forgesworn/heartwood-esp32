// firmware/src/nvs.rs
//
// NVS storage for root secret. Plaintext NVS — encryption deferred. Also the
// one blob write every module uses: [`ReplaceBlob::replace_blob`].

use std::ffi::CString;

use esp_idf_svc::handle::RawHandle;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use esp_idf_svc::sys::{self, esp, EspError};

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
/// with a type change, so do not use it here, and do not name this method
/// `set_blob` either: the inherent method would win the call.
///
/// The new copy is written while the old one still occupies its entries, so
/// a replace needs room for both at once. A write that does not fit fails and
/// the old value stays; `set_blob` would already have erased it.
pub trait ReplaceBlob {
    fn replace_blob(&self, key: &str, value: &[u8]) -> Result<(), EspError>;
}

impl ReplaceBlob for EspNvs<NvsDefault> {
    fn replace_blob(&self, key: &str, value: &[u8]) -> Result<(), EspError> {
        let c_key = CString::new(key)
            .map_err(|_| EspError::from_infallible::<{ sys::ESP_ERR_INVALID_ARG }>())?;
        // SAFETY: the handle is open for as long as `self` lives, the key is a
        // NUL-terminated string that outlives the call, and ESP-IDF copies
        // exactly `value.len()` bytes from `value`.
        esp!(unsafe {
            sys::nvs_set_blob(
                self.handle(),
                c_key.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
            )
        })?;
        // A no-op in ESP-IDF v5.3.2 (the write above is already on flash);
        // called as esp-idf-svc does, in case a later version caches.
        esp!(unsafe { sys::nvs_commit(self.handle()) })
    }
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
