//! Private writer I/O. No erase, anchor write, namespace repair or generic key API.
use super::super::super::{
    journal::InventoryHold,
    journal_nvs::{self, Name, OwnedBlob, RawHandle},
};
use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use std::ptr;

#[cfg(test)]
use crate::allocation_nvs_host_sys as sys;
#[cfg(not(test))]
use esp_idf_svc::sys;

pub(super) enum Target {
    Record(u8),
    Slot(u8),
}
impl Target {
    fn key(&self) -> Result<String, InventoryHold> {
        match self {
            Self::Record(n) if (1..=32).contains(n) => Ok(format!("m{n:02}")),
            Self::Slot(n) if *n <= 1 => Ok(format!("snap{n}")),
            _ => Err(InventoryHold::Format),
        }
    }
}

// Only the parent controller can open this, after its read-only inventory,
// external enrolment/capacity and encrypted-root gates. RW open itself may
// create an empty namespace if an outside partition writer races; the parent
// must recheck exact complete inventory before any history write.
pub(super) struct WriteHandle<'owner> {
    raw: sys::nvs_handle_t,
    _owner: &'owner EspNvs<NvsDefault>,
    failed: bool,
}
impl Drop for WriteHandle<'_> {
    fn drop(&mut self) {
        unsafe {
            sys::nvs_close(self.raw);
        }
    }
}
impl RawHandle for WriteHandle<'_> {
    fn raw(&self) -> sys::nvs_handle_t {
        self.raw
    }
}
impl<'owner> WriteHandle<'owner> {
    #[cfg(test)]
    pub(super) fn failed_for_test(&self) -> bool {
        self.failed
    }
    pub(super) fn open(
        owner: &'owner EspNvs<NvsDefault>,
        namespace: &str,
    ) -> Result<Self, InventoryHold> {
        let name = Name::from_bytes(namespace.as_bytes())?;
        let mut raw = 0;
        // SAFETY: bounded NUL-terminated name/output. The held partition owner
        // outlives this handle; this does not initialise or erase a partition.
        let err =
            unsafe { sys::nvs_open(name.ptr(), sys::nvs_open_mode_t_NVS_READWRITE, &mut raw) };
        if err == sys::ESP_ERR_NVS_NOT_FOUND {
            return Err(InventoryHold::Missing);
        }
        if err != sys::ESP_OK || raw == 0 {
            return Err(InventoryHold::Storage);
        }
        Ok(Self {
            raw,
            _owner: owner,
            failed: false,
        })
    }

    pub(super) fn inventory(&mut self, namespace: &str) -> Result<Vec<OwnedBlob>, InventoryHold> {
        if self.failed {
            return Err(InventoryHold::Storage);
        }
        let result = self.inventory_inner(namespace);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn inventory_inner(&self, namespace: &str) -> Result<Vec<OwnedBlob>, InventoryHold> {
        let first = journal_nvs::collect(self, namespace)?;
        let second = journal_nvs::collect(self, namespace)?;
        if first != second {
            return Err(InventoryHold::Changed);
        }
        Ok(first)
    }

    fn read(&self, name: &Name, width: usize) -> Result<Option<Vec<u8>>, InventoryHold> {
        let mut length = 0;
        // SAFETY: valid owned handle/name and initialised output length.
        let err = unsafe { sys::nvs_get_blob(self.raw, name.ptr(), ptr::null_mut(), &mut length) };
        if err == sys::ESP_ERR_NVS_NOT_FOUND {
            return Ok(None);
        }
        if err != sys::ESP_OK {
            return Err(InventoryHold::Storage);
        }
        if length != width {
            return Err(InventoryHold::Format);
        }
        let mut bytes = vec![0; width];
        let err = unsafe {
            sys::nvs_get_blob(self.raw, name.ptr(), bytes.as_mut_ptr().cast(), &mut length)
        };
        if err != sys::ESP_OK {
            return Err(InventoryHold::Storage);
        }
        if length != width {
            return Err(InventoryHold::Format);
        }
        Ok(Some(bytes))
    }

    // No anchor variant; only a controller-created next immutable record or
    // inactive snapshot. Exact expected old bytes detect observed target drift.
    pub(super) fn write(
        &mut self,
        target: Target,
        expected: Option<&[u8]>,
        frame: &[u8],
    ) -> Result<(), InventoryHold> {
        if self.failed {
            return Err(InventoryHold::Storage);
        }
        let result = self.write_inner(target, expected, frame);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn write_inner(
        &self,
        target: Target,
        expected: Option<&[u8]>,
        frame: &[u8],
    ) -> Result<(), InventoryHold> {
        let key = target.key()?;
        let width = journal_nvs_width(&key)?;
        if frame.len() != width {
            return Err(InventoryHold::Format);
        }
        let name = Name::from_bytes(key.as_bytes())?;
        let before = self.read(&name, width)?;
        if matches!(target, Target::Record(_)) {
            if expected.is_some() {
                return Err(InventoryHold::Records);
            }
            if let Some(bytes) = &before {
                // Exact retry performs no mutation; another record never gets
                // overwritten even if the caller supplies it as expected old.
                return if bytes == frame {
                    Ok(())
                } else {
                    Err(InventoryHold::Records)
                };
            }
        } else if before.as_deref() != expected {
            return Err(InventoryHold::Changed);
        }
        // SAFETY: live RW handle, exact validated key/width and immutable frame
        // buffer for this call. SDK set_blob writes now; there is NO pre-erase.
        if unsafe { sys::nvs_set_blob(self.raw, name.ptr(), frame.as_ptr().cast(), frame.len()) }
            != sys::ESP_OK
        {
            return Err(InventoryHold::Storage);
        }
        // Check even though ESP-IDF5.3.2 commit is currently a handle/no-op gate.
        if unsafe { sys::nvs_commit(self.raw) } != sys::ESP_OK {
            return Err(InventoryHold::Storage);
        }
        if self.read(&name, width)?.as_deref() != Some(frame) {
            return Err(InventoryHold::Changed);
        }
        Ok(())
    }
}
fn journal_nvs_width(key: &str) -> Result<usize, InventoryHold> {
    super::super::super::journal::expected_blob_width(key).ok_or(InventoryHold::Format)
}
