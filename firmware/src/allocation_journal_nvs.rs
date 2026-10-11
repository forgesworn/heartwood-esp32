//! Dormant, read-only adapter. No initialization, write or iterator-error elision.
#![allow(dead_code)]
use super::{journal, InventoryHold};
use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use std::ptr;
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use crate::allocation_nvs_host_sys as sys;
#[cfg(not(test))]
use esp_idf_svc::sys;

pub(super) struct ReadHandle<'a> {
    raw: sys::nvs_handle_t,
    // Keeps the existing default partition alive; never take/reinitialize it.
    _owner: &'a EspNvs<NvsDefault>,
}
impl<'a> ReadHandle<'a> {
    pub(super) fn open(
        _owner: &'a EspNvs<NvsDefault>,
        namespace: &str,
    ) -> Result<Self, InventoryHold> {
        let name = Name::from_bytes(namespace.as_bytes())?;
        let mut raw = 0;
        // SAFETY: bounded NUL-terminated name and valid output pointer; the
        // held default-partition owner outlives this handle. READONLY never creates.
        let err = unsafe { sys::nvs_open(name.ptr(), sys::nvs_open_mode_t_NVS_READONLY, &mut raw) };
        if err == sys::ESP_ERR_NVS_NOT_FOUND {
            return Err(InventoryHold::Missing);
        }
        if err != sys::ESP_OK || raw == 0 {
            return Err(InventoryHold::Storage);
        }
        Ok(Self { raw, _owner })
    }
}
impl Drop for ReadHandle<'_> {
    fn drop(&mut self) {
        unsafe {
            sys::nvs_close(self.raw);
        }
    }
}

pub(super) trait RawHandle {
    fn raw(&self) -> sys::nvs_handle_t;
}
impl RawHandle for ReadHandle<'_> {
    fn raw(&self) -> sys::nvs_handle_t {
        self.raw
    }
}

struct Entries<'handle, H: RawHandle> {
    raw: sys::nvs_iterator_t,
    _owner: &'handle H,
}
impl<H: RawHandle> Drop for Entries<'_, H> {
    fn drop(&mut self) {
        // SDK next() consumes/updates its pointer. Never retain a copied pointer
        // or release the pre-next value. NULL is allowed by the SDK.
        unsafe {
            sys::nvs_release_iterator(self.raw);
        }
    }
}
struct Info(sys::nvs_entry_info_t);
impl Drop for Info {
    fn drop(&mut self) {
        self.0.namespace_name.zeroize();
        self.0.key.zeroize();
        self.0.type_ = 0;
    }
}
pub(super) struct Name {
    bytes: Zeroizing<[u8; 16]>,
    len: usize,
}
impl Name {
    pub(super) fn from_bytes(b: &[u8]) -> Result<Self, InventoryHold> {
        if b.is_empty() || b.len() > 15 || !b.is_ascii() || b.contains(&0) {
            return Err(InventoryHold::Format);
        }
        let mut out = Self {
            bytes: Zeroizing::new([0; 16]),
            len: b.len(),
        };
        out.bytes[..b.len()].copy_from_slice(b);
        Ok(out)
    }
    fn from_raw(b: &[core::ffi::c_char; 16]) -> Result<Self, InventoryHold> {
        let mut bytes = Zeroizing::new([0; 16]);
        for (out, &v) in bytes.iter_mut().zip(b) {
            *out = v as u8;
        }
        let len = bytes
            .iter()
            .position(|&v| v == 0)
            .ok_or(InventoryHold::Format)?;
        Self::from_bytes(&bytes[..len])
    }
    fn text(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).expect("validated ASCII name")
    }
    pub(super) fn ptr(&self) -> *const core::ffi::c_char {
        self.bytes.as_ptr().cast()
    }
}
#[derive(PartialEq, Eq)]
pub(super) struct OwnedBlob {
    pub(super) key: String,
    pub(super) bytes: Vec<u8>,
}

pub(super) fn collect<H: RawHandle>(
    handle: &H,
    namespace: &str,
) -> Result<Vec<OwnedBlob>, InventoryHold> {
    let mut it = Entries {
        raw: ptr::null_mut(),
        _owner: handle,
    };
    // SAFETY: valid live handle, exact SDK enum and initialized output pointer.
    let start = unsafe {
        sys::nvs_entry_find_in_handle(handle.raw(), sys::nvs_type_t_NVS_TYPE_ANY, &mut it.raw)
    };
    if start == sys::ESP_ERR_NVS_NOT_FOUND {
        if !it.raw.is_null() {
            return Err(InventoryHold::Storage);
        }
        return Ok(Vec::new());
    }
    if start != sys::ESP_OK || it.raw.is_null() {
        return Err(InventoryHold::Storage);
    }
    let mut out: Vec<OwnedBlob> = Vec::new();
    loop {
        if out.len() >= 35 {
            return Err(InventoryHold::Format);
        }
        let mut info = Info(sys::nvs_entry_info_t::default());
        // SAFETY: non-null live iterator and valid zero-initialized output.
        if unsafe { sys::nvs_entry_info(it.raw, &mut info.0) } != sys::ESP_OK {
            return Err(InventoryHold::Storage);
        }
        let ns = Name::from_raw(&info.0.namespace_name)?;
        let name = Name::from_raw(&info.0.key)?;
        if ns.text() != namespace || info.0.type_ != sys::nvs_type_t_NVS_TYPE_BLOB {
            return Err(InventoryHold::Format);
        }
        let width = journal::expected_blob_width(name.text()).ok_or(InventoryHold::Format)?;
        if out.iter().any(|b| b.key == name.text()) {
            return Err(InventoryHold::Format);
        }
        let mut length = 0;
        // Query exactly this enumerated blob, then read it at its frozen width.
        if unsafe { sys::nvs_get_blob(handle.raw(), name.ptr(), ptr::null_mut(), &mut length) }
            != sys::ESP_OK
        {
            return Err(InventoryHold::Storage);
        }
        if length != width {
            return Err(InventoryHold::Format);
        }
        let mut bytes = vec![0; width];
        if unsafe {
            sys::nvs_get_blob(
                handle.raw(),
                name.ptr(),
                bytes.as_mut_ptr().cast(),
                &mut length,
            )
        } != sys::ESP_OK
        {
            return Err(InventoryHold::Storage);
        }
        if length != width {
            return Err(InventoryHold::Format);
        }
        out.push(OwnedBlob {
            key: name.text().to_owned(),
            bytes,
        });
        // SAFETY: mutate only the current pointer. Any non-NOT_FOUND error is
        // HOLD, never end-of-inventory. Pointer/status contradictions also HOLD.
        let err = unsafe { sys::nvs_entry_next(&mut it.raw) };
        if err == sys::ESP_ERR_NVS_NOT_FOUND {
            if !it.raw.is_null() {
                return Err(InventoryHold::Storage);
            }
            break;
        }
        if err != sys::ESP_OK || it.raw.is_null() {
            return Err(InventoryHold::Storage);
        }
    }
    out.sort_unstable_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

/// Root-only caller derives the namespace; the original master NVS holds the
/// default partition alive. Two matching scans detect observed drift, not ABA
/// or atomicity against independently opened writers. Report remains local only.
pub(super) fn inspect(
    owner: &EspNvs<NvsDefault>,
    namespace: &str,
    root: &super::NormalizedMasterRootV1,
    issuer: &[u8; 32],
) -> Result<super::Report, InventoryHold> {
    let handle = ReadHandle::open(owner, namespace)?;
    let first = collect(&handle, namespace)?;
    let second = collect(&handle, namespace)?;
    if first != second {
        return Err(InventoryHold::Changed);
    }
    let blobs: Vec<_> = first
        .iter()
        .map(|b| super::StoredBlob {
            key: &b.key,
            bytes: &b.bytes,
        })
        .collect();
    journal::inspect(root, issuer, &blobs)
}
