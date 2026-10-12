//! Dormant dedicated-partition owner. Acquisition may initialize/recover NVS
//! metadata, but never erases, falls back, retries or deinitializes. This is not
//! migration, measured-capacity, selected-master or witness authority.
#![allow(dead_code)]
#![cfg_attr(test, allow(unused_unsafe))]
use super::{crypto, journal, journal_nvs, HeldAllocationRoot, InventoryHold, Report, StoredBlob};
#[cfg(test)]
use crate::allocation_partition_host_sys as sys;
#[cfg(not(test))]
use esp_idf_svc::sys;
use sha2::{Digest, Sha256};
use std::{
    marker::PhantomData,
    ptr,
    rc::Rc,
    sync::atomic::{AtomicU8, Ordering},
};
use zeroize::Zeroizing;
include!("allocation_partition_profiles.rs");
const VIRGIN: u8 = 0;
const ACQUIRING: u8 = 1;
const LIVE: u8 = 2;
const POISONED: u8 = 3;
const RETIRED: u8 = 4;
static BOOT: AtomicU8 = AtomicU8::new(VIRGIN);
const LABEL: &[u8] = b"hwalloc\0";
const MIB: u32 = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Board {
    V3,
    V4,
    TDisplay,
    C6,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Observation {
    chip: *mut sys::esp_flash_t,
    partition: *const sys::esp_partition_t,
    physical: u32,
    addressable: u32,
    fingerprint: [u8; 32],
    offset: u32,
}
// No caller-supplied bytes/label/profile, public handle, Clone or Debug. Rc's
// marker prevents moving/sharing the driver owner across execution threads.
pub(super) struct AllocationPartition {
    board: Board,
    observed: Observation,
    _thread: PhantomData<Rc<()>>,
}
struct Acquisition;
impl Drop for Acquisition {
    fn drop(&mut self) {
        let _ = BOOT.compare_exchange(ACQUIRING, POISONED, Ordering::SeqCst, Ordering::SeqCst);
    }
}
impl AllocationPartition {
    #[cfg(not(test))]
    pub(super) fn acquire() -> Result<Self, InventoryHold> {
        #[cfg(feature = "heltec-v3")]
        let board = Board::V3;
        #[cfg(feature = "heltec-v4")]
        let board = Board::V4;
        #[cfg(feature = "tdisplay")]
        let board = Board::TDisplay;
        #[cfg(feature = "c6")]
        let board = Board::C6;
        Self::acquire_for_board(board)
    }
    fn acquire_for_board(board: Board) -> Result<Self, InventoryHold> {
        BOOT.compare_exchange(VIRGIN, ACQUIRING, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| InventoryHold::Storage)?;
        let _attempt = Acquisition;
        let observed = observe(board)?;
        if observe(board)? != observed {
            return Err(InventoryHold::Changed);
        }
        // SAFETY: the SDK descriptor has been checked against actual default
        // chip bytes/geometry twice. No convenience wrapper or auto erase.
        // Even ESP_OK may involve normal metadata writes/recovery.
        let err = unsafe { sys::nvs_flash_init_partition_ptr(observed.partition) };
        // Check after init on error too; the entire acquisition is terminal.
        let after = observe(board);
        if after? != observed {
            return Err(InventoryHold::Changed);
        }
        if err != sys::ESP_OK {
            return Err(InventoryHold::Storage);
        }
        BOOT.compare_exchange(ACQUIRING, LIVE, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| InventoryHold::Changed)?;
        Ok(Self {
            board,
            observed,
            _thread: PhantomData,
        })
    }
    fn recheck(&self) -> Result<(), InventoryHold> {
        if BOOT.load(Ordering::SeqCst) != LIVE {
            return Err(InventoryHold::Changed);
        }
        let result = observe(self.board).and_then(|now| {
            if now == self.observed {
                Ok(())
            } else {
                Err(InventoryHold::Changed)
            }
        });
        if result.is_err() {
            BOOT.store(POISONED, Ordering::SeqCst);
        }
        result
    }
    /// Only an actually held root can select the internal namespace. The
    /// resulting report proves local authenticated bytes, never first use.
    pub(super) fn inspect(&self, root: &HeldAllocationRoot<'_>) -> Result<Report, InventoryHold> {
        let result = (|| {
            root.recheck().map_err(|_| InventoryHold::Custody)?;
            self.recheck()?;
            if !crypto::backend_ready() {
                return Err(InventoryHold::Crypto);
            }
            let namespace = Zeroizing::new(journal::namespace(&root.root));
            let handle = ReadHandle::open(self, &namespace)?;
            let first = journal_nvs::collect(&handle, &namespace)?;
            let second = journal_nvs::collect(&handle, &namespace)?;
            if first != second {
                return Err(InventoryHold::Changed);
            }
            let blobs: Vec<_> = first
                .iter()
                .map(|b| StoredBlob {
                    key: &b.key,
                    bytes: &b.bytes,
                })
                .collect();
            journal::inspect(&root.root, &root.issuer, &blobs)
        })(); // All iterators and the handle close before both final checks.
        let custody = root.recheck().map_err(|_| InventoryHold::Custody);
        let identity = self.recheck(); // Also on error, even if root check fails.
        identity?;
        custody?;
        result
    }
}
impl Drop for AllocationPartition {
    fn drop(&mut self) {
        let _ = BOOT.compare_exchange(LIVE, RETIRED, Ordering::SeqCst, Ordering::SeqCst);
        // Driver intentionally remains initialized until reset. No deinit.
    }
}
struct Partitions(sys::esp_partition_iterator_t);
impl Drop for Partitions {
    fn drop(&mut self) {
        unsafe { sys::esp_partition_iterator_release(self.0) }
    }
}
fn observe(board: Board) -> Result<Observation, InventoryHold> {
    let chip = unsafe { sys::esp_flash_default_chip };
    if chip.is_null() {
        return Err(InventoryHold::Storage);
    }
    let (mut physical, mut addressable) = (0u32, 0u32);
    // SDK get_size is configured/image-header size, NOT physical capacity.
    if unsafe { sys::esp_flash_get_physical_size(chip, &mut physical) } != sys::ESP_OK
        || unsafe { sys::esp_flash_get_size(chip, &mut addressable) } != sys::ESP_OK
    {
        return Err(InventoryHold::Storage);
    }
    if ![4 * MIB, 8 * MIB, 16 * MIB].contains(&physical)
        || ![4 * MIB, 8 * MIB, 16 * MIB].contains(&addressable)
        || addressable > physical
    {
        return Err(InventoryHold::Binding);
    }
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 256];
    for offset in (0..4096u32).step_by(256) {
        if unsafe { sys::esp_flash_read(chip, chunk.as_mut_ptr().cast(), 0x8000 + offset, 256) }
            != sys::ESP_OK
        {
            return Err(InventoryHold::Storage);
        }
        hash.update(chunk);
    }
    let fingerprint: [u8; 32] = hash.finalize().into();
    let offset = match (board, physical, fingerprint) {
        (Board::V3 | Board::V4, n, STANDARD) if n == 8 * MIB => 0x420000,
        (Board::V4, n, STANDARD | LEGACY_TWO | LEGACY_BIG) if n == 16 * MIB => 0x420000,
        (Board::TDisplay | Board::C6, n, SINGLE) if n == 4 * MIB => 0x320000,
        _ => return Err(InventoryHold::Binding),
    };
    // These exact profiles end at the allocation partition's end; every old
    // range is below it. Addressability is checked independently of physical.
    if offset + 0x40000 > addressable {
        return Err(InventoryHold::Binding);
    }
    let mut entries = Partitions(unsafe {
        sys::esp_partition_find(
            sys::esp_partition_type_t_ESP_PARTITION_TYPE_ANY,
            sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY,
            LABEL.as_ptr().cast(),
        )
    });
    if entries.0.is_null() {
        return Err(InventoryHold::Missing);
    }
    let partition = unsafe { sys::esp_partition_get(entries.0) };
    if partition.is_null() {
        return Err(InventoryHold::Storage);
    }
    // SAFETY: descriptor returned by the live SDK iterator is stable for the
    // app lifetime. Never dereference a caller's pointer or old observation.
    let p = unsafe { &*partition };
    let mut label = [0u8; 17];
    label[..7].copy_from_slice(&LABEL[..7]);
    if p.flash_chip != chip
        || p.type_ != sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA
        || p.subtype != sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_DATA_NVS
        || p.address != offset
        || p.size != 0x40000
        || p.erase_size != 4096
        || p.encrypted
        || p.readonly
        || p.label.map(|v| v as u8) != label
    {
        return Err(InventoryHold::Binding);
    }
    entries.0 = unsafe { sys::esp_partition_next(entries.0) };
    if !entries.0.is_null() {
        return Err(InventoryHold::Binding);
    }
    Ok(Observation {
        chip,
        partition,
        physical,
        addressable,
        fingerprint,
        offset,
    })
}
struct ReadHandle<'a> {
    owner: &'a AllocationPartition,
    raw: sys::nvs_handle_t,
}
impl<'a> ReadHandle<'a> {
    fn open(owner: &'a AllocationPartition, namespace: &str) -> Result<Self, InventoryHold> {
        let name = journal_nvs::Name::from_bytes(namespace.as_bytes())?;
        owner.recheck()?;
        let mut out = Self { owner, raw: 0 };
        let err = unsafe {
            sys::nvs_open_from_partition(
                LABEL.as_ptr().cast(),
                name.ptr(),
                sys::nvs_open_mode_t_NVS_READONLY,
                &mut out.raw,
            )
        };
        owner.recheck()?; // out closes even on a postcheck failure/status conflict.
        if err == sys::ESP_ERR_NVS_NOT_FOUND && out.raw == 0 {
            return Err(InventoryHold::Missing);
        }
        if err != sys::ESP_OK || out.raw == 0 {
            return Err(InventoryHold::Storage);
        }
        Ok(out)
    }
}
impl journal_nvs::RawHandle for ReadHandle<'_> {
    fn raw(&self) -> sys::nvs_handle_t {
        self.raw
    }
    fn recheck(&self) -> Result<(), InventoryHold> {
        self.owner.recheck()
    }
}
impl Drop for ReadHandle<'_> {
    fn drop(&mut self) {
        if self.raw != 0 {
            unsafe { sys::nvs_close(self.raw) }
        }
    }
}
#[cfg(test)]
#[path = "../../common/src/allocation_partition_host_tests.rs"]
mod tests;
