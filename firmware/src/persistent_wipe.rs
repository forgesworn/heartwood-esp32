//! Complete persistent-state erasure for destructive reset paths.
//!
//! The web flasher's `config` partition is a second source of Wi-Fi and
//! operator state: erasing NVS alone lets that state seed itself back on the
//! next boot. Both physical factory reset and the PIN-attempt threshold call
//! this module, which erases and verifies `config` first, then the complete NVS
//! partition. A caller must not reboot or claim success when this returns an
//! error.

use core::ffi::{c_char, c_void};
use core::fmt;

use esp_idf_svc::sys;
use heartwood_common::persistent_state::{PersistentRegion, PERSISTENT_WIPE_ORDER};

const VERIFY_CHUNK: usize = 256;

/// A destructive erase or its full-partition verification failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WipeError {
    PartitionMissing(PersistentRegion),
    Erase {
        region: PersistentRegion,
        code: sys::esp_err_t,
    },
    VerifyRead {
        region: PersistentRegion,
        code: sys::esp_err_t,
    },
    VerifyNotBlank(PersistentRegion),
}

impl fmt::Display for WipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PartitionMissing(region) => {
                write!(f, "{} partition not found", region_name(*region))
            }
            Self::Erase { region, code } => {
                write!(f, "{} erase failed ({code})", region_name(*region))
            }
            Self::VerifyRead { region, code } => {
                write!(f, "{} verify read failed ({code})", region_name(*region))
            }
            Self::VerifyNotBlank(region) => {
                write!(f, "{} was not blank after erase", region_name(*region))
            }
        }
    }
}

fn region_name(region: PersistentRegion) -> &'static str {
    match region {
        PersistentRegion::FlashConfig => "config",
        PersistentRegion::Nvs => "nvs",
    }
}

/// Erase every region capable of restoring signer configuration.
///
/// `config` is deliberately first. If it is absent (old partition tables), it
/// is already incapable of reseeding NVS and is treated as blank. NVS itself
/// is mandatory: a missing NVS partition is an error, not a successful reset.
/// Every present partition is read back in full and must contain only `0xff`.
pub fn erase_all() -> Result<(), WipeError> {
    for region in PERSISTENT_WIPE_ORDER {
        erase_region(region)?;
    }
    Ok(())
}

fn erase_region(region: PersistentRegion) -> Result<(), WipeError> {
    let partition = unsafe { find_partition(region) };
    if partition.is_null() {
        if region == PersistentRegion::FlashConfig {
            log::info!("[wipe] no config partition; nothing can re-seed NVS");
            return Ok(());
        }
        return Err(WipeError::PartitionMissing(region));
    }

    let size = unsafe { (*partition).size as usize };
    let erase_result = unsafe { sys::esp_partition_erase_range(partition, 0, size) };
    if erase_result != sys::ESP_OK {
        return Err(WipeError::Erase {
            region,
            code: erase_result,
        });
    }

    verify_blank(partition, size, region)?;
    log::warn!("[wipe] erased and verified {} partition ({size} bytes)", region_name(region));
    Ok(())
}

unsafe fn find_partition(region: PersistentRegion) -> *const sys::esp_partition_t {
    match region {
        PersistentRegion::FlashConfig => {
            let label = b"config\0";
            sys::esp_partition_find_first(
                sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
                sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY,
                label.as_ptr() as *const c_char,
            )
        }
        PersistentRegion::Nvs => sys::esp_partition_find_first(
            sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
            sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_DATA_NVS,
            core::ptr::null(),
        ),
    }
}

fn verify_blank(
    partition: *const sys::esp_partition_t,
    size: usize,
    region: PersistentRegion,
) -> Result<(), WipeError> {
    let mut offset = 0usize;
    let mut buf = [0u8; VERIFY_CHUNK];
    while offset < size {
        let len = core::cmp::min(buf.len(), size - offset);
        let read_result = unsafe {
            sys::esp_partition_read_raw(
                partition,
                offset,
                buf.as_mut_ptr() as *mut c_void,
                len,
            )
        };
        if read_result != sys::ESP_OK {
            return Err(WipeError::VerifyRead {
                region,
                code: read_result,
            });
        }
        if buf[..len].iter().any(|byte| *byte != 0xff) {
            return Err(WipeError::VerifyNotBlank(region));
        }
        offset += len;
    }
    Ok(())
}
