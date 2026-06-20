// firmware/src/boot_config.rs
//
//! Reads the flash-time `config` partition written by the web flasher
//! (Raspberry Pi Imager model — see
//! docs/2026-06-19-web-flasher-flash-and-configure.md). Validates a small
//! header + CRC32 and returns the `NetConfig` JSON; `main` seeds it into NVS on
//! first boot so the existing NVS read path is unchanged.
//!
//! Blob layout written by the flasher:
//!   "HWCF" (4) | version u8 (1) | json_len u16 LE (2) | crc32 u32 LE (4) | json | 0xFF pad
//!
//! A missing partition, blank flash (0xFF), bad magic/version/length, or a CRC
//! mismatch are all treated as "no flash-time config" — the device simply
//! carries on, so this is safe on devices flashed with the older 5-partition
//! table (the partition is just not found).

use core::ffi::{c_char, c_void};
use esp_idf_svc::sys;

const MAGIC: [u8; 4] = *b"HWCF";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 11; // 4 magic + 1 version + 2 len + 4 crc
const MAX_JSON: usize = 512; // matches net_config_store::NET_CONFIG_MAX_LEN

/// Read and validate the flash-time `config` partition. Returns the JSON bytes
/// and the blob's CRC32 (so `main` can detect a re-flash and re-seed), else
/// `None`.
pub fn read_flash_config() -> Option<(Vec<u8>, u32)> {
    unsafe {
        let label = b"config\0";
        let it = sys::esp_partition_find(
            sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
            sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY,
            label.as_ptr() as *const c_char,
        );
        if it.is_null() {
            return None;
        }
        let part = sys::esp_partition_get(it);
        sys::esp_partition_iterator_release(it);
        if part.is_null() {
            return None;
        }

        let mut header = [0u8; HEADER_LEN];
        if sys::esp_partition_read(part, 0, header.as_mut_ptr() as *mut c_void, HEADER_LEN)
            != sys::ESP_OK
        {
            return None;
        }
        if header[0..4] != MAGIC || header[4] != VERSION {
            return None;
        }
        let len = u16::from_le_bytes([header[5], header[6]]) as usize;
        let crc = u32::from_le_bytes([header[7], header[8], header[9], header[10]]);
        if len == 0 || len > MAX_JSON {
            return None;
        }

        let mut json = vec![0u8; len];
        if sys::esp_partition_read(part, HEADER_LEN, json.as_mut_ptr() as *mut c_void, len)
            != sys::ESP_OK
        {
            return None;
        }

        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&json);
        if hasher.finalize() != crc {
            log::warn!("[boot_config] config partition CRC mismatch — ignoring");
            return None;
        }
        log::info!("[boot_config] valid flash-time config ({len} bytes, crc {crc:08x})");
        Some((json, crc))
    }
}
