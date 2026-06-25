//! Flash-backed key store.
//!
//! The lx106 has no NVS, so the master seed and the bridge-session secret live
//! in a reserved 4 KB flash sector — read once at boot, (re)written by the
//! provisioning frames. Record layout:
//!
//! ```text
//! [magic "HWK1" (4)] [master_seed (32)] [bridge_secret (32)] [crc32-le (4)]
//! ```
//!
//! NOTE: `esp8266-hal`'s flash ops return `Result<(), Void>` (never error), so
//! writes are best-effort — we cannot detect a failed erase/write here.

use esp8266_hal::flash::ESPFlash;

/// Reserved key-store sector. Well clear of the firmware image (~172 KB from
/// 0x0) and below the top system-param sectors of the 4 MB flash.
const KEY_SECTOR_ADDR: u32 = 0x3F_0000;
const MAGIC: [u8; 4] = *b"HWK1";
const RECORD_LEN: usize = 4 + 32 + 32 + 4;

#[derive(Clone)]
pub struct Keys {
    pub master_seed: [u8; 32],
    pub bridge_secret: [u8; 32],
}

/// Read the key record from flash. `None` if unprovisioned or corrupt.
pub fn load(flash: &mut ESPFlash) -> Option<Keys> {
    let mut buf = [0u8; RECORD_LEN];
    flash.read(KEY_SECTOR_ADDR, &mut buf).ok()?;
    if buf[0..4] != MAGIC {
        return None;
    }
    let want = u32::from_le_bytes([buf[68], buf[69], buf[70], buf[71]]);
    if crc32fast::hash(&buf[0..68]) != want {
        return None;
    }
    let mut keys = Keys { master_seed: [0u8; 32], bridge_secret: [0u8; 32] };
    keys.master_seed.copy_from_slice(&buf[4..36]);
    keys.bridge_secret.copy_from_slice(&buf[36..68]);
    Some(keys)
}

/// Erase the sector and write the key record (best-effort — see module note).
pub fn store(flash: &mut ESPFlash, keys: &Keys) {
    let mut buf = [0u8; RECORD_LEN];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4..36].copy_from_slice(&keys.master_seed);
    buf[36..68].copy_from_slice(&keys.bridge_secret);
    let crc = crc32fast::hash(&buf[0..68]);
    buf[68..72].copy_from_slice(&crc.to_le_bytes());

    let _ = flash.erase_sectors(KEY_SECTOR_ADDR, 1);
    let _ = flash.write_bytes(KEY_SECTOR_ADDR, &buf);
}
