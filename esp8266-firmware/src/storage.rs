//! Flash-backed key store.
//!
//! The lx106 has no NVS, so the master seed, the bridge-session secret, and the
//! master's derivation mode live in a reserved 4 KB flash sector — read once at
//! boot, (re)written by the provisioning frames. Record layout:
//!
//! ```text
//! [magic "HWK2" (4)] [master_seed (32)] [bridge_secret (32)] [mode (1)] [crc32-le (4)]
//! ```
//!
//! The `mode` byte is the [`heartwood_common::types::MasterMode`] discriminant —
//! it decides how persona keys derive from the seed (tree modes treat the stored
//! secret as the tree root; Bunker HMACs it). Records written by the pre-mode
//! firmware ("HWK1", no mode byte) are still read and default to TreeMnemonic.
//!
//! NOTE: `esp8266-hal`'s flash ops return `Result<(), Void>` (never error), so
//! writes are best-effort — we cannot detect a failed erase/write here.

use esp8266_hal::flash::ESPFlash;

/// Reserved key-store sector. Well clear of the firmware image (~172 KB from
/// 0x0) and below the top system-param sectors of the 4 MB flash.
const KEY_SECTOR_ADDR: u32 = 0x3F_0000;
const MAGIC: [u8; 4] = *b"HWK2";
const MAGIC_V1: [u8; 4] = *b"HWK1"; // legacy: seed + bridge_secret, no mode byte
const RECORD_LEN: usize = 4 + 32 + 32 + 1 + 4; // 73

/// Default mode for a seed provisioned without an explicit mode (raw 32-byte
/// PROVISION form, or a legacy HWK1 record): treat the stored secret as the tree
/// root — matches the `mode:1` PROVISION_LIST has always reported.
pub const DEFAULT_MODE: u8 = 1; // MasterMode::TreeMnemonic

#[derive(Clone)]
pub struct Keys {
    pub master_seed: [u8; 32],
    pub bridge_secret: [u8; 32],
    /// MasterMode discriminant (0 Bunker, 1 TreeMnemonic, 2 TreeNsec).
    pub mode: u8,
}

/// Read the key record from flash. `None` if unprovisioned or corrupt.
pub fn load(flash: &mut ESPFlash) -> Option<Keys> {
    let mut buf = [0u8; RECORD_LEN];
    flash.read(KEY_SECTOR_ADDR, &mut buf).ok()?;

    if buf[0..4] == MAGIC {
        // v2: master_seed + bridge_secret + mode, crc over the first 69 bytes.
        let want = u32::from_le_bytes([buf[69], buf[70], buf[71], buf[72]]);
        if crc32fast::hash(&buf[0..69]) != want {
            return None;
        }
        let mut keys = Keys { master_seed: [0u8; 32], bridge_secret: [0u8; 32], mode: buf[68] };
        keys.master_seed.copy_from_slice(&buf[4..36]);
        keys.bridge_secret.copy_from_slice(&buf[36..68]);
        Some(keys)
    } else if buf[0..4] == MAGIC_V1 {
        // Legacy record (no mode byte): crc over the first 68 bytes; default mode.
        let want = u32::from_le_bytes([buf[68], buf[69], buf[70], buf[71]]);
        if crc32fast::hash(&buf[0..68]) != want {
            return None;
        }
        let mut keys =
            Keys { master_seed: [0u8; 32], bridge_secret: [0u8; 32], mode: DEFAULT_MODE };
        keys.master_seed.copy_from_slice(&buf[4..36]);
        keys.bridge_secret.copy_from_slice(&buf[36..68]);
        Some(keys)
    } else {
        None
    }
}

/// Erase the sector and write the key record (best-effort — see module note).
pub fn store(flash: &mut ESPFlash, keys: &Keys) {
    let mut buf = [0u8; RECORD_LEN];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4..36].copy_from_slice(&keys.master_seed);
    buf[36..68].copy_from_slice(&keys.bridge_secret);
    buf[68] = keys.mode;
    let crc = crc32fast::hash(&buf[0..69]);
    buf[69..73].copy_from_slice(&crc.to_le_bytes());

    let _ = flash.erase_sectors(KEY_SECTOR_ADDR, 1);
    let _ = flash.write_bytes(KEY_SECTOR_ADDR, &buf);
}
