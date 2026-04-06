// firmware/src/masters.rs
//
// Multi-master NVS storage. Each master occupies a numbered slot (0-7)
// with a secret, label, mode, and cached pubkey.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use heartwood_common::types::MasterMode;
use zeroize::Zeroize;

/// Maximum number of masters the device can hold.
pub const MAX_MASTERS: u8 = 8;

/// A loaded master identity (secret material in memory).
pub struct LoadedMaster {
    pub slot: u8,
    pub secret: [u8; 32],
    pub label: String,
    pub mode: MasterMode,
    pub pubkey: [u8; 32],
}

impl Drop for LoadedMaster {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Read the master count from NVS.
pub fn read_master_count(nvs: &EspNvs<NvsDefault>) -> u8 {
    let mut buf = [0u8; 1];
    match nvs.get_blob("master_count", &mut buf) {
        Ok(Some(b)) if b.len() == 1 => buf[0],
        _ => 0,
    }
}

/// Write the master count to NVS.
fn write_master_count(nvs: &mut EspNvs<NvsDefault>, count: u8) -> Result<(), &'static str> {
    nvs.set_blob("master_count", &[count])
        .map_err(|_| "failed to write master_count")
}

/// Load all masters from NVS into memory.
pub fn load_all(nvs: &EspNvs<NvsDefault>) -> Vec<LoadedMaster> {
    let count = read_master_count(nvs);
    let mut masters = Vec::with_capacity(count as usize);

    for slot in 0..count {
        match load_one(nvs, slot) {
            Some(m) => masters.push(m),
            None => log::warn!("Failed to load master slot {slot}"),
        }
    }

    masters
}

/// Load a single master from NVS.
fn load_one(nvs: &EspNvs<NvsDefault>, slot: u8) -> Option<LoadedMaster> {
    let prefix = format!("master_{slot}");

    let mut secret = [0u8; 32];
    let secret_key = format!("{prefix}_secret");
    match nvs.get_blob(&secret_key, &mut secret) {
        Ok(Some(b)) if b.len() == 32 => {}
        _ => return None,
    }

    let mut label_buf = [0u8; 32];
    let label_key = format!("{prefix}_label");
    let label = match nvs.get_blob(&label_key, &mut label_buf) {
        Ok(Some(b)) => String::from_utf8_lossy(b).to_string(),
        _ => "default".to_string(),
    };

    let mut mode_buf = [0u8; 1];
    let mode_key = format!("{prefix}_mode");
    let mode = match nvs.get_blob(&mode_key, &mut mode_buf) {
        Ok(Some(b)) if b.len() == 1 => {
            MasterMode::from_u8(b[0]).unwrap_or(MasterMode::TreeMnemonic)
        }
        _ => MasterMode::TreeMnemonic,
    };

    let mut pubkey = [0u8; 32];
    let pubkey_key = format!("{prefix}_pubkey");
    match nvs.get_blob(&pubkey_key, &mut pubkey) {
        Ok(Some(b)) if b.len() == 32 => {}
        _ => return None,
    }

    Some(LoadedMaster {
        slot,
        secret,
        label,
        mode,
        pubkey,
    })
}

/// Add a new master to NVS. Returns the assigned slot number.
pub fn add_master(
    nvs: &mut EspNvs<NvsDefault>,
    secret: &[u8; 32],
    label: &str,
    mode: MasterMode,
    pubkey: &[u8; 32],
) -> Result<u8, &'static str> {
    let count = read_master_count(nvs);
    if count >= MAX_MASTERS {
        return Err("maximum masters reached");
    }

    let slot = count;
    let prefix = format!("master_{slot}");

    nvs.set_blob(&format!("{prefix}_secret"), secret)
        .map_err(|_| "failed to write secret")?;
    nvs.set_blob(&format!("{prefix}_label"), label.as_bytes())
        .map_err(|_| "failed to write label")?;
    nvs.set_blob(&format!("{prefix}_mode"), &[mode as u8])
        .map_err(|_| "failed to write mode")?;
    nvs.set_blob(&format!("{prefix}_pubkey"), pubkey)
        .map_err(|_| "failed to write pubkey")?;

    write_master_count(nvs, count + 1)?;

    log::info!("Added master slot {slot}: label={label}");
    Ok(slot)
}

/// Remove a master by slot index. Shifts higher slots down to fill the gap.
pub fn remove_master(nvs: &mut EspNvs<NvsDefault>, slot: u8) -> Result<(), &'static str> {
    let count = read_master_count(nvs);
    if slot >= count {
        return Err("slot out of range");
    }

    // Shift higher slots down.
    for i in slot..count - 1 {
        let src = format!("master_{}", i + 1);
        let dst = format!("master_{i}");

        for suffix in &["_secret", "_label", "_mode", "_pubkey", "_conn"] {
            let mut buf = [0u8; 64];
            let src_key = format!("{src}{suffix}");
            let dst_key = format!("{dst}{suffix}");
            if let Ok(Some(data)) = nvs.get_blob(&src_key, &mut buf) {
                let len = data.len();
                let _ = nvs.set_blob(&dst_key, &buf[..len]);
            }
        }
    }

    // Clear the last slot.
    let last = format!("master_{}", count - 1);
    for suffix in &["_secret", "_label", "_mode", "_pubkey", "_conn"] {
        let key = format!("{last}{suffix}");
        let _ = nvs.remove(&key);
    }

    write_master_count(nvs, count - 1)?;
    log::info!("Removed master slot {slot}");
    Ok(())
}

/// Find a master by x-only public key (32 bytes).
pub fn find_by_pubkey(masters: &[LoadedMaster], pubkey: &[u8; 32]) -> Option<usize> {
    masters.iter().position(|m| &m.pubkey == pubkey)
}
