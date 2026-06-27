// firmware/src/personas.rs
//
// Persisted persona registry. Each entry maps a derived identity's x-only
// pubkey to the (master_slot, purpose, index) needed to re-derive its signing
// key on demand. This lets a persona be addressed by its own bunker URI and
// survive reboot. Only metadata is stored — never key material; the secret is
// re-derived from the owning master's secret when a request arrives.
//
// NVS key names are capped at 15 chars by ESP-IDF, so per-entry keys use the
// compact `p{n}_*` form (the master module uses the longer `master_{slot}_*`).

use esp_idf_svc::nvs::{EspNvs, NvsDefault};

/// Maximum number of personas the device can hold.
pub const MAX_PERSONAS: u8 = 32;

/// A persisted persona (no secret — re-derived from the owning master on use).
pub struct LoadedPersona {
    pub master_slot: u8,
    pub purpose: String,
    pub index: u32,
    pub name: Option<String>,
    pub pubkey: [u8; 32],
}

/// Read the persona count from NVS.
pub fn read_count(nvs: &EspNvs<NvsDefault>) -> u8 {
    let mut buf = [0u8; 1];
    match nvs.get_blob("persona_count", &mut buf) {
        Ok(Some(b)) if b.len() == 1 => buf[0],
        _ => 0,
    }
}

fn write_count(nvs: &mut EspNvs<NvsDefault>, count: u8) -> Result<(), &'static str> {
    nvs.set_blob("persona_count", &[count])
        .map_err(|_| "failed to write persona_count")
}

/// Load all personas from NVS into memory.
pub fn load_all(nvs: &EspNvs<NvsDefault>) -> Vec<LoadedPersona> {
    let count = read_count(nvs);
    let mut out = Vec::with_capacity(count as usize);
    for n in 0..count {
        match load_one(nvs, n) {
            Some(p) => out.push(p),
            None => log::warn!("Failed to load persona entry {n}"),
        }
    }
    out
}

fn load_one(nvs: &EspNvs<NvsDefault>, n: u8) -> Option<LoadedPersona> {
    let mut ms = [0u8; 1];
    match nvs.get_blob(&format!("p{n}_ms"), &mut ms) {
        Ok(Some(b)) if b.len() == 1 => {}
        _ => return None,
    }

    let mut ix = [0u8; 4];
    match nvs.get_blob(&format!("p{n}_ix"), &mut ix) {
        Ok(Some(b)) if b.len() == 4 => {}
        _ => return None,
    }

    let mut pubkey = [0u8; 32];
    match nvs.get_blob(&format!("p{n}_pk"), &mut pubkey) {
        Ok(Some(b)) if b.len() == 32 => {}
        _ => return None,
    }

    let mut purpose_buf = [0u8; 128];
    let purpose = match nvs.get_blob(&format!("p{n}_pp"), &mut purpose_buf) {
        Ok(Some(b)) if !b.is_empty() => String::from_utf8_lossy(b).to_string(),
        _ => return None,
    };

    let mut name_buf = [0u8; 64];
    let name = match nvs.get_blob(&format!("p{n}_nm"), &mut name_buf) {
        Ok(Some(b)) if !b.is_empty() => Some(String::from_utf8_lossy(b).to_string()),
        _ => None,
    };

    Some(LoadedPersona {
        master_slot: ms[0],
        purpose,
        index: u32::from_be_bytes(ix),
        name,
        pubkey,
    })
}

/// Whether a pubkey is already in the in-memory registry.
pub fn contains_pubkey(personas: &[LoadedPersona], pubkey: &[u8; 32]) -> bool {
    personas.iter().any(|p| &p.pubkey == pubkey)
}

/// Find a persona by x-only public key (32 bytes).
pub fn find_by_pubkey(personas: &[LoadedPersona], pubkey: &[u8; 32]) -> Option<usize> {
    personas.iter().position(|p| &p.pubkey == pubkey)
}

/// Persist a new persona to NVS. The caller is responsible for checking the
/// in-memory registry first (`contains_pubkey`) so the same identity isn't
/// stored twice.
pub fn add(
    nvs: &mut EspNvs<NvsDefault>,
    master_slot: u8,
    purpose: &str,
    index: u32,
    name: Option<&str>,
    pubkey: &[u8; 32],
) -> Result<(), &'static str> {
    let count = read_count(nvs);
    if count >= MAX_PERSONAS {
        return Err("maximum personas reached");
    }
    let n = count;

    nvs.set_blob(&format!("p{n}_ms"), &[master_slot])
        .map_err(|_| "failed to write persona master_slot")?;
    nvs.set_blob(&format!("p{n}_ix"), &index.to_be_bytes())
        .map_err(|_| "failed to write persona index")?;
    nvs.set_blob(&format!("p{n}_pk"), pubkey)
        .map_err(|_| "failed to write persona pubkey")?;
    nvs.set_blob(&format!("p{n}_pp"), purpose.as_bytes())
        .map_err(|_| "failed to write persona purpose")?;
    nvs.set_blob(&format!("p{n}_nm"), name.unwrap_or("").as_bytes())
        .map_err(|_| "failed to write persona name")?;

    write_count(nvs, count + 1)?;
    log::info!("Stored persona entry {n}: purpose={purpose} index={index}");
    Ok(())
}
