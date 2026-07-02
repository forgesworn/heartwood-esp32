// firmware/src/identity_meta.rs
//
// Per-identity DISPLAY metadata — a human name and a small pre-resized avatar
// bitmap — provisioned by Sapwood at setup (SET_IDENTITY_META, 0x5B) and stored
// on the signer. The device never fetches or JPEG-decodes an image itself (that
// won't fit ESP32 RAM); Sapwood does the shrink in-browser and hands over ready
// Rgb565 bytes. See docs / memory: signer-display-metadata-provisioned.
//
// Stored in NVS keyed by MASTER SLOT (master-only display for now). NVS is only
// 16-24KB, so one ~8KB avatar is fine; per-persona avatars will need a dedicated
// flash region rather than NVS.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};

use crate::masters::LoadedMaster;

/// A signer identity's display metadata: name + a square Rgb565 avatar.
pub struct IdentityMeta {
    pub name: String,
    pub w: u8,
    pub h: u8,
    /// `w*h*2` bytes, Rgb565 big-endian (each pixel high byte first).
    pub avatar: Vec<u8>,
}

/// Persist display metadata for the master at `slot`, overwriting any existing.
pub fn save(
    nvs: &mut EspNvs<NvsDefault>,
    slot: u8,
    name: &str,
    w: u8,
    h: u8,
    avatar: &[u8],
) -> Result<(), String> {
    nvs.set_blob(&format!("iman{slot}"), name.as_bytes())
        .map_err(|e| format!("name blob: {e:?}"))?;
    let mut blob = Vec::with_capacity(2 + avatar.len());
    blob.push(w);
    blob.push(h);
    blob.extend_from_slice(avatar);
    nvs.set_blob(&format!("imav{slot}"), &blob)
        .map_err(|e| format!("avatar blob: {e:?}"))?;
    Ok(())
}

/// Load display metadata for the master at `slot`, if Sapwood has provisioned it.
pub fn load(nvs: &EspNvs<NvsDefault>, slot: u8) -> Option<IdentityMeta> {
    let mut name_buf = [0u8; 256];
    let name = match nvs.get_blob(&format!("iman{slot}"), &mut name_buf) {
        Ok(Some(b)) => String::from_utf8_lossy(b).into_owned(),
        _ => return None,
    };
    // Heap buffer sized to the stored blob (a 64x64 avatar is ~8KB — too big
    // for the task stack). Asking NVS for the exact length matters: a fixed
    // 24KB buffer needed a contiguous block a fragmented mid-TLS heap could
    // not supply, and OOM-aborted the relay loop (rst:0xc on the T-Display).
    let avatar_key = format!("imav{slot}");
    let blob_len = match nvs.blob_len(&avatar_key) {
        Ok(Some(n)) if n >= 2 => n,
        _ => return None,
    };
    let mut avatar_buf = vec![0u8; blob_len];
    let (w, h, avatar) = match nvs.get_blob(&avatar_key, &mut avatar_buf) {
        Ok(Some(b)) if b.len() >= 2 => (b[0], b[1], b[2..].to_vec()),
        _ => return None,
    };
    if avatar.len() != (w as usize) * (h as usize) * 2 {
        return None; // corrupt / partial
    }
    Some(IdentityMeta { name, w, h, avatar })
}

/// Parse + store a SET_IDENTITY_META payload. Returns true (ACK) on success.
/// Payload: `[pubkey 32][w 1][h 1][name_len 1][name UTF-8][avatar w*h*2]`.
/// The pubkey must match a loaded master (persona display is a later phase).
pub fn handle_frame(
    payload: &[u8],
    masters: &[LoadedMaster],
    nvs: &mut EspNvs<NvsDefault>,
) -> bool {
    if payload.len() < 35 {
        log::warn!("[idmeta] payload too short ({})", payload.len());
        return false;
    }
    let pubkey: [u8; 32] = match payload[0..32].try_into() {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let w = payload[32];
    let h = payload[33];
    let name_len = payload[34] as usize;
    if payload.len() < 35 + name_len {
        return false;
    }
    let name = match core::str::from_utf8(&payload[35..35 + name_len]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let avatar = &payload[35 + name_len..];
    if avatar.len() != (w as usize) * (h as usize) * 2 {
        log::warn!("[idmeta] avatar len {} != {}*{}*2", avatar.len(), w, h);
        return false;
    }
    let slot = match masters.iter().find(|m| m.pubkey == pubkey) {
        Some(m) => m.slot,
        None => {
            log::warn!("[idmeta] pubkey not a known master; ignoring");
            return false;
        }
    };
    match save(nvs, slot, name, w, h, avatar) {
        Ok(()) => {
            log::info!("[idmeta] stored meta for master slot {slot}: '{name}' {w}x{h}");
            true
        }
        Err(e) => {
            log::error!("[idmeta] save failed: {e}");
            false
        }
    }
}
