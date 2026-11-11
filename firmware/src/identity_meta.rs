// firmware/src/identity_meta.rs
//
// Per-identity DISPLAY metadata — a human name and a small pre-resized avatar
// bitmap — provisioned by Sapwood at setup (SET_IDENTITY_META, 0x5B) and stored
// on the signer. The device never fetches or JPEG-decodes an image itself (that
// won't fit ESP32 RAM); Sapwood does the shrink in-browser and hands over ready
// Rgb565 bytes (two a pixel) or RGB332 bytes (one a pixel; the length picks,
// see `heartwood_common::identity_avatar`). See docs / memory:
// signer-display-metadata-provisioned.
//
// Stored in NVS keyed by MASTER SLOT (master-only display for now), as
// `[w][h][pixels]` exactly as received: never expanded, so a 64x64 RGB332
// picture costs 4,098 bytes where Rgb565 costs 8,194. NVS is only 16-24KB, so
// one ~8KB avatar is fine; per-persona avatars will need a dedicated flash
// region rather than NVS.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};

use crate::masters::LoadedMaster;

/// A signer identity's display metadata: name + a square avatar.
pub struct IdentityMeta {
    pub name: String,
    pub w: u8,
    pub h: u8,
    /// `w*h*2` bytes, Rgb565 big-endian (each pixel high byte first), or
    /// `w*h` bytes, RGB332 (`RRRGGGBB`); `identity_avatar::classify` says which.
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
    write_avatar_blob(nvs, &format!("imav{slot}"), &blob)
}

/// Write the avatar blob. ESP-IDF writes a new blob before it erases the one
/// it replaces, so on a tight partition a smaller picture cannot land beside
/// the stored one. When the write fails and an older picture is stored, erase
/// it and write once more, but only if the room estimate says the new blob
/// then fits (`identity_avatar::replace_verdict`): a working picture is never
/// removed for a write that would still fail, or when the stats cannot be
/// read. The picture is cosmetic; Sapwood can send it again.
fn write_avatar_blob(nvs: &mut EspNvs<NvsDefault>, key: &str, blob: &[u8]) -> Result<(), String> {
    let first = match nvs.set_blob(key, blob) {
        Ok(_) => return Ok(()),
        Err(e) => format!("avatar blob: {e:?}"),
    };
    let Ok(Some(old_len)) = nvs.blob_len(key) else {
        return Err(first);
    };
    let room = crate::nvs_stats::read().map(|stats| heartwood_common::nvs_room::NvsRoom {
        free_entries: stats.free_entries,
        total_entries: stats.total_entries,
        reclaimable_entries: 0,
    });
    let verdict = heartwood_common::identity_avatar::replace_verdict(blob.len(), old_len, room);
    if !verdict.remove_and_retry() {
        log::warn!("[idmeta] avatar write failed ({verdict:?}); stored picture kept");
        return Err(first);
    }
    log::warn!("[idmeta] avatar write failed; removing the {old_len}-byte stored picture and retrying once");
    nvs.remove(key).map_err(|e| format!("avatar blob: remove old: {e:?}"))?;
    nvs.set_blob(key, blob)
        .map_err(|e| format!("avatar blob (old picture removed): {e:?}"))
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
    if heartwood_common::identity_avatar::classify(w, h, avatar.len()).is_none() {
        return None; // corrupt / partial
    }
    Some(IdentityMeta { name, w, h, avatar })
}

/// Parse + store a SET_IDENTITY_META payload. Returns true (ACK) on success.
/// Payload: `[pubkey 32][w 1][h 1][name_len 1][name UTF-8][avatar]`, the
/// avatar `w*h*2` bytes (Rgb565) or `w*h` bytes (RGB332).
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
    if heartwood_common::identity_avatar::classify(w, h, avatar.len()).is_none() {
        log::warn!("[idmeta] avatar len {} is not {}*{}*2 or {}*{}", avatar.len(), w, h, w, h);
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
