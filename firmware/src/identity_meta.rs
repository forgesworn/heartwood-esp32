// firmware/src/identity_meta.rs
//
// Per-identity DISPLAY metadata — a human name and a small pre-resized avatar
// bitmap — provisioned by Sapwood at setup (SET_IDENTITY_META, 0x5B) and stored
// on the signer. The device never fetches or JPEG-decodes an image itself (that
// won't fit ESP32 RAM); Sapwood does the shrink in-browser and hands over ready
// Rgb565 bytes. See docs / memory: signer-display-metadata-provisioned.
//
// Stored in NVS keyed by MASTER SLOT (master-only display for now). The picture
// arrives as Rgb565 and is stored at one byte a pixel, RGB332, behind a version
// header (`heartwood_common::identity_avatar`), so a 48x48 one takes 2,308 bytes
// of a 16-24 KB partition rather than 4,610; pictures stored by earlier firmware
// are still read. Per-persona avatars will need a dedicated flash region rather
// than NVS.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use crate::nvs::ReplaceBlob;

use crate::masters::LoadedMaster;

/// A signer identity's display metadata: name + a square avatar.
pub struct IdentityMeta {
    pub name: String,
    pub w: u8,
    pub h: u8,
    /// The pixels, header stripped: `w*h` bytes of RGB332, or `w*h*2` of
    /// Rgb565 big-endian for a picture stored by earlier firmware. The length
    /// says which (`identity_avatar::classify`).
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
    use heartwood_common::identity_avatar::{encode_stored, StoreError};
    // `avatar` is the wire's Rgb565; one buffer of w*h + 4 bytes holds what
    // is stored.
    let blob = encode_stored(w, h, avatar).map_err(|e| match e {
        StoreError::BadLength => format!("avatar length {} != {w}*{h}*2", avatar.len()),
        StoreError::NoMemory => "avatar: device low on memory".to_string(),
    })?;
    // An avatar is the one large write a user makes besides a pairing; it
    // must not take the room that keeps the pairing tables and phone records
    // rewritable, nor be what the next save of them has to drop
    // (`nvs::avatar_allowed`).
    let avatar_key = format!("imav{slot}");
    if !crate::nvs::avatar_allowed(nvs, &avatar_key, blob.len()) {
        return Err("storage_full: not enough storage left for the avatar; the pairings need the room".into());
    }
    nvs.replace_blob(&format!("iman{slot}"), name.as_bytes())
        .map_err(|e| format!("name blob: {e:?}"))?;
    nvs.replace_blob(&avatar_key, &blob)
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
    // Heap buffer sized to the stored blob (a legacy 64x64 avatar is ~8KB,
    // too big for the task stack). Asking NVS for the exact length matters: a
    // fixed 24KB buffer needed a contiguous block a fragmented mid-TLS heap
    // could not supply, and OOM-aborted the relay loop (rst:0xc on the
    // T-Display). The one buffer is read into and then trimmed in place.
    let avatar_key = format!("imav{slot}");
    let blob_len = match nvs.blob_len(&avatar_key) {
        Ok(Some(n)) if n >= 2 => n,
        _ => return None,
    };
    let mut avatar = Vec::new();
    avatar.try_reserve_exact(blob_len).ok()?;
    avatar.resize(blob_len, 0);
    let read = match nvs.get_blob(&avatar_key, &mut avatar) {
        Ok(Some(b)) => b.len(),
        _ => return None,
    };
    avatar.truncate(read);
    // A version-1 or legacy picture; anything else is corrupt or partial.
    let stored = heartwood_common::identity_avatar::decode_stored(&avatar)?;
    avatar.drain(..stored.pixels_at);
    Some(IdentityMeta { name, w: stored.w, h: stored.h, avatar })
}

/// Parse + store a SET_IDENTITY_META payload. `Ok` (ACK) on success; `Err`
/// carries the NACK's payload, empty except for the growth gate's
/// `storage_full:` refusal, so a host can tell "free some room" from a bad
/// frame or a fault.
/// Payload: `[pubkey 32][w 1][h 1][name_len 1][name UTF-8][avatar w*h*2]`.
/// The pubkey must match a loaded master (persona display is a later phase).
pub fn handle_frame(
    payload: &[u8],
    masters: &[LoadedMaster],
    nvs: &mut EspNvs<NvsDefault>,
) -> Result<(), String> {
    if payload.len() < 35 {
        log::warn!("[idmeta] payload too short ({})", payload.len());
        return Err(String::new());
    }
    let pubkey: [u8; 32] = match payload[0..32].try_into() {
        Ok(pk) => pk,
        Err(_) => return Err(String::new()),
    };
    let w = payload[32];
    let h = payload[33];
    let name_len = payload[34] as usize;
    if payload.len() < 35 + name_len {
        return Err(String::new());
    }
    let name = match core::str::from_utf8(&payload[35..35 + name_len]) {
        Ok(s) => s,
        Err(_) => return Err(String::new()),
    };
    let avatar = &payload[35 + name_len..];
    if avatar.len() != (w as usize) * (h as usize) * 2 {
        log::warn!("[idmeta] avatar len {} != {}*{}*2", avatar.len(), w, h);
        return Err(String::new());
    }
    let slot = match masters.iter().find(|m| m.pubkey == pubkey) {
        Some(m) => m.slot,
        None => {
            log::warn!("[idmeta] pubkey not a known master; ignoring");
            return Err(String::new());
        }
    };
    match save(nvs, slot, name, w, h, avatar) {
        Ok(()) => {
            log::info!("[idmeta] stored meta for master slot {slot}: '{name}' {w}x{h}");
            Ok(())
        }
        Err(e) if e.starts_with("storage_full:") => {
            log::warn!("[idmeta] not stored: {e}");
            Err(e)
        }
        Err(e) => {
            log::error!("[idmeta] save failed: {e}");
            Err(String::new())
        }
    }
}
