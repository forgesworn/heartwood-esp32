// firmware/src/data_key_store.rs
//
// The board side of `heartwood_common::data_key`: NVS as a `BlobStore`, the
// watchdog and TRNG as a `Platform`, and this boot's data key held in RAM.
//
// The data key sits in RAM for the boot once an unlock or an at-rest enable
// has produced it, next to the seeds it seals and the note key it wraps. It is
// needed later in the boot to change the PIN or vault key without re-sealing,
// and to enrol a phone. A plaintext board never has one.

use std::sync::Mutex;

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use crate::nvs::ReplaceBlob;
use heartwood_common::data_key::{BlobStore, Platform, StoreError, DK_LEN, MAX_PHONES_BLOB_LEN};
use zeroize::Zeroize;

/// Nothing this module stores is larger than the packed phone records.
const MAX_BLOB: usize = MAX_PHONES_BLOB_LEN;

/// NVS as the data-key store. Reads go through `blob_len` so a buffer is
/// always the stored size; a blob above [`MAX_BLOB`] is reported as an error,
/// never truncated.
pub struct NvsBlobs<'a>(pub &'a mut EspNvs<NvsDefault>);

impl NvsBlobs<'_> {
    fn get_from(nvs: &EspNvs<NvsDefault>, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let len = match nvs.blob_len(key) {
            Ok(None) => return Ok(None),
            Ok(Some(len)) if len <= MAX_BLOB => len,
            Ok(Some(_)) | Err(_) => return Err(StoreError),
        };
        let mut buf = vec![0u8; len.max(1)];
        match nvs.get_blob(key, &mut buf) {
            Ok(Some(bytes)) if bytes.len() == len => Ok(Some(bytes.to_vec())),
            _ => Err(StoreError),
        }
    }
}

impl BlobStore for NvsBlobs<'_> {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Self::get_from(self.0, key)
    }

    fn set(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.0.replace_blob(key, value).map_err(|_| StoreError)
    }

    fn remove(&mut self, key: &str) -> Result<(), StoreError> {
        self.0.remove(key).map(|_| ()).map_err(|_| StoreError)
    }
}

/// NVS as the data-key store for a revocation: writes go through
/// `ReplaceBlob::revoke_blob`, so a key whose policy allows it (the phone
/// records) is still rewritten when the partition has no room for a second
/// copy, by erasing first. Reads and removes are [`NvsBlobs`]'s.
pub struct RevokingBlobs<'a>(pub &'a mut EspNvs<NvsDefault>);

impl BlobStore for RevokingBlobs<'_> {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        NvsBlobs::get_from(self.0, key)
    }

    fn set(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.0.revoke_blob(key, value).map_err(|_| StoreError)
    }

    fn remove(&mut self, key: &str) -> Result<(), StoreError> {
        self.0.remove(key).map(|_| ()).map_err(|_| StoreError)
    }
}

/// TRNG, watchdog and progress for the data-key operations.
pub struct Board<'p> {
    pub progress: Option<&'p mut dyn FnMut(usize, usize)>,
}

impl Board<'_> {
    pub fn quiet() -> Board<'static> {
        Board { progress: None }
    }
}

impl Platform for Board<'_> {
    fn fill_random(&mut self, buf: &mut [u8]) {
        crate::fill_random(buf);
    }

    fn before_kdf(&mut self) {
        // Yield so IDLE0 runs between PBKDF2 stretches (its watchdog aborts
        // after 60 s of unbroken compute), then feed our own.
        esp_idf_hal::delay::FreeRtos::delay_ms(20);
        crate::wdt::feed();
    }

    fn progress(&mut self, done: usize, total: usize) {
        crate::wdt::feed();
        if let Some(p) = self.progress.as_mut() {
            p(done, total);
        }
    }
}

/// Locked restarts of a board with phones enrolled (u32, big-endian). Written
/// once per entry into the locked relay phase, not once per boot, so a board
/// with no phones never writes it and a brownout loop that never reaches WiFi
/// never wears it.
const LOCKED_BOOTS_KEY: &str = "lk_boots";
/// `[0]` when the owner has switched off the operator's lock announcement
/// (the one that p-tags a stable key). Absent means on.
const ANNOUNCE_OPERATOR_KEY: &str = "ann_op";

/// Count this locked restart and return the new count. A storage failure
/// still returns the incremented value. A count that fails to persist repeats
/// on the next restart, which a phone still prompts for, because it treats an
/// announcement as a duplicate only when the one-time author matches too.
pub fn next_locked_boot(nvs: &mut EspNvs<NvsDefault>) -> u32 {
    let mut buf = [0u8; 4];
    let current = match nvs.get_blob(LOCKED_BOOTS_KEY, &mut buf) {
        Ok(Some(b)) if b.len() == 4 => u32::from_be_bytes(buf),
        _ => 0,
    };
    let next = current.saturating_add(1);
    if let Err(e) = nvs.replace_blob(LOCKED_BOOTS_KEY, &next.to_be_bytes()) {
        log::warn!("locked-restart count not saved: {e}");
    }
    next
}

/// The locked-restart count as it stands, without counting anything. A relay
/// update carries it so it seals to the same size as this boot's lock
/// announcements.
pub fn locked_boots(nvs: &EspNvs<NvsDefault>) -> u32 {
    let mut buf = [0u8; 4];
    match nvs.get_blob(LOCKED_BOOTS_KEY, &mut buf) {
        Ok(Some(b)) if b.len() == 4 => u32::from_be_bytes(buf),
        _ => 0,
    }
}

/// Whether the locked board should also publish the operator's announcement.
pub fn announce_operator(nvs: &EspNvs<NvsDefault>) -> bool {
    let mut buf = [0u8; 1];
    !matches!(nvs.get_blob(ANNOUNCE_OPERATOR_KEY, &mut buf), Ok(Some([0])))
}

/// Switch the operator's lock announcement on (the default) or off.
pub fn set_announce_operator(nvs: &mut EspNvs<NvsDefault>, on: bool) -> Result<(), ()> {
    if on {
        nvs.remove(ANNOUNCE_OPERATOR_KEY).map(|_| ()).map_err(|_| ())
    } else {
        nvs.replace_blob(ANNOUNCE_OPERATOR_KEY, &[0]).map_err(|_| ())
    }
}

static DATA_KEY: Mutex<Option<[u8; DK_LEN]>> = Mutex::new(None);

/// This boot's data key, if it has one.
pub fn current() -> Option<[u8; DK_LEN]> {
    *DATA_KEY.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn remember(dk: [u8; DK_LEN]) {
    let mut slot = DATA_KEY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(old) = slot.as_mut() {
        old.zeroize();
    }
    *slot = Some(dk);
}

pub fn forget() {
    let mut slot = DATA_KEY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(old) = slot.as_mut() {
        old.zeroize();
    }
    *slot = None;
}
