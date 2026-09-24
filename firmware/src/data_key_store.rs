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
use heartwood_common::data_key::{BlobStore, Platform, StoreError, DK_LEN, MAX_PHONES_BLOB_LEN};
use zeroize::Zeroize;

/// Nothing this module stores is larger than the packed phone records.
const MAX_BLOB: usize = MAX_PHONES_BLOB_LEN;

/// NVS as the data-key store. Reads go through `blob_len` so a buffer is
/// always the stored size; a blob above [`MAX_BLOB`] is reported as an error,
/// never truncated.
pub struct NvsBlobs<'a>(pub &'a mut EspNvs<NvsDefault>);

impl BlobStore for NvsBlobs<'_> {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let len = match self.0.blob_len(key) {
            Ok(None) => return Ok(None),
            Ok(Some(len)) if len <= MAX_BLOB => len,
            Ok(Some(_)) | Err(_) => return Err(StoreError),
        };
        let mut buf = vec![0u8; len.max(1)];
        match self.0.get_blob(key, &mut buf) {
            Ok(Some(bytes)) if bytes.len() == len => Ok(Some(bytes.to_vec())),
            _ => Err(StoreError),
        }
    }

    fn set(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.0.set_blob(key, value).map_err(|_| StoreError)
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
