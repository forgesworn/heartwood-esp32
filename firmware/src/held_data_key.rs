// Existing boot data-key ownership, with a nonblocking private custody guard.
use heartwood_common::data_key::{self, Purpose, DK_LEN};
use std::sync::{Mutex, MutexGuard};
use zeroize::{Zeroize, Zeroizing};

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

/// No seed or data-key export. Holding this prevents remember/forget until Drop.
/// A busy or poisoned mutex holds; never recover poison for new allocation work.
#[allow(dead_code)] // Dormant prerequisite; no runtime allocation owner yet.
pub(crate) struct HeldDataKey(MutexGuard<'static, Option<[u8; DK_LEN]>>);

#[allow(dead_code)]
impl HeldDataKey {
    pub(crate) fn try_hold() -> Result<Self, ()> {
        DATA_KEY.try_lock().map(Self).map_err(|_| ())
    }

    fn open_seed(&self, blob: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
        let key = self.0.as_ref()?;
        Some(Zeroizing::new(
            data_key::open(key, Purpose::Seed, blob).ok()?,
        ))
    }

    pub(crate) fn authenticates_seed(&self, blob: &[u8]) -> bool {
        self.open_seed(blob).is_some()
    }

    pub(crate) fn matches_seed(&self, blob: &[u8], loaded: &[u8; 32]) -> bool {
        self.open_seed(blob).is_some_and(|seed| *seed == *loaded)
    }
}
