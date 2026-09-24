// common/src/data_key.rs
//
// The data key (DK) and its unlockers: phase 1 of phone unlock
// (docs/specs/2026-09-24-phone-unlock-design.md section 1).
//
// Before this module every seed was sealed DIRECTLY under the PIN or vault
// key, one 100k-round PBKDF2 per identity. Now a random 32-byte data key seals
// the seeds (and the note locker's key) with no stretching, and the data key
// itself is stored only in wrapped form, once per unlocker:
//
//   `dk_sec`   seed_cipher::encrypt_seed(secret, DK). The secret is the PIN or
//              the host-held vault key; the board holds one at a time, exactly
//              as before, so there is one wrapper for it.
//   `dk_ph`    the packed phone records (at most 16), each wrapping DK under a
//              key derived from that phone's slot secret S.
//
// An unlock is one stretch (or none, for a phone) instead of one per identity.
// Revoking a phone deletes its record; nothing is re-keyed.
//
// Sealed-blob construction: the note_seal shape (encrypt-then-MAC, the same
// shape NIP-44 v2 uses) with a fixed 32-byte payload and a purpose byte that is
// both authenticated and mixed into the sub-keys, so a sealed seed can never be
// accepted as a note key or a phone wrap:
//   enc_key = HMAC-SHA256(key, "heartwood-dk-enc" || purpose)
//   mac_key = HMAC-SHA256(key, "heartwood-dk-mac" || purpose)
//   ct      = ChaCha20(enc_key, nonce) XOR payload                 (32 bytes)
//   tag     = HMAC-SHA256(mac_key, magic || version || purpose || nonce || ct)
//   blob    = "HWDK" || version(1) || purpose(1) || nonce(12) || ct || tag
// 82 bytes, which is neither of seed_cipher's lengths (92, 101), so a seed
// blob identifies its own format on flash.
//
// Migration needs no separate journal, because every stored blob names its own
// format and the invariant below holds at every write:
//
//   A data-key-sealed seed exists on flash only while a `dk_sec` that opens
//   under the current secret exists.
//
// Every operation here writes in an order that keeps it (see the cut-point
// tests at the bottom). ESP-IDF NVS commits a blob write atomically: after a
// power cut either the old or the new value is present.

use alloc::string::String;
use alloc::vec::Vec;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::seed_cipher::{self, SeedCipherError};

type HmacSha256 = Hmac<Sha256>;

pub const DK_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 32;
/// magic(4) + version(1) + purpose(1) + nonce + ct(32) + tag.
pub const SEALED_LEN: usize = 4 + 1 + 1 + NONCE_LEN + DK_LEN + TAG_LEN; // 82

const SEALED_MAGIC: [u8; 4] = *b"HWDK";
const SEALED_VERSION: u8 = 1;
const HEADER_LEN: usize = 6;

/// NVS key holding the secret (PIN or vault key) wrapper of DK.
pub const SECRET_WRAP_KEY: &str = "dk_sec";
/// NVS key holding the packed phone records.
pub const PHONES_KEY: &str = "dk_ph";

/// The encrypted-seed key for a master slot. ESP-IDF caps NVS keys at 15
/// characters; this is the spelling `masters.rs` has always used.
pub fn seed_enc_key(slot: u8) -> String {
    alloc::format!("m{slot}_seed_enc")
}

/// The plaintext-seed key for a master slot.
pub fn seed_plain_key(slot: u8) -> String {
    alloc::format!("master_{slot}_secret")
}

/// What a sealed blob is for. Authenticated, so blobs cannot be swapped
/// between purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Purpose {
    Seed = 1,
    NoteKey = 2,
    PhoneWrap = 3,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SealError {
    /// Not a sealed blob of this format.
    BadFormat,
    /// Sealed for a different purpose.
    WrongPurpose,
    /// The MAC did not verify: wrong key or a tampered blob.
    WrongKeyOrTampered,
}

fn subkey(key: &[u8; DK_LEN], label: &[u8], purpose: Purpose) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(label);
    mac.update(&[purpose as u8]);
    mac.finalize().into_bytes().into()
}

/// Seal a 32-byte payload under a 32-byte key. `nonce` must be random and
/// fresh per seal; the caller supplies it so this stays deterministic and
/// host-testable.
pub fn seal(
    key: &[u8; DK_LEN],
    purpose: Purpose,
    payload: &[u8; DK_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; SEALED_LEN] {
    let mut enc = subkey(key, b"heartwood-dk-enc", purpose);
    let mut mk = subkey(key, b"heartwood-dk-mac", purpose);

    let mut out = [0u8; SEALED_LEN];
    out[..4].copy_from_slice(&SEALED_MAGIC);
    out[4] = SEALED_VERSION;
    out[5] = purpose as u8;
    out[HEADER_LEN..HEADER_LEN + NONCE_LEN].copy_from_slice(nonce);
    let ct_at = HEADER_LEN + NONCE_LEN;
    out[ct_at..ct_at + DK_LEN].copy_from_slice(payload);
    ChaCha20::new((&enc).into(), nonce.into()).apply_keystream(&mut out[ct_at..ct_at + DK_LEN]);

    let mut mac = HmacSha256::new_from_slice(&mk).expect("HMAC accepts any key length");
    mac.update(&out[..ct_at + DK_LEN]);
    let tag = mac.finalize().into_bytes();
    out[ct_at + DK_LEN..].copy_from_slice(&tag);

    enc.zeroize();
    mk.zeroize();
    out
}

/// Whether a blob is in this module's sealed format (any purpose). Checks the
/// shape only; [`open`] does the authentication.
pub fn is_sealed(blob: &[u8]) -> bool {
    blob.len() == SEALED_LEN && blob[..4] == SEALED_MAGIC && blob[4] == SEALED_VERSION
}

/// Open a sealed blob. A wrong key, a wrong purpose or any tampering is an
/// error, never garbage.
pub fn open(key: &[u8; DK_LEN], purpose: Purpose, blob: &[u8]) -> Result<[u8; DK_LEN], SealError> {
    if !is_sealed(blob) {
        return Err(SealError::BadFormat);
    }
    if blob[5] != purpose as u8 {
        return Err(SealError::WrongPurpose);
    }
    let ct_at = HEADER_LEN + NONCE_LEN;
    let mut mk = subkey(key, b"heartwood-dk-mac", purpose);
    let mut mac = HmacSha256::new_from_slice(&mk).expect("HMAC accepts any key length");
    mac.update(&blob[..ct_at + DK_LEN]);
    let verified = mac.verify_slice(&blob[ct_at + DK_LEN..]);
    mk.zeroize();
    if verified.is_err() {
        return Err(SealError::WrongKeyOrTampered);
    }

    let nonce: &[u8; NONCE_LEN] = blob[HEADER_LEN..ct_at].try_into().expect("fixed layout");
    let mut out = [0u8; DK_LEN];
    out.copy_from_slice(&blob[ct_at..ct_at + DK_LEN]);
    let mut enc = subkey(key, b"heartwood-dk-enc", purpose);
    ChaCha20::new((&enc).into(), nonce.into()).apply_keystream(&mut out);
    enc.zeroize();
    Ok(out)
}

/// How a stored encrypted seed is sealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedFormat {
    /// Directly under the PIN or vault key (seed_cipher, the pre-DK format).
    Secret,
    /// Under the data key.
    DataKey,
}

/// Classify a stored encrypted seed by its shape, without any crypto.
pub fn seed_format(blob: &[u8]) -> Option<SeedFormat> {
    if is_sealed(blob) && blob[5] == Purpose::Seed as u8 {
        Some(SeedFormat::DataKey)
    } else if seed_cipher::is_blob_len(blob.len()) {
        Some(SeedFormat::Secret)
    } else {
        None
    }
}

/// Whether `len` is the length of any encrypted-seed format this firmware
/// reads. NVS readers size their buffers with [`MAX_SEED_BLOB_LEN`].
pub const fn is_seed_blob_len(len: usize) -> bool {
    seed_cipher::is_blob_len(len) || len == SEALED_LEN
}

pub const MAX_SEED_BLOB_LEN: usize = if seed_cipher::MAX_BLOB_LEN > SEALED_LEN {
    seed_cipher::MAX_BLOB_LEN
} else {
    SEALED_LEN
};

// ---------------------------------------------------------------------------
// Phone records
// ---------------------------------------------------------------------------

pub const MAX_PHONES: usize = 16;
pub const LABEL_MAX: usize = 16;
pub const SLOT_SECRET_LEN: usize = 32;
/// id(4) + phone key(32) + label length(1) + label + wrapped DK.
pub const MAX_RECORD_LEN: usize = 4 + 32 + 1 + LABEL_MAX + SEALED_LEN; // 135
const PHONES_MAGIC: [u8; 4] = *b"HWPH";
const PHONES_VERSION: u8 = 1;
/// magic(4) + version(1) + count(1).
const PHONES_HEADER_LEN: usize = 6;
/// The largest `dk_ph` blob: sixteen records with full-length labels.
pub const MAX_PHONES_BLOB_LEN: usize = PHONES_HEADER_LEN + MAX_PHONES * MAX_RECORD_LEN; // 2166
const PHONE_HKDF_SALT: &[u8] = b"heartwood-phone-unlock-v1";

/// One enrolled phone. Stored unsealed, because it is needed while locked.
/// Holds no secret that can unlock anything: `wrapped_dk` needs the phone's
/// slot secret S, which the board never stores.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhoneRecord {
    /// Handle for revoke and the UI. Only ever sent encrypted.
    pub id: u32,
    /// K = HKDF(S, "phone"). Recognises and seals lock announcements for this
    /// phone (phase 2). Never on the wire.
    pub phone_key: [u8; 32],
    /// Set at enrolment; never on the wire.
    pub label: String,
    /// DK sealed under HKDF(S, "wrap" || id).
    pub wrapped_dk: [u8; SEALED_LEN],
}

impl Drop for PhoneRecord {
    fn drop(&mut self) {
        self.phone_key.zeroize();
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PhoneError {
    /// Sixteen phones are already enrolled.
    Full,
    DuplicateId,
    LabelTooLong,
    UnknownId,
    /// S does not open this record's wrapper (or the record is tampered).
    WrongSecret,
}

fn hkdf32(ikm: &[u8], info: &[&[u8]]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(PHONE_HKDF_SALT), ikm);
    let mut info_buf = Vec::new();
    for part in info {
        info_buf.extend_from_slice(part);
    }
    let mut out = [0u8; 32];
    hk.expand(&info_buf, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// K = HKDF(S, "phone"). The phone derives the same value from its S.
pub fn phone_key(slot_secret: &[u8; SLOT_SECRET_LEN]) -> [u8; 32] {
    hkdf32(slot_secret, &[b"phone"])
}

fn phone_wrap_key(slot_secret: &[u8; SLOT_SECRET_LEN], id: u32) -> [u8; 32] {
    hkdf32(slot_secret, &[b"wrap", &id.to_be_bytes()])
}

/// The enrolled phones, as packed into `dk_ph`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PhoneSet {
    records: Vec<PhoneRecord>,
}

impl PhoneSet {
    pub fn records(&self) -> &[PhoneRecord] {
        &self.records
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Add a phone. The board draws S and `id`; this derives K and wraps DK.
    pub fn enrol(
        &mut self,
        id: u32,
        label: &str,
        slot_secret: &[u8; SLOT_SECRET_LEN],
        dk: &[u8; DK_LEN],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<(), PhoneError> {
        if label.len() > LABEL_MAX {
            return Err(PhoneError::LabelTooLong);
        }
        if self.records.len() >= MAX_PHONES {
            return Err(PhoneError::Full);
        }
        if self.records.iter().any(|r| r.id == id) {
            return Err(PhoneError::DuplicateId);
        }
        let mut wk = phone_wrap_key(slot_secret, id);
        let wrapped_dk = seal(&wk, Purpose::PhoneWrap, dk, nonce);
        wk.zeroize();
        self.records.push(PhoneRecord {
            id,
            phone_key: phone_key(slot_secret),
            label: String::from(label),
            wrapped_dk,
        });
        Ok(())
    }

    /// Remove a phone's record, and with it its authority to unlock.
    pub fn revoke(&mut self, id: u32) -> Result<(), PhoneError> {
        let at = self
            .records
            .iter()
            .position(|r| r.id == id)
            .ok_or(PhoneError::UnknownId)?;
        self.records.remove(at);
        Ok(())
    }

    /// Recover DK from a phone's delivery of `{id, S}`.
    pub fn unwrap(
        &self,
        id: u32,
        slot_secret: &[u8; SLOT_SECRET_LEN],
    ) -> Result<[u8; DK_LEN], PhoneError> {
        let record = self
            .records
            .iter()
            .find(|r| r.id == id)
            .ok_or(PhoneError::UnknownId)?;
        let mut wk = phone_wrap_key(slot_secret, id);
        let out = open(&wk, Purpose::PhoneWrap, &record.wrapped_dk);
        wk.zeroize();
        out.map_err(|_| PhoneError::WrongSecret)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PHONES_HEADER_LEN + self.records.len() * MAX_RECORD_LEN);
        out.extend_from_slice(&PHONES_MAGIC);
        out.push(PHONES_VERSION);
        out.push(self.records.len() as u8);
        for r in &self.records {
            out.extend_from_slice(&r.id.to_be_bytes());
            out.extend_from_slice(&r.phone_key);
            out.push(r.label.len() as u8);
            out.extend_from_slice(r.label.as_bytes());
            out.extend_from_slice(&r.wrapped_dk);
        }
        out
    }

    /// Strict decode: any malformation is `None`, so a damaged blob reads as
    /// damaged rather than as fewer phones.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < PHONES_HEADER_LEN
            || bytes[..4] != PHONES_MAGIC
            || bytes[4] != PHONES_VERSION
        {
            return None;
        }
        let count = bytes[5] as usize;
        if count > MAX_PHONES {
            return None;
        }
        let mut at = PHONES_HEADER_LEN;
        let mut records: Vec<PhoneRecord> = Vec::with_capacity(count);
        for _ in 0..count {
            let id = u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?);
            at += 4;
            let phone_key: [u8; 32] = bytes.get(at..at + 32)?.try_into().ok()?;
            at += 32;
            let label_len = *bytes.get(at)? as usize;
            at += 1;
            if label_len > LABEL_MAX {
                return None;
            }
            let label = core::str::from_utf8(bytes.get(at..at + label_len)?).ok()?;
            at += label_len;
            let wrapped_dk: [u8; SEALED_LEN] = bytes.get(at..at + SEALED_LEN)?.try_into().ok()?;
            at += SEALED_LEN;
            if !is_sealed(&wrapped_dk) || wrapped_dk[5] != Purpose::PhoneWrap as u8 {
                return None;
            }
            if records.iter().any(|r| r.id == id) {
                return None;
            }
            records.push(PhoneRecord {
                id,
                phone_key,
                label: String::from(label),
                wrapped_dk,
            });
        }
        if at != bytes.len() {
            return None;
        }
        Some(Self { records })
    }
}

// ---------------------------------------------------------------------------
// Storage operations
// ---------------------------------------------------------------------------

/// A storage failure. The firmware's NVS adapter reports every error as this;
/// the host tests use it to model a power cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreError;

/// Key-value blob storage: NVS on the board, a map in the tests.
pub trait BlobStore {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>;
    fn set(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError>;
    fn remove(&mut self, key: &str) -> Result<(), StoreError>;
}

/// The slow, secret-keyed wrap of DK. Production uses [`Pbkdf2`]; the tests
/// swap in a two-round variant so the cut-point models run in reasonable time.
pub trait SecretKdf {
    fn wrap(&self, secret: &[u8], dk: &[u8; DK_LEN], salt: &[u8; 16], nonce: &[u8; 12]) -> Vec<u8>;
    /// Unwrap through this board's KDF engine (possibly an accelerator).
    fn unwrap(&self, secret: &[u8], blob: &[u8]) -> Result<[u8; DK_LEN], SeedCipherError>;
    /// Unwrap through the pure-Rust reference KDF. Used to verify a fresh wrap,
    /// so a sealing engine never grades its own work (see
    /// `seed_cipher::decrypt_seed_reference`).
    fn unwrap_reference(&self, secret: &[u8], blob: &[u8])
        -> Result<[u8; DK_LEN], SeedCipherError>;
}

/// The production secret wrap: seed_cipher's PBKDF2 construction.
pub struct Pbkdf2;

impl SecretKdf for Pbkdf2 {
    fn wrap(&self, secret: &[u8], dk: &[u8; DK_LEN], salt: &[u8; 16], nonce: &[u8; 12]) -> Vec<u8> {
        seed_cipher::encrypt_seed(secret, dk, salt, nonce)
    }
    fn unwrap(&self, secret: &[u8], blob: &[u8]) -> Result<[u8; DK_LEN], SeedCipherError> {
        seed_cipher::decrypt_seed(secret, blob)
    }
    fn unwrap_reference(
        &self,
        secret: &[u8],
        blob: &[u8],
    ) -> Result<[u8; DK_LEN], SeedCipherError> {
        seed_cipher::decrypt_seed_reference(secret, blob)
    }
}

/// What the firmware supplies around the storage logic.
pub trait Platform {
    fn fill_random(&mut self, buf: &mut [u8]);
    /// Called immediately before every PBKDF2 stretch (the board yields and
    /// feeds its watchdog here).
    fn before_kdf(&mut self) {}
    /// Unlock progress: `done` of `total` locked seeds opened.
    fn progress(&mut self, _done: usize, _total: usize) {}
}

/// Seeds recovered by an unlock, and the data key if one is wrapped.
pub struct Unlocked {
    /// `(slot, seed)` for every locked slot, in the order given.
    pub seeds: Vec<(u8, [u8; 32])>,
    pub dk: Option<[u8; DK_LEN]>,
    /// A `dk_sec` exists but does not open under this secret, and no seed
    /// depends on it. Left by a secret change on firmware without this module.
    /// [`migrate`] replaces it and drops the phone records it wrapped for.
    pub stale_secret_wrap: bool,
}

impl Drop for Unlocked {
    fn drop(&mut self) {
        for (_, seed) in self.seeds.iter_mut() {
            seed.zeroize();
        }
        if let Some(dk) = self.dk.as_mut() {
            dk.zeroize();
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum UnlockError {
    /// The secret opens neither the DK wrapper nor a seed.
    WrongSecret,
    /// A seed blob is missing, unrecognised, or does not open under a DK the
    /// secret did open. The seeds are not released.
    Damaged(&'static str),
    /// A phone unlock found a seed still sealed under the secret (migration
    /// has not run). Only the PIN or vault key can open it.
    NeedsSecret,
    Storage,
}

impl From<StoreError> for UnlockError {
    fn from(_: StoreError) -> Self {
        UnlockError::Storage
    }
}

fn read_locked<S: BlobStore>(
    store: &S,
    locked_slots: &[u8],
) -> Result<Vec<(u8, Vec<u8>, SeedFormat)>, UnlockError> {
    let mut out = Vec::with_capacity(locked_slots.len());
    for &slot in locked_slots {
        let blob = store
            .get(&seed_enc_key(slot))?
            .ok_or(UnlockError::Damaged("locked slot has no sealed seed"))?;
        let format = seed_format(&blob).ok_or(UnlockError::Damaged("unrecognised sealed seed"))?;
        out.push((slot, blob, format));
    }
    Ok(out)
}

/// Unlock with the PIN or vault key. All-or-nothing: no seed is released
/// unless every locked slot opened.
///
/// The work is one PBKDF2 stretch for the wrapper plus one per seed still in
/// the pre-DK format. After [`migrate`], that is one stretch in total.
pub fn unlock_with_secret<S: BlobStore, K: SecretKdf, P: Platform>(
    store: &S,
    locked_slots: &[u8],
    secret: &[u8],
    kdf: &K,
    platform: &mut P,
) -> Result<Unlocked, UnlockError> {
    let blobs = read_locked(store, locked_slots)?;
    let wrap = store.get(SECRET_WRAP_KEY)?;
    let needs_dk = blobs.iter().any(|(_, _, f)| *f == SeedFormat::DataKey);
    let total = blobs.len();

    let mut unlocked = Unlocked {
        seeds: Vec::with_capacity(total),
        dk: None,
        stale_secret_wrap: false,
    };

    // When any seed depends on DK, its wrapper is the secret check: one
    // stretch, and a wrong secret is refused before any seed is touched.
    if needs_dk {
        let wrap = wrap.as_deref().ok_or(UnlockError::Damaged(
            "seed sealed under a data key, but no data key is wrapped",
        ))?;
        platform.before_kdf();
        unlocked.dk = Some(
            kdf.unwrap(secret, wrap)
                .map_err(|_| UnlockError::WrongSecret)?,
        );
    }

    for (done, (slot, blob, format)) in blobs.iter().enumerate() {
        platform.progress(done, total);
        let seed = match format {
            SeedFormat::DataKey => {
                let dk = unlocked.dk.as_ref().expect("opened above");
                open(dk, Purpose::Seed, blob).map_err(|_| {
                    UnlockError::Damaged("sealed seed does not open under the data key")
                })?
            }
            SeedFormat::Secret => {
                platform.before_kdf();
                kdf.unwrap(secret, blob)
                    .map_err(|_| UnlockError::WrongSecret)?
            }
        };
        unlocked.seeds.push((*slot, seed));
    }
    platform.progress(total, total);

    // No seed depended on the wrapper, so the secret has already been proven
    // by the seeds. A wrapper that does not open under it is stale rather than
    // a wrong secret; migration replaces it.
    if !needs_dk {
        if let Some(wrap) = wrap.as_deref() {
            platform.before_kdf();
            match kdf.unwrap(secret, wrap) {
                Ok(dk) => unlocked.dk = Some(dk),
                Err(_) => unlocked.stale_secret_wrap = true,
            }
        }
    }
    Ok(unlocked)
}

/// Unlock with a data key recovered from a phone. No stretch at all. Refuses
/// if any seed is still sealed under the secret.
pub fn unlock_with_data_key<S: BlobStore>(
    store: &S,
    locked_slots: &[u8],
    dk: &[u8; DK_LEN],
) -> Result<Unlocked, UnlockError> {
    let blobs = read_locked(store, locked_slots)?;
    let mut unlocked = Unlocked {
        seeds: Vec::with_capacity(blobs.len()),
        dk: Some(*dk),
        stale_secret_wrap: false,
    };
    for (slot, blob, format) in blobs.iter() {
        if *format != SeedFormat::DataKey {
            return Err(UnlockError::NeedsSecret);
        }
        let seed = open(dk, Purpose::Seed, blob).map_err(|_| UnlockError::WrongSecret)?;
        unlocked.seeds.push((*slot, seed));
    }
    Ok(unlocked)
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChangeError {
    /// A freshly written value did not verify. Nothing that depended on it was
    /// written after it.
    Verify(&'static str),
    /// Seeds are sealed at rest but this boot holds no data key: the board has
    /// not finished migrating. Unlock again (which migrates) and retry.
    NoDataKey,
    Storage,
}

impl From<StoreError> for ChangeError {
    fn from(_: StoreError) -> Self {
        ChangeError::Storage
    }
}

fn set_verified<S: BlobStore>(
    store: &mut S,
    key: &str,
    value: &[u8],
    what: &'static str,
) -> Result<(), ChangeError> {
    store.set(key, value)?;
    if store.get(key)?.as_deref() == Some(value) {
        Ok(())
    } else {
        Err(ChangeError::Verify(what))
    }
}

fn remove_verified<S: BlobStore>(
    store: &mut S,
    key: &str,
    what: &'static str,
) -> Result<(), ChangeError> {
    store.remove(key)?;
    if store.get(key)?.is_none() {
        Ok(())
    } else {
        Err(ChangeError::Verify(what))
    }
}

/// Wrap `dk` under `secret`, verify through the reference KDF, and store it.
fn write_secret_wrap<S: BlobStore, K: SecretKdf, P: Platform>(
    store: &mut S,
    secret: &[u8],
    dk: &[u8; DK_LEN],
    kdf: &K,
    platform: &mut P,
) -> Result<(), ChangeError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    platform.fill_random(&mut salt);
    platform.fill_random(&mut nonce);
    platform.before_kdf();
    let wrap = kdf.wrap(secret, dk, &salt, &nonce);
    platform.before_kdf();
    if kdf.unwrap_reference(secret, &wrap).as_ref() != Ok(dk) {
        return Err(ChangeError::Verify("data key wrap does not reopen"));
    }
    set_verified(store, SECRET_WRAP_KEY, &wrap, "data key wrap read-back")
}

/// Seal one seed under DK, verify, and store it in the slot's sealed key. The
/// plaintext key, if any, is removed only after the sealed blob verified.
fn write_sealed_seed<S: BlobStore, P: Platform>(
    store: &mut S,
    slot: u8,
    seed: &[u8; 32],
    dk: &[u8; DK_LEN],
    platform: &mut P,
) -> Result<(), ChangeError> {
    let mut nonce = [0u8; NONCE_LEN];
    platform.fill_random(&mut nonce);
    let sealed = seal(dk, Purpose::Seed, seed, &nonce);
    match open(dk, Purpose::Seed, &sealed) {
        Ok(mut check) => {
            let same = check == *seed;
            check.zeroize();
            if !same {
                return Err(ChangeError::Verify("sealed seed does not reopen"));
            }
        }
        Err(_) => return Err(ChangeError::Verify("sealed seed does not reopen")),
    }
    set_verified(store, &seed_enc_key(slot), &sealed, "sealed seed read-back")?;
    if store.get(&seed_plain_key(slot))?.is_some() {
        remove_verified(store, &seed_plain_key(slot), "plaintext seed removal")?;
    }
    Ok(())
}

fn fresh_dk<P: Platform>(platform: &mut P) -> [u8; DK_LEN] {
    let mut dk = [0u8; DK_LEN];
    platform.fill_random(&mut dk);
    dk
}

/// Bring a just-unlocked board onto the data key: make sure DK is wrapped under
/// `secret`, then reseal every seed still in the pre-DK format. Returns the
/// number of seeds resealed. Idempotent: run it after every secret unlock.
///
/// Order, and why every cut is safe:
///  1. If there is no DK: drop any phone records (they wrapped a DK that is
///     gone), then write the new `dk_sec`. A cut here leaves every seed in the
///     pre-DK format, which the secret still opens.
///  2. Reseal the pre-DK seeds one at a time. A cut leaves a mix, and the
///     secret opens both kinds: DK through `dk_sec`, the rest directly.
pub fn migrate<S: BlobStore, K: SecretKdf, P: Platform>(
    store: &mut S,
    secret: &[u8],
    unlocked: &mut Unlocked,
    kdf: &K,
    platform: &mut P,
) -> Result<usize, ChangeError> {
    if unlocked.dk.is_none() {
        if unlocked.stale_secret_wrap || store.get(PHONES_KEY)?.is_some() {
            remove_verified(store, PHONES_KEY, "stale phone records removal")?;
        }
        let dk = fresh_dk(platform);
        write_secret_wrap(store, secret, &dk, kdf, platform)?;
        unlocked.dk = Some(dk);
        unlocked.stale_secret_wrap = false;
    }
    let dk = unlocked.dk.expect("established above");
    let mut resealed = 0;
    for (slot, seed) in unlocked.seeds.iter() {
        let current = store.get(&seed_enc_key(*slot))?;
        if current.as_deref().and_then(seed_format) == Some(SeedFormat::DataKey) {
            continue;
        }
        write_sealed_seed(store, *slot, seed, &dk, platform)?;
        resealed += 1;
    }
    Ok(resealed)
}

/// Set or change the PIN or vault key on an unlocked board. `seeds` is every
/// master's seed in RAM; `dk` is this boot's data key, if it has one. Returns
/// the data key now in force.
///
///  - Already sealed (`dk` is `Some`): reseal any seed not yet under DK while
///    the OLD wrapper is still in force, then replace the wrapper in one write.
///    Before that write the old secret opens everything; after it, the new.
///    DK does not change, so enrolled phones keep working.
///  - Plaintext board (`dk` is `None`, no sealed seed): mint DK, drop any
///    stale phone records, write the wrapper under the new secret, then seal
///    each seed. A cut before the first seed leaves a plaintext board with an
///    orphan wrapper, which the next enable replaces; after it, the new
///    secret opens the sealed seeds.
///  - Sealed but no `dk`: refused ([`ChangeError::NoDataKey`]). Writing a new
///    wrapper would strand seeds still sealed under the old secret.
pub fn set_secret<S: BlobStore, K: SecretKdf, P: Platform>(
    store: &mut S,
    new_secret: &[u8],
    seeds: &[(u8, [u8; 32])],
    dk: Option<[u8; DK_LEN]>,
    kdf: &K,
    platform: &mut P,
) -> Result<[u8; DK_LEN], ChangeError> {
    match dk {
        Some(dk) => {
            for (slot, seed) in seeds {
                let current = store.get(&seed_enc_key(*slot))?;
                if current.as_deref().and_then(seed_format) != Some(SeedFormat::DataKey) {
                    write_sealed_seed(store, *slot, seed, &dk, platform)?;
                }
            }
            write_secret_wrap(store, new_secret, &dk, kdf, platform)?;
            Ok(dk)
        }
        None => {
            for (slot, _) in seeds {
                if store.get(&seed_enc_key(*slot))?.is_some() {
                    return Err(ChangeError::NoDataKey);
                }
            }
            let dk = fresh_dk(platform);
            if store.get(PHONES_KEY)?.is_some() {
                remove_verified(store, PHONES_KEY, "stale phone records removal")?;
            }
            write_secret_wrap(store, new_secret, &dk, kdf, platform)?;
            for (slot, seed) in seeds {
                write_sealed_seed(store, *slot, seed, &dk, platform)?;
            }
            Ok(dk)
        }
    }
}

/// Turn at-rest encryption off: store every seed in plaintext, then drop the
/// phone records and the wrapper. A cut part-way leaves some seeds sealed
/// with the wrapper still present, so the secret still unlocks.
pub fn clear_secret<S: BlobStore>(
    store: &mut S,
    seeds: &[(u8, [u8; 32])],
) -> Result<(), ChangeError> {
    for (slot, seed) in seeds {
        set_verified(
            store,
            &seed_plain_key(*slot),
            seed,
            "plaintext seed read-back",
        )?;
        if store.get(&seed_enc_key(*slot))?.is_some() {
            remove_verified(store, &seed_enc_key(*slot), "sealed seed removal")?;
        }
    }
    if store.get(PHONES_KEY)?.is_some() {
        remove_verified(store, PHONES_KEY, "phone records removal")?;
    }
    if store.get(SECRET_WRAP_KEY)?.is_some() {
        remove_verified(store, SECRET_WRAP_KEY, "data key wrap removal")?;
    }
    Ok(())
}

/// Read the enrolled phones. Absent is an empty set; a damaged blob is `Err`,
/// so a caller never mistakes damage for "no phones".
pub fn load_phones<S: BlobStore>(store: &S) -> Result<PhoneSet, UnlockError> {
    match store.get(PHONES_KEY)? {
        None => Ok(PhoneSet::default()),
        Some(bytes) => {
            PhoneSet::decode(&bytes).ok_or(UnlockError::Damaged("phone records unreadable"))
        }
    }
}

/// Store the enrolled phones, removing the key when the set is empty.
pub fn save_phones<S: BlobStore>(store: &mut S, phones: &PhoneSet) -> Result<(), ChangeError> {
    if phones.is_empty() {
        if store.get(PHONES_KEY)?.is_some() {
            remove_verified(store, PHONES_KEY, "phone records removal")?;
        }
        Ok(())
    } else {
        set_verified(
            store,
            PHONES_KEY,
            &phones.encode(),
            "phone records read-back",
        )
    }
}

// ---------------------------------------------------------------------------
// Note-locker key
// ---------------------------------------------------------------------------

/// The note locker's key as sealed under DK: no stretch at unlock.
pub fn seal_note_key(
    dk: &[u8; DK_LEN],
    note_key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> [u8; SEALED_LEN] {
    seal(dk, Purpose::NoteKey, note_key, nonce)
}

/// Open a note key sealed by [`seal_note_key`].
pub fn open_note_key(dk: &[u8; DK_LEN], blob: &[u8]) -> Result<[u8; 32], SealError> {
    open(dk, Purpose::NoteKey, blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use core::cell::Cell;

    const SEEDS: [[u8; 32]; 3] = [[0x11; 32], [0x22; 32], [0x33; 32]];
    const PIN_A: &[u8] = b"1234";
    const PIN_B: &[u8] = b"987654";

    // -- sealed format -----------------------------------------------------

    #[test]
    fn seal_round_trips_and_names_its_purpose() {
        let key = [7u8; 32];
        let blob = seal(&key, Purpose::Seed, &SEEDS[0], &[1u8; 12]);
        assert_eq!(blob.len(), SEALED_LEN);
        assert!(is_sealed(&blob));
        assert_eq!(open(&key, Purpose::Seed, &blob), Ok(SEEDS[0]));
        assert_eq!(
            open(&key, Purpose::NoteKey, &blob),
            Err(SealError::WrongPurpose)
        );
        assert_ne!(
            &blob[18..50],
            &SEEDS[0][..],
            "ciphertext is not the payload"
        );
    }

    #[test]
    fn seal_refuses_a_wrong_key_and_every_single_bit_flip() {
        let key = [7u8; 32];
        let blob = seal(&key, Purpose::Seed, &SEEDS[0], &[1u8; 12]);
        let mut wrong = key;
        wrong[31] ^= 1;
        assert_eq!(
            open(&wrong, Purpose::Seed, &blob),
            Err(SealError::WrongKeyOrTampered)
        );
        for i in 0..SEALED_LEN {
            let mut t = blob;
            t[i] ^= 0x01;
            assert!(
                open(&key, Purpose::Seed, &t).is_err(),
                "flip at byte {i} accepted"
            );
        }
        assert_eq!(
            open(&key, Purpose::Seed, &blob[..81]),
            Err(SealError::BadFormat)
        );
    }

    #[test]
    fn purposes_use_distinct_keys_not_just_a_label() {
        // Rewriting the purpose byte must not produce a blob that opens.
        let key = [7u8; 32];
        let mut blob = seal(&key, Purpose::NoteKey, &SEEDS[0], &[1u8; 12]);
        blob[5] = Purpose::Seed as u8;
        assert_eq!(
            open(&key, Purpose::Seed, &blob),
            Err(SealError::WrongKeyOrTampered)
        );
    }

    #[test]
    fn a_seed_blob_names_its_own_format() {
        assert!(!seed_cipher::is_blob_len(SEALED_LEN));
        let blob = seal(&[7u8; 32], Purpose::Seed, &SEEDS[0], &[1u8; 12]);
        assert_eq!(seed_format(&blob), Some(SeedFormat::DataKey));
        assert_eq!(
            seed_format(&[0u8; seed_cipher::BLOB_LEN]),
            Some(SeedFormat::Secret)
        );
        assert_eq!(
            seed_format(&[0u8; seed_cipher::LEGACY_BLOB_LEN]),
            Some(SeedFormat::Secret)
        );
        let note = seal(&[7u8; 32], Purpose::NoteKey, &SEEDS[0], &[1u8; 12]);
        assert_eq!(seed_format(&note), None, "a note key is not a seed");
        assert_eq!(seed_format(&[0u8; 40]), None);
        assert!(is_seed_blob_len(SEALED_LEN));
        assert_eq!(MAX_SEED_BLOB_LEN, seed_cipher::BLOB_LEN);
    }

    // -- phone records -----------------------------------------------------

    fn s(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn a_phone_unwraps_dk_with_its_own_secret_only() {
        let dk = [0xD0; 32];
        let mut set = PhoneSet::default();
        set.enrol(7, "Pixel 8", &s(1), &dk, &[2u8; 12]).unwrap();
        set.enrol(9, "spare", &s(2), &dk, &[3u8; 12]).unwrap();
        assert_eq!(set.unwrap(7, &s(1)), Ok(dk));
        assert_eq!(set.unwrap(9, &s(2)), Ok(dk));
        assert_eq!(set.unwrap(7, &s(2)), Err(PhoneError::WrongSecret));
        assert_eq!(set.unwrap(8, &s(1)), Err(PhoneError::UnknownId));
        assert_eq!(set.records()[0].phone_key, phone_key(&s(1)));
        assert_ne!(set.records()[0].phone_key, s(1), "K is derived, not S");
    }

    #[test]
    fn revoking_one_phone_leaves_the_others() {
        let dk = [0xD0; 32];
        let mut set = PhoneSet::default();
        set.enrol(1, "a", &s(1), &dk, &[2u8; 12]).unwrap();
        set.enrol(2, "b", &s(2), &dk, &[3u8; 12]).unwrap();
        set.revoke(1).unwrap();
        assert_eq!(set.unwrap(1, &s(1)), Err(PhoneError::UnknownId));
        assert_eq!(set.unwrap(2, &s(2)), Ok(dk));
        assert_eq!(set.revoke(1), Err(PhoneError::UnknownId));
    }

    #[test]
    fn a_record_moved_to_another_id_does_not_open() {
        // The wrap key binds the id, so relabelling a record's id on flash
        // does not let S for one phone open another phone's slot.
        let dk = [0xD0; 32];
        let mut set = PhoneSet::default();
        set.enrol(1, "a", &s(1), &dk, &[2u8; 12]).unwrap();
        let mut bytes = set.encode();
        bytes[PHONES_HEADER_LEN..PHONES_HEADER_LEN + 4].copy_from_slice(&2u32.to_be_bytes());
        let moved = PhoneSet::decode(&bytes).unwrap();
        assert_eq!(moved.unwrap(2, &s(1)), Err(PhoneError::WrongSecret));
    }

    #[test]
    fn enrolment_refuses_cleanly_at_the_limit() {
        let dk = [0xD0; 32];
        let mut set = PhoneSet::default();
        for id in 0..MAX_PHONES as u32 {
            set.enrol(id, "sixteen chars ok", &s(id as u8), &dk, &[0u8; 12])
                .unwrap();
        }
        assert_eq!(
            set.enrol(99, "x", &s(99), &dk, &[0u8; 12]),
            Err(PhoneError::Full)
        );
        assert_eq!(
            set.enrol(0, "x", &s(0), &dk, &[0u8; 12]),
            Err(PhoneError::Full)
        );
        let bytes = set.encode();
        assert_eq!(bytes.len(), MAX_PHONES_BLOB_LEN);
        assert_eq!(PhoneSet::decode(&bytes).unwrap(), set);
    }

    #[test]
    fn enrolment_refuses_duplicates_and_long_labels() {
        let dk = [0xD0; 32];
        let mut set = PhoneSet::default();
        set.enrol(1, "a", &s(1), &dk, &[0u8; 12]).unwrap();
        assert_eq!(
            set.enrol(1, "b", &s(2), &dk, &[0u8; 12]),
            Err(PhoneError::DuplicateId)
        );
        assert_eq!(
            set.enrol(2, "seventeen chars!!", &s(2), &dk, &[0u8; 12]),
            Err(PhoneError::LabelTooLong)
        );
    }

    #[test]
    fn phone_blob_layout_is_frozen() {
        let dk = [0xD0; 32];
        let mut set = PhoneSet::default();
        set.enrol(0x0102_0304, "ab", &s(1), &dk, &[2u8; 12])
            .unwrap();
        let bytes = set.encode();
        assert_eq!(&bytes[..6], b"HWPH\x01\x01");
        assert_eq!(&bytes[6..10], &[1, 2, 3, 4]);
        assert_eq!(&bytes[10..42], &phone_key(&s(1)));
        assert_eq!(&bytes[42..45], b"\x02ab");
        assert_eq!(&bytes[45..49], b"HWDK");
        assert_eq!(bytes[50], Purpose::PhoneWrap as u8);
        assert_eq!(bytes.len(), 6 + 4 + 32 + 1 + 2 + SEALED_LEN);
        assert_eq!(
            PhoneSet::decode(&PhoneSet::default().encode()),
            Some(PhoneSet::default())
        );
    }

    #[test]
    fn phone_blob_decode_is_strict() {
        let dk = [0xD0; 32];
        let mut set = PhoneSet::default();
        set.enrol(1, "a", &s(1), &dk, &[0u8; 12]).unwrap();
        set.enrol(2, "b", &s(2), &dk, &[0u8; 12]).unwrap();
        let good = set.encode();
        assert!(PhoneSet::decode(&good).is_some());

        let mut trailing = good.clone();
        trailing.push(0);
        assert!(PhoneSet::decode(&trailing).is_none());
        assert!(PhoneSet::decode(&good[..good.len() - 1]).is_none());

        let mut magic = good.clone();
        magic[0] = b'X';
        assert!(PhoneSet::decode(&magic).is_none());

        let mut count = good.clone();
        count[5] = 17;
        assert!(PhoneSet::decode(&count).is_none());

        let mut dup = good.clone();
        let second = PHONES_HEADER_LEN + 4 + 32 + 1 + 1 + SEALED_LEN;
        dup[second..second + 4].copy_from_slice(&1u32.to_be_bytes());
        assert!(PhoneSet::decode(&dup).is_none());

        let mut label = good.clone();
        label[PHONES_HEADER_LEN + 36] = LABEL_MAX as u8 + 1;
        assert!(PhoneSet::decode(&label).is_none());

        let mut utf8 = good.clone();
        utf8[PHONES_HEADER_LEN + 37] = 0xFF;
        assert!(PhoneSet::decode(&utf8).is_none());

        let mut purpose = good;
        purpose[PHONES_HEADER_LEN + 38 + 5] = Purpose::Seed as u8;
        assert!(PhoneSet::decode(&purpose).is_none());
    }

    // -- storage model -----------------------------------------------------

    /// In-memory NVS with a power-cut switch. `cut_after` counts mutating
    /// writes; the write that crosses it is either lost (`apply_cut_write`
    /// false) or lands (true), and then the "power" is off for good: every
    /// later operation fails, which the code under test sees as a store error
    /// and stops. Both halves are real: NVS commits a blob atomically, so a
    /// cut write is all-or-nothing.
    #[derive(Clone, Default)]
    struct Mem {
        map: BTreeMap<String, Vec<u8>>,
        writes: Cell<usize>,
        cut_after: Option<usize>,
        apply_cut_write: bool,
        dead: Cell<bool>,
    }

    impl Mem {
        fn gate(&self) -> Result<bool, StoreError> {
            if self.dead.get() {
                return Err(StoreError);
            }
            let n = self.writes.get();
            self.writes.set(n + 1);
            match self.cut_after {
                Some(cut) if n == cut => {
                    self.dead.set(true);
                    Ok(self.apply_cut_write)
                }
                _ => Ok(true),
            }
        }
        /// Power back on: same flash, no cut armed.
        fn reboot(&self) -> Mem {
            Mem {
                map: self.map.clone(),
                ..Mem::default()
            }
        }
        fn armed(&self, cut_after: usize, apply: bool) -> Mem {
            Mem {
                map: self.map.clone(),
                cut_after: Some(cut_after),
                apply_cut_write: apply,
                ..Mem::default()
            }
        }
    }

    impl BlobStore for Mem {
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
            if self.dead.get() {
                return Err(StoreError);
            }
            Ok(self.map.get(key).cloned())
        }
        fn set(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
            let apply = self.gate()?;
            if apply {
                self.map.insert(String::from(key), value.to_vec());
            }
            if self.dead.get() {
                Err(StoreError)
            } else {
                Ok(())
            }
        }
        fn remove(&mut self, key: &str) -> Result<(), StoreError> {
            let apply = self.gate()?;
            if apply {
                self.map.remove(key);
            }
            if self.dead.get() {
                Err(StoreError)
            } else {
                Ok(())
            }
        }
    }

    /// Two-round PBKDF2 so the cut-point sweeps stay fast. The construction is
    /// seed_cipher's, unchanged; only the cost differs.
    struct CheapKdf;
    impl SecretKdf for CheapKdf {
        fn wrap(&self, secret: &[u8], dk: &[u8; 32], salt: &[u8; 16], nonce: &[u8; 12]) -> Vec<u8> {
            seed_cipher::encrypt_seed_with_iterations(secret, dk, salt, nonce, 2)
        }
        fn unwrap(&self, secret: &[u8], blob: &[u8]) -> Result<[u8; 32], SeedCipherError> {
            seed_cipher::decrypt_seed(secret, blob)
        }
        fn unwrap_reference(
            &self,
            secret: &[u8],
            blob: &[u8],
        ) -> Result<[u8; 32], SeedCipherError> {
            seed_cipher::decrypt_seed_reference(secret, blob)
        }
    }

    #[derive(Default)]
    struct Board {
        counter: u8,
        stretches: usize,
    }
    impl Platform for Board {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                self.counter = self.counter.wrapping_add(1);
                *b = self.counter;
            }
        }
        fn before_kdf(&mut self) {
            self.stretches += 1;
        }
    }

    const SLOTS: [u8; 3] = [0, 1, 2];

    fn seeds() -> Vec<(u8, [u8; 32])> {
        SLOTS.iter().map(|&s| (s, SEEDS[s as usize])).collect()
    }

    /// A board as the previous firmware left it: every seed sealed directly
    /// under `secret`, no data key.
    fn legacy_board(secret: &[u8]) -> Mem {
        let mut m = Mem::default();
        for (slot, seed) in seeds() {
            let blob = seed_cipher::encrypt_seed_with_iterations(
                secret,
                &seed,
                &[slot; 16],
                &[slot; 12],
                2,
            );
            m.set(&seed_enc_key(slot), &blob).unwrap();
        }
        m.reboot()
    }

    fn plaintext_board() -> Mem {
        let mut m = Mem::default();
        for (slot, seed) in seeds() {
            m.set(&seed_plain_key(slot), &seed).unwrap();
        }
        m.reboot()
    }

    fn locked_slots(m: &Mem) -> Vec<u8> {
        SLOTS
            .iter()
            .copied()
            .filter(|&s| m.map.contains_key(&seed_enc_key(s)))
            .collect()
    }

    /// What a reboot sees: which seeds are plaintext, and whether `secret`
    /// unlocks the rest. `Some(seeds)` only if the board is fully usable.
    fn boot_with(m: &Mem, secret: &[u8]) -> Option<Vec<(u8, [u8; 32])>> {
        let m = m.reboot();
        let locked = locked_slots(&m);
        let mut all: Vec<(u8, [u8; 32])> = Vec::new();
        for &slot in SLOTS.iter() {
            if !locked.contains(&slot) {
                let plain = m.map.get(&seed_plain_key(slot))?;
                all.push((slot, plain.as_slice().try_into().ok()?));
            }
        }
        if !locked.is_empty() {
            let u =
                unlock_with_secret(&m, &locked, secret, &CheapKdf, &mut Board::default()).ok()?;
            all.extend(u.seeds.iter().copied());
        }
        all.sort();
        Some(all)
    }

    fn unlock_and_migrate(m: &mut Mem, secret: &[u8]) -> Result<Unlocked, ChangeError> {
        let locked = locked_slots(m);
        let mut u = unlock_with_secret(m, &locked, secret, &CheapKdf, &mut Board::default())
            .map_err(|_| ChangeError::Storage)?;
        migrate(m, secret, &mut u, &CheapKdf, &mut Board::default())?;
        Ok(u)
    }

    // -- unlock ------------------------------------------------------------

    #[test]
    fn a_legacy_board_still_unlocks_and_refuses_a_wrong_secret() {
        let m = legacy_board(PIN_A);
        let mut b = Board::default();
        let u = unlock_with_secret(&m, &SLOTS, PIN_A, &CheapKdf, &mut b).unwrap();
        assert_eq!(u.seeds, seeds());
        assert_eq!(u.dk, None);
        assert_eq!(b.stretches, 3, "one stretch per seed before migration");
        assert_eq!(
            unlock_with_secret(&m, &SLOTS, PIN_B, &CheapKdf, &mut Board::default()).err(),
            Some(UnlockError::WrongSecret)
        );
    }

    #[test]
    fn migration_makes_unlock_one_stretch() {
        let mut m = legacy_board(PIN_A);
        let u = unlock_and_migrate(&mut m, PIN_A).unwrap();
        let dk = u.dk.unwrap();
        for slot in SLOTS {
            assert_eq!(
                seed_format(&m.map[&seed_enc_key(slot)]),
                Some(SeedFormat::DataKey)
            );
        }
        let mut b = Board::default();
        let again = unlock_with_secret(&m, &SLOTS, PIN_A, &CheapKdf, &mut b).unwrap();
        assert_eq!(again.seeds, seeds());
        assert_eq!(again.dk, Some(dk));
        assert_eq!(b.stretches, 1);
        // Idempotent: nothing left to reseal.
        let mut again = again;
        assert_eq!(
            migrate(&mut m, PIN_A, &mut again, &CheapKdf, &mut Board::default()),
            Ok(0)
        );
    }

    #[test]
    fn a_migrated_board_refuses_a_wrong_secret_before_touching_seeds() {
        let mut m = legacy_board(PIN_A);
        unlock_and_migrate(&mut m, PIN_A).unwrap();
        let mut b = Board::default();
        assert_eq!(
            unlock_with_secret(&m, &SLOTS, PIN_B, &CheapKdf, &mut b).err(),
            Some(UnlockError::WrongSecret)
        );
        assert_eq!(b.stretches, 1);
    }

    #[test]
    fn a_tampered_wrapper_or_seed_is_refused() {
        let mut m = legacy_board(PIN_A);
        unlock_and_migrate(&mut m, PIN_A).unwrap();

        let mut w = m.reboot();
        w.map.get_mut(SECRET_WRAP_KEY).unwrap()[40] ^= 1;
        assert_eq!(
            unlock_with_secret(&w, &SLOTS, PIN_A, &CheapKdf, &mut Board::default()).err(),
            Some(UnlockError::WrongSecret)
        );

        let mut t = m.reboot();
        t.map.get_mut(&seed_enc_key(1)).unwrap()[30] ^= 1;
        assert!(matches!(
            unlock_with_secret(&t, &SLOTS, PIN_A, &CheapKdf, &mut Board::default()).err(),
            Some(UnlockError::Damaged(_))
        ));

        let mut gone = m.reboot();
        gone.map.remove(SECRET_WRAP_KEY);
        assert!(matches!(
            unlock_with_secret(&gone, &SLOTS, PIN_A, &CheapKdf, &mut Board::default()).err(),
            Some(UnlockError::Damaged(_))
        ));
    }

    #[test]
    fn a_stale_wrapper_is_replaced_and_its_phones_dropped() {
        // Firmware without this module changed the PIN after a partial
        // migration left a wrapper: the seeds are all pre-DK under the new
        // PIN, and dk_sec is under the old one.
        let mut m = legacy_board(PIN_B);
        let stale = CheapKdf.wrap(PIN_A, &[9u8; 32], &[1; 16], &[1; 12]);
        m.map.insert(String::from(SECRET_WRAP_KEY), stale);
        let mut phones = PhoneSet::default();
        phones.enrol(1, "old", &s(1), &[9u8; 32], &[0; 12]).unwrap();
        m.map.insert(String::from(PHONES_KEY), phones.encode());

        let mut u =
            unlock_with_secret(&m, &SLOTS, PIN_B, &CheapKdf, &mut Board::default()).unwrap();
        assert!(u.stale_secret_wrap);
        assert_eq!(u.dk, None);
        migrate(&mut m, PIN_B, &mut u, &CheapKdf, &mut Board::default()).unwrap();
        assert!(!m.map.contains_key(PHONES_KEY));
        assert_eq!(boot_with(&m, PIN_B), Some(seeds()));
    }

    // -- the power-cut models ---------------------------------------------

    /// Run `op` against a copy of `start` with a cut armed after every
    /// possible write, both with the cut write lost and landed, and check
    /// `after_cut` on what a reboot finds. Returns how many writes a clean run
    /// performs, so a test can see it actually swept something.
    fn sweep(
        start: &Mem,
        op: &dyn Fn(&mut Mem) -> Result<(), ChangeError>,
        after_cut: &dyn Fn(&Mem, usize, bool),
    ) -> usize {
        let mut clean = start.reboot();
        op(&mut clean).expect("clean run succeeds");
        let total = clean.writes.get();
        assert!(total > 0);
        for cut in 0..total {
            for apply in [false, true] {
                let mut m = start.armed(cut, apply);
                assert!(op(&mut m).is_err(), "cut {cut} was not reached");
                after_cut(&m.reboot(), cut, apply);
            }
        }
        total
    }

    #[test]
    fn migration_survives_a_cut_at_every_write() {
        let start = legacy_board(PIN_A);
        let writes = sweep(
            &start,
            &|m| unlock_and_migrate(m, PIN_A).map(|_| ()),
            &|m, cut, apply| {
                // An interrupted migration unlocks with the same secret...
                assert_eq!(
                    boot_with(m, PIN_A),
                    Some(seeds()),
                    "cut {cut} apply {apply}"
                );
                assert_eq!(boot_with(m, PIN_B), None);
                // ...and the next unlock finishes it.
                let mut m = m.reboot();
                unlock_and_migrate(&mut m, PIN_A).unwrap();
                let mut b = Board::default();
                unlock_with_secret(&m, &SLOTS, PIN_A, &CheapKdf, &mut b).unwrap();
                assert_eq!(b.stretches, 1, "cut {cut} apply {apply}");
            },
        );
        assert_eq!(writes, 4, "wrapper plus three seeds");
    }

    #[test]
    fn changing_the_secret_survives_a_cut_at_every_write() {
        let mut start = legacy_board(PIN_A);
        let dk = unlock_and_migrate(&mut start, PIN_A).unwrap().dk;
        sweep(
            &start.reboot(),
            &|m| set_secret(m, PIN_B, &seeds(), dk, &CheapKdf, &mut Board::default()).map(|_| ()),
            &|m, cut, apply| {
                let a = boot_with(m, PIN_A);
                let b = boot_with(m, PIN_B);
                assert!(
                    (a == Some(seeds())) ^ (b == Some(seeds())),
                    "cut {cut} apply {apply}: exactly one secret must open the board"
                );
            },
        );
    }

    #[test]
    fn changing_the_secret_mid_migration_never_strands_a_seed() {
        // Half-migrated: slot 0 under DK, slots 1 and 2 still under PIN_A.
        let start = legacy_board(PIN_A);
        let mut m = start.armed(1, true);
        assert!(unlock_and_migrate(&mut m, PIN_A).is_err());
        let mut m = m.reboot();
        assert_eq!(
            seed_format(&m.map[&seed_enc_key(0)]),
            Some(SeedFormat::DataKey)
        );
        assert_eq!(
            seed_format(&m.map[&seed_enc_key(1)]),
            Some(SeedFormat::Secret)
        );

        let locked = locked_slots(&m);
        let u = unlock_with_secret(&m, &locked, PIN_A, &CheapKdf, &mut Board::default()).unwrap();
        let dk = u.dk;
        assert!(dk.is_some());
        let half = m.reboot();
        sweep(
            &half,
            &|m| set_secret(m, PIN_B, &seeds(), dk, &CheapKdf, &mut Board::default()).map(|_| ()),
            &|m, cut, apply| {
                let a = boot_with(m, PIN_A);
                let b = boot_with(m, PIN_B);
                assert!(
                    (a == Some(seeds())) ^ (b == Some(seeds())),
                    "cut {cut} apply {apply}"
                );
            },
        );
        set_secret(
            &mut m,
            PIN_B,
            &seeds(),
            dk,
            &CheapKdf,
            &mut Board::default(),
        )
        .unwrap();
        assert_eq!(boot_with(&m, PIN_B), Some(seeds()));
    }

    #[test]
    fn enabling_on_a_plaintext_board_survives_a_cut_at_every_write() {
        let start = plaintext_board();
        sweep(
            &start,
            &|m| set_secret(m, PIN_A, &seeds(), None, &CheapKdf, &mut Board::default()).map(|_| ()),
            &|m, cut, apply| {
                assert_eq!(
                    boot_with(m, PIN_A),
                    Some(seeds()),
                    "cut {cut} apply {apply}"
                );
            },
        );
        let mut m = start.reboot();
        set_secret(
            &mut m,
            PIN_A,
            &seeds(),
            None,
            &CheapKdf,
            &mut Board::default(),
        )
        .unwrap();
        for slot in SLOTS {
            assert!(
                !m.map.contains_key(&seed_plain_key(slot)),
                "plaintext left in slot {slot}"
            );
        }
        assert_eq!(boot_with(&m, PIN_B), None);
    }

    #[test]
    fn enabling_refuses_when_seeds_are_sealed_but_no_data_key_is_held() {
        let mut m = legacy_board(PIN_A);
        assert_eq!(
            set_secret(
                &mut m,
                PIN_B,
                &seeds(),
                None,
                &CheapKdf,
                &mut Board::default()
            ),
            Err(ChangeError::NoDataKey)
        );
        assert_eq!(boot_with(&m, PIN_A), Some(seeds()));
    }

    #[test]
    fn disabling_survives_a_cut_at_every_write() {
        let mut start = legacy_board(PIN_A);
        unlock_and_migrate(&mut start, PIN_A).unwrap();
        let mut phones = PhoneSet::default();
        phones.enrol(1, "p", &s(1), &[0; 32], &[0; 12]).unwrap();
        start.map.insert(String::from(PHONES_KEY), phones.encode());
        sweep(
            &start.reboot(),
            &|m| clear_secret(m, &seeds()),
            &|m, cut, apply| {
                assert_eq!(
                    boot_with(m, PIN_A),
                    Some(seeds()),
                    "cut {cut} apply {apply}"
                );
            },
        );
        let mut m = start.reboot();
        clear_secret(&mut m, &seeds()).unwrap();
        assert!(
            m.map.keys().all(|k| k.starts_with("master_")),
            "{:?}",
            m.map.keys()
        );
        assert_eq!(
            boot_with(&m, PIN_B),
            Some(seeds()),
            "plaintext needs no secret"
        );
    }

    #[test]
    fn a_secret_change_keeps_enrolled_phones_working() {
        let mut m = legacy_board(PIN_A);
        let dk = unlock_and_migrate(&mut m, PIN_A).unwrap().dk.unwrap();
        let mut phones = PhoneSet::default();
        phones.enrol(5, "phone", &s(5), &dk, &[4; 12]).unwrap();
        save_phones(&mut m, &phones).unwrap();

        set_secret(
            &mut m,
            PIN_B,
            &seeds(),
            Some(dk),
            &CheapKdf,
            &mut Board::default(),
        )
        .unwrap();
        let loaded = load_phones(&m).unwrap();
        let from_phone = loaded.unwrap(5, &s(5)).unwrap();
        let u = unlock_with_data_key(&m, &SLOTS, &from_phone).unwrap();
        assert_eq!(u.seeds, seeds());
    }

    #[test]
    fn a_phone_cannot_unlock_before_migration_or_with_a_wrong_key() {
        let m = legacy_board(PIN_A);
        assert_eq!(
            unlock_with_data_key(&m, &SLOTS, &[1; 32]).err(),
            Some(UnlockError::NeedsSecret)
        );
        let mut m = m.reboot();
        unlock_and_migrate(&mut m, PIN_A).unwrap();
        assert_eq!(
            unlock_with_data_key(&m, &SLOTS, &[1; 32]).err(),
            Some(UnlockError::WrongSecret)
        );
    }

    #[test]
    fn phone_records_round_trip_through_storage_and_damage_is_not_empty() {
        let mut m = Mem::default();
        assert_eq!(load_phones(&m), Ok(PhoneSet::default()));
        let mut phones = PhoneSet::default();
        phones.enrol(1, "p", &s(1), &[0; 32], &[0; 12]).unwrap();
        save_phones(&mut m, &phones).unwrap();
        assert_eq!(load_phones(&m), Ok(phones.clone()));
        m.map.get_mut(PHONES_KEY).unwrap().push(0);
        assert!(load_phones(&m).is_err());
        phones.revoke(1).unwrap();
        save_phones(&mut m, &phones).unwrap();
        assert!(!m.map.contains_key(PHONES_KEY));
    }

    #[test]
    fn the_note_key_seal_is_not_a_seed() {
        let dk = [3u8; 32];
        let nk = [4u8; 32];
        let blob = seal_note_key(&dk, &nk, &[5; 12]);
        assert_eq!(open_note_key(&dk, &blob), Ok(nk));
        assert_eq!(seed_format(&blob), None);
        assert_eq!(
            open(&dk, Purpose::Seed, &blob),
            Err(SealError::WrongPurpose)
        );
    }
}
