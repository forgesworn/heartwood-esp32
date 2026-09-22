// no_std for bare-metal consumers (the ESP8266 firmware); std under `cfg(test)`
// so the crate's own host tests still link the test harness. `alloc` is always
// available — modules pull Vec/String/etc. from it.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod deadline;
pub mod derive;
pub mod encoding;
pub mod entropy;
pub mod frame;
pub mod hex;
pub mod http_date;
pub mod kinds;
pub mod ota_target;
pub mod types;
pub mod validate;

#[cfg(feature = "nip46")]
pub mod backup;

#[cfg(feature = "nip46")]
pub mod nip46;

#[cfg(feature = "nip44")]
pub mod nip44;

/// Canonical, encrypted-device-only rendezvous provisioning payloads. This is
/// deliberately available only alongside NIP-44: the scalar-bearing record
/// must never be emitted except as the plaintext immediately handed to that
/// encryption primitive.
#[cfg(feature = "nip44")]
pub mod rendezvous_provision;

#[cfg(all(feature = "nip46", feature = "nip44"))]
pub mod nip59;

#[cfg(feature = "nip46")]
pub mod escalate;

#[cfg(feature = "nip04")]
pub mod nip04;

#[cfg(feature = "nip46")]
pub mod policy;

// G4 foundation only; not connected to the firmware's active policy engine.
#[cfg(feature = "nip46")]
pub mod client_grants;

pub mod net_config;

pub mod mgmt;

pub mod persistent_state;

pub mod persona_pack;

pub mod reply_clock;

pub mod approval_queue;

pub mod held_reply;

pub mod wrap_ledger;

pub mod rendezvous_receipts;

pub mod trust;

pub mod note_store;

#[cfg(feature = "nip46")]
pub mod note_wrap;

#[cfg(feature = "nip46")]
pub mod note_cmd;

pub mod note_fmt;

#[cfg(feature = "mnemonic")]
pub mod mnemonic;

/// LUD-25 seed-recoverable note secrets. See the module docs for why this is a
/// separate tree from `derive`'s: different purpose, different shape, and the
/// only path on this device with an unhardened level in it.
#[cfg(feature = "cash")]
pub mod cash;

/// Which mints this device can derive notes for, and how far up each ladder
/// it has walked. The state behind [`cash`]'s arithmetic.
#[cfg(feature = "cash")]
pub mod cash_store;

/// LUD-25 Part 2: notes paid to this device's own keys, which it derives
/// from the identity that owns the lightning address.
#[cfg(feature = "cash")]
pub mod cash_key;

#[cfg(feature = "ota-sign")]
pub mod ota_sign;

/// Per-device cable identity challenge/response. It identifies a board to a
/// host by a key that is independent of every signer/master identity.
#[cfg(feature = "device-identity")]
pub mod device_identity;

/// PBKDF2-HMAC-SHA256 over a swappable SHA-256 compression function, so a
/// board with a SHA accelerator can run the sealed-seed KDF on the peripheral
/// while every other build keeps the pure-Rust path.
#[cfg(feature = "seed-encrypt")]
pub mod kdf;

#[cfg(feature = "seed-encrypt")]
pub mod seed_cipher;

#[cfg(feature = "seed-encrypt")]
pub mod note_seal;

#[cfg(feature = "mnemonic")]
pub mod restore;

#[cfg(feature = "mnemonic")]
pub mod recovery_words;
