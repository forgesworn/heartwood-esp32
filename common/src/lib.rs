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
pub mod types;
pub mod validate;

#[cfg(feature = "nip46")]
pub mod backup;

#[cfg(feature = "nip46")]
pub mod nip46;

#[cfg(feature = "nip44")]
pub mod nip44;

#[cfg(all(feature = "nip46", feature = "nip44"))]
pub mod nip59;

#[cfg(feature = "nip46")]
pub mod escalate;

#[cfg(feature = "nip04")]
pub mod nip04;

#[cfg(feature = "nip46")]
pub mod policy;

pub mod net_config;

pub mod mgmt;

pub mod persistent_state;

pub mod persona_pack;

pub mod reply_clock;

pub mod approval_queue;

pub mod held_reply;

pub mod wrap_ledger;

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

#[cfg(feature = "seed-encrypt")]
pub mod seed_cipher;

#[cfg(feature = "seed-encrypt")]
pub mod note_seal;

#[cfg(feature = "mnemonic")]
pub mod restore;

#[cfg(feature = "mnemonic")]
pub mod recovery_words;
