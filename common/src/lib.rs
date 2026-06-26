// no_std for bare-metal consumers (the ESP8266 firmware); std under `cfg(test)`
// so the crate's own host tests still link the test harness. `alloc` is always
// available — modules pull Vec/String/etc. from it.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod derive;
pub mod encoding;
pub mod frame;
pub mod hex;
pub mod types;
pub mod validate;

#[cfg(feature = "nip46")]
pub mod backup;

#[cfg(feature = "nip46")]
pub mod nip46;

#[cfg(feature = "nip44")]
pub mod nip44;

#[cfg(feature = "nip04")]
pub mod nip04;

#[cfg(feature = "nip46")]
pub mod policy;

pub mod net_config;

pub mod mgmt;

#[cfg(feature = "mnemonic")]
pub mod mnemonic;

#[cfg(feature = "mnemonic")]
pub mod restore;
