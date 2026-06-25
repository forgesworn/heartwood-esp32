//! ESP8266 feasibility spike: can a BIP-340 Schnorr signer compile to
//! xtensa-lx106 (the ESP8266 core) under `no_std`?
//!
//! This is a COMPILE/SIZE probe, not a runnable firmware. It exports two
//! `extern "C"` entries — HMAC-SHA256 child-key derivation and a BIP-340
//! Schnorr signature with pure-Rust `k256` — so the full signing code path is
//! reachable (not dead-code-stripped) and its machine code can be sized.
//!
//! See `README.md` for the measured result and the go/no-go verdict.

#![no_std]

use hmac::{Hmac, Mac};
use k256::schnorr::signature::Signer;
use k256::schnorr::{Signature, SigningKey};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Sign a 32-byte Nostr event id with a 32-byte secret key, BIP-340 Schnorr.
///
/// `seed32`/`msg32` are 32-byte buffers; `out64` receives the 64-byte
/// signature. Returns 0 on success, negative on error.
///
/// # Safety
/// Raw-pointer FFI: the three buffers must be valid and correctly sized.
#[no_mangle]
pub unsafe extern "C" fn heartwood_schnorr_sign(
    seed32: *const u8,
    msg32: *const u8,
    out64: *mut u8,
) -> i32 {
    let seed = core::slice::from_raw_parts(seed32, 32);
    let msg = core::slice::from_raw_parts(msg32, 32);

    let sk = match SigningKey::from_bytes(seed) {
        Ok(k) => k,
        Err(_) => return -1,
    };

    // Deterministic BIP-340 sign (aux_rand = 0). Nostr signs the 32-byte event
    // id directly, which is exactly a 32-byte BIP-340 message.
    let sig: Signature = match sk.try_sign(msg) {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let bytes = sig.to_bytes();
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), out64, 64);
    0
}

/// Derive a 32-byte child key from a 32-byte seed and a label via HMAC-SHA256
/// — the same primitive `heartwood-common::derive` uses (wire the exact
/// label/order to it for byte-compatibility before any real use).
///
/// # Safety
/// Raw-pointer FFI: `seed32`/`out32` are 32 bytes; `info`/`info_len` a valid slice.
#[no_mangle]
pub unsafe extern "C" fn heartwood_derive_child(
    seed32: *const u8,
    info: *const u8,
    info_len: usize,
    out32: *mut u8,
) -> i32 {
    let seed = core::slice::from_raw_parts(seed32, 32);
    let info = core::slice::from_raw_parts(info, info_len);

    let mut mac = match HmacSha256::new_from_slice(seed) {
        Ok(m) => m,
        Err(_) => return -1,
    };
    mac.update(info);
    let out = mac.finalize().into_bytes(); // 32 bytes
    core::ptr::copy_nonoverlapping(out.as_ptr(), out32, 32);
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
