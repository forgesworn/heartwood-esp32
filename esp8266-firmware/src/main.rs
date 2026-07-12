//! Heartwood ESP8266 tethered-signer firmware.
//!
//! The device half of the daemon-mediated signer: it speaks the HW serial frame
//! protocol over UART0 to the `heartwood-bridge` daemon, which couriers NIP-46
//! traffic to/from the Nostr relays. This is the bare-metal counterpart of the
//! ESP32 firmware's serial path.
//!
//! Implemented (compiles + links; untested on hardware):
//!   - `PROVISION` (0x01) → `ACK`: button-gated write of the master seed to a
//!     reserved flash sector (`storage`) — a compromised host cannot silently
//!     overwrite the key. `SET_BRIDGE_SECRET` (0x23) → `ACK` pairs the
//!     bridge-session secret.
//!   - `SESSION_AUTH` (0x21) → `SESSION_ACK` (0x22): authenticate the bridge.
//!   - `FIRMWARE_INFO` (0x59) → `0x5A`: version/board.
//!   - `PROVISION_LIST` (0x05) → `0x07`: report the k256 npub identity.
//!   - `ENCRYPTED_REQUEST` (0x10) → `SIGN_ENVELOPE_RESPONSE` (0x35): the inline
//!     NIP-44 decrypt → NIP-46 dispatch → re-encrypt → sign-kind:24133 path,
//!     reusing `heartwood-common`. Unknown frames → `NACK` (0x15).
//!
//! Known gaps: the NIP-44 nonce RNG needs an entropy review (see
//! `sign_path::random_nonce`).

#![no_std]
#![no_main]

extern crate alloc;

mod bech32;
mod button;
mod crypto;
mod frame;
mod heap;
mod identity;
mod oled;
mod selftest;
mod sign_path;
mod storage;

use esp8266_hal::flash::ESPFlash;
use esp8266_hal::prelude::*;
use esp8266_hal::target::Peripherals;
use panic_halt as _;

use storage::Keys;

const FIRMWARE_INFO_JSON: &str = concat!(
    "{\"version\":\"",
    env!("CARGO_PKG_VERSION"),
    "\",\"board\":\"esp8266\"}"
);

#[entry]
fn main() -> ! {
    heap::init();

    let dp = Peripherals::take().unwrap();

    // Disable the watchdog: the signer blocks on `serial.read()` while idle and
    // runs multi-second EC math during a sign — an active WDT would reset it.
    dp.WDT.watchdog().disable();

    let pins = dp.GPIO.split();
    // UART0: GPIO1 = TX, GPIO3 = RX — the pins wired to the USB-UART bridge.
    let mut serial = dp
        .UART0
        .serial(pins.gpio1.into_uart(), pins.gpio3.into_uart());

    // esp8266-hal's serial() leaves UART0 at the boot ROM's baud (~74880); the
    // daemon talks 115200. Set the divisor directly — the HAL has no baud API.
    set_uart0_baud_115200();

    // Brief settle before we start talking to the host.
    let (mut timer1, _) = dp.TIMER.timers();
    timer1.delay_ms(50);

    // Load the master seed + bridge secret from flash (None = unprovisioned).
    let mut flash = dp.SPI0.flash();
    let mut keys = storage::load(&mut flash);

    // OLED on GPIO14 (SDA) / GPIO12 (SCL): show the device identity on boot, so
    // the operator can read the npub without the daemon.
    // Box it: the SSD1306 buffered mode holds a 1 KB framebuffer, too big to keep
    // in main's frame for the whole program on the lx106's small stack.
    let mut oled = alloc::boxed::Box::new(oled::Oled::new(
        pins.gpio14.into_open_drain_output(),
        pins.gpio12.into_open_drain_output(),
    ));

    // Power-on self-test: validate the crypto against known-answer vectors on the
    // real silicon before trusting it with a key. Refuse to operate if it fails —
    // a signer with corrupt crypto is worse than a dead one.
    oled.show_status("self-test...");
    if let Err(which) = selftest::run() {
        oled.show_lines(&["SELF-TEST FAILED", "", which, "", "do not use"]);
        loop {}
    }

    match keys.as_ref().and_then(|k| crypto::pubkey(&k.master_seed)) {
        Some(pk) => {
            let mut npub = [0u8; 63];
            match bech32::encode(b"npub", &pk, &mut npub) {
                Some(n) => oled.show_npub(core::str::from_utf8(&npub[..n]).unwrap_or("")),
                None => oled.show_lines(&["Heartwood signer", "", "(npub error)"]),
            }
        }
        None => oled.show_lines(&["Heartwood signer", "", "unprovisioned", "provision over USB"]),
    }

    // Box the frame buffers onto the heap — MAX_FRAME (~4 KB each) is too large
    // for the lx106's small stack.
    let mut reader = alloc::boxed::Box::new(frame::Reader::new());
    let mut out = alloc::vec![0u8; frame::MAX_FRAME];
    let mut authenticated = false;
    // nsec-tree state: cached derived personas + per-client active-identity
    // sessions. RAM-only; both empty until a heartwood_* request populates them.
    let mut cache = identity::IdentityCache::new();
    let mut sessions = identity::Sessions::new();

    loop {
        let byte = match nb::block!(serial.read()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Some(frame_type) = reader.push(byte) {
            let resp = handle(
                frame_type,
                reader.payload(),
                &mut keys,
                &mut authenticated,
                &mut cache,
                &mut sessions,
                &mut flash,
                &mut out,
                oled.as_mut(),
            );
            if let Some(len) = resp {
                for &b in &out[..len] {
                    let _ = nb::block!(serial.write(b));
                }
            }
        }
    }
}

/// Dispatch one received frame. Returns `Some(len)` of a response frame written
/// into `out`, or `None` if there is nothing to reply.
#[allow(clippy::too_many_arguments)]
fn handle(
    frame_type: u8,
    payload: &[u8],
    keys: &mut Option<Keys>,
    authenticated: &mut bool,
    cache: &mut identity::IdentityCache,
    sessions: &mut identity::Sessions,
    flash: &mut ESPFlash,
    out: &mut [u8],
    oled: &mut oled::Oled,
) -> Option<usize> {
    match frame_type {
        // Provision the master seed: write it (plus the existing bridge secret)
        // to flash. Payload is the raw 32-byte seed, or the ESP32 form
        // [mode][label_len][label][secret_32] — we take the trailing 32 bytes.
        // Gated on a physical button hold: a compromised host must not be able to
        // silently overwrite the signing key.
        frame::PROVISION => {
            if payload.len() < 32 {
                return frame::build(out, frame::NACK, &[]);
            }
            oled.show_lines(&["PROVISION SEED?", "", "writes a new key", "", "hold FLASH = approve"]);
            if !button::await_approval() {
                oled.show_status("denied");
                return frame::build(out, frame::NACK, &[]);
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&payload[payload.len() - 32..]);
            // The ESP32 form is [mode][label_len][label][secret_32]; the raw
            // 32-byte form carries no mode. Take the leading mode byte when it is
            // a valid MasterMode (0..=2), else default (treat the seed as a tree root).
            let mode = if payload.len() > 32 && payload[0] <= 2 {
                payload[0]
            } else {
                storage::DEFAULT_MODE
            };
            let bridge_secret = keys.as_ref().map_or([0u8; 32], |k| k.bridge_secret);
            let new = Keys { master_seed: seed, bridge_secret, mode };
            storage::store(flash, &new);
            *keys = Some(new);
            oled.show_status("provisioned");
            frame::build(out, frame::ACK, &[])
        }

        // Provision the 32-byte bridge-session secret (alongside the seed).
        frame::SET_BRIDGE_SECRET => {
            if payload.len() != 32 {
                return frame::build(out, frame::NACK, &[]);
            }
            let mut bridge_secret = [0u8; 32];
            bridge_secret.copy_from_slice(payload);
            let (master_seed, mode) = keys
                .as_ref()
                .map_or(([0u8; 32], storage::DEFAULT_MODE), |k| (k.master_seed, k.mode));
            let new = Keys { master_seed, bridge_secret, mode };
            storage::store(flash, &new);
            *keys = Some(new);
            frame::build(out, frame::ACK, &[])
        }

        // Bridge-session authentication: constant-time compare the 32-byte secret
        // against the provisioned one. 0x00 = ok / 0x01 = wrong / 0x02 = none.
        frame::SESSION_AUTH => {
            let status = match keys.as_ref() {
                None => 0x02u8,
                Some(k) if payload.len() == 32 && ct_eq(payload, &k.bridge_secret) => {
                    *authenticated = true;
                    0x00
                }
                Some(_) => {
                    *authenticated = false;
                    0x01
                }
            };
            frame::build(out, frame::SESSION_ACK, &[status])
        }

        // Read-only version/board query — safe regardless of auth.
        frame::FIRMWARE_INFO => frame::build(
            out,
            frame::FIRMWARE_INFO_RESPONSE,
            FIRMWARE_INFO_JSON.as_bytes(),
        ),

        // Report the signing identity: derive the npub from the provisioned seed.
        // Unprovisioned (or invalid seed) → empty list.
        frame::PROVISION_LIST => {
            let info = keys
                .as_ref()
                .and_then(|k| crypto::pubkey(&k.master_seed).map(|pk| (pk, k.mode)));
            match info {
                Some((pk, mode)) => {
                    let mut npub = [0u8; 63];
                    let n = bech32::encode(b"npub", &pk, &mut npub)?;
                    let mut json = [0u8; 160];
                    let mut j = 0;
                    let pre = br#"[{"slot":0,"label":"default","mode":"#;
                    json[j..j + pre.len()].copy_from_slice(pre);
                    j += pre.len();
                    json[j] = b'0' + mode.min(9); // the MasterMode digit (0..=2)
                    j += 1;
                    let mid = br#","npub":""#;
                    json[j..j + mid.len()].copy_from_slice(mid);
                    j += mid.len();
                    json[j..j + n].copy_from_slice(&npub[..n]);
                    j += n;
                    let post = br#""}]"#;
                    json[j..j + post.len()].copy_from_slice(post);
                    j += post.len();
                    frame::build(out, frame::PROVISION_LIST_RESPONSE, &json[..j])
                }
                None => frame::build(out, frame::PROVISION_LIST_RESPONSE, b"[]"),
            }
        }

        // The inline sign path. Gated on a successful SESSION_AUTH + a seed.
        frame::ENCRYPTED_REQUEST => {
            if !*authenticated {
                return frame::build(out, frame::NACK, &[]);
            }
            match keys
                .as_ref()
                .and_then(|k| sign_path::handle(&k.master_seed, k.mode, payload, cache, sessions, oled))
            {
                // If the signed envelope is larger than a frame can carry (a big
                // event on this RAM-limited device), NACK rather than silently
                // sending nothing — so the daemon fails loudly, not by timeout.
                Some(event_json) => {
                    frame::build(out, frame::SIGN_ENVELOPE_RESPONSE, event_json.as_bytes())
                        .or_else(|| frame::build(out, frame::NACK, &[]))
                }
                None => frame::build(out, frame::NACK, &[]),
            }
        }

        _ => frame::build(out, frame::NACK, &[]),
    }
}

/// Constant-time byte-slice equality (avoid leaking the secret via timing).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Set UART0 to 115200 baud by writing the clock-divisor register directly.
/// esp8266-hal 0.5 exposes no baud API, so `serial()` leaves UART0 at the boot
/// ROM's ~74880 baud — mismatched with the daemon's 115200. `UART0_CLKDIV`
/// (0x6000_0014) = APB clock / baud; the board runs at 80 MHz (esp8266-hal's
/// assumed clock), so 80_000_000 / 115_200 = 694.
fn set_uart0_baud_115200() {
    const UART0_CLKDIV: *mut u32 = 0x6000_0014 as *mut u32;
    const DIVISOR: u32 = 80_000_000 / 115_200;
    unsafe { core::ptr::write_volatile(UART0_CLKDIV, DIVISOR) };
}
