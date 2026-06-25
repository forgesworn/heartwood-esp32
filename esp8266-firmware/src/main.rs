//! Heartwood ESP8266 tethered-signer firmware.
//!
//! The device half of the daemon-mediated signer: it speaks the HW serial frame
//! protocol over UART0 to the `heartwood-bridge` daemon, which couriers NIP-46
//! traffic to/from the Nostr relays. This is the bare-metal counterpart of the
//! ESP32 firmware's serial path.
//!
//! Implemented (compiles + links; untested on hardware):
//!   - `SESSION_AUTH` (0x21) → `SESSION_ACK` (0x22): authenticate the bridge.
//!   - `FIRMWARE_INFO` (0x59) → `0x5A`: version/board.
//!   - `PROVISION_LIST` (0x05) → `0x07`: report the k256 npub identity.
//!   - `ENCRYPTED_REQUEST` (0x10) → `SIGN_ENVELOPE_RESPONSE` (0x35): the inline
//!     NIP-44 decrypt → NIP-46 dispatch → re-encrypt → sign-kind:24133 path,
//!     reusing `heartwood-common`. Unknown frames → `NACK` (0x15).
//!
//! Placeholders / known gaps: the master seed + bridge secret are hardcoded
//! (flash storage TODO), no button approval (auto-approve), and the NIP-44 nonce
//! RNG needs an entropy review (see `sign_path::random_nonce`).

#![no_std]
#![no_main]

extern crate alloc;

mod bech32;
mod crypto;
mod frame;
mod heap;
mod sign_path;

use esp8266_hal::prelude::*;
use esp8266_hal::target::Peripherals;
use panic_halt as _;

/// Bridge-session secret. Placeholder until it's read from a reserved flash
/// sector (the ESP32 stores it in NVS; the lx106 has no NVS). Matches the
/// daemon's expectation that the host presents a 32-byte shared secret.
const BRIDGE_SECRET: [u8; 32] = [0x42; 32];

/// Master signing secret. Placeholder until read from a reserved flash sector
/// (the ESP32 stores it in NVS; the lx106 has none). Any valid secp256k1 scalar
/// works for the scaffold — the device derives its npub identity from this.
const MASTER_SEED: [u8; 32] = [0x11; 32];

#[entry]
fn main() -> ! {
    heap::init();

    let dp = Peripherals::take().unwrap();

    // Disable the watchdog: the signer blocks on `serial.read()` while idle and
    // runs multi-second EC math during a sign — an active WDT would reset it
    // mid-operation. (esp8266-hal's WatchdogExt; `disable` via embedded_hal.)
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

    // Box the frame buffers onto the heap — MAX_FRAME (~4 KB each) is too large
    // for the lx106's small stack.
    let mut reader = alloc::boxed::Box::new(frame::Reader::new());
    let mut out = alloc::vec![0u8; frame::MAX_FRAME];
    let mut authenticated = false;

    loop {
        let byte = match nb::block!(serial.read()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if let Some(frame_type) = reader.push(byte) {
            if let Some(len) = handle(frame_type, reader.payload(), &mut authenticated, &mut out) {
                for &b in &out[..len] {
                    let _ = nb::block!(serial.write(b));
                }
            }
        }
    }
}

/// Dispatch one received frame. Returns `Some(len)` of a response frame written
/// into `out`, or `None` if there is nothing to reply.
fn handle(frame_type: u8, payload: &[u8], authenticated: &mut bool, out: &mut [u8]) -> Option<usize> {
    match frame_type {
        // Bridge-session authentication: constant-time compare the 32-byte
        // secret, reply SESSION_ACK with 0x00 = ok / 0x01 = wrong secret.
        frame::SESSION_AUTH => {
            let status = if payload.len() == 32 && ct_eq(payload, &BRIDGE_SECRET) {
                *authenticated = true;
                0x00u8
            } else {
                *authenticated = false;
                0x01u8
            };
            frame::build(out, frame::SESSION_ACK, &[status])
        }

        // Read-only version/board query — safe regardless of auth.
        frame::FIRMWARE_INFO => frame::build(
            out,
            frame::FIRMWARE_INFO_RESPONSE,
            br#"{"version":"0.0.1","board":"esp8266"}"#,
        ),

        // Report the signing identity: derive the x-only pubkey from the master
        // seed, bech32-encode it as an npub, return the JSON the daemon parses:
        // [{slot,label,mode,npub}].
        frame::PROVISION_LIST => {
            let pk = crypto::pubkey(&MASTER_SEED)?;
            let mut npub = [0u8; 63];
            let n = bech32::encode(b"npub", &pk, &mut npub)?;
            let mut json = [0u8; 160];
            let mut j = 0;
            let pre = br#"[{"slot":0,"label":"default","mode":1,"npub":""#;
            json[j..j + pre.len()].copy_from_slice(pre);
            j += pre.len();
            json[j..j + n].copy_from_slice(&npub[..n]);
            j += n;
            let post = br#""}]"#;
            json[j..j + post.len()].copy_from_slice(post);
            j += post.len();
            frame::build(out, frame::PROVISION_LIST_RESPONSE, &json[..j])
        }

        // The inline sign path: NIP-44 decrypt → NIP-46 dispatch → re-encrypt →
        // sign the kind:24133 envelope (heartwood-common does the crypto).
        // Gated on a successful SESSION_AUTH, like the ESP32.
        frame::ENCRYPTED_REQUEST => {
            if !*authenticated {
                frame::build(out, frame::NACK, &[])
            } else {
                match sign_path::handle(&MASTER_SEED, payload) {
                    Some(event_json) => {
                        frame::build(out, frame::SIGN_ENVELOPE_RESPONSE, event_json.as_bytes())
                    }
                    None => frame::build(out, frame::NACK, &[]),
                }
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
