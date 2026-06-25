//! Heartwood ESP8266 tethered-signer firmware.
//!
//! The device half of the daemon-mediated signer: it speaks the HW serial frame
//! protocol over UART0 to the `heartwood-bridge` daemon, which couriers NIP-46
//! traffic to/from the Nostr relays. This is the bare-metal counterpart of the
//! ESP32 firmware's serial path.
//!
//! Control plane implemented so far (no allocator needed):
//!   - `SESSION_AUTH` (0x21) → `SESSION_ACK` (0x22): authenticate the bridge.
//!   - `FIRMWARE_INFO` (0x59) → `0x5A`: version/board.
//!   - unknown frames → `NACK` (0x15).
//!
//! Still to come (needs flash key storage + the crypto stack, likely an
//! allocator): `PROVISION_LIST` (0x05) and the inline `ENCRYPTED_REQUEST`
//! (0x10) → `SIGN_ENVELOPE_RESPONSE` (0x35) signing path.

#![no_std]
#![no_main]

mod frame;

use esp8266_hal::prelude::*;
use esp8266_hal::target::Peripherals;
use panic_halt as _;

/// Bridge-session secret. Placeholder until it's read from a reserved flash
/// sector (the ESP32 stores it in NVS; the lx106 has no NVS). Matches the
/// daemon's expectation that the host presents a 32-byte shared secret.
const BRIDGE_SECRET: [u8; 32] = [0x42; 32];

#[entry]
fn main() -> ! {
    let dp = Peripherals::take().unwrap();
    let pins = dp.GPIO.split();
    // UART0: GPIO1 = TX, GPIO3 = RX — the pins wired to the USB-UART bridge.
    let mut serial = dp
        .UART0
        .serial(pins.gpio1.into_uart(), pins.gpio3.into_uart());

    // Brief settle before we start talking to the host.
    let (mut timer1, _) = dp.TIMER.timers();
    timer1.delay_ms(50);

    let mut reader = frame::Reader::new();
    let mut out = [0u8; frame::MAX_FRAME];
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

        // PROVISION_LIST / ENCRYPTED_REQUEST need key storage + the crypto
        // stack — not yet implemented; NACK so the daemon fails cleanly.
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
