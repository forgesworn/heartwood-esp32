// firmware/src/display_flip.rs
//
//! Persisted screen orientation: upright, or turned through 180 degrees.
//!
//! A board sits whichever way its case or cable allows, and the Heltec and
//! T-Display carry their buttons on one edge, so an owner who turns the board
//! round gets the screen upside down and the button labels on the wrong side.
//! Only 180 degrees: every screen is laid out landscape, and a quarter turn
//! would squash all of them.
//!
//! The flip is applied when the panel is flushed (the mono OLED turns its own
//! scan direction round; the colour panels send their frame reversed), so no
//! screen code changes. The approval cards read [`is_flipped`] to put their
//! button labels beside the buttons.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use crate::nvs::ReplaceBlob;
use heartwood_common::types::{FRAME_TYPE_DISPLAY_FLIP_RESP, FRAME_TYPE_NACK};

use crate::serial::SerialPort;

const KEY: &str = "disp_flip";
/// How long the approve button is held on the device page to turn the screen.
const HOLD_MS: u128 = 2_000;

/// The orientation the panel is running with, as applied, not as stored.
static FLIPPED: AtomicBool = AtomicBool::new(false);

/// Whether the screen is currently turned through 180 degrees.
pub fn is_flipped() -> bool {
    FLIPPED.load(Ordering::Relaxed)
}

/// Whether the flip is persisted on.
pub fn read(nvs: &EspNvs<NvsDefault>) -> bool {
    let mut buf = [0u8; 1];
    matches!(nvs.get_blob(KEY, &mut buf), Ok(Some(b)) if b.len() == 1 && b[0] == 1)
}

/// Persist the flag. Callers apply it separately, after the write succeeds, so
/// the running and stored orientation never disagree silently.
pub fn write(nvs: &mut EspNvs<NvsDefault>, flipped: bool) -> Result<(), String> {
    nvs.replace_blob(KEY, &[u8::from(flipped)])
        .map_err(|e| format!("persist display orientation: {e:?}"))
}

/// Turn the panel and repaint what is on it.
pub fn apply(display: &mut crate::oled::Display<'_>, flipped: bool) {
    FLIPPED.store(flipped, Ordering::Relaxed);
    display.set_flipped(flipped);
    display.flush().ok();
}

/// Persist, then apply. The one path both the cable and the relay use.
pub fn set(
    nvs: &mut EspNvs<NvsDefault>,
    display: &mut crate::oled::Display<'_>,
    flipped: bool,
) -> Result<(), String> {
    write(nvs, flipped)?;
    apply(display, flipped);
    log::info!("display orientation: {}", if flipped { "flipped" } else { "upright" });
    Ok(())
}

/// On the device page of the idle carousel, a 2 s hold of the approve button
/// turns the screen round and keeps it that way. Returns false, having done
/// nothing, for a short press (the caller pages on as before) or no press.
///
/// On the board itself because a board in a case may never meet Sapwood, and
/// not at power-on because the approve button is GPIO0, whose low level at
/// reset selects the ROM download mode. Same shape as the notes page's hold
/// (offline_qr::launch_if_requested).
pub fn toggle_if_held(
    nvs: &mut EspNvs<NvsDefault>,
    display: &mut crate::oled::Display<'_>,
    buttons: &crate::button::Buttons<'_>,
) -> bool {
    if !buttons.a.is_low() {
        return false;
    }
    let started = Instant::now();
    while buttons.a.is_low() && started.elapsed().as_millis() < HOLD_MS {
        crate::wdt::feed();
        esp_idf_hal::delay::FreeRtos::delay_ms(20);
    }
    if started.elapsed().as_millis() < HOLD_MS {
        return false;
    }
    let flipped = !is_flipped();
    match set(nvs, display, flipped) {
        Ok(()) => crate::oled::show_result(
            display,
            if flipped { "SCREEN\nFLIPPED" } else { "SCREEN\nUPRIGHT" },
        ),
        Err(e) => {
            log::warn!("{e}");
            crate::oled::show_error(display, "Could not save\norientation");
            esp_idf_hal::delay::FreeRtos::delay_ms(2000);
        }
    }
    // The hold belongs to this gesture, never to the carousel.
    while buttons.a.is_low() {
        crate::wdt::feed();
        esp_idf_hal::delay::FreeRtos::delay_ms(20);
    }
    esp_idf_hal::delay::FreeRtos::delay_ms(30);
    crate::button::clear_press_edge();
    true
}

/// Handle a DISPLAY_FLIP frame (0x66). An empty payload asks; `[0]` or `[1]`
/// sets, and needs an authenticated bridge session (no press: turning the
/// picture round grants nothing). Answers DISPLAY_FLIP_RESP `[flipped]`.
pub fn handle_frame(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    nvs: &mut EspNvs<NvsDefault>,
    display: &mut crate::oled::Display<'_>,
    bridge_authenticated: bool,
) {
    match payload {
        [] => {}
        [value @ (0 | 1)] => {
            if !bridge_authenticated {
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"bridge auth required");
                return;
            }
            if let Err(e) = set(nvs, display, *value == 1) {
                log::warn!("{e}");
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"could not save the setting");
                return;
            }
        }
        _ => {
            crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"payload is empty, 0 or 1");
            return;
        }
    }
    crate::protocol::write_frame(usb, FRAME_TYPE_DISPLAY_FLIP_RESP, &[u8::from(is_flipped())]);
}
