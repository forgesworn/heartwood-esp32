// firmware/src/button.rs
//
// PRG button (GPIO 0) handler with press-duration measurement.
// Long hold (>=2s) = approve, short press (<2s) = deny.
//
// GPIO 0 is active low: pressed = LOW, released = HIGH (internal pull-up).

use std::time::{Duration, Instant};

use esp_idf_hal::gpio::{Input, PinDriver};

/// Result of a button interaction.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ButtonResult {
    /// User held the button for at least 2 seconds — request approved.
    Approve,
    /// User pressed and released in under 2 seconds — request denied.
    Deny,
}

/// Minimum hold duration to count as approval.
const LONG_HOLD_THRESHOLD: Duration = Duration::from_millis(2000);

/// Debounce window applied on both press and release edges.
const DEBOUNCE: Duration = Duration::from_millis(50);

/// Polling interval between GPIO reads (ms).
const POLL_INTERVAL_MS: u32 = 20;

/// Wait for a complete press/release cycle on the PRG button.
///
/// Returns `Some(ButtonResult)` once the button has been pressed and released,
/// or `None` if `timeout` elapses before a press begins.
///
/// # Arguments
///
/// * `pin`    — borrowed input driver for GPIO 0 (active-low, pull-up)
/// * `timeout` — maximum time to wait for the press to begin
pub fn wait_for_press(
    pin: &PinDriver<'_, Input>,
    timeout: Duration,
) -> Option<ButtonResult> {
    let deadline = Instant::now() + timeout;

    // Wait for the button to be pressed (active low — pin goes LOW).
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        if pin.is_low() {
            break;
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(POLL_INTERVAL_MS);
    }

    // Debounce: ignore transient noise on the falling edge.
    esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE.as_millis() as u32);

    // Measure how long the button is held down.
    let press_start = Instant::now();

    loop {
        if Instant::now() >= deadline {
            // Timeout whilst held — treat whatever we have so far as the result.
            break;
        }
        if pin.is_high() {
            // Debounce the rising edge before accepting the release.
            esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE.as_millis() as u32);
            break;
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(POLL_INTERVAL_MS);
    }

    let held = Instant::now() - press_start;

    if held >= LONG_HOLD_THRESHOLD {
        Some(ButtonResult::Approve)
    } else {
        Some(ButtonResult::Deny)
    }
}

// ---------------------------------------------------------------------------
// Tap / hold press primitive — for one-button text entry
// ---------------------------------------------------------------------------

/// A classified press on the PRG button, the vocabulary the on-device
/// recovery-phrase picker is driven by: **tap** moves the highlight, **hold**
/// selects whatever is highlighted (including the on-screen "delete" item). Two
/// gestures, no double-tap timing — so a tap registers instantly on release
/// and cycling stays snappy. Distinct from [`ButtonResult`] (signing approve/deny).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Press {
    /// A short tap — advance the highlight to the next choice.
    Tap,
    /// A deliberate hold — select the highlighted choice.
    Hold,
}

/// Hold duration that counts as a [`Press::Hold`] (select). Comfortably above a
/// quick tap, and well below the 2 s save/approval hold used elsewhere, so the
/// vocabularies don't collide.
const PRESS_HOLD_MS: u128 = 400;

/// Wait for one classified press on the PRG button.
///
/// Returns `None` if `idle_timeout` elapses before any press begins (so the
/// caller can keep its screen alive without blocking forever). A hold is
/// reported the instant it crosses [`PRESS_HOLD_MS`] — then the button is
/// drained to its release, so the *next* `read_press` (e.g. a confirmation hold
/// on the following screen) starts from a clean release and can't be satisfied
/// by the same continuous press.
pub fn read_press(pin: &PinDriver<'_, Input>, idle_timeout: Duration) -> Option<Press> {
    let idle_deadline = Instant::now() + idle_timeout;

    // Wait for the press to begin.
    loop {
        if Instant::now() >= idle_deadline {
            return None;
        }
        if pin.is_low() {
            break;
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(POLL_INTERVAL_MS);
    }
    esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE.as_millis() as u32);

    // Measure it: a hold past the threshold fires immediately (then drains);
    // otherwise releasing makes it a tap.
    let press_start = Instant::now();
    loop {
        if pin.is_high() {
            esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE.as_millis() as u32);
            return Some(Press::Tap);
        }
        if press_start.elapsed().as_millis() >= PRESS_HOLD_MS {
            drain_release(pin);
            return Some(Press::Hold);
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(POLL_INTERVAL_MS);
    }
}

/// Block until the button is released, with a debounce on the rising edge.
fn drain_release(pin: &PinDriver<'_, Input>) {
    while pin.is_low() {
        esp_idf_hal::delay::FreeRtos::delay_ms(POLL_INTERVAL_MS);
    }
    esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE.as_millis() as u32);
}
