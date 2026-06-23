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
/// recovery-phrase picker is driven by: a **single tap** moves the highlight, a
/// **double-tap** selects whatever is highlighted (including the on-screen
/// "delete" item). A single press of *any* length is one tap, so lingering on
/// the button can never select by accident, and there is no hold duration to
/// time. Distinct from [`ButtonResult`] (the 2 s signing approve/deny hold).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Press {
    /// A single tap — advance the highlight to the next choice.
    Tap,
    /// A double-tap — select the highlighted choice.
    Double,
}

/// Window after a tap's release in which a second tap counts as a double-tap
/// (select). Short enough that single-tap "next" stays responsive; long enough
/// to double-tap comfortably on the small PRG button. Well clear of the 2 s
/// save/approval hold used elsewhere, so the vocabularies don't collide.
const DOUBLE_TAP_WINDOW_MS: u64 = 300;

/// Wait for one classified press on the PRG button.
///
/// Returns `None` if `idle_timeout` elapses before any press begins (so the
/// caller can keep its screen alive without blocking forever). A single press
/// of *any* duration is a [`Press::Tap`] — so lingering on the button never
/// selects by accident. If a second press begins within [`DOUBLE_TAP_WINDOW_MS`]
/// of the first's release, the pair is a [`Press::Double`] (select); both
/// presses are drained so the next read starts from a clean release.
pub fn read_press(pin: &PinDriver<'_, Input>, idle_timeout: Duration) -> Option<Press> {
    let idle_deadline = Instant::now() + idle_timeout;

    // Wait for the first press to begin.
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

    // A single press of any length is one tap — wait out its release so a long
    // hold can never be mistaken for a selection.
    drain_release(pin);

    // A second press within the window turns the pair into a double-tap (select).
    let window_deadline = Instant::now() + Duration::from_millis(DOUBLE_TAP_WINDOW_MS);
    loop {
        if Instant::now() >= window_deadline {
            return Some(Press::Tap);
        }
        if pin.is_low() {
            esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE.as_millis() as u32);
            drain_release(pin);
            return Some(Press::Double);
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
