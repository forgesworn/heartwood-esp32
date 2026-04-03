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
