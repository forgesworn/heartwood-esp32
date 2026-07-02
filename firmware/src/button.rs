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
// Gesture detection (single / double / long) — for one-button text entry
// ---------------------------------------------------------------------------

/// A classified button gesture, the vocabulary the on-device recovery-phrase
/// picker is driven by. Distinct from [`ButtonResult`] (the two-state
/// approve/deny used by signing) — text entry needs a third action (delete).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gesture {
    /// A single short tap — advance the highlight to the next choice.
    Single,
    /// Two quick taps — select the highlighted choice.
    Double,
    /// A deliberate hold — delete the last letter / step back.
    Long,
}

/// Hold duration that counts as a [`Gesture::Long`] (delete). Shorter than the
/// 2 s signing-approval hold: delete fires the instant this is crossed so the
/// owner gets immediate feedback while typing, rather than waiting for release.
const GESTURE_LONG_MS: u128 = 600;

/// Window after a tap in which a second tap is read as a [`Gesture::Double`].
/// Kept tight so single-tap cycling (the frequent action) stays responsive.
const DOUBLE_GAP_MS: u128 = 250;

/// Wait for one classified gesture on the PRG button.
///
/// Returns `None` if `idle_timeout` elapses before any press begins, letting
/// the caller keep its screen alive / re-arm without blocking forever. A long
/// hold is reported the moment it crosses [`GESTURE_LONG_MS`] (then the button
/// is drained to its release); a short tap is held for up to [`DOUBLE_GAP_MS`]
/// to see whether a second tap turns it into a double.
pub fn read_gesture(pin: &PinDriver<'_, Input>, idle_timeout: Duration) -> Option<Gesture> {
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

    // Measure the first press. A hold past the threshold is a Long (delete),
    // reported immediately, then we drain the rest of the hold.
    let press_start = Instant::now();
    loop {
        if pin.is_high() {
            break; // released — it was a tap
        }
        if press_start.elapsed().as_millis() >= GESTURE_LONG_MS {
            drain_release(pin);
            return Some(Gesture::Long);
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(POLL_INTERVAL_MS);
    }
    esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE.as_millis() as u32);

    // Tap completed. Watch for a second tap within the double-click window.
    let gap_deadline = Instant::now() + Duration::from_millis(DOUBLE_GAP_MS as u64);
    loop {
        if Instant::now() >= gap_deadline {
            return Some(Gesture::Single);
        }
        if pin.is_low() {
            esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE.as_millis() as u32);
            drain_release(pin);
            return Some(Gesture::Double);
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

// ---------------------------------------------------------------------------
// Two-button text entry — for boards with a second button (e.g. the T-Display)
// ---------------------------------------------------------------------------

/// One action from the two-button picker. Two buttons × (tap / hold) give four
/// distinct actions, so every action has its own press — no double-taps, and
/// backspace is always one hold away:
///
///   A tap  → Prev     B tap  → Next
///   A hold → Back     B hold → Select
///
/// The same vocabulary is used on every restore screen: tap to move, **hold B**
/// for the affirmative (pick / save), **hold A** for back / delete / cancel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoBtn {
    /// A tap — move the highlight to the previous choice.
    Prev,
    /// B tap — move the highlight to the next choice.
    Next,
    /// B hold — select / confirm the highlighted item.
    Select,
    /// A hold — back / delete the last letter / cancel.
    Back,
}

/// Block until one action is read from either button. Both are active-low. A
/// hold past [`GESTURE_LONG_MS`] fires immediately (then drains to release); a
/// shorter press fires as a tap on release. Debounced, and drained so one
/// physical press yields exactly one action.
pub fn read_two_button_gesture(a: &PinDriver<'_, Input>, b: &PinDriver<'_, Input>) -> TwoBtn {
    // Wait for the first press on either button.
    let is_a = loop {
        if a.is_low() {
            break true;
        }
        if b.is_low() {
            break false;
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(POLL_INTERVAL_MS);
    };
    let pin = if is_a { a } else { b };
    esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE.as_millis() as u32);

    // Measure the hold: a long press is reported the moment it crosses the
    // threshold; otherwise it's a tap once released.
    let press_start = Instant::now();
    let long = loop {
        if pin.is_high() {
            break false; // released before the threshold — a tap
        }
        if press_start.elapsed().as_millis() >= GESTURE_LONG_MS {
            break true;
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(POLL_INTERVAL_MS);
    };
    drain_release(pin);

    match (is_a, long) {
        (true, false) => TwoBtn::Prev,   // A tap
        (false, false) => TwoBtn::Next,  // B tap
        (false, true) => TwoBtn::Select, // B hold
        (true, true) => TwoBtn::Back,    // A hold
    }
}
