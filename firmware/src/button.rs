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
        crate::wdt::feed();
        if Instant::now() >= deadline {
            // A sub-poll tap may still have latched an edge; a tap aimed at
            // an expiring prompt must not replay as a carousel page later.
            clear_press_edge();
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
        crate::wdt::feed();
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

    // This flow consumed the press off the pin; drop the edge the sampler
    // latched from it so it cannot act a second time.
    clear_press_edge();

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
        crate::wdt::feed();
        if Instant::now() >= idle_deadline {
            clear_press_edge();
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
            clear_press_edge();
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
/// Also drops any latched press edge — the drained press was consumed here.
fn drain_release(pin: &PinDriver<'_, Input>) {
    while pin.is_low() {
        crate::wdt::feed();
        esp_idf_hal::delay::FreeRtos::delay_ms(POLL_INTERVAL_MS);
    }
    esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE.as_millis() as u32);
    clear_press_edge();
}

// ---------------------------------------------------------------------------
// Buttons — the board's physical buttons as one handle
// ---------------------------------------------------------------------------
//
// The multi-board plan's decision B (docs/2026-06-24-multi-board-display-port.md):
// every handler takes `&Buttons` instead of a bare approval pin, so two-button
// behaviour is type-visible. A = approve/select, B (where present) =
// cancel/back.

use core::sync::atomic::{AtomicBool, Ordering};

/// Whether the running board has a usable second button — read by screen
/// code (which never sees `Buttons`) to pick two-button hint copy.
static TWO_BUTTON_UI: AtomicBool = AtomicBool::new(false);

/// True when this board has a usable B button.
pub fn has_button_b() -> bool {
    TWO_BUTTON_UI.load(Ordering::Relaxed)
}

/// The board's buttons: A approves/selects, B (where present) cancels/backs.
pub struct Buttons<'d> {
    /// Primary / approval button (active-low, pulled up).
    pub a: PinDriver<'d, Input>,
    /// Second button where the board has one; `None` on single-button boards
    /// or when B failed its bring-up sanity check.
    pub b: Option<PinDriver<'d, Input>>,
}

impl<'d> Buttons<'d> {
    /// Build the handle, sanity-checking B: it must idle HIGH across a short
    /// sample window. GPIO35 on the classic ESP32 is input-only with no
    /// internal pull, so a clone missing the external pull-up floats — and a
    /// floating-low B would cancel every approval. Such a pin is dropped and
    /// the board behaves as single-button.
    pub fn new(a: PinDriver<'d, Input>, b: Option<PinDriver<'d, Input>>) -> Self {
        let b = b.filter(|pin| {
            for _ in 0..5 {
                if pin.is_low() {
                    log::warn!("Button B reads low at boot; treating board as single-button");
                    return false;
                }
                esp_idf_hal::delay::FreeRtos::delay_ms(20);
            }
            true
        });
        TWO_BUTTON_UI.store(b.is_some(), Ordering::Relaxed);
        spawn_press_latch(a.pin() as i32);
        Self { a, b }
    }

    /// Debounced "B is pressed" (active low). False on single-button boards.
    pub fn b_pressed(&self) -> bool {
        let Some(b) = &self.b else { return false };
        if !b.is_low() {
            return false;
        }
        // Confirm the level survives a debounce interval before acting on it.
        esp_idf_hal::delay::FreeRtos::delay_ms(30);
        b.is_low()
    }

    /// Block until B is released (bounded), with a debounce on the rising edge.
    pub fn drain_b(&self) {
        let Some(b) = &self.b else { return };
        let start = std::time::Instant::now();
        while b.is_low() && start.elapsed() < Duration::from_secs(10) {
            crate::wdt::feed();
            esp_idf_hal::delay::FreeRtos::delay_ms(POLL_INTERVAL_MS);
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE.as_millis() as u32);
        // An A tap latched during a B-driven flow was aimed at that flow,
        // not at the idle carousel — drop it.
        clear_press_edge();
    }
}

// ---------------------------------------------------------------------------
// Press-edge latch — for loops that cannot poll fast enough (#61)
// ---------------------------------------------------------------------------
//
// The WiFi relay loop samples button A roughly once per outer pass (~1 s —
// socket recv timeouts dominate), so a short tap lands between samples and
// is silently missed: the dismiss-tap on a held confirmation card usually
// did nothing. A GPIO interrupt would need `&mut PinDriver` to re-arm after
// each fire, which the shared `&Buttons` threaded through the handlers
// cannot provide — so a tiny sampler thread watches the raw GPIO level
// instead and latches each falling edge into an atomic. Slow loops consume
// the latch with [`take_press_edge`]; flows that consume a press directly
// off the pin (approval holds, gesture readers) clear it on exit so one
// physical press never acts twice.

static PRESS_EDGE: AtomicBool = AtomicBool::new(false);
static LATCH_SPAWNED: AtomicBool = AtomicBool::new(false);

/// Sampler cadence. Contact bounce (< ~10 ms) is shorter than one interval,
/// so a bounce dip is rarely sampled at all; [`LATCH_MIN_GAP_MS`] covers the
/// ones that are.
const LATCH_POLL_MS: u32 = 15;

/// Minimum spacing between latched edges. Anything faster is bounce, not a
/// human tapping twice.
const LATCH_MIN_GAP_MS: u128 = 150;

/// Spawn the sampler for the given GPIO (active-low). Called from
/// [`Buttons::new`]; a second call is a no-op. Reads the raw level via
/// `gpio_get_level` so it never contends with the owning `PinDriver`.
fn spawn_press_latch(gpio: i32) {
    if LATCH_SPAWNED.swap(true, Ordering::Relaxed) {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("btn-latch".into())
        .stack_size(3072)
        .spawn(move || {
            let mut was_low = unsafe { esp_idf_svc::sys::gpio_get_level(gpio) } == 0;
            let mut last_edge = Instant::now();
            loop {
                esp_idf_hal::delay::FreeRtos::delay_ms(LATCH_POLL_MS);
                let low = unsafe { esp_idf_svc::sys::gpio_get_level(gpio) } == 0;
                if low && !was_low && last_edge.elapsed().as_millis() >= LATCH_MIN_GAP_MS {
                    PRESS_EDGE.store(true, Ordering::Relaxed);
                    last_edge = Instant::now();
                }
                was_low = low;
            }
        });
    if let Err(e) = spawned {
        // Non-fatal: level sampling still works, only sub-poll taps degrade.
        log::warn!("press-latch thread failed to spawn: {e}");
    }
}

/// Consume a latched press edge. True at most once per physical press.
pub fn take_press_edge() -> bool {
    PRESS_EDGE.swap(false, Ordering::Relaxed)
}

/// Drop any pending latched edge. Called by flows that consume a press
/// directly off the pin, so the latch cannot replay it elsewhere.
pub fn clear_press_edge() {
    PRESS_EDGE.store(false, Ordering::Relaxed);
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
        crate::wdt::feed();
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
