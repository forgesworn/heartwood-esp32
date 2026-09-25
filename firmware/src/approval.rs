// firmware/src/approval.rs
//
// Shared button approval loop used by bridge secret provisioning,
// sign_event, factory reset, and OTA -- any operation needing
// interactive confirmation.

use std::time::{Duration, Instant};

use crate::oled::Display;

/// Result of the approval loop.
pub enum ApprovalResult {
    Approved,
    Denied,
    TimedOut,
}

/// Debounce window on the A button's press and release edges. A single noisy
/// GPIO read must neither start a hold nor be read as an early release (which
/// would deny the request outright).
const DEBOUNCE_MS: u32 = 30;

/// Run the interactive button approval loop.
///
/// Shows `show_fn` on the OLED each second with the remaining countdown,
/// waits for a 2-second hold of the A button. While the button is held, a
/// graphical progress bar fills from 0% to 100% over 2 seconds. On boards
/// with a second button, a B press is an explicit cancel. Returns the
/// approval result; on timeout the countdown screen is replaced with an
/// explicit "no change made" card so a stale prompt can never linger looking
/// live.
pub fn run_approval_loop<F>(
    display: &mut Display<'_>,
    buttons: &crate::button::Buttons<'_>,
    timeout_secs: u64,
    mut show_fn: F,
) -> ApprovalResult
where
    F: FnMut(&mut Display<'_>, u32),
{
    let result = approval_loop_inner(display, buttons, timeout_secs, None, |d, remaining, _, _| show_fn(d, remaining));
    // This loop consumed its presses (and B-cancels) directly off the pins;
    // drop any edge the sampler latched from them, or the approval hold
    // replays in `service_button` and instantly dismisses the very card the
    // approval just presented (#61's latch meeting #60's hold).
    crate::button::clear_press_edge();
    result
}

/// [`run_approval_loop`] for the unlock-phone enrol card, gated by
/// `phone_unlock::EnrolGate`, the same rule the relay card follows: the
/// pages turn only after each has been on screen its full dwell, and the A
/// button does nothing, neither approving nor declining, until every page
/// has had its dwell, 12 s have passed and the button has been seen up since
/// (for [`DEBOUNCE_MS`], so one bouncing read cannot arm it). A hold that
/// starts before that never counts, however long it runs. B, where the board
/// has one, still cancels at any time: it is the explicit "no". `show_fn`
/// gets the remaining seconds, the page to show and whether a hold counts,
/// and is called whenever any of them changes.
pub fn run_enrol_approval_loop<F>(
    display: &mut Display<'_>,
    buttons: &crate::button::Buttons<'_>,
    timeout_secs: u64,
    show_fn: F,
) -> ApprovalResult
where
    F: FnMut(&mut Display<'_>, u32, usize, bool),
{
    let mut gate = heartwood_common::phone_unlock::EnrolGate::default();
    let result = approval_loop_inner(display, buttons, timeout_secs, Some(&mut gate), show_fn);
    crate::button::clear_press_edge();
    result
}

fn approval_loop_inner<F>(
    display: &mut Display<'_>,
    buttons: &crate::button::Buttons<'_>,
    timeout_secs: u64,
    mut gate: Option<&mut heartwood_common::phone_unlock::EnrolGate>,
    mut show_fn: F,
) -> ApprovalResult
where
    F: FnMut(&mut Display<'_>, u32, usize, bool),
{
    let start = Instant::now();
    let deadline = start + Duration::from_secs(timeout_secs);
    let mut last_remaining = timeout_secs as u32 + 1;
    let mut pressed = false;
    let mut press_start = Instant::now();
    let mut last_pct: u32 = 101; // force first draw
    let mut last_view: Option<(usize, bool)> = None;
    // When A was last seen down, for the gate's debounced "up".
    let mut last_down = Instant::now();

    loop {
        crate::wdt::feed();
        let now = Instant::now();
        if now >= deadline {
            crate::oled::show_request_expired(display);
            return ApprovalResult::TimedOut;
        }

        let remaining = (deadline - now).as_secs() as u32;
        if buttons.a.is_low() {
            last_down = now;
        }
        // No gate (every caller but the enrol card): exactly the loop it
        // always was, a hold already down when the card appears included.
        let (page, armed) = match gate.as_deref_mut() {
            None => (0, true),
            Some(g) => {
                let settled_up = now.duration_since(last_down) >= Duration::from_millis(u64::from(DEBOUNCE_MS));
                let elapsed_ms = now.duration_since(start).as_millis().min(u128::from(u64::MAX)) as u64;
                (g.step(elapsed_ms, !settled_up), g.armed())
            }
        };

        // Show the caller's screen (countdown) when button is not held; the
        // enrol card also whenever its page or gate changes, so the page the
        // gate counts is the page on screen.
        if (remaining != last_remaining || last_view != Some((page, armed))) && !pressed {
            show_fn(display, remaining, page, armed);
            last_remaining = remaining;
            last_view = Some((page, armed));
        }

        // B button (where present) is an explicit cancel — never an approve.
        if !pressed && buttons.b_pressed() {
            buttons.drain_b();
            crate::oled::show_cancelled(display);
            esp_idf_hal::delay::FreeRtos::delay_ms(500);
            return ApprovalResult::Denied;
        }

        // Before the gate, A is ignored outright: a tap is not a decline
        // and a hold is not a start.
        if !armed {
            esp_idf_hal::delay::FreeRtos::delay_ms(20);
            continue;
        }

        let mut low = buttons.a.is_low();
        if low && !pressed {
            // Debounce the falling edge before starting the hold timer.
            esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE_MS);
            if buttons.a.is_low() {
                pressed = true;
                press_start = Instant::now();
                last_pct = 101; // force redraw
            }
            continue;
        }
        if !low && pressed {
            // Debounce the rising edge — contact bounce mid-hold must not be
            // read as a deliberate early release (an instant deny).
            esp_idf_hal::delay::FreeRtos::delay_ms(DEBOUNCE_MS);
            low = buttons.a.is_low();
        }
        if low && pressed {
            let held_ms = Instant::now().duration_since(press_start).as_millis() as u32;
            if held_ms >= 2000 {
                crate::oled::show_approved(display);
                esp_idf_hal::delay::FreeRtos::delay_ms(300);
                return ApprovalResult::Approved;
            }
            // Update hold progress bar (redraw every ~5% to avoid flicker)
            let pct = (held_ms * 100 / 2000).min(100);
            if pct / 5 != last_pct / 5 {
                crate::oled::show_hold_progress(display, pct);
                last_pct = pct;
            }
        }
        if !low && pressed {
            crate::oled::show_denied(display);
            esp_idf_hal::delay::FreeRtos::delay_ms(500);
            return ApprovalResult::Denied;
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(20);
    }
}
