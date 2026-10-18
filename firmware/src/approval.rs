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
/// would deny the request outright). The same span arms a card
/// (`heartwood_common::button_arm`).
const DEBOUNCE_MS: u32 = heartwood_common::button_arm::SETTLE_UP_MS as u32;

/// Run the interactive button approval loop.
///
/// Shows `show_fn` on the OLED each second with the remaining countdown,
/// waits for a 2-second hold (`card_hold::CARD_HOLD_MS`) of the A button,
/// counted only from a press that
/// starts after the button has been seen up (debounced) with the card on
/// screen, so a hold already down when it appears never answers it. While
/// the button is held, a
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
    let result = approval_loop_inner(
        display,
        buttons,
        timeout_secs,
        crate::card_hold::CARD_HOLD_MS,
        None,
        |d, remaining, _, _| show_fn(d, remaining),
        crate::oled::show_hold_progress,
    );
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
    let result = approval_loop_inner(
        display,
        buttons,
        timeout_secs,
        crate::card_hold::CARD_HOLD_MS,
        Some(&mut gate),
        show_fn,
        crate::oled::show_hold_progress,
    );
    crate::button::clear_press_edge();
    result
}

/// [`run_approval_loop`] for the FULL ACCESS card (one-hold pairing spec
/// 4.2): approved only by a [`crate::card_hold::FULL_ACCESS_HOLD_MS`] (5 s)
/// hold, a shorter press declines, and `show_hold` draws the hold screen
/// (the words and the hold's progress, 0 to 100) while the button is down,
/// in place of the generic CONFIRMING screen.
pub fn run_full_access_approval_loop<F, H>(
    display: &mut Display<'_>,
    buttons: &crate::button::Buttons<'_>,
    timeout_secs: u64,
    mut show_fn: F,
    show_hold: H,
) -> ApprovalResult
where
    F: FnMut(&mut Display<'_>, u32),
    H: FnMut(&mut Display<'_>, u32),
{
    let result = approval_loop_inner(
        display,
        buttons,
        timeout_secs,
        crate::card_hold::FULL_ACCESS_HOLD_MS,
        None,
        |d, remaining, _, _| show_fn(d, remaining),
        show_hold,
    );
    crate::button::clear_press_edge();
    result
}

#[allow(clippy::too_many_arguments)]
fn approval_loop_inner<F, H>(
    display: &mut Display<'_>,
    buttons: &crate::button::Buttons<'_>,
    timeout_secs: u64,
    // The hold that approves this card (`card_hold::hold_ms`).
    hold: u32,
    mut gate: Option<&mut heartwood_common::phone_unlock::EnrolGate>,
    mut show_fn: F,
    mut show_hold: H,
) -> ApprovalResult
where
    F: FnMut(&mut Display<'_>, u32, usize, bool),
    H: FnMut(&mut Display<'_>, u32),
{
    let start = Instant::now();
    let deadline = start + Duration::from_secs(timeout_secs);
    let mut last_remaining = timeout_secs as u32 + 1;
    let mut pressed = false;
    let mut press_start = Instant::now();
    let mut last_pct: u32 = 101; // force first draw
    let mut last_view: Option<(usize, bool)> = None;
    // The enrol card: `oled::draw_generation` just after its face was last
    // drawn, to tell when something else has drawn over it.
    let mut drawn_gen: Option<u32> = None;
    // Every card, gated or not, arms only once A has been seen up for
    // `button_arm::SETTLE_UP_MS`: a hold already down when the card appears
    // (the tail of an earlier decision, a pinned GPIO 0, a press made for a
    // card that has just been taken off the screen) is never counted towards
    // this one. The rule is pure and host-tested (`ButtonArm`); the gated
    // card feeds the same settled "up" to its `EnrolGate`.
    let mut arm = heartwood_common::button_arm::ButtonArm::default();

    loop {
        crate::wdt::feed();
        let now = Instant::now();
        if now >= deadline {
            crate::oled::show_request_expired(display);
            return ApprovalResult::TimedOut;
        }

        let remaining = (deadline - now).as_secs() as u32;
        let elapsed_ms = now.duration_since(start).as_millis().min(u128::from(u64::MAX)) as u64;
        let settled_up = arm.settled_up(elapsed_ms, buttons.a.is_low());
        let (page, armed) = match gate.as_deref_mut() {
            None => (0, arm.armed()),
            Some(g) => {
                // Drawn over since its last draw (nothing in this loop does,
                // bar its own hold bar): the page starts its dwell again and
                // the face is drawn at once, as on the relay.
                if !pressed && drawn_gen.is_some_and(|gen| gen != crate::oled::draw_generation()) {
                    g.restart_page(elapsed_ms);
                    last_view = None;
                }
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
            if gate.is_some() {
                drawn_gen = Some(crate::oled::draw_generation());
            }
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
        let held_ms = if pressed {
            Instant::now().duration_since(press_start).as_millis().min(u128::from(u32::MAX)) as u32
        } else {
            0
        };
        if low && pressed {
            if crate::card_hold::judge(hold, held_ms, None) == crate::card_hold::Press::Approved {
                crate::oled::show_approved(display);
                esp_idf_hal::delay::FreeRtos::delay_ms(300);
                return ApprovalResult::Approved;
            }
            // Update hold progress bar (redraw every ~5% to avoid flicker)
            let pct = crate::card_hold::hold_pct(hold, held_ms);
            if pct / 5 != last_pct / 5 {
                show_hold(display, pct);
                last_pct = pct;
            }
        }
        if !low && pressed {
            // Let go before the hold was reached (this loop polls every
            // 20 ms while the button is down, so a full hold has already
            // approved above): a short press declines.
            crate::oled::show_denied(display);
            esp_idf_hal::delay::FreeRtos::delay_ms(500);
            return ApprovalResult::Denied;
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(20);
    }
}
