// firmware/src/approval.rs
//
// Shared button approval loop used by bridge secret provisioning,
// sign_event, factory reset, and OTA -- any operation needing
// interactive confirmation.

use esp_idf_hal::gpio::{Input, PinDriver};
use std::time::{Duration, Instant};

use crate::oled::Display;

/// Result of the approval loop.
pub enum ApprovalResult {
    Approved,
    Denied,
    TimedOut,
}

/// Run the interactive button approval loop.
///
/// Shows `show_fn` on the OLED each second with the remaining countdown,
/// waits for a 2-second button hold. While the button is held, a graphical
/// progress bar fills from 0% to 100% over 2 seconds. Returns the approval
/// result.
pub fn run_approval_loop<F>(
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, Input>,
    timeout_secs: u64,
    mut show_fn: F,
) -> ApprovalResult
where
    F: FnMut(&mut Display<'_>, u32),
{
    let start = Instant::now();
    let deadline = start + Duration::from_secs(timeout_secs);
    let mut last_remaining = timeout_secs as u32 + 1;
    let mut pressed = false;
    let mut press_start = Instant::now();
    let mut last_pct: u32 = 101; // force first draw

    loop {
        let now = Instant::now();
        if now >= deadline {
            return ApprovalResult::TimedOut;
        }

        let remaining = (deadline - now).as_secs() as u32;

        // Show the caller's screen (countdown) when button is not held.
        if remaining != last_remaining && !pressed {
            show_fn(display, remaining);
            last_remaining = remaining;
        }

        let low = button_pin.is_low();
        if low && !pressed {
            pressed = true;
            press_start = now;
            last_pct = 101; // force redraw
        }
        if low && pressed {
            let held_ms = now.duration_since(press_start).as_millis() as u32;
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
