// firmware/src/approval.rs
//
// Shared button approval loop used by bridge secret provisioning,
// sign_event, factory reset, and OTA — any operation needing
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
/// waits for a 2-second button hold. Returns the approval result.
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

    loop {
        let now = Instant::now();
        if now >= deadline {
            return ApprovalResult::TimedOut;
        }

        let remaining = (deadline - now).as_secs() as u32;

        if remaining != last_remaining && !pressed {
            show_fn(display, remaining);
            last_remaining = remaining;
        }

        let low = button_pin.is_low();
        if low && !pressed {
            pressed = true;
            press_start = now;
            crate::oled::show_error(display, "Hold 2s...");
        }
        if low && pressed {
            if now.duration_since(press_start) >= Duration::from_millis(2000) {
                crate::oled::show_error(display, "Approved!");
                esp_idf_hal::delay::FreeRtos::delay_ms(300);
                return ApprovalResult::Approved;
            }
        }
        if !low && pressed {
            crate::oled::show_error(display, "Denied (short)");
            esp_idf_hal::delay::FreeRtos::delay_ms(500);
            return ApprovalResult::Denied;
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(20);
    }
}
