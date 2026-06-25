//! Physical approval gate — the FLASH button (GPIO0, active-low) on the NodeMCU.
//!
//! The daemon is only a courier; physical presence is the approval for a sign.
//! GPIO0 is read via the raw input register (it's an input with the board's
//! external pull-up after boot) and the hold is timed with the xtensa cycle
//! counter — so there is no HAL pin object to thread through the sign path.
//!
//! When the OLED lands this gains a prompt; for now the user, having just asked
//! their phone to sign, confirms by holding the on-device button.

use xtensa_lx::timer::get_cycle_count;

/// `GPIO_IN` (0x6000_0318): bit N = the input level of GPIO N.
const GPIO_IN: *const u32 = 0x6000_0318 as *const u32;

const CLOCK_HZ: u32 = 80_000_000;
/// Hold the button this long to confirm (debounces a stray tap).
const HOLD_CYCLES: u32 = CLOCK_HZ / 2 * 3; // ~1.5 s
/// Give up (deny) if no confirming hold within this window.
const TIMEOUT_CYCLES: u32 = CLOCK_HZ * 20; // ~20 s

/// True while the FLASH button is pressed (GPIO0 pulled low).
fn pressed() -> bool {
    unsafe { core::ptr::read_volatile(GPIO_IN) & 1 == 0 }
}

/// Block until the button is held continuously for [`HOLD_CYCLES`], or deny once
/// [`TIMEOUT_CYCLES`] elapses. The watchdog is disabled (see `main`), so this
/// busy-wait is safe. The 20 s window stays well inside the 32-bit cycle
/// counter's ~53 s wrap, so `wrapping_sub` measures elapsed time correctly.
pub fn await_approval() -> bool {
    let start = get_cycle_count();
    let mut hold_start: Option<u32> = None;
    loop {
        let now = get_cycle_count();
        if now.wrapping_sub(start) > TIMEOUT_CYCLES {
            return false;
        }
        if pressed() {
            let held_from = *hold_start.get_or_insert(now);
            if now.wrapping_sub(held_from) >= HOLD_CYCLES {
                return true;
            }
        } else {
            hold_start = None; // released — the hold must be continuous
        }
    }
}
