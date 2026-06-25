//! Heartwood ESP8266 tethered-signer firmware — compile-only scaffold.
//!
//! Stage 0: prove the bare-metal runtime + HAL link into a flashable image on
//! the modern `esp` toolchain. Minimal entry that just takes the peripherals
//! and idles. UART + the HW serial frame protocol + signing go on top once
//! this links.

#![no_std]
#![no_main]

use esp8266_hal::prelude::*;
use esp8266_hal::target::Peripherals;
use panic_halt as _;

#[entry]
fn main() -> ! {
    let dp = Peripherals::take().unwrap();
    let (mut timer1, _) = dp.TIMER.timers();

    loop {
        timer1.delay_ms(1000);
    }
}
