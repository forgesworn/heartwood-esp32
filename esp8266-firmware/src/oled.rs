//! SSD1306 128x64 OLED over bit-banged I2C.
//!
//! The ESP8266 has no hardware I2C peripheral, so I2C is bit-banged on the board's
//! OLED pins (SDA = GPIO14, SCL = GPIO12) with open-drain GPIOs — driven low or
//! released to the board's pull-ups — and cycle-counter delays. `ssd1306` +
//! `embedded-graphics` (the embedded-hal 0.2 generation) render the text.
//!
//! All transfers are best-effort: the bit-bang master never reports an error, so
//! a missing/!wired display just draws into the void rather than faulting.

use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyle},
    pixelcolor::BinaryColor,
    prelude::*,
    text::Text,
};
use embedded_hal::blocking::i2c::Write;
use embedded_hal::digital::v2::{InputPin, OutputPin};
use esp8266_hal::gpio::{Gpio12, Gpio14, OpenDrain, Output};
use ssd1306::{mode::BufferedGraphicsMode, prelude::*, I2CDisplayInterface, Ssd1306};
use xtensa_lx::timer::get_cycle_count;

type Sda = Gpio14<Output<OpenDrain>>;
type Scl = Gpio12<Output<OpenDrain>>;

/// ~2.5 µs at 80 MHz → roughly a 200 kHz bit clock (SSD1306 tolerates ≤ 400 kHz).
const HALF_BIT_CYCLES: u32 = 200;

/// Bit-banged I2C master over two open-drain pins.
pub struct BitBangI2c {
    sda: Sda,
    scl: Scl,
}

impl BitBangI2c {
    fn delay() {
        let start = get_cycle_count();
        while get_cycle_count().wrapping_sub(start) < HALF_BIT_CYCLES {}
    }
    fn sda_release(&mut self) {
        let _ = self.sda.set_high(); // high-Z; the bus pull-up brings it high
    }
    fn sda_low(&mut self) {
        let _ = self.sda.set_low();
    }
    fn scl_release(&mut self) {
        let _ = self.scl.set_high();
    }
    fn scl_low(&mut self) {
        let _ = self.scl.set_low();
    }
    fn sda_high(&self) -> bool {
        self.sda.is_high().unwrap_or(true)
    }

    fn start(&mut self) {
        self.sda_release();
        self.scl_release();
        Self::delay();
        self.sda_low();
        Self::delay();
        self.scl_low();
        Self::delay();
    }
    fn stop(&mut self) {
        self.sda_low();
        self.scl_release();
        Self::delay();
        self.sda_release();
        Self::delay();
    }
    fn write_byte(&mut self, byte: u8) {
        for i in (0..8).rev() {
            if (byte >> i) & 1 == 1 {
                self.sda_release();
            } else {
                self.sda_low();
            }
            Self::delay();
            self.scl_release();
            Self::delay();
            self.scl_low();
            Self::delay();
        }
        // 9th clock = ACK: release SDA, pulse SCL, ignore the slave's ACK bit.
        self.sda_release();
        Self::delay();
        self.scl_release();
        Self::delay();
        let _ = self.sda_high();
        self.scl_low();
        Self::delay();
    }
}

impl Write for BitBangI2c {
    type Error = core::convert::Infallible;
    fn write(&mut self, addr: u8, bytes: &[u8]) -> Result<(), Self::Error> {
        self.start();
        self.write_byte(addr << 1); // R/W = 0 (write)
        for &b in bytes {
            self.write_byte(b);
        }
        self.stop();
        Ok(())
    }
}

type Display =
    Ssd1306<I2CInterface<BitBangI2c>, DisplaySize128x64, BufferedGraphicsMode<DisplaySize128x64>>;

/// The OLED, in buffered graphics mode.
pub struct Oled {
    display: Display,
}

impl Oled {
    /// Initialise the OLED on GPIO14 (SDA) / GPIO12 (SCL).
    pub fn new(sda: Sda, scl: Scl) -> Oled {
        let interface = I2CDisplayInterface::new(BitBangI2c { sda, scl });
        let mut display = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate0)
            .into_buffered_graphics_mode();
        let _ = display.init();
        Oled { display }
    }

    /// Clear and draw up to six ~21-char lines (FONT_6X10).
    pub fn show_lines(&mut self, lines: &[&str]) {
        let style = MonoTextStyle::new(&FONT_6X10, BinaryColor::On);
        self.display.clear();
        for (i, line) in lines.iter().enumerate() {
            let y = 9 + (i as i32) * 11;
            let _ = Text::new(line, Point::new(0, y), style).draw(&mut self.display);
        }
        let _ = self.display.flush();
    }

    /// Show the device identity (npub wrapped across three lines).
    pub fn show_npub(&mut self, npub: &str) {
        let b = npub.as_bytes();
        let slice = |from: usize, to: usize| -> &str {
            if from >= b.len() {
                ""
            } else {
                core::str::from_utf8(&b[from..to.min(b.len())]).unwrap_or("")
            }
        };
        self.show_lines(&[
            "Heartwood signer",
            "",
            slice(0, 21),
            slice(21, 42),
            slice(42, 63),
        ]);
    }

    /// Prompt to approve a sign request: show what's being signed and the hint.
    pub fn show_sign_prompt(&mut self, kind: u64, content: &str) {
        let kind_line = alloc::format!("kind {}", kind);
        let preview: alloc::string::String = content.chars().take(21).collect();
        self.show_lines(&["SIGN REQUEST?", &kind_line, &preview, "", "hold FLASH = approve"]);
    }

    /// A brief one-line status under the banner (e.g. after a sign).
    pub fn show_status(&mut self, msg: &str) {
        self.show_lines(&["Heartwood signer", "", msg]);
    }
}
