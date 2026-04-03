// heartwood-esp32/src/main.rs
//
// nsec-tree signing token spike for Heltec WiFi LoRa 32 V4.
// Derives a child identity from a hardcoded test seed and displays the npub
// on the built-in SSD1306 OLED.

mod derive;
mod encoding;
mod types;

use esp_idf_hal::delay::FreeRtos;
use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::i2c::{I2cConfig, I2cDriver};
use esp_idf_hal::prelude::*;

use embedded_graphics::mono_font::ascii::FONT_5X8;
use embedded_graphics::mono_font::MonoTextStyleBuilder;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::text::Text;
use ssd1306::mode::DisplayConfig;
use ssd1306::prelude::*;
use ssd1306::rotation::DisplayRotation;
use ssd1306::size::DisplaySize128x64;
use ssd1306::I2CDisplayInterface;
use ssd1306::Ssd1306;

/// Hardcoded 32-byte test seed (0x01..0x20).
/// This is NOT a real secret — it is a fixed test vector for protocol validation.
const TEST_ROOT_SECRET: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Expected npub for the derived child (purpose="persona/test", index=0).
/// Computed from heartwood-core with the same inputs.
const EXPECTED_CHILD_NPUB: &str =
    "npub1rx8u4wk9ytu8aak4f9wcaqdgk0lj4rjhdu4j9n7dj2mg68l9cdqs2fjf2t";

fn main() {
    // Initialise ESP-IDF runtime (logging, event loop, etc.)
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("Heartwood ESP32 — nsec-tree signing token spike");

    // --- Crypto: derive identity ---

    let root = derive::create_tree_root(&TEST_ROOT_SECRET)
        .expect("root creation must succeed");
    log::info!("Root npub: {}", root.master_npub);

    let mut identity = derive::derive(&root, "persona/test", 0)
        .expect("child derivation must succeed");
    log::info!("Child npub: {}", identity.npub);

    // Protocol correctness check
    assert_eq!(
        identity.npub, EXPECTED_CHILD_NPUB,
        "derived npub does not match heartwood-core — protocol mismatch!"
    );
    log::info!("Protocol vector verified — npub matches heartwood-core");

    // The npub to display
    let npub = identity.npub.clone();

    // Zeroise private key material — we only need the public key from here
    identity.zeroize();
    root.destroy();

    // --- OLED: display npub ---

    let peripherals = Peripherals::take().expect("failed to take peripherals");

    // Toggle OLED reset pin (GPIO21) high
    let mut rst = PinDriver::output(peripherals.pins.gpio21).expect("RST pin");
    rst.set_low().ok();
    FreeRtos::delay_ms(10);
    rst.set_high().ok();
    FreeRtos::delay_ms(10);

    // Configure I2C for the built-in OLED (SDA=GPIO17, SCL=GPIO18)
    let i2c_config = I2cConfig::new().baudrate(400.kHz().into());
    let i2c = I2cDriver::new(
        peripherals.i2c0,
        peripherals.pins.gpio17, // SDA
        peripherals.pins.gpio18, // SCL
        &i2c_config,
    )
    .expect("I2C init failed");

    let interface = I2CDisplayInterface::new(i2c);
    let mut display = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate0)
        .into_buffered_graphics_mode();
    display.init().expect("OLED init failed");
    display.clear_buffer();

    // Use a small font so the npub fits (63 chars total)
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    // Split the npub across lines (128px / 5px per char = 25 chars per line)
    let chars_per_line = 25;
    let mut y = 8i32;
    let mut pos = 0;
    while pos < npub.len() {
        let end = core::cmp::min(pos + chars_per_line, npub.len());
        let line = &npub[pos..end];
        Text::new(line, Point::new(0, y), text_style)
            .draw(&mut display)
            .ok();
        y += 10;
        pos = end;
    }

    display.flush().expect("OLED flush failed");
    log::info!("npub displayed on OLED");

    // Keep running — the display stays on
    loop {
        FreeRtos::delay_ms(1000);
    }
}
