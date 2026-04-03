// firmware/src/oled.rs
//
// OLED display helpers for the Heltec V4 built-in SSD1306 (128x64).

use embedded_graphics::mono_font::ascii::FONT_5X8;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::mono_font::MonoTextStyleBuilder;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::text::Text;
use esp_idf_hal::delay::FreeRtos;
use esp_idf_hal::gpio::{AnyOutputPin, PinDriver};
use esp_idf_hal::i2c::I2cDriver;
use ssd1306::mode::BufferedGraphicsMode;
use ssd1306::prelude::*;
use ssd1306::rotation::DisplayRotation;
use ssd1306::size::DisplaySize128x64;
use ssd1306::I2CDisplayInterface;
use ssd1306::Ssd1306;

/// 128px / 5px per char = 25 chars per line.
const CHARS_PER_LINE: usize = 25;

pub type Display<'a> = Ssd1306<
    ssd1306::prelude::I2CInterface<I2cDriver<'a>>,
    DisplaySize128x64,
    BufferedGraphicsMode<DisplaySize128x64>,
>;

/// Initialise the OLED: reset pin toggle, I2C setup, display init.
/// The reset PinDriver is deliberately leaked — GPIO 21 must stay HIGH
/// or the SSD1306 is held in reset and the display goes blank.
pub fn init<'a>(
    i2c: I2cDriver<'a>,
    rst_pin: AnyOutputPin,
) -> Display<'a> {
    // Toggle reset pin — hold low for 50ms, then high with 100ms settle time
    let mut rst = PinDriver::output(rst_pin).expect("RST pin");
    rst.set_high().ok();
    FreeRtos::delay_ms(1);
    rst.set_low().ok();
    FreeRtos::delay_ms(50);
    rst.set_high().ok();
    FreeRtos::delay_ms(100);
    // Keep rst pin HIGH — dropping it would float the pin and reset the display
    std::mem::forget(rst);

    let interface = I2CDisplayInterface::new_custom_address(i2c, 0x3C);
    let mut display = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate0)
        .into_buffered_graphics_mode();
    match display.init() {
        Ok(()) => {
            display.clear_buffer();
            if let Err(e) = display.flush() {
                log::warn!("OLED flush failed during init: {:?} — display may not work", e);
            }
        }
        Err(e) => {
            log::warn!("OLED init failed: {:?} — continuing without display", e);
        }
    }
    display
}

/// Display an npub on the OLED, split across lines.
pub fn show_npub(display: &mut Display<'_>, npub: &str) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    let mut y = 8i32;
    let mut pos = 0;
    while pos < npub.len() {
        let end = core::cmp::min(pos + CHARS_PER_LINE, npub.len());
        let line = &npub[pos..end];
        Text::new(line, Point::new(0, y), text_style)
            .draw(display)
            .ok();
        y += 10;
        pos = end;
    }

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Display "Awaiting secret..." on the OLED.
pub fn show_awaiting(display: &mut Display<'_>) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    Text::new("Awaiting secret...", Point::new(0, 30), text_style)
        .draw(display)
        .ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Display an error message on the OLED.
pub fn show_error(display: &mut Display<'_>, msg: &str) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    Text::new(msg, Point::new(0, 30), text_style)
        .draw(display)
        .ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Display a signing request with purpose, kind, content preview, and countdown.
///
/// Layout (128×64 SSD1306, FONT_5X8):
///   Line 1 (y=8):  "Sign as <purpose>?"
///   Line 2 (y=18): "Kind <number>"
///   Line 3 (y=28): "<content line 1>
///   Line 4 (y=38):  <content line 2>"
///   Line 5 (y=56): "[====------] 18s"
pub fn show_sign_request(
    display: &mut Display<'_>,
    purpose: &str,
    kind: u64,
    content_preview: &str,
    seconds_remaining: u32,
) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    // Line 1: "Sign as <purpose>?" — use "master" if purpose is empty or "master"
    let label = if purpose.is_empty() || purpose == "master" {
        "master".to_string()
    } else {
        purpose.to_string()
    };
    let heading = format!("Sign as {}?", label);
    let heading = &heading[..heading.len().min(CHARS_PER_LINE)];
    Text::new(heading, Point::new(0, 8), text_style)
        .draw(display)
        .ok();

    // Line 2: "Kind <number>"
    let kind_str = format!("Kind {}", kind);
    let kind_str = &kind_str[..kind_str.len().min(CHARS_PER_LINE)];
    Text::new(kind_str, Point::new(0, 18), text_style)
        .draw(display)
        .ok();

    // Lines 3–4: content preview, max 50 chars, wrapped at CHARS_PER_LINE.
    // Opening quote on first line, closing quote (or ellipsis+quote) on last line.
    let capped: &str = if content_preview.len() > 50 {
        &content_preview[..50]
    } else {
        content_preview
    };
    let truncated = capped.len() < content_preview.len();

    // Split into at most two display lines, each up to CHARS_PER_LINE chars.
    // Reserve 1 char for the opening quote on the first line.
    let first_cap = CHARS_PER_LINE - 1; // room for leading '"'
    if capped.len() <= first_cap {
        // Fits on one line — show on line 3 only, with both quotes.
        let suffix = if truncated { "...\"" } else { "\"" };
        let line3 = format!("\"{}{}",  capped, suffix);
        let line3 = &line3[..line3.len().min(CHARS_PER_LINE + 4)]; // suffix may push slightly over
        Text::new(line3, Point::new(0, 28), text_style)
            .draw(display)
            .ok();
    } else {
        // Split: first CHARS_PER_LINE-1 chars on line 3, remainder on line 4.
        let (part1, part2_raw) = capped.split_at(first_cap);
        let line3 = format!("\"{}",  part1);
        Text::new(&line3[..line3.len().min(CHARS_PER_LINE)], Point::new(0, 28), text_style)
            .draw(display)
            .ok();

        let second_cap = CHARS_PER_LINE - if truncated { 4 } else { 1 };
        let part2 = if part2_raw.len() > second_cap {
            &part2_raw[..second_cap]
        } else {
            part2_raw
        };
        let suffix = if truncated { "...\"" } else { "\"" };
        let line4 = format!("{}{}", part2, suffix);
        Text::new(&line4[..line4.len().min(CHARS_PER_LINE)], Point::new(0, 38), text_style)
            .draw(display)
            .ok();
    }

    // Line 5: countdown bar
    show_countdown_bar(display, seconds_remaining, 30, text_style);

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Draw a countdown bar at y=56: "[====------] 18s"
/// Bar width is 16 characters; filled proportion equals remaining/total.
fn show_countdown_bar(
    display: &mut Display<'_>,
    remaining: u32,
    total: u32,
    text_style: MonoTextStyle<'_, BinaryColor>,
) {
    const BAR_WIDTH: usize = 16;

    let filled = if total == 0 {
        0
    } else {
        ((remaining as usize) * BAR_WIDTH) / (total as usize)
    };
    let filled = filled.min(BAR_WIDTH);
    let empty = BAR_WIDTH - filled;

    // Build "[====------]" manually into a fixed-size buffer (no heap alloc needed).
    let mut bar = [b'-'; BAR_WIDTH];
    for b in bar.iter_mut().take(filled) {
        *b = b'=';
    }
    // Safety: bar contains only ASCII '=' and '-'.
    let bar_str = core::str::from_utf8(&bar).unwrap_or("----------------");

    // Format the full line — "18s" suffix, right-aligned after the closing bracket.
    let line = format!("[{}] {}s", bar_str, remaining);
    let line = &line[..line.len().min(CHARS_PER_LINE + 4)];
    Text::new(line, Point::new(0, 56), text_style)
        .draw(display)
        .ok();

    // Suppress unused-variable warning for `empty` in no_std contexts.
    let _ = empty;
}

/// Display a result message centred on the OLED, then pause for 2 seconds.
pub fn show_result(display: &mut Display<'_>, message: &str) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    Text::new(message, Point::new(0, 30), text_style)
        .draw(display)
        .ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }

    FreeRtos::delay_ms(2000);
}
