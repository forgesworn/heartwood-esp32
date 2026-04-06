// firmware/src/oled.rs
//
// OLED display helpers for the Heltec V4 built-in SSD1306 (128x64).

use embedded_graphics::mono_font::ascii::{FONT_5X8, FONT_6X10, FONT_7X14, FONT_10X20};
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::mono_font::MonoTextStyleBuilder;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{PrimitiveStyle, Rectangle};
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

/// 128px / 7px per char = 18 chars per line.
const CHARS_PER_LINE: usize = 18;

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

/// Display an npub on the OLED with header and structured layout.
///
/// Layout:
///   Header:   "IDENTITY" (FONT_6X10, tracked)
///   Rule:     1px horizontal line
///   Body:     npub split across lines (FONT_5X8 for density)
pub fn show_npub(display: &mut Display<'_>, npub: &str) {
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    let mono = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    Text::new("IDENTITY", Point::new(2, 10), header).draw(display).ok();

    // Rule
    Rectangle::new(Point::new(0, 14), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    // npub in small font: 128/5 = 25 chars per line, fits npub1... in ~3 lines
    let chars_small = 25usize;
    let mut y = 26i32;
    let mut pos = 0;
    while pos < npub.len() && y < 64 {
        let end = core::cmp::min(pos + chars_small, npub.len());
        let line = &npub[pos..end];
        Text::new(line, Point::new(2, y), mono).draw(display).ok();
        y += 10;
        pos = end;
    }

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Display "Awaiting secret..." with a structured idle screen.
///
/// Layout:
///   Header:  "HEARTWOOD HSM" (FONT_6X10)
///   Rule:    1px line
///   Centre:  "Awaiting" (FONT_10X20)
///   Label:   "connect secret" (FONT_5X8)
pub fn show_awaiting(display: &mut Display<'_>) {
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    Text::new("HEARTWOOD HSM", Point::new(4, 10), header).draw(display).ok();

    Rectangle::new(Point::new(0, 14), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    Text::new("Awaiting", Point::new(14, 38), large).draw(display).ok();
    Text::new("connect secret", Point::new(24, 52), small).draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Display an error message on the OLED.
pub fn show_error(display: &mut Display<'_>, msg: &str) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
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
/// Layout:
///   Header:  "SIGN AS {purpose}?" (FONT_6X10, tracked)
///   Rule:    1px line
///   Kind:    "Kind {n}" (FONT_7X14)
///   Content: preview (FONT_5X8)
///   Bar:     graphical countdown + seconds
pub fn show_sign_request(
    display: &mut Display<'_>,
    purpose: &str,
    kind: u64,
    content_preview: &str,
    seconds_remaining: u32,
) {
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    let body = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
        .text_color(BinaryColor::On)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    // Header
    let label = if purpose.is_empty() || purpose == "master" { "master" } else { purpose };
    let heading = format!("SIGN AS {}?", &label[..label.len().min(12)]);
    Text::new(&heading, Point::new(2, 10), header).draw(display).ok();

    Rectangle::new(Point::new(0, 14), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    // Kind (large)
    let kind_str = format!("Kind {}", kind);
    Text::new(&kind_str, Point::new(2, 30), body).draw(display).ok();

    // Content preview (small font for more text)
    let max_preview = 25usize; // FONT_5X8: 128/5 = 25
    let content = if content_preview.len() > max_preview {
        format!("{}...", &content_preview[..max_preview - 3])
    } else {
        content_preview.to_string()
    };
    Text::new(&content, Point::new(2, 42), small).draw(display).ok();

    // Graphical countdown bar
    draw_countdown_bar(display, seconds_remaining, 30);

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Draw a graphical countdown bar at the bottom of the screen.
///
/// Outline rectangle with filled portion proportional to remaining/total,
/// plus seconds label to the right.
fn draw_countdown_bar(
    display: &mut Display<'_>,
    remaining: u32,
    total: u32,
) {
    let small = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    let bar_x = 2i32;
    let bar_y = 52i32;
    let bar_w = 100u32;
    let bar_h = 8u32;

    // Track
    Rectangle::new(Point::new(bar_x, bar_y), Size::new(bar_w, bar_h))
        .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, 1))
        .draw(display).ok();

    // Fill
    let fill_w = if total > 0 {
        (remaining * (bar_w - 4)) / total
    } else {
        0
    };
    if fill_w > 0 {
        Rectangle::new(Point::new(bar_x + 2, bar_y + 2), Size::new(fill_w, bar_h - 4))
            .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
            .draw(display).ok();
    }

    // Seconds
    let secs = format!("{}s", remaining);
    Text::new(&secs, Point::new(bar_x + bar_w as i32 + 4, bar_y + 7), small)
        .draw(display).ok();
}

/// Display a result message with decorative framing, then pause for 2 seconds.
///
/// Layout:
///   Top rule + bottom rule framing the message
///   Message centred in FONT_7X14
pub fn show_result(display: &mut Display<'_>, message: &str) {
    display.clear_buffer();

    let body = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
        .text_color(BinaryColor::On)
        .build();

    // Top rule
    Rectangle::new(Point::new(0, 18), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    // Centred message
    let msg_w = message.len() as i32 * 7;
    let x = ((128 - msg_w) / 2).max(0);
    Text::new(message, Point::new(x, 38), body).draw(display).ok();

    // Bottom rule
    Rectangle::new(Point::new(0, 44), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }

    FreeRtos::delay_ms(2000);
}

/// Display the multi-master boot screen after the animation.
///
/// Layout:
///   Header:  "HEARTWOOD HSM" (FONT_6X10)
///   Rule:    1px line
///   Count:   "{n}" large + "masters" label
///   Status:  "Awaiting bridge..." (FONT_5X8)
pub fn show_boot(display: &mut Display<'_>, master_count: u8) {
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();
    let body = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
        .text_color(BinaryColor::On)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    // Top bar
    Rectangle::new(Point::new(0, 0), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    // "HEARTWOOD HSM" = 13 chars * 6px = 78px; centre = (128-78)/2 = 25
    Text::new("HEARTWOOD HSM", Point::new(25, 12), header).draw(display).ok();

    Rectangle::new(Point::new(0, 16), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    // Master count centred (large) with label well below
    let count_str = format!("{}", master_count);
    let count_x = ((128 - count_str.len() as i32 * 10) / 2).max(0);
    Text::new(&count_str, Point::new(count_x, 36), large).draw(display).ok();

    // "masters" in small font, well separated from the large number
    Text::new("masters", Point::new(46, 46), small).draw(display).ok();

    // Bottom status area
    Rectangle::new(Point::new(0, 52), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    Text::new("awaiting bridge...", Point::new(14, 63), small).draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Display bridge connected status with structured layout.
///
/// Layout:
///   Header:  "BRIDGE CONNECTED" (FONT_6X10)
///   Rule:    1px line
///   Stats:   master count (large) + client count
pub fn show_bridge_connected(
    display: &mut Display<'_>,
    master_count: u8,
    client_count: usize,
) {
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();
    let body = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
        .text_color(BinaryColor::On)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    Text::new("BRIDGE CONNECTED", Point::new(2, 10), header).draw(display).ok();

    Rectangle::new(Point::new(0, 14), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    // Master count large on left
    let m_str = format!("{}", master_count);
    Text::new(&m_str, Point::new(2, 38), large).draw(display).ok();
    Text::new("masters", Point::new(22, 36), small).draw(display).ok();

    // Client count on right side
    let c_str = format!("{}", client_count);
    Text::new(&c_str, Point::new(72, 38), body).draw(display).ok();
    Text::new("clients", Point::new(88, 36), small).draw(display).ok();

    // Status indicator: solid bar at bottom
    Rectangle::new(Point::new(0, 58), Size::new(128, 6))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Display a signing request with master label, method, kind, content, and countdown.
///
/// Layout:
///   Header:  master label (FONT_6X10, tracked)
///   Rule:    1px line
///   Method:  method + kind (FONT_7X14)
///   Content: preview (FONT_5X8)
///   Bar:     graphical countdown
pub fn show_master_sign_request(
    display: &mut Display<'_>,
    master_label: &str,
    method: &str,
    kind: Option<u64>,
    content_preview: &str,
    seconds_remaining: u32,
) {
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    let body = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
        .text_color(BinaryColor::On)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    // Header: master label
    let label = &master_label[..master_label.len().min(21)]; // FONT_6X10: 128/6 = 21
    Text::new(label, Point::new(2, 10), header).draw(display).ok();

    Rectangle::new(Point::new(0, 14), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    // Method + kind
    let method_str = match kind {
        Some(k) => format!("{} k:{}", method, k),
        None => method.to_string(),
    };
    let method_str = &method_str[..method_str.len().min(CHARS_PER_LINE)];
    Text::new(method_str, Point::new(2, 30), body).draw(display).ok();

    // Content preview (small font)
    let max_preview = 25usize;
    let preview = if content_preview.len() > max_preview {
        format!("{}...", &content_preview[..max_preview - 3])
    } else {
        content_preview.to_string()
    };
    Text::new(&preview, Point::new(2, 42), small).draw(display).ok();

    // Graphical countdown bar
    draw_countdown_bar(display, seconds_remaining, 30);

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Display an auto-approved request flash with structured layout.
///
/// Layout:
///   Header:  "AUTO-APPROVED" (FONT_6X10)
///   Rule:    1px line
///   Label:   master label (FONT_7X14)
///   Method:  method name (FONT_5X8)
///   Bar:     solid confirmation bar at bottom
pub fn show_auto_approved(display: &mut Display<'_>, master_label: &str, method: &str) {
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    let body = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
        .text_color(BinaryColor::On)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    Text::new("AUTO-APPROVED", Point::new(4, 10), header).draw(display).ok();

    Rectangle::new(Point::new(0, 14), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    let label = &master_label[..master_label.len().min(CHARS_PER_LINE)];
    Text::new(label, Point::new(2, 32), body).draw(display).ok();

    let method_str = &method[..method.len().min(25)];
    Text::new(method_str, Point::new(2, 46), small).draw(display).ok();

    // Confirmation bar
    Rectangle::new(Point::new(0, 56), Size::new(128, 4))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

// ---------------------------------------------------------------------------
// Approval feedback screens
// ---------------------------------------------------------------------------

/// Display "hold to confirm" with a graphical progress bar filling over time.
///
/// `hold_pct` is 0-100 representing how far through the 2-second hold.
pub fn show_hold_progress(display: &mut Display<'_>, hold_pct: u32) {
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();

    Text::new("CONFIRMING", Point::new(14, 10), header).draw(display).ok();

    Rectangle::new(Point::new(0, 14), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    // Large percentage
    let pct_str = format!("{}%", hold_pct.min(100));
    let pct_x = ((128 - pct_str.len() as i32 * 10) / 2).max(0);
    Text::new(&pct_str, Point::new(pct_x, 38), large).draw(display).ok();

    // Progress bar
    let bar_y = 48;
    let bar_w = 124u32;
    let bar_x = 2;

    Rectangle::new(Point::new(bar_x, bar_y), Size::new(bar_w, 8))
        .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, 1))
        .draw(display).ok();

    let fill_w = (hold_pct.min(100) * (bar_w - 2)) / 100;
    if fill_w > 0 {
        Rectangle::new(Point::new(bar_x + 1, bar_y + 1), Size::new(fill_w, 6))
            .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
            .draw(display).ok();
    }

    display.flush().ok();
}

/// Display the "Approved" confirmation screen.
pub fn show_approved(display: &mut Display<'_>) {
    display.clear_buffer();

    let large = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();

    // Top rule
    Rectangle::new(Point::new(0, 16), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    Text::new("APPROVED", Point::new(24, 38), large).draw(display).ok();

    // Bottom rule
    Rectangle::new(Point::new(0, 44), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    // Solid confirmation bar
    Rectangle::new(Point::new(0, 58), Size::new(128, 6))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    display.flush().ok();
}

/// Display the "Denied" screen.
pub fn show_denied(display: &mut Display<'_>) {
    display.clear_buffer();

    let large = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    // Top rule
    Rectangle::new(Point::new(0, 16), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    Text::new("DENIED", Point::new(34, 38), large).draw(display).ok();

    // Bottom rule
    Rectangle::new(Point::new(0, 44), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    Text::new("released too early", Point::new(14, 58), small).draw(display).ok();

    display.flush().ok();
}

/// Display a "Signed!" confirmation screen.
pub fn show_signed(display: &mut Display<'_>) {
    display.clear_buffer();

    let large = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();

    Rectangle::new(Point::new(0, 16), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    Text::new("SIGNED", Point::new(34, 38), large).draw(display).ok();

    Rectangle::new(Point::new(0, 44), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    Rectangle::new(Point::new(0, 58), Size::new(128, 6))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    display.flush().ok();
}

/// Display a "Signing..." in-progress screen.
pub fn show_signing(display: &mut Display<'_>) {
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();

    Text::new("PROCESSING", Point::new(14, 10), header).draw(display).ok();

    Rectangle::new(Point::new(0, 14), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    Text::new("Signing", Point::new(19, 40), large).draw(display).ok();

    display.flush().ok();
}

// ---------------------------------------------------------------------------
// Boot animation
// ---------------------------------------------------------------------------

/// Boot animation: binary cat + decrypt reveal.
///
/// Phase 1: A cat made of 0s and 1s walks across the screen. At the centre
/// it "glitches" (deja vu -- briefly appears twice). Like The Matrix.
/// Phase 2: Screen clears, HEARTWOOD decrypts letter by letter.
pub fn show_boot_animation(display: &mut Display<'_>) {
    let mut lfsr: u16 = 0xACE1;
    let mut next_byte = |lfsr: &mut u16| -> u8 {
        let bit = *lfsr & 1;
        *lfsr >>= 1;
        if bit != 0 { *lfsr ^= 0xB400; }
        (*lfsr & 0xFF) as u8
    };

    // Elegant cat silhouette: 20 cols x 18 rows, drawn at 3x3 pixel scale.
    // On-screen size: 60 x 54 pixels -- big, fills most of the 128x64 display.
    // Solid black silhouette with white eye dot, matching reference pixel art.
    // Tail curves gracefully, ears are two distinct points, legs stride cleanly.
    //
    // Bit 19 = col 0 (leftmost/tail), bit 0 = col 19 (rightmost/head).
    // Use `cols = 20` with draw_sprite_hd at cell size 3.
    const CAT_COLS: usize = 20;
    const CELL: u32 = 3;

    // Column reference for the 20-bit field:
    //   col: 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19
    //   bit:19 18 17 16 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0

    // Tail curled up (rows 0-6)
    #[rustfmt::skip]
    const TAIL_UP: [u32; 7] = [
        0x10000, // r0: ...#................  col 3: tip curled
        0x08000, // r1: ....#...............  col 4
        0x04000, // r2: .....#..............  col 5: descends smoothly
        0x04000, // r3: .....#..............  col 5
        0x06000, // r4: .....##.............  cols 5-6: thickens
        0x07000, // r5: .....###............  cols 5-7: widens
        0x0F800, // r6: .....#####..........  cols 5-9: meets body
    ];

    // Tail relaxed/down (rows 0-6)
    #[rustfmt::skip]
    const TAIL_DN: [u32; 7] = [
        0x00000, // r0: ....................
        0x20000, // r1: ..#.................  col 2: tip droops
        0x10000, // r2: ...#................  col 3
        0x08000, // r3: ....#...............  col 4
        0x06000, // r4: .....##.............  cols 5-6
        0x07000, // r5: .....###............  cols 5-7
        0x0F800, // r6: .....#####..........  cols 5-9
    ];

    // Body + head (rows 7-12, shared across all frames)
    // Eye = gap at col 15 in row 9
    #[rustfmt::skip]
    const BODY: [u32; 6] = [
        0x0FC18, // r7:  .....######...##....  cols 5-10 + 14-15 (ears)
        0x0FF3C, // r8:  .....##########.####  cols 5-13 + 15-18 (head dome, gap 14=between)
        //              Actually let me recalculate these properly.
        // r7: cols 5,6,7,8,9,10 + cols 14,15 = ears
        //     bits: 14,13,12,11,10,9 + 5,4 = 0x7C00 + 0x30 = 0x7C30
        // WAIT. That's wrong. Let me recalculate.
        //
        // col 5 = bit 14  = 0x4000
        // col 6 = bit 13  = 0x2000
        // col 7 = bit 12  = 0x1000
        // col 8 = bit 11  = 0x0800
        // col 9 = bit 10  = 0x0400
        // col 10 = bit 9  = 0x0200
        // cols 5-10 = 0x7E00
        // col 14 = bit 5  = 0x0020
        // col 15 = bit 4  = 0x0010
        // cols 14-15 = 0x0030
        // Total r7 = 0x7E30 ... but that doesn't match my hex above. Let me redo ALL rows.
        0, 0, 0, 0, // placeholders, will be replaced below
    ];
    // I'll compute these inline instead to avoid mistakes.

    // Leg poses (rows 13-17, 4 walk phases)
    // Will also compute inline.

    // --- Corrected sprite data using explicit bit-setting ---

    // Helper: set bits for columns a..=b (inclusive)
    // col C -> bit (19 - C)
    // range [a,b] -> bits (19-a) down to (19-b)
    // mask = ((1 << (b - a + 1)) - 1) << (19 - b)
    const fn cols(a: u32, b: u32) -> u32 {
        let width = b - a + 1;
        let shift = 19 - b;
        ((1 << width) - 1) << shift
    }
    const fn col(c: u32) -> u32 {
        1 << (19 - c)
    }

    // Tail curled up (rows 0-6)
    let tail_up: [u32; 7] = [
        col(3),                                     // r0: tip curled
        col(4),                                     // r1: descends
        col(5),                                     // r2
        col(5),                                     // r3
        cols(5,6),                                  // r4: thickens
        cols(5,7),                                  // r5: widens
        cols(4,9),                                  // r6: meets body
    ];

    // Tail relaxed down (rows 0-6)
    let tail_dn: [u32; 7] = [
        0,                                          // r0: nothing high
        col(2),                                     // r1: tip out left
        col(3),                                     // r2
        col(4),                                     // r3
        cols(5,6),                                  // r4: thickens
        cols(5,7),                                  // r5: widens
        cols(4,9),                                  // r6: meets body
    ];

    // Body + head (rows 7-12)
    let body: [u32; 6] = [
        cols(4,9)  | col(14) | col(16),             // r7:  body + ear tips (two points)
        cols(4,11) | cols(13,17),                    // r8:  body + head dome
        cols(4,13) | col(15) | cols(17,18),          // r9:  body + head, EYE gap at col 14 & 16
        cols(4,13) | cols(14,18),                    // r10: body + lower head (filled)
        cols(3,18),                                  // r11: full body continuous
        cols(3,18),                                  // r12: body
    ];

    // Leg poses (rows 13-17)
    let legs_a: [u32; 5] = [  // stride right
        cols(3,6)  | cols(8,11) | cols(14,17),      // r13: legs split
        cols(3,5)  | cols(8,11) | cols(15,17),      // r14: upper legs
        cols(2,4)  | cols(8,10) | cols(16,17),      // r15: mid
        cols(2,3)  | cols(9,10) | col(17),           // r16: lower
        col(1)     | col(9)     | col(18),           // r17: paws wide stride
    ];
    let legs_b: [u32; 5] = [  // legs passing
        cols(3,18),                                  // r13: body base still solid
        cols(4,6)  | cols(9,12) | cols(15,17),      // r14: legs close
        cols(4,5)  | cols(9,11) | cols(16,17),      // r15: mid
        col(5)     | cols(9,10) | col(16),           // r16: lower
        col(5)     | col(10)    | col(16),           // r17: paws close
    ];
    let legs_c: [u32; 5] = [  // stride left
        cols(3,6)  | cols(9,12) | cols(14,17),      // r13: legs split other
        cols(4,6)  | cols(9,12) | cols(15,17),      // r14
        cols(4,5)  | cols(10,12)| cols(16,17),      // r15
        col(4)     | cols(10,11)| col(17),           // r16
        col(3)     | col(11)    | col(18),           // r17: paws wide other
    ];
    let legs_d: [u32; 5] = [  // legs crossing
        cols(3,18),                                  // r13: body base still solid
        cols(5,7)  | cols(10,12)| cols(14,16),      // r14: legs close other
        cols(5,6)  | cols(10,11)| cols(15,16),      // r15
        col(6)     | cols(10,11)| col(15),           // r16
        col(6)     | col(11)    | col(15),           // r17: paws together
    ];
    let all_legs: [[u32; 5]; 4] = [legs_a, legs_b, legs_c, legs_d];

    // Assemble an 18-row frame from tail (7) + body (6) + legs (5).
    let make_frame = |tail: &[u32; 7], legs: &[u32; 5]| -> [u32; 18] {
        let mut f = [0u32; 18];
        f[..7].copy_from_slice(tail);
        f[7..13].copy_from_slice(&body);
        f[13..18].copy_from_slice(legs);
        f
    };

    let cat_y: i32 = 3; // near top -- cat is 54px tall, screen is 64
    let cat_w_px: i32 = CAT_COLS as i32 * CELL as i32; // 60px
    let glitch_px: i32 = 35;

    // Lead-in: 3 empty frames.
    for _ in 0..3 {
        display.clear_buffer();
        display.flush().ok();
        FreeRtos::delay_ms(40);
    }

    let mut cat_x: i32 = -cat_w_px;
    let mut anim_frame: u32 = 0;

    while cat_x < 132 {
        display.clear_buffer();

        let tail = if (anim_frame / 5) % 2 == 0 { &tail_up } else { &tail_dn };
        let legs = &all_legs[(anim_frame as usize) % 4];
        let sprite = make_frame(tail, legs);

        draw_sprite_hd(display, &sprite, cat_x, cat_y, CAT_COLS, CELL);

        // Deja vu glitch: ghost cat behind for 6 frames.
        if cat_x >= glitch_px && cat_x <= glitch_px + 18 {
            let ghost_tail = if ((anim_frame + 3) / 5) % 2 == 0 { &tail_up } else { &tail_dn };
            let ghost_legs = &all_legs[((anim_frame + 2) as usize) % 4];
            let ghost = make_frame(ghost_tail, ghost_legs);
            draw_sprite_hd(display, &ghost, cat_x - cat_w_px - 6, cat_y, CAT_COLS, CELL);
        }

        // Moving ground: scrolling dashes beneath the cat.
        let ground_y = cat_y + 18 * CELL as i32 + 2; // just below paws
        let ground_offset = (anim_frame as i32 * 2) % 8;
        for px in (0..128).step_by(8) {
            let gx = px - ground_offset;
            if gx >= 0 && gx < 128 {
                Rectangle::new(Point::new(gx, ground_y), Size::new(4, 1))
                    .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
                    .draw(display).ok();
            }
        }

        display.flush().ok();
        anim_frame += 1;
        cat_x += 3;
        FreeRtos::delay_ms(35);
    }

    // Lead-out: 3 empty frames.
    for _ in 0..3 {
        display.clear_buffer();
        display.flush().ok();
        FreeRtos::delay_ms(40);
    }

    // Phase 2: HEARTWOOD decrypt reveal.
    const TITLE: &[u8] = b"HEARTWOOD";
    const LEN: usize = 9;
    const START_X: i32 = 19;
    const Y: i32 = 35;

    let big_style = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();
    let sub_style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();

    let mut resolved: usize = 0;

    for frame in 0u32..25 {
        display.clear_buffer();

        if frame >= 3 && frame % 2 == 1 && resolved < LEN {
            resolved += 1;
        }

        for i in 0..LEN {
            let ch = if i < resolved {
                TITLE[i]
            } else {
                0x21 + (next_byte(&mut lfsr) % 94)
            };
            let buf = [ch];
            let s = core::str::from_utf8(&buf).unwrap_or("?");
            let x = START_X + (i as i32 * 10);
            Text::new(s, Point::new(x, Y), big_style).draw(display).ok();
        }

        // Show version once title is fully resolved.
        if resolved >= LEN {
            let version = concat!("v", env!("CARGO_PKG_VERSION"));
            let vx = ((128 - version.len() as i32 * 6) / 2).max(0);
            Text::new(version, Point::new(vx, 56), sub_style).draw(display).ok();
        }

        display.flush().ok();
        FreeRtos::delay_ms(60);
    }

}

/// Draw an HD sprite as NxN pixel blocks.
///
/// `sprite` is a slice of u32 rows (bit `cols-1` = leftmost pixel).
/// `cols` is the number of columns in the sprite data.
/// `cell` is the pixel size of each sprite cell (2 = 2x2 blocks).
fn draw_sprite_hd(
    display: &mut Display<'_>,
    sprite: &[u32],
    x_px: i32,
    y_px: i32,
    cols: usize,
    cell: u32,
) {
    let c = cell as i32;
    for (row_idx, &row_bits) in sprite.iter().enumerate() {
        for col in 0..cols as i32 {
            if (row_bits >> (cols as i32 - 1 - col)) & 1 == 1 {
                let px = x_px + col * c;
                let py = y_px + row_idx as i32 * c;
                if px > -c && px < 128 && py >= 0 && (py + c) <= 64 {
                    Rectangle::new(Point::new(px, py), Size::new(cell, cell))
                        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
                        .draw(display).ok();
                }
            }
        }
    }
}

#[allow(dead_code)]
fn _unused(display: &mut Display<'_>) {
    // Phase 2: reveal.
    display.clear_buffer();

    let title_style = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();
    let sub_style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();

    Text::new("HEARTWOOD", Point::new(19, 22), title_style).draw(display).ok();

    let version = concat!("v", env!("CARGO_PKG_VERSION"));
    let version_x = ((128 - version.len() as i32 * 6) / 2).max(0);
    Text::new(version, Point::new(version_x, 50), sub_style).draw(display).ok();

    display.flush().ok();
    FreeRtos::delay_ms(1000);
}

// ---------------------------------------------------------------------------
// OTA update display
// ---------------------------------------------------------------------------

/// Display the OTA approval prompt with firmware size and countdown.
///
/// Layout (128x64):
///   Line 1 (y=12): "FIRMWARE UPDATE" in FONT_6X10
///   Line 2 (y=30): "{size}KB" in FONT_10X20 (large, centred)
///   Line 3 (y=46): "Hold 2s to approve" in FONT_5X8
///   Line 4 (y=56-62): graphical countdown bar + seconds
pub fn show_ota_approval(
    display: &mut Display<'_>,
    size_kb: u32,
    seconds_remaining: u32,
    total_seconds: u32,
) {
    display.clear_buffer();

    let small = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();
    let medium = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();

    // Header
    Text::new("FIRMWARE UPDATE", Point::new(4, 10), medium).draw(display).ok();

    // Horizontal rule
    Rectangle::new(Point::new(0, 14), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    // Firmware size -- large and centred
    let size_str = format!("{} KB", size_kb);
    let size_x = ((128 - size_str.len() as i32 * 10) / 2).max(0);
    Text::new(&size_str, Point::new(size_x, 36), large).draw(display).ok();

    // Instruction
    Text::new("Hold 2s to approve", Point::new(4, 48), small).draw(display).ok();

    // Graphical countdown bar: track (outline) + fill
    let bar_y = 54;
    let bar_h = 8u32;
    let bar_w = 100u32;
    let bar_x = 2;

    // Track outline
    Rectangle::new(Point::new(bar_x, bar_y), Size::new(bar_w, bar_h))
        .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, 1))
        .draw(display).ok();

    // Fill (proportional to time remaining)
    let fill_w = if total_seconds > 0 {
        ((seconds_remaining as u32) * (bar_w - 4)) / total_seconds
    } else {
        0
    };
    if fill_w > 0 {
        Rectangle::new(Point::new(bar_x + 2, bar_y + 2), Size::new(fill_w, bar_h - 4))
            .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
            .draw(display).ok();
    }

    // Seconds label right of bar
    let secs = format!("{}s", seconds_remaining);
    Text::new(&secs, Point::new(bar_x + bar_w as i32 + 4, bar_y + 7), small)
        .draw(display).ok();

    display.flush().ok();
}

/// Display OTA transfer progress with a graphical progress bar.
///
/// Layout (128x64):
///   Line 1 (y=10):  "OTA" in FONT_6X10 + percentage right-aligned
///   Row 14-24:       graphical progress bar (full width, 10px tall)
///   Line 3 (y=38):  "{received}/{total} KB" in FONT_6X10
///   Line 4 (y=50):  "chunk {n}/{total}" in FONT_5X8
///   Bottom (y=60):   8 hash nibbles as a subtle fingerprint
pub fn show_ota_progress(
    display: &mut Display<'_>,
    percent: u32,
    bytes_received: u32,
    total_size: u32,
    chunk_num: u32,
    total_chunks: u32,
) {
    display.clear_buffer();

    let small = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();
    let medium = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();

    // Top row: "OTA" label + large percentage
    Text::new("OTA", Point::new(2, 10), medium).draw(display).ok();

    let pct_str = format!("{}%", percent);
    let pct_x = (128 - pct_str.len() as i32 * 10).max(40);
    Text::new(&pct_str, Point::new(pct_x, 12), large).draw(display).ok();

    // Progress bar: full-width graphical bar
    let bar_y = 26;
    let bar_h = 6u32;
    let bar_w = 124u32;
    let bar_x = 2;

    // Track
    Rectangle::new(Point::new(bar_x, bar_y), Size::new(bar_w, bar_h))
        .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, 1))
        .draw(display).ok();

    // Fill
    let fill_w = (percent * (bar_w - 2)) / 100;
    if fill_w > 0 {
        Rectangle::new(Point::new(bar_x + 1, bar_y + 1), Size::new(fill_w, bar_h - 2))
            .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
            .draw(display).ok();
    }

    // Bytes transferred
    let kb_recv = bytes_received / 1024;
    let kb_total = (total_size + 1023) / 1024;
    let bytes_str = format!("{}/{} KB", kb_recv, kb_total);
    Text::new(&bytes_str, Point::new(2, 44), medium).draw(display).ok();

    // Chunk counter
    let chunk_str = format!("chunk {}/{}", chunk_num, total_chunks);
    Text::new(&chunk_str, Point::new(2, 56), small).draw(display).ok();

    // Transfer rate indicator: a small animated dot pattern at bottom-right
    // that shifts based on chunk number to show activity
    let dot_x = 100 + ((chunk_num % 4) as i32 * 6);
    Rectangle::new(Point::new(dot_x, 54), Size::new(3, 3))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    display.flush().ok();
}

/// Display the OTA verification screen (SHA-256 check in progress).
///
/// Shows a pulsing-style animation by alternating between two frames.
pub fn show_ota_verifying(display: &mut Display<'_>) {
    display.clear_buffer();

    let medium = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();

    Text::new("VERIFYING", Point::new(14, 28), large).draw(display).ok();
    Text::new("SHA-256 check", Point::new(20, 46), medium).draw(display).ok();

    // Full progress bar (complete)
    Rectangle::new(Point::new(2, 52), Size::new(124, 6))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    display.flush().ok();
}

/// Display the OTA success screen with a brief animation.
pub fn show_ota_complete(display: &mut Display<'_>) {
    // Frame 1: the word builds
    display.clear_buffer();
    let large = MonoTextStyleBuilder::new()
        .font(&FONT_10X20)
        .text_color(BinaryColor::On)
        .build();
    let medium = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();

    // Top line
    Rectangle::new(Point::new(0, 0), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    Text::new("VERIFIED", Point::new(24, 24), large).draw(display).ok();

    // Divider
    Rectangle::new(Point::new(20, 30), Size::new(88, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    Text::new("Rebooting...", Point::new(22, 46), medium).draw(display).ok();

    // Bottom line
    Rectangle::new(Point::new(0, 63), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    display.flush().ok();
}

// ---------------------------------------------------------------------------
// Display power management
// ---------------------------------------------------------------------------

/// Turn the SSD1306 display panel off to prevent burn-in and save power.
///
/// The display RAM is preserved — calling [`wake_display`] and flushing
/// will restore the last frame without needing a full re-init.
pub fn sleep_display(display: &mut Display<'_>) {
    if let Err(e) = display.set_display_on(false) {
        log::warn!("OLED sleep failed: {:?}", e);
    }
}

/// Turn the SSD1306 display panel back on after a sleep.
pub fn wake_display(display: &mut Display<'_>) {
    if let Err(e) = display.set_display_on(true) {
        log::warn!("OLED wake failed: {:?}", e);
    }
}

/// Display an identity switch notification (shown for ~2 seconds).
/// Display an identity switch notification with structured layout.
///
/// Layout:
///   Header:  "IDENTITY SWITCH" (FONT_6X10)
///   Rule:    1px line
///   Label:   master label (FONT_7X14)
///   Purpose: "-> purpose" (FONT_7X14)
///   npub:    truncated (FONT_5X8)
pub fn show_identity_switch(
    display: &mut Display<'_>,
    master_label: &str,
    purpose: &str,
    npub: &str,
) {
    display.clear_buffer();

    let header_style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();
    let body = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
        .text_color(BinaryColor::On)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    Text::new("IDENTITY SWITCH", Point::new(2, 10), header_style).draw(display).ok();

    Rectangle::new(Point::new(0, 14), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    let label = &master_label[..master_label.len().min(CHARS_PER_LINE)];
    Text::new(label, Point::new(2, 30), body).draw(display).ok();

    let purpose_line = format!("-> {}", purpose);
    let purpose_line = &purpose_line[..purpose_line.len().min(CHARS_PER_LINE)];
    Text::new(&purpose_line, Point::new(2, 46), body).draw(display).ok();

    // npub in small font for more characters
    let npub_short = &npub[..npub.len().min(25)];
    Text::new(npub_short, Point::new(2, 58), small).draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }

    FreeRtos::delay_ms(2000);
}
