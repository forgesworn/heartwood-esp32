// firmware/src/oled.rs
//
// OLED display helpers for the Heltec V4 built-in SSD1306 (128x64).

use embedded_graphics::mono_font::ascii::{FONT_5X8, FONT_6X10, FONT_7X14, FONT_10X20};
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::mono_font::MonoTextStyleBuilder;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::Pixel;
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
    let small = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    Text::new("HEARTWOOD HSM", Point::new(4, 10), header).draw(display).ok();

    Rectangle::new(Point::new(0, 14), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    // Large master count
    let count_str = format!("{}", master_count);
    Text::new(&count_str, Point::new(2, 38), large).draw(display).ok();
    Text::new("masters loaded", Point::new(22, 36), small).draw(display).ok();

    // Bottom status
    Rectangle::new(Point::new(0, 48), Size::new(128, 1))
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(display).ok();

    Text::new("Awaiting bridge...", Point::new(2, 60), small).draw(display).ok();

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

    // Hold the confirmation screen for 3 seconds so the user can verify
    // what was signed before the display returns to the idle screen.
    FreeRtos::delay_ms(3000);
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

/// Boot animation: HD pixel-art cat + decrypt reveal.
///
/// Phase 1: A cat silhouette walks across the screen at 1:1 pixel scale.
/// At centre screen it "glitches" (deja vu -- ghost cat behind). Like The Matrix.
/// Phase 2: Screen clears, HEARTWOOD decrypts letter by letter.
pub fn show_boot_animation(display: &mut Display<'_>) {
    let mut lfsr: u16 = 0xACE1;
    let mut next_byte = |lfsr: &mut u16| -> u8 {
        let bit = *lfsr & 1;
        *lfsr >>= 1;
        if bit != 0 { *lfsr ^= 0xB400; }
        (*lfsr & 0xFF) as u8
    };

    use crate::cat_sprites::{FRAMES, FRAME_COUNT, FRAME_COLS};

    // 16 procedural frames: each has unique tail + legs computed from gait cycle.
    // Vertical bob: 1px up on odd frames for weight feel.

    // Deja vu triggers when the cat's midpoint reaches screen centre (px 64).
    let glitch_x: i32 = 64 - (FRAME_COLS as i32 / 2); // ~36

    // Lead-in: 2 empty frames.
    for _ in 0..2 {
        display.clear_buffer();
        display.flush().ok();
        FreeRtos::delay_ms(50);
    }

    let mut x: i32 = -(FRAME_COLS as i32);
    let mut step: u32 = 0;

    while x < 128 {
        display.clear_buffer();

        let frame_idx = (step as usize) % FRAME_COUNT;
        // Vertical bob (1px) + horizontal sway (1px, slower period).
        let y = if step % 2 == 0 { 6 } else { 5 };
        let sway: i32 = if (step / 4) % 2 == 0 { 0 } else { 1 };
        draw_sprite_hd(display, &FRAMES[frame_idx], x + sway, y);

        // Deja vu glitch: ghost cat appears 40px behind for 3 frames.
        if x >= glitch_x && x <= glitch_x + 6 {
            let ghost_idx = ((step as usize) + FRAME_COUNT / 2) % FRAME_COUNT;
            let ghost_y = if (step + 1) % 2 == 0 { 6 } else { 5 };
            draw_sprite_hd(display, &FRAMES[ghost_idx], x - 40, ghost_y);
        }

        // Moving ground: scrolling dashes at the bottom.
        let ground_y = 63;
        let ground_offset = (step as i32 * 3) % 6;
        for px in (0..128).step_by(6) {
            let gx = px - ground_offset;
            if gx >= 0 && gx < 128 {
                use embedded_graphics::primitives::{Line, PrimitiveStyle};
                Line::new(Point::new(gx, ground_y), Point::new(gx + 2, ground_y))
                    .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, 1))
                    .draw(display).ok();
            }
        }

        display.flush().ok();
        step += 1;
        x += 2;
        FreeRtos::delay_ms(45);
    }

    // Lead-out: 2 empty frames.
    for _ in 0..2 {
        display.clear_buffer();
        display.flush().ok();
        FreeRtos::delay_ms(50);
    }

    // Phase 2: HEARTWOOD decrypt reveal (unchanged).
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

        if resolved >= LEN {
            let version = concat!("v", env!("CARGO_PKG_VERSION"));
            let vx = ((128 - version.len() as i32 * 6) / 2).max(0);
            Text::new(version, Point::new(vx, 56), sub_style).draw(display).ok();
        }

        display.flush().ok();
        FreeRtos::delay_ms(60);
    }
}

/// Draw a 56x56 pixel sprite at the given pixel offset.
/// Bits are packed as u64 per row: bit 55 = leftmost column, bit 0 = rightmost.
fn draw_sprite_hd(
    display: &mut Display<'_>,
    frame: &[u64; 56],
    x_offset: i32,
    y_offset: i32,
) {
    for row in 0..56i32 {
        let bits = frame[row as usize];
        if bits == 0 { continue; }
        let py = y_offset + row;
        if py < 0 || py >= 64 { continue; }
        for col in 0..56i32 {
            if (bits >> (55 - col)) & 1 == 1 {
                let px = x_offset + col;
                if px >= 0 && px < 128 {
                    Pixel(Point::new(px, py), BinaryColor::On)
                        .draw(display).ok();
                }
            }
        }
    }
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
