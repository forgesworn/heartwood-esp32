// firmware/src/oled.rs
//
// OLED display helpers for the Heltec V4 built-in SSD1306 (128x64).

use embedded_graphics::mono_font::ascii::{FONT_5X8, FONT_6X10, FONT_7X14, FONT_10X20};
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

/// Display an npub on the OLED, split across lines.
pub fn show_npub(display: &mut Display<'_>, npub: &str) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
        .text_color(BinaryColor::On)
        .build();

    let mut y = 14i32;
    let mut pos = 0;
    while pos < npub.len() {
        let end = core::cmp::min(pos + CHARS_PER_LINE, npub.len());
        let line = &npub[pos..end];
        Text::new(line, Point::new(0, y), text_style)
            .draw(display)
            .ok();
        y += 16;
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
        .font(&FONT_7X14)
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
/// Layout (128x64 SSD1306, FONT_7X14, 18 chars/line, 4 lines):
///   Line 1 (y=14): "Sign as <purpose>?"
///   Line 2 (y=30): "Kind <number>"
///   Line 3 (y=46): content preview (truncated)
///   Line 4 (y=62): "[========--] 18s"
pub fn show_sign_request(
    display: &mut Display<'_>,
    purpose: &str,
    kind: u64,
    content_preview: &str,
    seconds_remaining: u32,
) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
        .text_color(BinaryColor::On)
        .build();

    // Line 1: "Sign as <purpose>?"
    let label = if purpose.is_empty() || purpose == "master" { "master" } else { purpose };
    let heading = format!("Sign as {}?", label);
    let heading = &heading[..heading.len().min(CHARS_PER_LINE)];
    Text::new(heading, Point::new(0, 14), text_style)
        .draw(display)
        .ok();

    // Line 2: "Kind <number>"
    let kind_str = format!("Kind {}", kind);
    let kind_str = &kind_str[..kind_str.len().min(CHARS_PER_LINE)];
    Text::new(kind_str, Point::new(0, 30), text_style)
        .draw(display)
        .ok();

    // Line 3: content preview (single line, truncated)
    let content = if content_preview.len() > CHARS_PER_LINE {
        format!("{}...", &content_preview[..CHARS_PER_LINE - 3])
    } else {
        content_preview.to_string()
    };
    Text::new(&content, Point::new(0, 46), text_style)
        .draw(display)
        .ok();

    // Line 4: countdown bar
    show_countdown_bar(display, seconds_remaining, 30, text_style);

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Draw a countdown bar at y=58: "[====------] 18s"
/// Bar width is 12 characters; filled proportion equals remaining/total.
fn show_countdown_bar(
    display: &mut Display<'_>,
    remaining: u32,
    total: u32,
    text_style: MonoTextStyle<'_, BinaryColor>,
) {
    const BAR_WIDTH: usize = 12;

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
    let bar_str = core::str::from_utf8(&bar).unwrap_or("------------");

    // Format the full line — "18s" suffix, right-aligned after the closing bracket.
    let line = format!("[{}] {}s", bar_str, remaining);
    let line = &line[..line.len().min(CHARS_PER_LINE + 4)];
    Text::new(line, Point::new(0, 62), text_style)
        .draw(display)
        .ok();

    // Suppress unused-variable warning for `empty` in no_std contexts.
    let _ = empty;
}

/// Display a result message centred on the OLED, then pause for 2 seconds.
pub fn show_result(display: &mut Display<'_>, message: &str) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
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

/// Display the multi-master boot screen.
pub fn show_boot(display: &mut Display<'_>, master_count: u8) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
        .text_color(BinaryColor::On)
        .build();

    Text::new("Heartwood HSM", Point::new(0, 14), text_style)
        .draw(display)
        .ok();

    let count_str = format!("{} masters loaded", master_count);
    Text::new(&count_str, Point::new(0, 34), text_style)
        .draw(display)
        .ok();

    Text::new("Awaiting bridge...", Point::new(0, 54), text_style)
        .draw(display)
        .ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Display bridge connected status.
pub fn show_bridge_connected(
    display: &mut Display<'_>,
    master_count: u8,
    client_count: usize,
) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
        .text_color(BinaryColor::On)
        .build();

    Text::new("Bridge connected", Point::new(0, 14), text_style)
        .draw(display)
        .ok();

    let masters_str = format!("{} masters active", master_count);
    Text::new(&masters_str, Point::new(0, 34), text_style)
        .draw(display)
        .ok();

    let clients_str = format!("{} clients", client_count);
    Text::new(&clients_str, Point::new(0, 54), text_style)
        .draw(display)
        .ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Display a signing request with master label, method, kind, content, and countdown.
pub fn show_master_sign_request(
    display: &mut Display<'_>,
    master_label: &str,
    method: &str,
    kind: Option<u64>,
    content_preview: &str,
    seconds_remaining: u32,
) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
        .text_color(BinaryColor::On)
        .build();

    // Line 1: master label.
    let label = &master_label[..master_label.len().min(CHARS_PER_LINE)];
    Text::new(label, Point::new(0, 14), text_style)
        .draw(display)
        .ok();

    // Line 2: method + kind.
    let method_str = match kind {
        Some(k) => format!("{} kind:{}", method, k),
        None => method.to_string(),
    };
    let method_str = &method_str[..method_str.len().min(CHARS_PER_LINE)];
    Text::new(method_str, Point::new(0, 30), text_style)
        .draw(display)
        .ok();

    // Line 3: content preview (single line, truncated).
    let preview = if content_preview.len() > CHARS_PER_LINE {
        format!("{}...", &content_preview[..CHARS_PER_LINE - 3])
    } else {
        content_preview.to_string()
    };
    Text::new(&preview, Point::new(0, 46), text_style)
        .draw(display)
        .ok();

    // Line 4: countdown bar.
    show_countdown_bar(display, seconds_remaining, 30, text_style);

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Display an auto-approved request flash (shown for ~1 second).
pub fn show_auto_approved(display: &mut Display<'_>, master_label: &str, method: &str) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
        .text_color(BinaryColor::On)
        .build();

    // Use a simple checkmark since the OLED font may not have Unicode tick.
    let header = format!("{} OK", &master_label[..master_label.len().min(CHARS_PER_LINE - 3)]);
    Text::new(&header, Point::new(0, 24), text_style)
        .draw(display)
        .ok();

    let method_str = &method[..method.len().min(CHARS_PER_LINE)];
    Text::new(method_str, Point::new(0, 44), text_style)
        .draw(display)
        .ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
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

    // Cat sprite: 14 columns x 7 rows. Faces right, tail curves up on left.
    // Bit 13 = col 0 (leftmost/tail), bit 0 = col 13 (rightmost/head).
    // 6 walk frames: 2 tail positions x 3 leg positions.
    const CAT_H: usize = 7;

    // Common body rows:
    // Row 2: ..#.....#####.  head with ear detail  = 0x083E
    // Row 3: ...#########..  body upper             = 0x07FC
    // Row 4: ...#########..  body lower             = 0x07FC

    const CAT: [[u16; CAT_H]; 6] = [
        [ // Frame 0: tail UP, legs stride right
            0x2000, // #.............  tail tip high
            0x1014, // .#.......#.#..  tail + ears
            0x083E, // ..#.....#####.  head
            0x07FC, // ...#########..  body
            0x07FC, // ...#########..  body
            0x0318, // ....##...##...  legs stride
            0x0408, // ...#......#...  paws wide
        ],
        [ // Frame 1: tail UP, legs passing
            0x2000, // #.............  tail tip high
            0x1014, // .#.......#.#..  tail + ears
            0x083E, // ..#.....#####.  head
            0x07FC, // ...#########..  body
            0x07FC, // ...#########..  body
            0x0190, // .....##..#....  legs passing
            0x0110, // .....#...#....  paws together
        ],
        [ // Frame 2: tail UP, legs stride left
            0x2000, // #.............  tail tip high
            0x1014, // .#.......#.#..  tail + ears
            0x083E, // ..#.....#####.  head
            0x07FC, // ...#########..  body
            0x07FC, // ...#########..  body
            0x0098, // ......#..##...  legs stride other
            0x0108, // .....#....#...  paws
        ],
        [ // Frame 3: tail DOWN, legs stride right
            0x0000, // ..............  no tip
            0x3014, // ##.......#.#..  tail low + ears
            0x083E, // ..#.....#####.  head
            0x07FC, // ...#########..  body
            0x07FC, // ...#########..  body
            0x0318, // ....##...##...  legs stride
            0x0408, // ...#......#...  paws wide
        ],
        [ // Frame 4: tail DOWN, legs passing
            0x0000, // ..............  no tip
            0x3014, // ##.......#.#..  tail low + ears
            0x083E, // ..#.....#####.  head
            0x07FC, // ...#########..  body
            0x07FC, // ...#########..  body
            0x0190, // .....##..#....  legs passing
            0x0110, // .....#...#....  paws together
        ],
        [ // Frame 5: tail DOWN, legs stride left
            0x0000, // ..............  no tip
            0x3014, // ##.......#.#..  tail low + ears
            0x083E, // ..#.....#####.  head
            0x07FC, // ...#########..  body
            0x07FC, // ...#########..  body
            0x0098, // ......#..##...  legs stride other
            0x0108, // .....#....#...  paws
        ],
    ];

    let tiny = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    const SPRITE_W: i32 = 14;
    const SCREEN_COLS: i32 = 26; // 128/5 rounded up

    let cat_row: i32 = 0; // top of screen
    let glitch_col: i32 = 7;

    // Lead-in: 2 empty frames.
    for _ in 0..2 {
        display.clear_buffer();
        display.flush().ok();
        FreeRtos::delay_ms(50);
    }

    let mut cat_col: i32 = -SPRITE_W;
    let mut frame: u32 = 0;

    while cat_col < SCREEN_COLS {
        display.clear_buffer();

        let sprite = &CAT[(frame as usize) % 6];

        // Draw the cat as 1s.
        draw_sprite(display, sprite, cat_col, cat_row, &tiny);

        // Deja vu glitch: ghost cat appears behind for 3 frames.
        if cat_col >= glitch_col && cat_col <= glitch_col + 4 {
            let ghost = &CAT[((frame + 3) as usize) % 6];
            draw_sprite(display, ghost, cat_col - 12, cat_row, &tiny);
        }

        // Moving ground: a scrolling line of dots at the bottom.
        let ground_y = 63;
        let ground_offset = (frame as i32 * 3) % 6;
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
        frame += 1;
        cat_col += 2;
        FreeRtos::delay_ms(45);
    }

    // Lead-out: 2 empty frames.
    for _ in 0..2 {
        display.clear_buffer();
        display.flush().ok();
        FreeRtos::delay_ms(50);
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

/// Draw a cat sprite as '1' characters at the given cell position.
fn draw_sprite(
    display: &mut Display<'_>,
    sprite: &[u16; 7],
    col_offset: i32,
    row_offset: i32,
    style: &embedded_graphics::mono_font::MonoTextStyle<'_, BinaryColor>,
) {
    for row in 0..7i32 {
        for col in 0..14i32 {
            // Bit 13 = col 0 (leftmost), bit 0 = col 13 (rightmost).
            if (sprite[row as usize] >> (13 - col)) & 1 == 1 {
                let sx = (col_offset + col) * 5;
                let sy = (row_offset + row) * 8 + 7;
                if sx >= 0 && sx < 128 && sy >= 0 && sy < 64 {
                    Text::new("1", Point::new(sx, sy), *style)
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
pub fn show_identity_switch(
    display: &mut Display<'_>,
    master_label: &str,
    purpose: &str,
    npub: &str,
) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_7X14)
        .text_color(BinaryColor::On)
        .build();

    let label = &master_label[..master_label.len().min(CHARS_PER_LINE)];
    Text::new(label, Point::new(0, 14), text_style)
        .draw(display)
        .ok();

    let purpose_line = format!("-> {}", purpose);
    let purpose_line = &purpose_line[..purpose_line.len().min(CHARS_PER_LINE)];
    Text::new(purpose_line, Point::new(0, 34), text_style)
        .draw(display)
        .ok();

    let npub_short = &npub[..npub.len().min(CHARS_PER_LINE)];
    Text::new(npub_short, Point::new(0, 54), text_style)
        .draw(display)
        .ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }

    FreeRtos::delay_ms(2000);
}
