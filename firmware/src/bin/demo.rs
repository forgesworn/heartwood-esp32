// firmware/src/bin/demo.rs
//
// Heartwood board-check demo — deliberately NOT the signer.
//
// Ships pre-flashed on boards we hand out so first plug-in shows Heartwood
// branding instead of a vendor demo, proves the display and both buttons
// work, and makes it unmissable that the real signer firmware still has to
// be flashed (sapwood.forgesworn.dev). The proof of life is a two-button
// jump-and-duck runner starring the Heartwood cat.
//
// Self-contained on purpose: it reuses only the pure display driver, palette
// and sprite data via `#[path]`, and never touches NVS, crypto, radios or the
// serial frame protocol. There is nothing to extract from a demo unit.
//
// Build: scripts/build-firmware.sh demo --release   (T-Display only for now)

// The shared modules expose the full signer-facing API; the demo uses a
// slice of it, so unused-item warnings are expected and silenced.
#[path = "../st7789.rs"]
#[allow(dead_code)]
mod st7789;
#[path = "../palette.rs"]
mod palette;
#[path = "../cat_sprites.rs"]
#[allow(dead_code)]
mod cat_sprites;

use embedded_graphics::mono_font::{ascii, MonoTextStyleBuilder};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{Line, PrimitiveStyle, Rectangle};
use embedded_graphics::text::Text;
use esp_idf_hal::delay::FreeRtos;
use esp_idf_hal::gpio::{AnyIOPin, Input, PinDriver, Pull};
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_hal::spi::config::{Config as SpiConfig, DriverConfig as SpiDriverConfig};
use esp_idf_hal::spi::{Dma, SpiDeviceDriver};
use esp_idf_hal::units::FromValueType;
use mipidsi::options::{ColorInversion, Rotation};

use cat_sprites::{FRAMES, FRAME_COUNT};
use palette::{ACCENT, DANGER, FG, MUTED, NOSTR, OK};
use st7789::St7789Display;

/// Where the real signer firmware comes from — shown on every screen.
const FLASH_URL: &str = "sapwood.forgesworn.dev";

// --- Game tuning (pixels, frames; ~30 fps) ---
/// Ground line height from the top of the 135-px panel.
const GROUND_Y: i32 = 120;
/// Cat sprite anchor (left edge).
const CAT_X: i32 = 20;
/// Cat collision box, tighter than the 56x56 sprite's whitespace.
const CAT_HIT_X: i32 = 10;
const CAT_HIT_W: i32 = 36;
const CAT_HIT_H: i32 = 40;
/// Ducked collision height (bottom-aligned).
const DUCK_HIT_H: i32 = 22;
/// Jump physics in tenths of a pixel per frame.
const JUMP_VELOCITY: i32 = -52;
const GRAVITY: i32 = 4;
/// Overhead bar: its underside sits this far above the ground — a ducked cat
/// clears it, a running one does not.
const BAR_CLEARANCE: i32 = 30;
const BAR_THICKNESS: i32 = 10;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// Ground block — jump over it.
    Spike,
    /// Overhead bar — duck under it.
    Bar,
}

#[derive(Clone, Copy)]
struct Obstacle {
    x: i32,
    kind: Kind,
    passed: bool,
}

/// Small deterministic PRNG (xorshift32) for obstacle spacing — no radio, so
/// the hardware RNG is pseudo anyway, and gameplay only needs variety.
struct Rng(u32);
impl Rng {
    fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
    fn range(&mut self, lo: u32, hi: u32) -> u32 {
        lo + self.next() % (hi - lo)
    }
}

fn main() {
    esp_idf_svc::sys::link_patches();

    let p = Peripherals::take().expect("peripherals");

    // ST7789 bring-up — same pin map as the signer's T-Display block.
    let spi = SpiDeviceDriver::new_single(
        p.spi2,
        p.pins.gpio18,
        p.pins.gpio19,
        None::<AnyIOPin>,
        Some(p.pins.gpio5),
        &SpiDriverConfig::new().dma(Dma::Auto(4096)),
        &SpiConfig::new().baudrate(26.MHz().into()),
    )
    .expect("SPI init");
    let dc = PinDriver::output(p.pins.gpio16).expect("DC pin");
    let rst = PinDriver::output(p.pins.gpio23).expect("RST pin");
    let backlight = PinDriver::output(p.pins.gpio4).expect("backlight pin");
    let spi_buffer: &'static mut [u8] = Box::leak(vec![0u8; 4096].into_boxed_slice());
    let mut display = St7789Display::new(
        spi,
        dc,
        rst,
        backlight,
        spi_buffer,
        135,
        240,
        52,
        40,
        Rotation::Deg90,
        false,
        ColorInversion::Inverted,
    );

    let button_a = PinDriver::input(p.pins.gpio0, Pull::Up).expect("button A");
    let button_b = PinDriver::input(p.pins.gpio35, Pull::Floating).expect("button B");

    let mut rng = Rng(unsafe { esp_idf_svc::sys::esp_random() } | 1);
    let mut best: u32 = 0;

    loop {
        title_screen(&mut display, &button_a, &button_b);
        let score = play(&mut display, &button_a, &button_b, &mut rng);
        best = best.max(score);
        game_over(&mut display, &button_a, score, best);
    }
}

/// Title card: branding, the flash-me line, and a live button check — each
/// button's label lights while it is held, so "do my buttons work?" is
/// answered before the game even starts.
fn title_screen(
    display: &mut St7789Display<'_>,
    a: &PinDriver<'_, Input>,
    b: &PinDriver<'_, Input>,
) {
    let title = MonoTextStyleBuilder::new()
        .font(&ascii::FONT_10X20)
        .text_color(NOSTR)
        .build();
    let body = MonoTextStyleBuilder::new().font(&ascii::FONT_6X10).text_color(FG).build();
    let muted = MonoTextStyleBuilder::new().font(&ascii::FONT_6X10).text_color(MUTED).build();
    let ok = MonoTextStyleBuilder::new().font(&ascii::FONT_6X10).text_color(OK).build();

    let mut frame: usize = 0;
    // Require a fresh A press (edge) so the reset-release doesn't auto-start.
    let mut a_was_low = a.is_low();
    loop {
        display.clear_buffer();
        Text::new("HEARTWOOD", Point::new(70, 24), title).draw(display).ok();
        Text::new("demo game - board check", Point::new(52, 40), muted).draw(display).ok();
        Text::new("This is NOT the signer.", Point::new(50, 58), body).draw(display).ok();
        Text::new("Flash it at:", Point::new(84, 70), muted).draw(display).ok();
        Text::new(FLASH_URL, Point::new(54, 82), ok).draw(display).ok();

        // Button check row: labels light while held.
        let a_style = if a.is_low() {
            MonoTextStyleBuilder::new().font(&ascii::FONT_6X10).text_color(ACCENT).build()
        } else {
            muted
        };
        let b_style = if b.is_low() {
            MonoTextStyleBuilder::new().font(&ascii::FONT_6X10).text_color(ACCENT).build()
        } else {
            muted
        };
        Text::new("[lower] jump", Point::new(24, 102), a_style).draw(display).ok();
        Text::new("[upper] duck", Point::new(140, 102), b_style).draw(display).ok();
        Text::new("press lower button to start", Point::new(40, 122), body).draw(display).ok();

        // A strolling cat keeps the panel obviously alive.
        let walk = &FRAMES[frame % FRAME_COUNT];
        draw_sprite(display, walk, 200, 36, 1, FG);

        display.flush().ok();
        frame += 1;

        let a_low = a.is_low();
        if a_low && !a_was_low {
            // Debounce, then wait for release so the press doesn't jump.
            FreeRtos::delay_ms(30);
            while a.is_low() {
                FreeRtos::delay_ms(10);
            }
            return;
        }
        a_was_low = a_low;
        FreeRtos::delay_ms(60);
    }
}

/// One run. Returns the score.
fn play(
    display: &mut St7789Display<'_>,
    a: &PinDriver<'_, Input>,
    b: &PinDriver<'_, Input>,
    rng: &mut Rng,
) -> u32 {
    let hud = MonoTextStyleBuilder::new().font(&ascii::FONT_6X10).text_color(MUTED).build();

    // Cat state: vertical offset from its grounded position, in tenths.
    let mut y_off_tenths: i32 = 0;
    let mut vy: i32 = 0;
    let mut airborne = false;

    let mut obstacles: Vec<Obstacle> = Vec::new();
    let mut next_spawn: i32 = 40;
    let mut score: u32 = 0;
    let mut frame: usize = 0;
    let mut a_was_low = a.is_low();

    loop {
        // --- Input ---
        let a_low = a.is_low();
        let ducking = b.is_low() && !airborne;
        if a_low && !a_was_low && !airborne && !ducking {
            vy = JUMP_VELOCITY;
            airborne = true;
        }
        a_was_low = a_low;

        // --- Physics ---
        if airborne {
            y_off_tenths += vy;
            vy += GRAVITY;
            if y_off_tenths >= 0 {
                y_off_tenths = 0;
                vy = 0;
                airborne = false;
            }
        }
        let y_off = y_off_tenths / 10;

        // --- World ---
        let speed = (2 + score as i32 / 8).min(6);
        for ob in obstacles.iter_mut() {
            ob.x -= speed;
            if !ob.passed && ob.x + 14 < CAT_X {
                ob.passed = true;
                score += 1;
            }
        }
        obstacles.retain(|ob| ob.x > -20);
        next_spawn -= speed;
        if next_spawn <= 0 {
            let kind = if rng.range(0, 3) == 0 { Kind::Bar } else { Kind::Spike };
            obstacles.push(Obstacle { x: 244, kind, passed: false });
            next_spawn = rng.range(70, 150) as i32;
        }

        // --- Collision (AABB against the cat's trimmed hitbox) ---
        let hit_h = if ducking { DUCK_HIT_H } else { CAT_HIT_H };
        let cat_top = GROUND_Y + y_off - hit_h;
        let cat_left = CAT_X + CAT_HIT_X;
        let cat_right = cat_left + CAT_HIT_W;
        for ob in &obstacles {
            let (left, right, top, bottom) = match ob.kind {
                Kind::Spike => (ob.x, ob.x + 10, GROUND_Y - 18, GROUND_Y),
                Kind::Bar => (
                    ob.x,
                    ob.x + 14,
                    GROUND_Y - BAR_CLEARANCE - BAR_THICKNESS,
                    GROUND_Y - BAR_CLEARANCE,
                ),
            };
            if cat_right > left && cat_left < right && GROUND_Y + y_off > top && cat_top < bottom {
                return score;
            }
        }

        // --- Draw ---
        display.clear_buffer();
        Line::new(Point::new(0, GROUND_Y), Point::new(239, GROUND_Y))
            .into_styled(PrimitiveStyle::with_stroke(MUTED, 1))
            .draw(display)
            .ok();
        for ob in &obstacles {
            match ob.kind {
                Kind::Spike => {
                    Rectangle::new(Point::new(ob.x, GROUND_Y - 18), Size::new(10, 18))
                        .into_styled(PrimitiveStyle::with_fill(DANGER))
                        .draw(display)
                        .ok();
                }
                Kind::Bar => {
                    Rectangle::new(
                        Point::new(ob.x, GROUND_Y - BAR_CLEARANCE - BAR_THICKNESS),
                        Size::new(14, BAR_THICKNESS as u32),
                    )
                    .into_styled(PrimitiveStyle::with_fill(ACCENT))
                    .draw(display)
                    .ok();
                }
            }
        }

        let sprite = &FRAMES[(frame / 2) % FRAME_COUNT];
        if ducking {
            // Crouch: bottom half of the sprite, grounded.
            draw_sprite_rows(display, sprite, CAT_X, GROUND_Y - 28, 28, 56, FG);
        } else {
            draw_sprite(display, sprite, CAT_X, GROUND_Y + y_off - 56, 1, FG);
        }

        let score_text = format_score(score);
        Text::new(&score_text, Point::new(190, 14), hud).draw(display).ok();
        display.flush().ok();

        frame += 1;
        FreeRtos::delay_ms(15);
    }
}

fn game_over(display: &mut St7789Display<'_>, a: &PinDriver<'_, Input>, score: u32, best: u32) {
    let title = MonoTextStyleBuilder::new()
        .font(&ascii::FONT_10X20)
        .text_color(DANGER)
        .build();
    let body = MonoTextStyleBuilder::new().font(&ascii::FONT_6X10).text_color(FG).build();
    let muted = MonoTextStyleBuilder::new().font(&ascii::FONT_6X10).text_color(MUTED).build();
    let ok = MonoTextStyleBuilder::new().font(&ascii::FONT_6X10).text_color(OK).build();

    display.clear_buffer();
    Text::new("CAUGHT!", Point::new(85, 34), title).draw(display).ok();
    let line = format!("score {score}   best {best}");
    Text::new(&line, Point::new(70, 58), body).draw(display).ok();
    Text::new("Ready for the real thing?", Point::new(46, 80), muted).draw(display).ok();
    Text::new(FLASH_URL, Point::new(54, 92), ok).draw(display).ok();
    Text::new("lower button = run again", Point::new(48, 116), body).draw(display).ok();
    display.flush().ok();

    // Ignore held-over presses, then wait for a fresh one.
    while a.is_low() {
        FreeRtos::delay_ms(10);
    }
    FreeRtos::delay_ms(150);
    loop {
        if a.is_low() {
            FreeRtos::delay_ms(30);
            while a.is_low() {
                FreeRtos::delay_ms(10);
            }
            return;
        }
        FreeRtos::delay_ms(15);
    }
}

fn format_score(score: u32) -> String {
    format!("{score:>5}")
}

/// Blit one 56x56 walk frame (MSB = leftmost column), scaled by `sc`.
fn draw_sprite(
    display: &mut St7789Display<'_>,
    frame: &[u64; 56],
    x: i32,
    y: i32,
    sc: i32,
    colour: Rgb565,
) {
    for (row, bits) in frame.iter().enumerate() {
        if *bits == 0 {
            continue;
        }
        for col in 0..56i32 {
            if (bits >> (55 - col)) & 1 == 1 {
                Rectangle::new(
                    Point::new(x + col * sc, y + row as i32 * sc),
                    Size::new(sc as u32, sc as u32),
                )
                .into_styled(PrimitiveStyle::with_fill(colour))
                .draw(display)
                .ok();
            }
        }
    }
}

/// Blit rows `start..end` of a frame with its bottom edge at `y` — the crouch.
fn draw_sprite_rows(
    display: &mut St7789Display<'_>,
    frame: &[u64; 56],
    x: i32,
    y: i32,
    start: usize,
    end: usize,
    colour: Rgb565,
) {
    for row in start..end {
        let bits = frame[row];
        if bits == 0 {
            continue;
        }
        for col in 0..56i32 {
            if (bits >> (55 - col)) & 1 == 1 {
                Rectangle::new(
                    Point::new(x + col, y + (row - start) as i32),
                    Size::new(1, 1),
                )
                .into_styled(PrimitiveStyle::with_fill(colour))
                .draw(display)
                .ok();
            }
        }
    }
}
