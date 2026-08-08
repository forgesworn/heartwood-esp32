// firmware/src/entropy_game.rs
//
// The entropy game: a minimal runner on the OLED. Obstacles scroll in from
// the right; the owner taps PRG (GPIO 0) to jump over them. Every accepted
// press records a microsecond-resolution timestamp, and the timestamps are
// digested into an entropy source that `entropy::stacked_entropy_16` mixes
// with the hardware RNG draw (see `heartwood_common::entropy` for the mixing
// contract and the conservative min-entropy assumptions).
//
// Why a game at all: the hardware RNG is trusted but not OWNER-verifiable.
// Button timing is the opposite — trivially observed by the owner ("I played
// it"), useless to a remote attacker, and worthless if the attacker can watch
// you play. Stacked, the two sources cover each other's failure modes.
//
// Design rules that keep the entropy honest:
//   - The STIMULUS randomness (obstacle gaps) comes from the hardware RNG,
//     never from the press stream being harvested — the user's own output
//     must not feed back into their input.
//   - Press timestamps are captured by busy-polling the GPIO between physics
//     steps (no FreeRtos sleep in the edge path), so the recorded time is the
//     true edge, not a 10 ms tick boundary.
//   - Success/failure of a jump is NOT harvested — near-binary outcomes carry
//     ~1 bit; the timing is where the entropy lives.
//   - The game is OPTIONAL: hold-to-skip (or a 30 s intro timeout) falls back
//     to hardware-only stacking, for headless or accessibility-limited
//     provisioning. Optional weak entropy beats mandatory absent entropy.

use embedded_graphics::mono_font::MonoTextStyleBuilder;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{PrimitiveStyle, Rectangle};
use embedded_graphics::text::Text;
use esp_idf_hal::gpio::{Input, PinDriver};

use crate::button::{self, ButtonResult};
use crate::layout::Layout;
use crate::oled::Display;
use crate::palette::{ACCENT, FG, MUTED};

/// Presses to collect before the game ends. At the conservative ~1-2 bits of
/// conditioned min-entropy per press (see `heartwood_common::entropy`), 64
/// presses give >= 64 bits of user entropy on top of the hardware draw.
const TARGET_PRESSES: usize = 64;

/// Hard cap on total game time, so a stalled player can't wedge provisioning.
const MAX_GAME_MS: i64 = 90_000;

/// Fixed physics timestep (≈30 fps).
const FRAME_US: i64 = 33_000;

/// Holding PRG this long during play aborts to the hardware-only path.
const ABORT_HOLD_MS: i64 = 2_000;

/// Minimum gap between accepted press edges (contact bounce guard).
const DEBOUNCE_US: i64 = 30_000;

/// How long the intro screen waits before defaulting to skip.
const INTRO_TIMEOUT_SECS: u64 = 30;

/// Microsecond timestamp from the monotonic esp_timer.
fn now_us() -> i64 {
    unsafe { esp_idf_svc::sys::esp_timer_get_time() }
}

/// Play the entropy game. Returns the timestamp digest to stack into key
/// entropy, or `None` when the owner skipped/aborted (hardware-only path).
pub fn run(display: &mut Display<'_>, button: &PinDriver<'_, Input>) -> Option<[u8; 32]> {
    if !intro(display, button) {
        log::info!("Entropy game skipped — hardware-only stacking");
        return None;
    }

    let l = layout_of(display);
    let mut timestamps = [0u64; TARGET_PRESSES];
    let mut count = 0usize;

    let start = now_us();
    let mut last_frame = start;
    let mut last_press_us = start - DEBOUNCE_US;
    let mut pressed_since = -1i64; // -1 = not held; else edge timestamp

    // World state, all in baseline 128x64 coordinates (scaled at draw time).
    let ground_y = 54i32;
    let player_x = 12i32;
    let mut player_y = ground_y;
    let mut vy = 0i32; // px/frame
    let mut obstacles: [(i32, bool); 4] = [(-40, false); 4]; // x, active
    let mut scroll = 0u32; // frames since start, drives spawn cadence
    let mut hit_flash_until = 0i64;

    loop {
        crate::wdt::feed();
        let now = now_us();

        // --- Input edge capture (busy-poll: timestamp the true edge) ---
        let low = button.is_low();
        if low && pressed_since < 0 && now - last_press_us >= DEBOUNCE_US {
            pressed_since = now;
            last_press_us = now;
            if count < TARGET_PRESSES {
                timestamps[count] = now as u64;
                count += 1;
            }
            // Jump if on the ground.
            if player_y >= ground_y {
                vy = -9;
            }
        }
        if !low && pressed_since >= 0 {
            pressed_since = -1;
        }
        // Abort on a deliberate hold (the button never came up).
        if pressed_since >= 0 && now - pressed_since >= ABORT_HOLD_MS * 1000 {
            while button.is_low() {
                esp_idf_hal::delay::FreeRtos::delay_ms(20);
            }
            log::info!("Entropy game aborted by hold — hardware-only stacking");
            timestamps.iter_mut().for_each(|b| *b = 0);
            return None;
        }

        // --- Fixed-timestep physics ---
        if now - last_frame >= FRAME_US {
            last_frame = now;
            scroll += 1;

            vy = (vy + 1).min(6); // gravity
            player_y = (player_y + vy).min(ground_y);

            // Spawn: a chance every 30 frames, driven by the HARDWARE RNG —
            // the stimulus must be independent of the harvested response stream.
            if scroll % 30 == 0 {
                let mut roll = [0u8; 1];
                crate::fill_random(&mut roll);
                if roll[0] % 3 == 0 {
                    if let Some(slot) = obstacles.iter_mut().find(|o| !o.1) {
                        *slot = (128, true);
                    }
                }
            }
            for o in obstacles.iter_mut() {
                if o.1 {
                    o.0 -= 2;
                    if o.0 < -12 {
                        o.1 = false;
                    }
                }
            }

            // Collision: flash only. Neither success nor failure is harvested.
            if player_y >= ground_y - 4
                && obstacles
                    .iter()
                    .any(|&(x, active)| active && (player_x - 8..player_x + 8).contains(&x))
            {
                hit_flash_until = now + 150_000;
            }

            render(display, &l, player_x, player_y, ground_y, &obstacles, count, now < hit_flash_until);
        }

        // --- End conditions ---
        if count >= TARGET_PRESSES {
            break;
        }
        if now - start >= MAX_GAME_MS * 1000 {
            log::info!("Entropy game timed out with {count}/{TARGET_PRESSES} presses");
            break;
        }
    }

    show_done(display, count);

    if count == 0 {
        timestamps.iter_mut().for_each(|b| *b = 0);
        return None;
    }
    let digest = heartwood_common::entropy::digest_timestamps(&timestamps[..count]);
    timestamps.iter_mut().for_each(|b| *b = 0);
    log::info!("Entropy game collected {count} presses");
    Some(digest)
}

/// Intro screen: tap to play, hold to skip. Timeout defaults to skip.
fn intro(display: &mut Display<'_>, button: &PinDriver<'_, Input>) -> bool {
    let l = layout_of(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();
    let muted = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(MUTED)
        .build();

    Text::new("ADD YOUR", Point::new(l.sx(28), l.sy(10)), header).draw(display).ok();
    Text::new("RANDOMNESS", Point::new(l.sx(24), l.sy(22)), header).draw(display).ok();
    Text::new("tap: jump the blocks", Point::new(l.sx(2), l.sy(40)), small).draw(display).ok();
    Text::new("hold: skip (chip RNG)", Point::new(l.sx(2), l.sy(50)), small).draw(display).ok();
    Text::new("timing becomes entropy", Point::new(l.sx(2), l.sy(62)), muted).draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }

    matches!(
        button::wait_for_press(button, std::time::Duration::from_secs(INTRO_TIMEOUT_SECS)),
        Some(ButtonResult::Deny) // a short tap — play
    )
}

/// Draw one frame. All coordinates are baseline-128x64, scaled for the panel.
fn render(
    display: &mut Display<'_>,
    l: &Layout,
    player_x: i32,
    player_y: i32,
    ground_y: i32,
    obstacles: &[(i32, bool); 4],
    count: usize,
    flash: bool,
) {
    display.clear_buffer();

    // Ground line.
    Rectangle::new(
        Point::new(0, l.sy(ground_y + 6)),
        Size::new(l.w as u32, l.s(1) as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(MUTED))
    .draw(display)
    .ok();

    // Player.
    Rectangle::new(
        Point::new(l.sx(player_x - 4), l.sy(player_y - 8)),
        Size::new(l.s(8) as u32, l.s(8) as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(if flash { ACCENT } else { FG }))
    .draw(display)
    .ok();

    // Obstacles.
    for &(x, active) in obstacles {
        if active {
            Rectangle::new(Point::new(l.sx(x - 3), l.sy(ground_y - 4)), Size::new(l.s(6) as u32, l.s(10) as u32))
                .into_styled(PrimitiveStyle::with_fill(ACCENT))
                .draw(display)
                .ok();
        }
    }

    // Progress.
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(MUTED)
        .build();
    let progress = format!("{count}/{TARGET_PRESSES}");
    Text::new(&progress, Point::new(l.sx(2), l.sy(8)), small).draw(display).ok();

    // The hit flash draws an attention bar across the top of the frame.
    if flash {
        Rectangle::new(Point::new(0, 0), Size::new(l.w as u32, l.s(2) as u32))
            .into_styled(PrimitiveStyle::with_fill(FG))
            .draw(display)
            .ok();
    }

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Brief completion screen before provisioning continues.
fn show_done(display: &mut Display<'_>, count: usize) {
    let l = layout_of(display);
    display.clear_buffer();
    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();
    Text::new("ENTROPY BANKED", Point::new(l.sx(6), l.sy(20)), header).draw(display).ok();
    let line = format!("{count} presses mixed with chip RNG");
    Text::new(&line, Point::new(l.sx(2), l.sy(44)), small).draw(display).ok();
    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
    esp_idf_hal::delay::FreeRtos::delay_ms(1200);
}

fn layout_of(display: &Display<'_>) -> Layout {
    let size = display.bounding_box().size;
    Layout::new(size.width as i32, size.height as i32)
}
