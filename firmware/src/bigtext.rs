// firmware/src/bigtext.rs
//
// Integer-scaled mono text.
//
// `Layout` steps the font tier up on the colour panels, but embedded-graphics'
// built-in ascii fonts stop at FONT_10X20. On the 128x64 OLED that fills a
// third of the height; on the 172x320 C6 the same glyphs occupy about a
// fifteenth of the screen, and the one word that matters most — a recovery word
// being read off or picked — renders as a thin band in the middle of a large
// display. Growing it means drawing the glyphs ourselves at an integer scale.
//
// Each glyph is read from the font's own atlas via `GetPixel`, so the shapes
// stay the font's, not an approximation, and a set pixel becomes a `scale`-by-
// `scale` block. Horizontal runs are coalesced into one rectangle per run,
// which keeps a 12-character word at scale 3 to a few hundred fills rather than
// several thousand — worth doing over SPI.
//
// No esp-idf dependency on purpose: `ui-preview` includes this file verbatim
// (`#[path]`) so the scaled screens can be rendered to PNG and checked without
// hardware, exactly as it does for `layout.rs`.

use embedded_graphics::{
    image::GetPixel,
    mono_font::MonoFont,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
};

/// Width in pixels of `text` drawn in `font` at `scale`, including the font's
/// inter-character spacing. Use it to centre or to decide whether a string
/// fits before drawing it.
pub fn scaled_text_width(text: &str, font: &MonoFont, scale: i32) -> i32 {
    let n = text.chars().count() as i32;
    if n == 0 {
        return 0;
    }
    let cw = font.character_size.width as i32;
    let sp = font.character_spacing as i32;
    (n * cw + (n - 1) * sp) * scale
}

/// Draw `text` in `font`, magnified `scale` times, with `origin` at the text's
/// alphabetic baseline — the same anchor `Text::new` uses, so a scaled call can
/// replace an unscaled one without moving the line.
///
/// `scale` below 1 is treated as 1. Characters the font does not carry render
/// as its replacement glyph, which is what `Text` does too.
pub fn draw_text_scaled<D>(
    target: &mut D,
    text: &str,
    origin: Point,
    font: &MonoFont,
    scale: i32,
    colour: D::Color,
) where
    D: DrawTarget,
{
    let scale = scale.max(1);
    let cw = font.character_size.width as i32;
    let ch = font.character_size.height as i32;
    let advance = (cw + font.character_spacing as i32) * scale;
    // `origin` is the baseline; the glyph box starts `baseline` rows above it.
    let top = origin.y - font.baseline as i32 * scale;
    let glyphs_per_row = (font.image.size().width as i32 / cw).max(1);

    let mut x = origin.x;
    for c in text.chars() {
        let glyph = font.glyph_mapping.index(c) as i32;
        let ax = (glyph % glyphs_per_row) * cw;
        let ay = (glyph / glyphs_per_row) * ch;

        for row in 0..ch {
            // Coalesce each horizontal run of set pixels into one fill. A blank
            // row costs nothing, which most rows of most glyphs are.
            let mut run_start: Option<i32> = None;
            for col in 0..=cw {
                let on = col < cw
                    && font.image.pixel(Point::new(ax + col, ay + row))
                        == Some(embedded_graphics::pixelcolor::BinaryColor::On);
                match (on, run_start) {
                    (true, None) => run_start = Some(col),
                    (false, Some(start)) => {
                        Rectangle::new(
                            Point::new(x + start * scale, top + row * scale),
                            Size::new(((col - start) * scale) as u32, scale as u32),
                        )
                        .into_styled(PrimitiveStyle::with_fill(colour))
                        .draw(target)
                        .ok();
                        run_start = None;
                    }
                    _ => {}
                }
            }
        }
        x += advance;
    }
}
