// firmware/src/oled.rs
//
// OLED display helpers for the Heltec V3/V4 built-in SSD1306 (128x64).
// Both boards wire the display to I2C on GPIO17 (SDA) / GPIO18 (SCL) with
// reset on GPIO21 and Vext power on GPIO36 (active low), so this module is
// hardware-identical between boards.

use embedded_graphics::mono_font::MonoTextStyleBuilder;
use embedded_graphics::pixelcolor::raw::RawU16;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{Circle, PrimitiveStyle, Rectangle};
use embedded_graphics::text::{Baseline, Text};

// The mono SSD1306 adapter thresholds colours to on/off; only that (mono-only)
// path names BinaryColor, Pixel and the black BG constant directly.
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
use embedded_graphics::pixelcolor::BinaryColor;
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
use embedded_graphics::Pixel;
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
use crate::palette::BG;

use crate::layout::Layout;
use crate::palette::{ACCENT, DANGER, FG, GHOST, MUTED, NOSTR, OK, WARN};
use esp_idf_hal::delay::FreeRtos;

// SSD1306 / I2C backend imports — used only by the mono-OLED `Display` alias
// and `init` below. Colour-TFT boards select the ST7789 backend and never pull
// these in, so they are gated to the mono boards to keep colour builds clean.
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
use esp_idf_hal::gpio::{AnyOutputPin, PinDriver};
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
use esp_idf_hal::i2c::I2cDriver;
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
use ssd1306::mode::BufferedGraphicsMode;
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
use ssd1306::prelude::*;
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
use ssd1306::rotation::DisplayRotation;
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
use ssd1306::size::DisplaySize128x64;
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
use ssd1306::I2CDisplayInterface;
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
use ssd1306::Ssd1306;


/// The active display backend, selected by board.
///
/// Mono SSD1306 (I2C) on the Heltec OLED boards; the colour ST7789 / JD9853
/// wrappers (SPI) on the TFT boards. Both expose the *same* surface to the
/// screen functions below — `clear_buffer` / `flush` / `set_display_on` plus an
/// embedded-graphics `DrawTarget<Color = Rgb565>` — so no screen code changes
/// between backends. The colour panels store the Rgb565 directly; the mono
/// wrapper thresholds every non-black colour to a lit pixel (see below).
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
type Ssd1306Panel<'a> = Ssd1306<
    ssd1306::prelude::I2CInterface<I2cDriver<'a>>,
    DisplaySize128x64,
    BufferedGraphicsMode<DisplaySize128x64>,
>;

/// Mono SSD1306 panel presented through the shared `DrawTarget<Color = Rgb565>`
/// surface. The colour-authored screens draw the same on every board; here each
/// non-black colour is thresholded to a lit pixel, so the Heltec OLEDs render
/// the familiar white-on-black with no per-screen changes.
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
pub struct Display<'a> {
    inner: Ssd1306Panel<'a>,
}

/// Opaque display error for the mono backend (mirrors `st7789::St7789Error`);
/// screen code only ever `.ok()`s or `{:?}`-logs it.
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
#[derive(Debug)]
pub struct MonoError;

#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
impl<'a> Display<'a> {
    /// Clear the back buffer to black. Mirrors `Ssd1306::clear_buffer`.
    pub fn clear_buffer(&mut self) {
        self.inner.clear_buffer();
    }

    /// Blit the back buffer to the panel. Mirrors `Ssd1306::flush`.
    pub fn flush(&mut self) -> Result<(), MonoError> {
        self.inner.flush().map_err(|_| MonoError)
    }

    /// Turn the panel on/off. Mirrors `Ssd1306::set_display_on`.
    pub fn set_display_on(&mut self, on: bool) -> Result<(), MonoError> {
        self.inner.set_display_on(on).map_err(|_| MonoError)
    }
}

#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
impl OriginDimensions for Display<'_> {
    fn size(&self) -> Size {
        self.inner.size()
    }
}

#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
impl DrawTarget for Display<'_> {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        // Threshold to the mono panel: black stays off, any other colour lights.
        let _ = self.inner.draw_iter(pixels.into_iter().map(|Pixel(p, c)| {
            Pixel(p, if c == BG { BinaryColor::Off } else { BinaryColor::On })
        }));
        Ok(())
    }
}

/// T-Display (classic ESP32 + ST7789 240×135) uses the ST7789 wrapper.
#[cfg(feature = "tdisplay")]
pub type Display<'a> = crate::st7789::St7789Display<'a>;

/// Waveshare ESP32-C6 (320×172 landscape JD9853 IPS panel) uses the JD9853 wrapper.
#[cfg(feature = "c6")]
pub type Display<'a> = crate::jd9853::Jd9853Display<'a>;

/// Initialise the OLED: reset pin toggle, I2C setup, display init.
/// The reset PinDriver is deliberately leaked — GPIO 21 must stay HIGH
/// or the SSD1306 is held in reset and the display goes blank.
///
/// SSD1306/I2C-specific; colour-TFT boards construct their display via
/// `st7789::St7789Display::new` from `board::bringup` instead.
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
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
    Display { inner: display }
}

/// Build the [`Layout`] for the active display from its reported size, so each
/// screen positions itself responsively. On the 128x64 mono OLED this is the
/// identity (the Heltec rendering is unchanged); on a colour TFT it fills the
/// panel and steps fonts up.
fn layout(display: &Display<'_>) -> Layout {
    let size = display.bounding_box().size;
    Layout::new(size.width as i32, size.height as i32)
}

/// Display an npub on the OLED with header and structured layout.
///
/// Layout:
///   Header:   "IDENTITY" (header font, tracked)
///   Rule:     1px horizontal line
///   Body:     npub split across lines (small font for density)
pub fn show_npub(
    display: &mut Display<'_>,
    name: Option<&str>,
    npub: &str,
    avatar: Option<(u8, u8, &[u8])>,
) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    // Bigger, more legible npub on the colour panels; the mono OLED keeps the
    // small font so all 63 characters still fit.
    let npub_font = if l.is_large() { l.font_body() } else { l.font_small() };
    let body = MonoTextStyleBuilder::new()
        .font(npub_font)
        .text_color(FG)
        .build();

    Text::new("MASTER", Point::new(l.sx(2), l.sy(10)), header).draw(display).ok();

    // Rule (brand accent)
    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display).ok();

    let gw = Layout::glyph_w(npub_font);
    if l.is_large() {
        // Colour panels: a short, centred npub (head...tail). The full 63-char
        // key in the big font runs edge to edge and clips on any panel offset;
        // the shortened form is what clients show. The full key belongs on the
        // QR page.
        let short = if npub.len() > 24 {
            format!("{}...{}", &npub[..10], &npub[npub.len() - 6..])
        } else {
            npub.to_string()
        };
        match name {
            // Kind 0 known: a contact card — avatar disc on the left, name
            // right-aligned, no npub (it belongs on the QR page).
            Some(n) => {
                let area_top = l.sy(14);
                let area_h = l.h - area_top;
                let cy = area_top + area_h / 2;
                // Avatar/disc radius: half the provisioned avatar if present, else
                // a default disc sized to the panel.
                let r = match avatar {
                    Some((w, _, _)) => (w as i32) / 2,
                    None => (area_h * 36 / 100).min(40),
                };
                let cx = l.sx(5) + r;
                match avatar {
                    // Blit the pre-resized Rgb565 avatar (Sapwood circular-cropped
                    // it on black, so it reads as a disc on the black background).
                    Some((w, h, bytes)) if bytes.len() == (w as usize) * (h as usize) * 2 => {
                        let (aw, ah) = (w as i32, h as i32);
                        let area = Rectangle::new(
                            Point::new(cx - aw / 2, cy - ah / 2),
                            Size::new(aw as u32, ah as u32),
                        );
                        let px = bytes
                            .chunks_exact(2)
                            .map(|c| Rgb565::from(RawU16::new(u16::from_be_bytes([c[0], c[1]]))));
                        display.fill_contiguous(&area, px).ok();
                    }
                    // No (valid) avatar yet: placeholder disc with the initial.
                    _ => {
                        Circle::new(Point::new(cx - r, cy - r), (r * 2) as u32)
                            .into_styled(PrimitiveStyle::with_fill(NOSTR))
                            .draw(display)
                            .ok();
                        let init =
                            n.chars().next().map(|c| c.to_ascii_uppercase()).unwrap_or('?').to_string();
                        let lf = l.font_large();
                        let init_style = MonoTextStyleBuilder::new().font(lf).text_color(FG).build();
                        let iw = Layout::glyph_w(lf);
                        let ih = lf.character_size.height as i32;
                        Text::new(&init, Point::new(cx - iw / 2, cy + ih / 3), init_style)
                            .draw(display)
                            .ok();
                    }
                }
                // Right block: name above the short npub, both right-aligned, the
                // pair vertically centred beside the avatar. Name shrinks if it
                // won't fit; generous right margin for this panel's short edge.
                let right = l.w - l.sx(14);
                let avail = right - (cx + r) - l.sx(4);
                let nf = if (n.len() as i32 * Layout::glyph_w(l.font_body())) <= avail {
                    l.font_body()
                } else {
                    l.font_small()
                };
                let sf = l.font_small();
                let nh = nf.character_size.height as i32;
                let sh = sf.character_size.height as i32;
                let gap = l.s(3);
                let block_top = cy - (nh + gap + sh) / 2;
                let name_style = MonoTextStyleBuilder::new().font(nf).text_color(FG).build();
                let nw = n.len() as i32 * Layout::glyph_w(nf);
                Text::new(n, Point::new(right - nw, block_top + nh), name_style).draw(display).ok();
                let sub_style = MonoTextStyleBuilder::new().font(sf).text_color(MUTED).build();
                let sw = short.len() as i32 * Layout::glyph_w(sf);
                Text::new(&short, Point::new(right - sw, block_top + nh + gap + sh), sub_style)
                    .draw(display)
                    .ok();
            }
            // No profile yet: just the short npub, centred.
            None => {
                let x = l.center_x(short.len() as i32 * gw);
                Text::new(&short, Point::new(x, l.sy(40)), body).draw(display).ok();
            }
        }
    } else {
        // Mono OLED: the small font fits the full npub wrapped across lines.
        // Reserve the draw margin (sx(2)) on both sides so the last glyph of each
        // line never clips off the panel edge.
        let margin = l.sx(2);
        let cpl = (((l.w - 2 * margin) / gw).max(1)) as usize;
        let glyph_h = npub_font.character_size.height as i32;
        let line_h = glyph_h + l.s(2);
        let n_lines = ((npub.len() + cpl - 1) / cpl) as i32;
        let top = l.sy(16);
        let block_h = n_lines * line_h;
        let mut y = top + ((l.h - top - block_h) / 2).max(0) + glyph_h;
        let mut pos = 0;
        while pos < npub.len() {
            let end = core::cmp::min(pos + cpl, npub.len());
            Text::new(&npub[pos..end], Point::new(l.sx(2), y), body).draw(display).ok();
            y += line_h;
            pos = end;
        }
    }

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Show ONE recovery-phrase word at a time, large and numbered, for the owner
/// to step through with the PRG button.
///
/// The recovery phrase is generated on-device (hardware RNG) and never sent to
/// the host — this screen is the only place it ever appears. Twelve tiny words
/// crammed onto the 128x64 panel proved illegible, so the provision handler
/// walks through them one big word per screen (FONT_10X20), each tagged
/// "WORD n OF 12", advancing on a button tap. It holds the walkthrough — and
/// blocks the caller from redrawing or rebooting — until the owner confirms, so
/// nothing can vanish before it is copied down.
pub fn show_recovery_word(display: &mut Display<'_>, index: usize, total: usize, word: &str) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let big = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(FG)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    let head = format!("WORD {} OF {}", index, total);
    Text::new(&head, Point::new(l.sx(2), l.sy(10)), header).draw(display).ok();
    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display)
        .ok();

    // The word, large and centred (FONT_10X20 is 10px per glyph).
    let glyphs = word.chars().count().min(12) as i32;
    let x = l.center_x(glyphs * Layout::glyph_w(l.font_large()));
    Text::new(word, Point::new(x, l.sy(44)), big).draw(display).ok();

    let footer = if index >= total { "tap PRG to finish" } else { "tap PRG for next" };
    Text::new(footer, Point::new(l.sx(2), l.sy(62)), small).draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// "Working" screen shown the moment a new identity starts generating. Drawing
/// the random entropy, the PBKDF2 seed stretch, the key derivation and the NVS
/// write together take a few seconds, during which the OLED would otherwise sit
/// on the previous screen with no sign anything is happening.
pub fn show_generating(display: &mut Display<'_>) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(FG)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    Text::new("NEW IDENTITY", Point::new(l.sx(4), l.sy(10)), header).draw(display).ok();
    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display)
        .ok();

    Text::new("Working", Point::new(l.sx(29), l.sy(40)), large).draw(display).ok();
    Text::new("creating your keys...", Point::new(l.sx(2), l.sy(58)), small).draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Final confirm screen after stepping through every recovery word: a long PRG
/// hold saves, a short tap restarts the walkthrough so the owner can re-check.
pub fn show_recovery_done(display: &mut Display<'_>) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let body = MonoTextStyleBuilder::new()
        .font(l.font_body())
        .text_color(FG)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    Text::new("ALL 12 SHOWN", Point::new(l.sx(2), l.sy(12)), header).draw(display).ok();
    Rectangle::new(Point::new(l.sx(0), l.sy(16)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(FG))
        .draw(display)
        .ok();

    Text::new("Hold PRG = save", Point::new(l.sx(4), l.sy(38)), body).draw(display).ok();
    Text::new("tap = show them again", Point::new(l.sx(4), l.sy(56)), small).draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

// ---------------------------------------------------------------------------
// Recovery-phrase RESTORE (on-device one-button word entry)
// ---------------------------------------------------------------------------

/// What the word-entry picker is currently highlighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Highlight {
    /// A letter being added (the big text is the prefix-so-far + this letter).
    Letter,
    /// A complete word ready to accept (underlined).
    Word,
    /// The on-screen delete control.
    Delete,
}

/// One-time intro shown when on-device restore begins, teaching the two-gesture
/// vocabulary before the terse picker takes over. The 12-word phrase is entered
/// here, on the device — never in the browser.
pub fn show_restore_intro(display: &mut Display<'_>, two_button: bool) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    Text::new("ENTER YOUR PHRASE", Point::new(l.sx(2), l.sy(10)), header).draw(display).ok();
    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display)
        .ok();

    let (a, b, c) = if two_button {
        ("A / B  = move", "hold B = pick", "hold A = delete")
    } else {
        ("1 tap  = next choice", "2 taps = pick it", "hold   = go back")
    };
    Text::new(a, Point::new(l.sx(4), l.sy(28)), small).draw(display).ok();
    Text::new(b, Point::new(l.sx(4), l.sy(42)), small).draw(display).ok();
    Text::new(c, Point::new(l.sx(4), l.sy(56)), small).draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// One step of the one-button picker: the currently highlighted ring item shown
/// large, a contextual subtitle, and the tap / hold legend. The caller composes
/// `big_text` (prefix+letter, or the whole word once it resolves) and picks the
/// [`Highlight`] kind; `subtitle` carries context (match count, "use this word").
/// `tap_accepts` is set when the word is the sole choice, so the legend reads
/// "tap=pick" (a single tap accepts) rather than "tap=next".
pub fn show_word_entry(
    display: &mut Display<'_>,
    word_index: usize,
    total: usize,
    big_text: &str,
    hl: Highlight,
    subtitle: &str,
    tap_accepts: bool,
    two_button: bool,
) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let big = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(FG)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    let head = format!("WORD {}/{}", word_index, total);
    Text::new(&head, Point::new(l.sx(2), l.sy(10)), header).draw(display).ok();
    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display)
        .ok();

    // The highlighted ring item, large and centred.
    let glyphs = big_text.chars().count().min(12) as i32;
    let x = l.center_x(glyphs * Layout::glyph_w(l.font_large()));
    Text::new(big_text, Point::new(x, l.sy(40)), big).draw(display).ok();
    if hl == Highlight::Word {
        // Underline: this is a complete word, not a letter.
        Rectangle::new(Point::new(x, l.sy(43)), Size::new((glyphs * Layout::glyph_w(l.font_large())) as u32, l.s(1) as u32))
            .into_styled(PrimitiveStyle::with_fill(FG))
            .draw(display)
            .ok();
    }

    Text::new(subtitle, Point::new(l.sx(2), l.sy(54)), small).draw(display).ok();
    // Two-button boards move with A and pick with B — no timing, so the legend
    // is fixed. One-button boards cycle on a tap (or accept the sole word) and
    // go back on a hold.
    let legend = if two_button {
        "A/B move  holdB pick  holdA back"
    } else if tap_accepts {
        "tap=pick   hold=back"
    } else {
        "tap=next   hold=back"
    };
    Text::new(legend, Point::new(l.sx(2), l.sy(63)), small).draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Review screen for one entered word: one-button boards tap to page and
/// double-tap to edit; two-button boards move with A/B and hold B to edit.
/// `invalid` flags that the 12 words failed the BIP-39 checksum, so a wrong
/// word is somewhere in the list and needs finding.
pub fn show_review_word(
    display: &mut Display<'_>,
    index: usize,
    total: usize,
    word: &str,
    invalid: bool,
    two_button: bool,
) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let big = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(FG)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    let head = format!("REVIEW {}/{}", index, total);
    Text::new(&head, Point::new(l.sx(2), l.sy(10)), header).draw(display).ok();
    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display)
        .ok();

    let glyphs = word.chars().count().min(12) as i32;
    let x = l.center_x(glyphs * Layout::glyph_w(l.font_large()));
    Text::new(word, Point::new(x, l.sy(40)), big).draw(display).ok();

    if invalid {
        Text::new("! phrase invalid - fix a word", Point::new(l.sx(2), l.sy(54)), small).draw(display).ok();
    }
    let legend = if two_button { "A/B move  holdB edit  holdA back" } else { "tap=next  2tap=edit" };
    Text::new(legend, Point::new(l.sx(2), l.sy(63)), small).draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Review screen for an action item (SAVE / CANCEL): a big label, a hint, and
/// the movement legend (tap / double-tap on one-button boards, A/B move plus
/// hold-A-back on two-button boards).
pub fn show_review_action(display: &mut Display<'_>, label: &str, hint: &str, two_button: bool) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let big = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(FG)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    Text::new("REVIEW", Point::new(l.sx(2), l.sy(10)), header).draw(display).ok();
    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display)
        .ok();

    let glyphs = label.chars().count().min(12) as i32;
    let x = l.center_x(glyphs * Layout::glyph_w(l.font_large()));
    Text::new(label, Point::new(x, l.sy(40)), big).draw(display).ok();

    Text::new(hint, Point::new(l.sx(2), l.sy(54)), small).draw(display).ok();
    let legend = if two_button { "A/B = move   holdA = back" } else { "tap=next  2tap=pick" };
    Text::new(legend, Point::new(l.sx(2), l.sy(63)), small).draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Shown after the words pass the checksum: the resulting npub for the owner to
/// verify it is the account they expected, gated behind a save hold (a tap goes
/// back to review). Verifying the npub catches a wrong-but-valid phrase.
pub fn show_restore_confirm(display: &mut Display<'_>, npub: &str, two_button: bool) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    Text::new("THIS ACCOUNT?", Point::new(l.sx(2), l.sy(10)), header).draw(display).ok();
    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display)
        .ok();

    // npub in small font: chars per line for this panel.
    let chars_small = l.chars_per_line(l.font_small());
    let mut y = 26i32;
    let mut pos = 0;
    while pos < npub.len() && l.sy(y) < l.sy(50) {
        let end = core::cmp::min(pos + chars_small, npub.len());
        Text::new(&npub[pos..end], Point::new(l.sx(2), l.sy(y)), small).draw(display).ok();
        y += 9;
        pos = end;
    }

    let hint = if two_button { "hold B = save   hold A = back" } else { "hold = save   tap = back" };
    Text::new(hint, Point::new(l.sx(2), l.sy(62)), small).draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Display the normal ready/idle signer screen.
///
/// Layout:
///   Header:  "SIGNER READY" (FONT_6X10)
///   Rule:    1px line
///   Centre:  "Sapwood" (FONT_10X20)
///   Help:    management/signing hints (FONT_5X8)
pub fn show_awaiting(display: &mut Display<'_>) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(FG)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    Text::new("SIGNER READY", Point::new(l.sx(4), l.sy(10)), header).draw(display).ok();

    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display).ok();

    let title = "Sapwood";
    Text::new(title, Point::new(l.center_x(title.len() as i32 * Layout::glyph_w(l.font_large())), l.sy(34)), large)
        .draw(display).ok();
    let manage = "USB/WiFi setup";
    Text::new(manage, Point::new(l.center_x(manage.len() as i32 * Layout::glyph_w(l.font_small())), l.sy(48)), small)
        .draw(display).ok();
    let apps = "apps: bunker";
    Text::new(apps, Point::new(l.center_x(apps.len() as i32 * Layout::glyph_w(l.font_small())), l.sy(58)), small)
        .draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Friendly "no identity yet" screen shown while a fresh device waits for its
/// first master to be provisioned over USB. Deliberately NOT the red error
/// screen: a new device with no key is a normal starting state, not a fault. A
/// brand-green header and centred call to action, so it reads as "set me up".
pub fn show_provision_wait(display: &mut Display<'_>) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new().font(l.font_header()).text_color(ACCENT).build();
    let large = MonoTextStyleBuilder::new().font(l.font_large()).text_color(FG).build();
    let small = MonoTextStyleBuilder::new().font(l.font_small()).text_color(MUTED).build();

    let hdr = "HEARTWOOD";
    Text::new(hdr, Point::new(l.center_x(hdr.len() as i32 * Layout::glyph_w(l.font_header())), l.sy(10)), header)
        .draw(display).ok();
    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT)).draw(display).ok();

    let title = "Set me up";
    Text::new(title, Point::new(l.center_x(title.len() as i32 * Layout::glyph_w(l.font_large())), l.sy(38)), large)
        .draw(display).ok();
    let hint = "Connect to Sapwood";
    Text::new(hint, Point::new(l.center_x(hint.len() as i32 * Layout::glyph_w(l.font_small())), l.sy(52)), small)
        .draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Success screen shown once the first master is provisioned, just before the
/// device reboots into signer mode. Green framing (a good outcome) with each
/// line centred on its own width. Replaces the generic result screen here,
/// whose full-width white rules read as a display glitch and whose centring is
/// wrong for a two-line message. Lingers, then the caller reboots.
pub fn show_provisioned(display: &mut Display<'_>) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new().font(l.font_header()).text_color(ACCENT).build();
    let large = MonoTextStyleBuilder::new().font(l.font_large()).text_color(OK).build();
    let small = MonoTextStyleBuilder::new().font(l.font_small()).text_color(MUTED).build();

    let hdr = "HEARTWOOD";
    Text::new(hdr, Point::new(l.center_x(hdr.len() as i32 * Layout::glyph_w(l.font_header())), l.sy(10)), header)
        .draw(display).ok();
    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT)).draw(display).ok();

    let title = "Provisioned";
    Text::new(title, Point::new(l.center_x(title.len() as i32 * Layout::glyph_w(l.font_large())), l.sy(38)), large)
        .draw(display).ok();
    let hint = "Starting wifi...";
    Text::new(hint, Point::new(l.center_x(hint.len() as i32 * Layout::glyph_w(l.font_small())), l.sy(52)), small)
        .draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }

    FreeRtos::delay_ms(2000);
}

/// Display an error message on the OLED.
pub fn show_error(display: &mut Display<'_>, msg: &str) {
    let l = layout(display);
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(l.font_body())
        .text_color(DANGER)
        .build();

    Text::new(msg, Point::new(l.sx(0), l.sy(30)), text_style)
        .draw(display)
        .ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

fn kind_line(kind: u64) -> String {
    match heartwood_common::kinds::kind_label(kind) {
        Some(name) => format!("{name} ({kind})"),
        None => format!("Kind {kind}"),
    }
}

/// Display a signing request with requester, kind, content preview, and countdown.
///
/// Layout:
///   Header:  "SIGN FOR {requester}?" (FONT_6X10, tracked)
///   Rule:    1px line
///   Kind:    "Kind {n}" (FONT_7X14)
///   Content: preview (FONT_5X8)
///   Bar:     graphical countdown + seconds
pub fn show_sign_request(
    display: &mut Display<'_>,
    requester: &str,
    kind: u64,
    content_preview: &str,
    seconds_remaining: u32,
) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let body = MonoTextStyleBuilder::new()
        .font(l.font_body())
        .text_color(FG)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    // Header
    let label = if requester.trim().is_empty() { "app" } else { requester.trim() };
    let heading = format!("SIGN FOR {}?", &label[..label.len().min(11)]);
    Text::new(&heading, Point::new(l.sx(2), l.sy(10)), header).draw(display).ok();

    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display).ok();

    // Kind — a friendly name when we know it ("App Data"), else "Kind {n}", so
    // the person holding the button can tell what the app is asking to sign.
    let kind_str = kind_line(kind);
    let kind_str = &kind_str[..kind_str.len().min(l.chars_per_line(l.font_body()))];
    Text::new(kind_str, Point::new(l.sx(2), l.sy(25)), body).draw(display).ok();

    // Content preview (small font for more text)
    let max_preview = l.chars_per_line(l.font_small());
    let content = if content_preview.len() > max_preview {
        format!("{}...", &content_preview[..max_preview - 3])
    } else {
        content_preview.to_string()
    };
    Text::new(&content, Point::new(l.sx(2), l.sy(35)), small).draw(display).ok();

    // How to approve: a 2-second HOLD signs, while a tap denies.
    let hint = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(ACCENT)
        .build();
    let hold = "Hold=sign tap=no";
    let hold = &hold[..hold.len().min(l.chars_per_line(l.font_small()))];
    Text::new(hold, Point::new(l.sx(2), l.sy(45)), hint).draw(display).ok();

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
    let l = layout(display);
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    let bar_x = l.sx(2);
    let bar_y = l.sy(52);
    let bar_w = l.s(100) as u32;
    let bar_h = l.s(8) as u32;

    // Track (muted outline)
    Rectangle::new(Point::new(bar_x, bar_y), Size::new(bar_w, bar_h))
        .into_styled(PrimitiveStyle::with_stroke(MUTED, l.s(1) as u32))
        .draw(display).ok();

    // Fill, coloured by urgency: plenty of time green, running low amber, almost
    // out red — so the owner can read the pressure at a glance, not just the digits.
    let pct_left = if total > 0 { remaining * 100 / total } else { 0 };
    let urgency = if pct_left > 50 {
        OK
    } else if pct_left > 20 {
        WARN
    } else {
        DANGER
    };
    let fill_w = if total > 0 {
        (remaining * (bar_w - l.s(4) as u32)) / total
    } else {
        0
    };
    if fill_w > 0 {
        Rectangle::new(Point::new(bar_x + l.s(2), bar_y + l.s(2)), Size::new(fill_w, bar_h - l.s(4) as u32))
            .into_styled(PrimitiveStyle::with_fill(urgency))
            .draw(display).ok();
    }

    // Seconds
    let secs = format!("{}s", remaining);
    Text::new(&secs, Point::new(bar_x + bar_w as i32 + l.s(4), bar_y + l.s(7)), small)
        .draw(display).ok();
}

/// Display a result message with decorative framing, then pause for 2 seconds.
///
/// Layout:
///   Top rule + bottom rule framing the message
///   Message centred in FONT_7X14
pub fn show_result(display: &mut Display<'_>, message: &str) {
    let l = layout(display);
    display.clear_buffer();

    let body = MonoTextStyleBuilder::new()
        .font(l.font_body())
        .text_color(FG)
        .build();

    // Top rule
    Rectangle::new(Point::new(l.sx(0), l.sy(18)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(FG))
        .draw(display).ok();

    // Centred message
    let msg_w = message.len() as i32 * Layout::glyph_w(l.font_body());
    let x = l.center_x(msg_w);
    Text::new(message, Point::new(x, l.sy(38)), body).draw(display).ok();

    // Bottom rule
    Rectangle::new(Point::new(l.sx(0), l.sy(44)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(FG))
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
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(FG)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    Text::new("HEARTWOOD SIGNER", Point::new(l.sx(4), l.sy(10)), header).draw(display).ok();

    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display).ok();

    // Large master count
    let count_str = format!("{}", master_count);
    Text::new(&count_str, Point::new(l.sx(2), l.sy(38)), large).draw(display).ok();
    Text::new("masters loaded", Point::new(l.sx(22), l.sy(36)), small).draw(display).ok();

    // Bottom status
    Rectangle::new(Point::new(l.sx(0), l.sy(48)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(FG))
        .draw(display).ok();

    Text::new("Sapwood USB ready", Point::new(l.sx(2), l.sy(60)), small).draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Display bridge connected status with structured layout.
///
/// Layout:
///   Header:  "SAPWOOD ONLINE" (FONT_6X10)
///   Rule:    1px line
///   Stats:   master count (large) + client count
pub fn show_bridge_connected(
    display: &mut Display<'_>,
    master_count: u8,
    client_count: usize,
) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(FG)
        .build();
    let body = MonoTextStyleBuilder::new()
        .font(l.font_body())
        .text_color(FG)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    Text::new("SAPWOOD ONLINE", Point::new(l.sx(2), l.sy(10)), header).draw(display).ok();

    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display).ok();

    // Master count large on left
    let m_str = format!("{}", master_count);
    Text::new(&m_str, Point::new(l.sx(2), l.sy(38)), large).draw(display).ok();
    Text::new("masters", Point::new(l.sx(22), l.sy(36)), small).draw(display).ok();

    // Client count on right side
    let c_str = format!("{}", client_count);
    Text::new(&c_str, Point::new(l.sx(72), l.sy(38)), body).draw(display).ok();
    Text::new("apps", Point::new(l.sx(88), l.sy(36)), small).draw(display).ok();

    // Status indicator: solid bar at bottom
    Rectangle::new(Point::new(l.sx(0), l.sy(58)), Size::new(l.w as u32, l.s(6) as u32))
        .into_styled(PrimitiveStyle::with_fill(FG))
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
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let body = MonoTextStyleBuilder::new()
        .font(l.font_body())
        .text_color(FG)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    // Header: SIGN AS {label}? — frame it as the question it is, like the
    // per-app screen, so it doesn't read as a bare label.
    let label = &master_label[..master_label.len().min(12)];
    let heading = format!("SIGN AS {}?", label);
    Text::new(&heading, Point::new(l.sx(2), l.sy(10)), header).draw(display).ok();

    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display).ok();

    // Method + kind (friendly kind name when known)
    let method_str = match kind {
        Some(k) => match heartwood_common::kinds::kind_label(k) {
            Some(name) => format!("{method} · {name}"),
            None => format!("{} k:{}", method, k),
        },
        None => method.to_string(),
    };
    let method_str = &method_str[..method_str.len().min(l.chars_per_line(l.font_body()))];
    Text::new(method_str, Point::new(l.sx(2), l.sy(25)), body).draw(display).ok();

    // Content preview (small font)
    let max_preview = l.chars_per_line(l.font_small());
    let preview = if content_preview.len() > max_preview {
        format!("{}...", &content_preview[..max_preview - 3])
    } else {
        content_preview.to_string()
    };
    Text::new(&preview, Point::new(l.sx(2), l.sy(35)), small).draw(display).ok();

    // How to approve: a 2-second HOLD signs, while a tap denies.
    let hint = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(ACCENT)
        .build();
    let hold = "Hold=sign tap=no";
    let hold = &hold[..hold.len().min(l.chars_per_line(l.font_small()))];
    Text::new(hold, Point::new(l.sx(2), l.sy(45)), hint).draw(display).ok();

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
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let body = MonoTextStyleBuilder::new()
        .font(l.font_body())
        .text_color(FG)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    Text::new("AUTO-APPROVED", Point::new(l.sx(4), l.sy(10)), header).draw(display).ok();

    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display).ok();

    let label = &master_label[..master_label.len().min(l.chars_per_line(l.font_body()))];
    Text::new(label, Point::new(l.sx(2), l.sy(32)), body).draw(display).ok();

    let method_str = &method[..method.len().min(l.chars_per_line(l.font_small()))];
    Text::new(method_str, Point::new(l.sx(2), l.sy(46)), small).draw(display).ok();

    // Confirmation bar
    Rectangle::new(Point::new(l.sx(0), l.sy(56)), Size::new(l.w as u32, l.s(4) as u32))
        .into_styled(PrimitiveStyle::with_fill(FG))
        .draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }
}

/// Display an automatic sign_event with enough context to audit what happened.
pub fn show_auto_signed(
    display: &mut Display<'_>,
    requester_label: &str,
    kind: u64,
) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let body = MonoTextStyleBuilder::new()
        .font(l.font_body())
        .text_color(FG)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    Text::new("AUTO-SIGNED", Point::new(l.sx(4), l.sy(10)), header).draw(display).ok();

    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display).ok();

    let requester = requester_label.trim();
    let requester = if requester.is_empty() { "app" } else { requester };
    let requester = &requester[..requester.len().min(l.chars_per_line(l.font_body()))];
    Text::new(requester, Point::new(l.sx(2), l.sy(25)), body).draw(display).ok();

    let kind_str = kind_line(kind);
    let kind_str = &kind_str[..kind_str.len().min(l.chars_per_line(l.font_body()))];
    Text::new(kind_str, Point::new(l.sx(2), l.sy(38)), body).draw(display).ok();

    let kind_number = format!("Nostr kind {kind}");
    let kind_number = &kind_number[..kind_number.len().min(l.chars_per_line(l.font_small()))];
    Text::new(kind_number, Point::new(l.sx(2), l.sy(50)), small).draw(display).ok();

    Rectangle::new(Point::new(l.sx(0), l.sy(56)), Size::new(l.w as u32, l.s(4) as u32))
        .into_styled(PrimitiveStyle::with_fill(FG))
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
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(OK)
        .build();

    Text::new("CONFIRMING", Point::new(l.sx(14), l.sy(10)), header).draw(display).ok();

    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display).ok();

    // Large percentage
    let pct_str = format!("{}%", hold_pct.min(100));
    let pct_x = l.center_x(pct_str.len() as i32 * Layout::glyph_w(l.font_large()));
    Text::new(&pct_str, Point::new(pct_x, l.sy(38)), large).draw(display).ok();

    // Progress bar
    let bar_y = l.sy(48);
    let bar_w = l.s(124) as u32;
    let bar_x = l.sx(2);

    Rectangle::new(Point::new(bar_x, bar_y), Size::new(bar_w, l.s(8) as u32))
        .into_styled(PrimitiveStyle::with_stroke(MUTED, l.s(1) as u32))
        .draw(display).ok();

    let fill_w = (hold_pct.min(100) * (bar_w - l.s(2) as u32)) / 100;
    if fill_w > 0 {
        Rectangle::new(Point::new(bar_x + l.s(1), bar_y + l.s(1)), Size::new(fill_w, l.s(6) as u32))
            .into_styled(PrimitiveStyle::with_fill(OK))
            .draw(display).ok();
    }

    display.flush().ok();
}

/// Display the "Approved" confirmation screen.
pub fn show_approved(display: &mut Display<'_>) {
    let l = layout(display);
    display.clear_buffer();

    let large = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(OK)
        .build();

    // Top rule
    Rectangle::new(Point::new(l.sx(0), l.sy(16)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(OK))
        .draw(display).ok();

    Text::new("APPROVED", Point::new(l.sx(24), l.sy(38)), large).draw(display).ok();

    // Bottom rule
    Rectangle::new(Point::new(l.sx(0), l.sy(44)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(OK))
        .draw(display).ok();

    // Solid confirmation bar
    Rectangle::new(Point::new(l.sx(0), l.sy(58)), Size::new(l.w as u32, l.s(6) as u32))
        .into_styled(PrimitiveStyle::with_fill(OK))
        .draw(display).ok();

    display.flush().ok();
}

/// Display the "Denied" screen.
pub fn show_denied(display: &mut Display<'_>) {
    let l = layout(display);
    display.clear_buffer();

    let large = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(DANGER)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(MUTED)
        .build();

    // Top rule
    Rectangle::new(Point::new(l.sx(0), l.sy(16)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(DANGER))
        .draw(display).ok();

    Text::new("DENIED", Point::new(l.sx(34), l.sy(38)), large).draw(display).ok();

    // Bottom rule
    Rectangle::new(Point::new(l.sx(0), l.sy(44)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(DANGER))
        .draw(display).ok();

    Text::new("released too early", Point::new(l.sx(14), l.sy(58)), small).draw(display).ok();

    display.flush().ok();
}

/// Display a "Signed!" confirmation screen.
pub fn show_signed(display: &mut Display<'_>) {
    let l = layout(display);
    display.clear_buffer();

    let large = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(OK)
        .build();

    Rectangle::new(Point::new(l.sx(0), l.sy(16)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(OK))
        .draw(display).ok();

    Text::new("SIGNED", Point::new(l.sx(34), l.sy(38)), large).draw(display).ok();

    Rectangle::new(Point::new(l.sx(0), l.sy(44)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(OK))
        .draw(display).ok();

    Rectangle::new(Point::new(l.sx(0), l.sy(58)), Size::new(l.w as u32, l.s(6) as u32))
        .into_styled(PrimitiveStyle::with_fill(OK))
        .draw(display).ok();

    display.flush().ok();

    // Flash the confirmation briefly. The response must be returned to the
    // transport layer promptly so the NIP-44 re-encryption and serial write
    // complete before the daemon's 60-second timeout expires. The idle
    // screen is redrawn by main.rs after the handler returns.
    FreeRtos::delay_ms(500);
}

/// Display a "Signing..." in-progress screen.
pub fn show_signing(display: &mut Display<'_>) {
    let l = layout(display);
    display.clear_buffer();

    let header = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(FG)
        .build();

    Text::new("PROCESSING", Point::new(l.sx(14), l.sy(10)), header).draw(display).ok();

    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display).ok();

    Text::new("Signing", Point::new(l.sx(19), l.sy(40)), large).draw(display).ok();

    display.flush().ok();
}

// ---------------------------------------------------------------------------
// Boot animation
// ---------------------------------------------------------------------------

/// Boot animation: HD pixel-art cat + decrypt reveal.
///
/// Phase 1: A cat silhouette walks across the screen.  At centre it "glitches"
/// (deja vu -- ghost cat behind).  Phase 2: screen clears, HEARTWOOD decrypts
/// letter by letter.  All coordinates scale via Layout so the animation fills
/// any panel (128×64 mono OLED or 320×172 colour C6) without modification.
pub fn show_boot_animation(display: &mut Display<'_>) {
    let mut lfsr: u16 = 0xACE1;
    let mut next_byte = |lfsr: &mut u16| -> u8 {
        let bit = *lfsr & 1;
        *lfsr >>= 1;
        if bit != 0 { *lfsr ^= 0xB400; }
        (*lfsr & 0xFF) as u8
    };

    use crate::cat_sprites::{FRAMES, FRAME_COUNT, FRAME_COLS};

    let l = layout(display);
    // Sprite scale: as large as fits both axes of the panel (min 1px/bit). The
    // 128×64 OLED stays at 1× (unchanged); the colour panels get a much bigger
    // cat — e.g. 2× on the 240×135 T-Display.
    let sc = (l.w / FRAME_COLS as i32).min(l.h / 56).max(1);
    let sprite_w = FRAME_COLS as i32 * sc;
    let sprite_h = 56i32 * sc;

    // Vertically centre the cat, leaving sc pixels of headroom above for the bob.
    let cat_y_base = (((l.h - sprite_h) / 2) - sc).max(0);
    let ground_y = (cat_y_base + sprite_h + sc).min(l.h - 1);

    // Deja vu triggers when the cat's midpoint reaches screen centre.
    let glitch_x = l.w / 2 - sprite_w / 2;
    let ghost_off = l.sx(40);

    // Lead-in: 2 empty frames.
    for _ in 0..2 {
        display.clear_buffer();
        display.flush().ok();
        FreeRtos::delay_ms(50);
    }

    let mut x: i32 = -sprite_w;
    let mut step: u32 = 0;

    while x < l.w {
        display.clear_buffer();

        let frame_idx = (step as usize) % FRAME_COUNT;
        // Bob: sc pixels down on even frames (weight feel).
        let y_pos = cat_y_base + if step % 2 == 0 { sc } else { 0 };
        let sway: i32 = if (step / 4) % 2 == 0 { 0 } else { sc };
        draw_sprite_hd(display, &FRAMES[frame_idx], x + sway, y_pos, sc, l.w, l.h, NOSTR);

        // Deja vu glitch: ghost cat behind for a few frames.
        if x >= glitch_x && x <= glitch_x + 6 * sc {
            let ghost_idx = ((step as usize) + FRAME_COUNT / 2) % FRAME_COUNT;
            let ghost_y = cat_y_base + if (step + 1) % 2 == 0 { sc } else { 0 };
            draw_sprite_hd(display, &FRAMES[ghost_idx], x - ghost_off, ghost_y, sc, l.w, l.h, GHOST);
        }

        // Moving ground: scrolling dashes just below the cat's feet.
        let dash_gap = (6 * sc).max(1);
        let dash_scroll = (step as i32 * 3 * sc) % dash_gap;
        let mut gx: i32 = -dash_scroll;
        while gx < l.w {
            if gx + 2 * sc > 0 {
                let x1 = gx.max(0);
                let x2 = (gx + 2 * sc - 1).min(l.w - 1);
                if x1 <= x2 {
                    use embedded_graphics::primitives::{Line, PrimitiveStyle};
                    Line::new(Point::new(x1, ground_y), Point::new(x2, ground_y))
                        .into_styled(PrimitiveStyle::with_stroke(FG, 1))
                        .draw(display).ok();
                }
            }
            gx += dash_gap;
        }

        display.flush().ok();
        step += 1;
        x += 2 * sc;
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

    let big_font = l.font_large();
    let sub_font = l.font_header();
    let glyph_w = Layout::glyph_w(big_font);
    let glyph_h = big_font.character_size.height as i32;

    // Magnify the title as far as fits the panel width and half its height:
    // 1× on the 128×64 OLED, ~2× on the 240×135 T-Display. Then centre it.
    let scale = (l.w / (LEN as i32 * glyph_w)).min(l.h / (2 * glyph_h)).max(1);
    let title_x0 = (l.w - LEN as i32 * glyph_w * scale) / 2;
    let title_y0 = (l.h - glyph_h * scale) / 2;

    // Each resolved letter gets its own hue (ending on Nostr purple); letters
    // still scrambling stay muted, so the reveal reads as a decrypt.
    const RAINBOW: [Rgb565; LEN] = [
        Rgb565::new(31, 0, 0),   // red
        Rgb565::new(31, 24, 0),  // orange
        Rgb565::new(31, 55, 0),  // yellow
        Rgb565::new(0, 50, 8),   // green
        Rgb565::new(0, 52, 31),  // cyan
        Rgb565::new(6, 20, 31),  // blue
        Rgb565::new(12, 8, 28),  // indigo
        Rgb565::new(17, 23, 30), // nostr purple
        Rgb565::new(31, 6, 26),  // magenta
    ];

    let sub_style = MonoTextStyleBuilder::new().font(sub_font).text_color(NOSTR).build();

    let mut resolved: usize = 0;

    for frame in 0u32..25 {
        display.clear_buffer();

        if frame >= 3 && frame % 2 == 1 && resolved < LEN {
            resolved += 1;
        }

        for i in 0..LEN {
            let (ch, colour) = if i < resolved {
                (TITLE[i], RAINBOW[i])
            } else {
                (0x21 + (next_byte(&mut lfsr) % 94), MUTED)
            };
            let buf = [ch];
            let s = core::str::from_utf8(&buf).unwrap_or("?");
            let style = MonoTextStyleBuilder::new().font(big_font).text_color(colour).build();
            let mut scaled = ScaledTarget {
                inner: &mut *display,
                scale,
                ox: title_x0 + i as i32 * glyph_w * scale,
                oy: title_y0,
            };
            Text::with_baseline(s, Point::zero(), style, Baseline::Top).draw(&mut scaled).ok();
        }

        if resolved >= LEN {
            let version = concat!("v", env!("CARGO_PKG_VERSION"));
            let vx = l.center_x(version.len() as i32 * Layout::glyph_w(sub_font));
            Text::new(version, Point::new(vx, l.sy(58)), sub_style).draw(display).ok();
        }

        display.flush().ok();
        FreeRtos::delay_ms(60);
    }
}

/// Draw a 56×56 sprite at the given pixel offset with pixel scaling.
/// Each set bit is rendered as an `sc × sc` filled block.
/// Bits are packed as u64 per row: bit 55 = leftmost column, bit 0 = rightmost.
/// A draw target that magnifies every pixel drawn through it into a
/// `scale`×`scale` block at origin `(ox, oy)`. It lets embedded-graphics `Text`
/// render larger than the biggest mono font (there is nothing above 10×20),
/// which is how the HEARTWOOD title is drawn 2× on the colour panels.
struct ScaledTarget<'a, 'd> {
    inner: &'a mut Display<'d>,
    scale: i32,
    ox: i32,
    oy: i32,
}

impl Dimensions for ScaledTarget<'_, '_> {
    fn bounding_box(&self) -> Rectangle {
        self.inner.bounding_box()
    }
}

impl DrawTarget for ScaledTarget<'_, '_> {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        for Pixel(p, c) in pixels {
            let x = self.ox + p.x * self.scale;
            let y = self.oy + p.y * self.scale;
            let _ = Rectangle::new(Point::new(x, y), Size::new(self.scale as u32, self.scale as u32))
                .into_styled(PrimitiveStyle::with_fill(c))
                .draw(self.inner);
        }
        Ok(())
    }
}

fn draw_sprite_hd(
    display: &mut Display<'_>,
    frame: &[u64; 56],
    x_offset: i32,
    y_offset: i32,
    sc: i32,
    display_w: i32,
    display_h: i32,
    colour: Rgb565,
) {
    for row in 0..56i32 {
        let bits = frame[row as usize];
        if bits == 0 { continue; }
        let py = y_offset + row * sc;
        if py >= display_h || py + sc <= 0 { continue; }
        for col in 0..56i32 {
            if (bits >> (55 - col)) & 1 == 1 {
                let px = x_offset + col * sc;
                if px >= display_w || px + sc <= 0 { continue; }
                // One filled sc×sc block per set bit — far fewer draw calls than
                // per-pixel; the DrawTarget clips any block that runs off-panel.
                Rectangle::new(Point::new(px, py), Size::new(sc as u32, sc as u32))
                    .into_styled(PrimitiveStyle::with_fill(colour))
                    .draw(display)
                    .ok();
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
    let l = layout(display);
    display.clear_buffer();

    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();
    let medium = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(FG)
        .build();

    // Header
    Text::new("FIRMWARE UPDATE", Point::new(l.sx(4), l.sy(10)), medium).draw(display).ok();

    // Horizontal rule
    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display).ok();

    // Firmware size -- large and centred
    let size_str = format!("{} KB", size_kb);
    let size_x = l.center_x(size_str.len() as i32 * Layout::glyph_w(l.font_large()));
    Text::new(&size_str, Point::new(size_x, l.sy(36)), large).draw(display).ok();

    // Instruction
    Text::new("Hold 2s to approve", Point::new(l.sx(4), l.sy(48)), small).draw(display).ok();

    // Graphical countdown bar: track (outline) + fill
    let bar_y = l.sy(54);
    let bar_h = l.s(8) as u32;
    let bar_w = l.s(100) as u32;
    let bar_x = l.sx(2);

    // Track outline
    Rectangle::new(Point::new(bar_x, bar_y), Size::new(bar_w, bar_h))
        .into_styled(PrimitiveStyle::with_stroke(FG, l.s(1) as u32))
        .draw(display).ok();

    // Fill (proportional to time remaining)
    let fill_w = if total_seconds > 0 {
        ((seconds_remaining as u32) * (bar_w - l.s(4) as u32)) / total_seconds
    } else {
        0
    };
    if fill_w > 0 {
        Rectangle::new(Point::new(bar_x + l.s(2), bar_y + l.s(2)), Size::new(fill_w, bar_h - l.s(4) as u32))
            .into_styled(PrimitiveStyle::with_fill(FG))
            .draw(display).ok();
    }

    // Seconds label right of bar
    let secs = format!("{}s", seconds_remaining);
    Text::new(&secs, Point::new(bar_x + bar_w as i32 + l.s(4), bar_y + l.s(7)), small)
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
    let l = layout(display);
    display.clear_buffer();

    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();
    let medium = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(FG)
        .build();

    // Top row: "OTA" label + large percentage
    Text::new("OTA", Point::new(l.sx(2), l.sy(10)), medium).draw(display).ok();

    let pct_str = format!("{}%", percent);
    let pct_x = (l.w - pct_str.len() as i32 * Layout::glyph_w(l.font_large())).max(l.sx(40));
    Text::new(&pct_str, Point::new(pct_x, l.sy(12)), large).draw(display).ok();

    // Progress bar: full-width graphical bar
    let bar_y = l.sy(26);
    let bar_h = l.s(6) as u32;
    let bar_w = l.s(124) as u32;
    let bar_x = l.sx(2);

    // Track
    Rectangle::new(Point::new(bar_x, bar_y), Size::new(bar_w, bar_h))
        .into_styled(PrimitiveStyle::with_stroke(FG, l.s(1) as u32))
        .draw(display).ok();

    // Fill
    let fill_w = (percent * (bar_w - l.s(2) as u32)) / 100;
    if fill_w > 0 {
        Rectangle::new(Point::new(bar_x + l.s(1), bar_y + l.s(1)), Size::new(fill_w, bar_h - l.s(2) as u32))
            .into_styled(PrimitiveStyle::with_fill(FG))
            .draw(display).ok();
    }

    // Bytes transferred
    let kb_recv = bytes_received / 1024;
    let kb_total = (total_size + 1023) / 1024;
    let bytes_str = format!("{}/{} KB", kb_recv, kb_total);
    Text::new(&bytes_str, Point::new(l.sx(2), l.sy(44)), medium).draw(display).ok();

    // Chunk counter
    let chunk_str = format!("chunk {}/{}", chunk_num, total_chunks);
    Text::new(&chunk_str, Point::new(l.sx(2), l.sy(56)), small).draw(display).ok();

    // Transfer rate indicator: a small animated dot pattern at bottom-right
    // that shifts based on chunk number to show activity
    let dot_x = l.sx(100) + ((chunk_num % 4) as i32 * l.s(6));
    Rectangle::new(Point::new(dot_x, l.sy(54)), Size::new(l.s(3) as u32, l.s(3) as u32))
        .into_styled(PrimitiveStyle::with_fill(FG))
        .draw(display).ok();

    display.flush().ok();
}

/// Display the OTA verification screen (SHA-256 check in progress).
///
/// Shows a pulsing-style animation by alternating between two frames.
pub fn show_ota_verifying(display: &mut Display<'_>) {
    let l = layout(display);
    display.clear_buffer();

    let medium = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let large = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(FG)
        .build();

    Text::new("VERIFYING", Point::new(l.sx(14), l.sy(28)), large).draw(display).ok();
    Text::new("SHA-256 check", Point::new(l.sx(20), l.sy(46)), medium).draw(display).ok();

    // Full progress bar (complete)
    Rectangle::new(Point::new(l.sx(2), l.sy(52)), Size::new(l.s(124) as u32, l.s(6) as u32))
        .into_styled(PrimitiveStyle::with_fill(FG))
        .draw(display).ok();

    display.flush().ok();
}

/// Display the OTA success screen with a brief animation.
pub fn show_ota_complete(display: &mut Display<'_>) {
    let l = layout(display);
    // Frame 1: the word builds
    display.clear_buffer();
    let large = MonoTextStyleBuilder::new()
        .font(l.font_large())
        .text_color(FG)
        .build();
    let medium = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();

    // Top line
    Rectangle::new(Point::new(l.sx(0), l.sy(0)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(FG))
        .draw(display).ok();

    Text::new("VERIFIED", Point::new(l.sx(24), l.sy(24)), large).draw(display).ok();

    // Divider
    Rectangle::new(Point::new(l.sx(20), l.sy(30)), Size::new(l.s(88) as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(FG))
        .draw(display).ok();

    Text::new("Rebooting...", Point::new(l.sx(22), l.sy(46)), medium).draw(display).ok();

    // Bottom line
    Rectangle::new(Point::new(l.sx(0), l.sy(63)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(FG))
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
    let l = layout(display);
    display.clear_buffer();

    let header_style = MonoTextStyleBuilder::new()
        .font(l.font_header())
        .text_color(ACCENT)
        .build();
    let body = MonoTextStyleBuilder::new()
        .font(l.font_body())
        .text_color(FG)
        .build();
    let small = MonoTextStyleBuilder::new()
        .font(l.font_small())
        .text_color(FG)
        .build();

    Text::new("IDENTITY SWITCH", Point::new(l.sx(2), l.sy(10)), header_style).draw(display).ok();

    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
        .draw(display).ok();

    let label = &master_label[..master_label.len().min(l.chars_per_line(l.font_body()))];
    Text::new(label, Point::new(l.sx(2), l.sy(30)), body).draw(display).ok();

    let purpose_line = format!("-> {}", purpose);
    let purpose_line = &purpose_line[..purpose_line.len().min(l.chars_per_line(l.font_body()))];
    Text::new(&purpose_line, Point::new(l.sx(2), l.sy(46)), body).draw(display).ok();

    // npub in small font for more characters
    let npub_short = &npub[..npub.len().min(l.chars_per_line(l.font_small()))];
    Text::new(npub_short, Point::new(l.sx(2), l.sy(58)), small).draw(display).ok();

    if let Err(e) = display.flush() {
        log::warn!("OLED flush failed: {:?}", e);
    }

    FreeRtos::delay_ms(2000);
}
