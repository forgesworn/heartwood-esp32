// ui-preview: render representative device screens to PNG at each board's panel
// size, so the responsive layout AND colour can be checked without hardware.
//
// Shares firmware/src/layout.rs and firmware/src/palette.rs verbatim (via
// #[path]) so the preview cannot drift from the firmware's geometry or colours.
// The draw functions below mirror the corresponding firmware screens in
// oled.rs, expressed through `Layout` + the semantic palette — i.e. this is the
// design those screens are being converted to.

#[path = "../../firmware/src/layout.rs"]
mod layout;
#[path = "../../firmware/src/palette.rs"]
mod palette;

use embedded_graphics::{
    mono_font::{MonoFont, MonoTextStyle, MonoTextStyleBuilder},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{Circle, PrimitiveStyle, Rectangle},
    text::Text,
};
use embedded_graphics_simulator::{OutputSettingsBuilder, SimulatorDisplay};
use layout::Layout;
use palette::*;

/// A text style in `font` drawn in `colour`.
fn style(font: &'static MonoFont<'static>, colour: Rgb565) -> MonoTextStyle<'static, Rgb565> {
    MonoTextStyleBuilder::new()
        .font(font)
        .text_color(colour)
        .build()
}

fn layout_of<D: Dimensions>(d: &D) -> Layout {
    let s = d.bounding_box().size;
    Layout::new(s.width as i32, s.height as i32)
}

/// Header text (accent) + 1px accent rule beneath it — the brand scaffold most
/// screens share.
fn header<D: DrawTarget<Color = Rgb565>>(d: &mut D, l: &Layout, title: &str) {
    Text::new(title, Point::new(l.sx(2), l.sy(10)), style(l.font_header(), ACCENT))
        .draw(d)
        .ok();
    Rectangle::new(
        Point::new(l.sx(0), l.sy(14)),
        Size::new(l.w as u32, l.s(1) as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(ACCENT))
    .draw(d)
    .ok();
}

/// Idle identity screen: header, rule, npub wrapped across lines (mirrors
/// `oled::show_npub`).
fn draw_idle<D: DrawTarget<Color = Rgb565>>(d: &mut D, name: Option<&str>, npub: &str) {
    let l = layout_of(d);
    header(d, &l, "MASTER");
    let npub_font = if l.is_large() { l.font_body() } else { l.font_small() };
    let body = style(npub_font, FG);
    let gw = npub_font.character_size.width as i32;

    // Short, centred npub (head...tail). The full 63-char key in the big font
    // runs edge to edge (24 chars/line) and clips on any panel offset; the
    // shortened form is what clients show. The full key lives on the QR page.
    let short = if npub.len() > 24 {
        format!("{}...{}", &npub[..10], &npub[npub.len() - 6..])
    } else {
        npub.to_string()
    };

    if l.is_large() {
        match name {
            // Kind 0 known: a contact card — avatar disc on the left, name
            // right-aligned, no npub (it lives on the QR page).
            Some(n) => {
                let area_top = l.sy(14);
                let area_h = l.h - area_top;
                let r = area_h * 36 / 100;
                let cy = area_top + area_h / 2;
                let cx = l.sx(5) + r;
                // Placeholder avatar disc with the initial, until the device can
                // fetch + decode the real picture.
                Circle::new(Point::new(cx - r, cy - r), (r * 2) as u32)
                    .into_styled(PrimitiveStyle::with_fill(NOSTR))
                    .draw(d)
                    .ok();
                let init = n.chars().next().map(|c| c.to_ascii_uppercase()).unwrap_or('?').to_string();
                let lf = l.font_large();
                let iw = lf.character_size.width as i32;
                let ih = lf.character_size.height as i32;
                Text::new(&init, Point::new(cx - iw / 2, cy + ih / 3), style(lf, FG)).draw(d).ok();
                // Name: right-aligned, vertically centred, shrunk if it won't fit.
                let right = l.w - l.sx(14);
                let avail = right - (cx + r) - l.sx(4);
                let nf = if (n.len() as i32 * l.font_body().character_size.width as i32) <= avail {
                    l.font_body()
                } else {
                    l.font_small()
                };
                let nw = n.len() as i32 * nf.character_size.width as i32;
                let nh = nf.character_size.height as i32;
                Text::new(n, Point::new(right - nw, cy + nh / 3), style(nf, FG)).draw(d).ok();
            }
            // No profile yet: just the short npub, centred.
            None => {
                let x = l.center_x(short.len() as i32 * gw);
                Text::new(&short, Point::new(x, l.sy(40)), body).draw(d).ok();
            }
        }
        return;
    }

    // Mono OLED: the small font fits the full npub wrapped across lines. Reserve
    // the draw margin on both sides so the last glyph never clips.
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
        let end = (pos + cpl).min(npub.len());
        Text::new(&npub[pos..end], Point::new(l.sx(2), y), body).draw(d).ok();
        y += line_h;
        pos = end;
    }
}

/// Signing request: header label, rule, method+kind, content preview, and a
/// countdown bar whose fill colour shifts green→amber→red as time runs out
/// (mirrors `oled::show_master_sign_request`).
fn draw_sign<D: DrawTarget<Color = Rgb565>>(
    d: &mut D,
    label: &str,
    method: &str,
    kind: u64,
    content: &str,
    secs: u32,
    total: u32,
) {
    let l = layout_of(d);
    header(d, &l, label);

    let body = style(l.font_body(), FG);
    let preview_style = style(l.font_small(), MUTED);
    let small = style(l.font_small(), FG);
    let m = format!("{} k:{}", method, kind);
    Text::new(&m, Point::new(l.sx(2), l.sy(30)), body).draw(d).ok();

    let max = l.chars_per_line(l.font_small());
    let preview: String = if content.len() > max {
        format!("{}...", &content[..max.saturating_sub(3)])
    } else {
        content.to_string()
    };
    Text::new(&preview, Point::new(l.sx(2), l.sy(42)), preview_style)
        .draw(d)
        .ok();

    // Countdown bar: muted track + proportional fill coloured by urgency.
    let bx = l.sx(2);
    let by = l.sy(52);
    let bw = l.s(100);
    let bh = l.s(8);
    Rectangle::new(Point::new(bx, by), Size::new(bw as u32, bh as u32))
        .into_styled(PrimitiveStyle::with_stroke(MUTED, l.s(1) as u32))
        .draw(d)
        .ok();
    let pct_left = if total > 0 { secs * 100 / total } else { 0 };
    let urgency = if pct_left > 50 {
        OK
    } else if pct_left > 20 {
        WARN
    } else {
        DANGER
    };
    let fill = if total > 0 {
        (secs * (bw as u32 - l.s(4) as u32)) / total
    } else {
        0
    };
    if fill > 0 {
        Rectangle::new(
            Point::new(bx + l.s(2), by + l.s(2)),
            Size::new(fill, (bh - l.s(4)).max(1) as u32),
        )
        .into_styled(PrimitiveStyle::with_fill(urgency))
        .draw(d)
        .ok();
    }
    Text::new(
        &format!("{}s", secs),
        Point::new(bx + bw + l.s(4), by + l.s(7)),
        small,
    )
    .draw(d)
    .ok();
}

/// Hold-to-confirm screen: header, big percentage + progress bar in success
/// green (mirrors `oled::show_hold_progress`).
fn draw_confirm<D: DrawTarget<Color = Rgb565>>(d: &mut D, pct: u32) {
    let l = layout_of(d);
    header(d, &l, "CONFIRMING");
    let large = style(l.font_large(), OK);
    let txt = format!("{}%", pct.min(100));
    let tw = txt.len() as i32 * Layout::glyph_w(l.font_large());
    Text::new(&txt, Point::new(l.center_x(tw), l.sy(38)), large)
        .draw(d)
        .ok();
    let bx = l.sx(2);
    let by = l.sy(48);
    let bw = l.s(124);
    let bh = l.s(8);
    Rectangle::new(Point::new(bx, by), Size::new(bw as u32, bh as u32))
        .into_styled(PrimitiveStyle::with_stroke(MUTED, l.s(1) as u32))
        .draw(d)
        .ok();
    let fill = (pct.min(100) * (bw as u32 - l.s(2) as u32)) / 100;
    if fill > 0 {
        Rectangle::new(
            Point::new(bx + l.s(1), by + l.s(1)),
            Size::new(fill, (bh - l.s(2)).max(1) as u32),
        )
        .into_styled(PrimitiveStyle::with_fill(OK))
        .draw(d)
        .ok();
    }
}

/// A full-screen result banner: one big centred word in `colour` (mirrors
/// `oled::show_approved` / `show_denied` / `show_signed`).
fn draw_result<D: DrawTarget<Color = Rgb565>>(d: &mut D, word: &str, colour: Rgb565) {
    let l = layout_of(d);
    let large = style(l.font_large(), colour);
    let tw = word.len() as i32 * Layout::glyph_w(l.font_large());
    Text::new(word, Point::new(l.center_x(tw), l.sy(36)), large)
        .draw(d)
        .ok();
    // A colour rule under the word ties the banner to the semantic state.
    Rectangle::new(
        Point::new(l.sx(0), l.sy(44)),
        Size::new(l.w as u32, l.s(1) as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(colour))
    .draw(d)
    .ok();
}

fn render(name: &str, w: u32, h: u32, draw: impl Fn(&mut SimulatorDisplay<Rgb565>)) {
    let mut d = SimulatorDisplay::<Rgb565>::new(Size::new(w, h));
    d.clear(BG).ok();
    draw(&mut d);
    let out = d.to_rgb_output_image(&OutputSettingsBuilder::new().scale(3).build());
    let path = format!("out/{name}.png");
    out.save_png(&path).unwrap();
    println!("wrote {path} ({w}x{h})");
}

fn main() {
    std::fs::create_dir_all("out").unwrap();
    let npub = "npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m";
    let boards = [("heltec", 128u32, 64u32), ("tdisplay", 240, 135), ("c6", 172, 320)];

    for (b, w, h) in boards {
        render(&format!("idle-{b}"), w, h, |d| draw_idle(d, None, npub));
        render(&format!("idle-named-{b}"), w, h, |d| draw_idle(d, Some("TheCryptoDonkey"), npub));
        render(&format!("sign-{b}"), w, h, |d| {
            draw_sign(d, "personal", "sign_event", 1, "gm nostr, building today", 18, 30)
        });
        render(&format!("sign-urgent-{b}"), w, h, |d| {
            draw_sign(d, "personal", "sign_event", 1, "gm nostr, building today", 4, 30)
        });
        render(&format!("confirm-{b}"), w, h, |d| draw_confirm(d, 60));
        render(&format!("approved-{b}"), w, h, |d| draw_result(d, "APPROVED", OK));
        render(&format!("denied-{b}"), w, h, |d| draw_result(d, "DENIED", DANGER));
    }
}
