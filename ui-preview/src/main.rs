// ui-preview: render representative device screens to PNG at each board's panel
// size, so the responsive layout can be checked without hardware.
//
// Shares firmware/src/layout.rs verbatim (via #[path]) so the preview cannot
// drift from the firmware's geometry. The draw functions below mirror the
// corresponding firmware screens in oled.rs, expressed through `Layout` — i.e.
// this is the design those screens are being converted to.

#[path = "../../firmware/src/layout.rs"]
mod layout;

use embedded_graphics::{
    mono_font::{MonoFont, MonoTextStyle, MonoTextStyleBuilder},
    pixelcolor::BinaryColor,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
    text::Text,
};
use embedded_graphics_simulator::{OutputSettingsBuilder, SimulatorDisplay};
use layout::Layout;

fn style(font: &'static MonoFont<'static>) -> MonoTextStyle<'static, BinaryColor> {
    MonoTextStyleBuilder::new()
        .font(font)
        .text_color(BinaryColor::On)
        .build()
}

fn layout_of<D: Dimensions>(d: &D) -> Layout {
    let s = d.bounding_box().size;
    Layout::new(s.width as i32, s.height as i32)
}

/// Header text + 1px rule beneath it, the scaffold most screens share.
fn header<D: DrawTarget<Color = BinaryColor>>(d: &mut D, l: &Layout, title: &str) {
    Text::new(title, Point::new(l.sx(2), l.sy(10)), style(l.font_header()))
        .draw(d)
        .ok();
    Rectangle::new(
        Point::new(l.sx(0), l.sy(14)),
        Size::new(l.w as u32, l.s(1) as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
    .draw(d)
    .ok();
}

/// Idle identity screen: header, rule, npub wrapped across lines (mirrors
/// `oled::show_npub`).
fn draw_idle<D: DrawTarget<Color = BinaryColor>>(d: &mut D, npub: &str) {
    let l = layout_of(d);
    header(d, &l, "IDENTITY");
    let small = style(l.font_small());
    let cpl = l.chars_per_line(l.font_small());
    let mut y = 26;
    let mut pos = 0;
    while pos < npub.len() && l.sy(y) < l.h {
        let end = (pos + cpl).min(npub.len());
        Text::new(&npub[pos..end], Point::new(l.sx(2), l.sy(y)), small)
            .draw(d)
            .ok();
        y += 10;
        pos = end;
    }
}

/// Signing request: header label, rule, method+kind, content preview, and a
/// graphical countdown bar (mirrors `oled::show_master_sign_request`).
fn draw_sign<D: DrawTarget<Color = BinaryColor>>(
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

    let body = style(l.font_body());
    let small = style(l.font_small());
    let m = format!("{} k:{}", method, kind);
    Text::new(&m, Point::new(l.sx(2), l.sy(30)), body).draw(d).ok();

    let max = l.chars_per_line(l.font_small());
    let preview: String = if content.len() > max {
        format!("{}...", &content[..max.saturating_sub(3)])
    } else {
        content.to_string()
    };
    Text::new(&preview, Point::new(l.sx(2), l.sy(42)), small)
        .draw(d)
        .ok();

    // Countdown bar: outlined track + proportional fill.
    let bx = l.sx(2);
    let by = l.sy(52);
    let bw = l.s(100);
    let bh = l.s(8);
    Rectangle::new(Point::new(bx, by), Size::new(bw as u32, bh as u32))
        .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, l.s(1) as u32))
        .draw(d)
        .ok();
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
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
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

/// Hold-to-confirm screen: header, big percentage, progress bar (mirrors
/// `oled::show_hold_progress`).
fn draw_confirm<D: DrawTarget<Color = BinaryColor>>(d: &mut D, pct: u32) {
    let l = layout_of(d);
    header(d, &l, "CONFIRMING");
    let large = style(l.font_large());
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
        .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, l.s(1) as u32))
        .draw(d)
        .ok();
    let fill = (pct.min(100) * (bw as u32 - l.s(2) as u32)) / 100;
    if fill > 0 {
        Rectangle::new(
            Point::new(bx + l.s(1), by + l.s(1)),
            Size::new(fill, (bh - l.s(2)).max(1) as u32),
        )
        .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
        .draw(d)
        .ok();
    }
}

fn render(name: &str, w: u32, h: u32, draw: impl Fn(&mut SimulatorDisplay<BinaryColor>)) {
    let mut d = SimulatorDisplay::<BinaryColor>::new(Size::new(w, h));
    draw(&mut d);
    let out = d.to_rgb_output_image(&OutputSettingsBuilder::new().scale(3).build());
    let path = format!("out/{name}.png");
    out.save_png(&path).unwrap();
    println!("wrote {path} ({w}x{h})");
}

fn main() {
    std::fs::create_dir_all("out").unwrap();
    let npub = "npub1qqqsyqcyq5rqwzqfpg9scrgwpugpzysn8tt8cg";
    let boards = [("heltec", 128u32, 64u32), ("tdisplay", 240, 135), ("c6", 172, 320)];

    for (b, w, h) in boards {
        render(&format!("idle-{b}"), w, h, |d| draw_idle(d, npub));
        render(&format!("sign-{b}"), w, h, |d| {
            draw_sign(d, "personal", "sign_event", 1, "gm nostr, building today", 18, 30)
        });
        render(&format!("confirm-{b}"), w, h, |d| draw_confirm(d, 60));
    }
}
