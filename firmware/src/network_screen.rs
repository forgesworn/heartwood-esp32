//! Shared network-page renderer: the preview draws the exact firmware code.
use embedded_graphics::{
    mono_font::{ascii, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
    text::Text,
};

use crate::{bigtext::draw_text_scaled, layout::Layout, palette::*};

fn shortened(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        value.to_string()
    } else {
        let mut text: String = value.chars().take(limit.saturating_sub(3)).collect();
        text.push_str("...");
        text
    }
}

pub fn draw<D: DrawTarget<Color = Rgb565>>(
    display: &mut D,
    mode: &str,
    ssid: Option<&str>,
    status: &str,
    rssi: Option<i8>,
) {
    let size = display.bounding_box().size;
    let l = Layout::new(size.width as i32, size.height as i32);
    let x = l.sx(4);
    let width = l.w - 2 * x;
    let large = l.is_large();
    let small = MonoTextStyle::new(l.font_small(), MUTED);
    let title = if mode == "USB bridge" {
        "USB / WIFI OFF"
    } else {
        "WI-FI"
    };
    Text::new(title, Point::new(x, l.sy(10)), small)
        .draw(display)
        .ok();

    // Give the SSID two large rows on colour panels, instead of shrinking a
    // long name to fine print. Mono panels have room for one readable row.
    let scale = if large { 2 } else { 1 };
    let font = if large && l.w >= 220 {
        &ascii::FONT_7X14
    } else if large {
        &ascii::FONT_6X10
    } else {
        &ascii::FONT_7X14
    };
    let columns = (width / (font.character_size.width as i32 * scale)) as usize;
    let name = shortened(
        ssid.unwrap_or("Not configured"),
        columns * if large { 2 } else { 1 },
    );
    let first: String = name.chars().take(columns).collect();
    draw_text_scaled(display, &first, Point::new(x, l.sy(26)), font, scale, FG);
    if large {
        let second: String = name.chars().skip(columns).collect();
        draw_text_scaled(display, &second, Point::new(x, l.sy(39)), font, scale, FG);
    }

    let colour = if status == "online" { OK } else { WARN };
    let status_font = if large {
        l.font_body()
    } else {
        l.font_header()
    };
    Text::new(
        status,
        Point::new(x, l.sy(if large { 51 } else { 43 })),
        MonoTextStyle::new(status_font, colour),
    )
    .draw(display)
    .ok();

    // Outlines keep empty bars distinguishable even on monochrome OLEDs.
    // RSSI is shown directly; bars are a rough signal guide, not throughput.
    let level = match rssi {
        Some(-55..=127) => 4,
        Some(-67..=-56) => 3,
        Some(-75..=-68) => 2,
        Some(_) => 1,
        None => 0,
    };
    let unit = if large { 2 } else { 1 };
    let bottom = l.sy(61);
    for bar in 0..4 {
        let height = (bar + 1) * if large { 4 } else { 3 };
        let rect = Rectangle::new(
            Point::new(x + bar * 5 * unit, bottom - height),
            Size::new((3 * unit) as u32, height as u32),
        );
        let style = if bar < level {
            PrimitiveStyle::with_fill(if level <= 1 { WARN } else { OK })
        } else {
            PrimitiveStyle::with_stroke(MUTED, 1)
        };
        rect.into_styled(style).draw(display).ok();
    }
    let strength = rssi
        .map(|value| format!("{value} dBm"))
        .unwrap_or_else(|| "-- dBm".into());
    Text::new(&strength, Point::new(x + 23 * unit, bottom), small)
        .draw(display)
        .ok();
    Text::new(
        "2/4",
        Point::new(l.w - x - 3 * Layout::glyph_w(l.font_small()), bottom),
        small,
    )
    .draw(display)
    .ok();
}
