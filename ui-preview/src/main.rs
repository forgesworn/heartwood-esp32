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

fn display_app_label(label: &str) -> String {
    let label = label.trim();
    let label = if label.is_empty() { "app" } else { label };
    let mut chars = label.chars();
    let Some(first) = chars.next() else {
        return "App".to_string();
    };

    let mut out = String::new();
    out.extend(first.to_uppercase());
    out.extend(chars);
    out
}

fn kind_name(kind: u64) -> &'static str {
    match kind {
        0 => "Profile",
        1 => "Note",
        3 => "Contacts",
        4 => "DM (NIP-04)",
        30078 => "App Data",
        _ => "Unknown Kind",
    }
}

fn ellipsize_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    if max_chars <= 3 {
        return value.chars().take(max_chars).collect();
    }

    let mut out: String = value.chars().take(max_chars - 3).collect();
    out.push_str("...");
    out
}

/// Normal ready screen shown while the signer is idle.
fn draw_ready<D: DrawTarget<Color = Rgb565>>(d: &mut D) {
    let l = layout_of(d);
    header(d, &l, "SIGNER READY");

    let large = style(l.font_large(), FG);
    let small = style(l.font_small(), FG);

    let title = "Sapwood";
    Text::new(title, Point::new(l.center_x(title.len() as i32 * Layout::glyph_w(l.font_large())), l.sy(34)), large)
        .draw(d)
        .ok();
    let manage = "USB/WiFi setup";
    Text::new(manage, Point::new(l.center_x(manage.len() as i32 * Layout::glyph_w(l.font_small())), l.sy(48)), small)
        .draw(d)
        .ok();
    let apps = "apps: bunker";
    Text::new(apps, Point::new(l.center_x(apps.len() as i32 * Layout::glyph_w(l.font_small())), l.sy(58)), small)
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
                // Right block: name above the short npub, both right-aligned,
                // the pair vertically centred beside the avatar. Name shrinks if
                // it won't fit; generous right margin for this panel's short edge.
                let right = l.w - l.sx(14);
                let avail = right - (cx + r) - l.sx(4);
                let nf = if (n.len() as i32 * l.font_body().character_size.width as i32) <= avail {
                    l.font_body()
                } else {
                    l.font_small()
                };
                let sf = l.font_small();
                let nh = nf.character_size.height as i32;
                let sh = sf.character_size.height as i32;
                let gap = l.s(3);
                let block_top = cy - (nh + gap + sh) / 2;
                let nw = n.len() as i32 * nf.character_size.width as i32;
                Text::new(n, Point::new(right - nw, block_top + nh), style(nf, FG)).draw(d).ok();
                let sw = short.len() as i32 * sf.character_size.width as i32;
                Text::new(&short, Point::new(right - sw, block_top + nh + gap + sh), style(sf, MUTED))
                    .draw(d)
                    .ok();
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

/// Signing request: hold-to-sign header, app label, friendly kind label, kind
/// number, and countdown bar (mirrors `oled::show_sign_request`).
fn draw_sign<D: DrawTarget<Color = Rgb565>>(
    d: &mut D,
    label: &str,
    _method: &str,
    kind: u64,
    _content: &str,
    secs: u32,
    total: u32,
) {
    let l = layout_of(d);
    header(d, &l, "HOLD TO SIGN");

    let body = style(l.font_body(), FG);
    let small = style(l.font_small(), FG);
    let app = ellipsize_chars(&display_app_label(label), l.chars_per_line(l.font_body()));
    Text::new(&app, Point::new(l.sx(2), l.sy(25)), body).draw(d).ok();

    let kind_label = ellipsize_chars(kind_name(kind), l.chars_per_line(l.font_small()));
    Text::new(&kind_label, Point::new(l.sx(2), l.sy(39)), small).draw(d).ok();

    let kind_number = ellipsize_chars(&format!("kind {kind}"), l.chars_per_line(l.font_small()));
    Text::new(&kind_number, Point::new(l.sx(2), l.sy(48)), small).draw(d).ok();

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

/// Network status card (mirrors `oled::show_status_card`). It deliberately
/// clears the whole frame first so a preceding legacy result screen cannot
/// leave either of its white rules behind.
fn draw_network_status<D>(d: &mut D, title: &str, hint: &str, colour: Rgb565)
where
    D: DrawTarget<Color = Rgb565> + Dimensions,
{
    let l = layout_of(d);
    d.clear(BG).ok();

    let header_text = "NETWORK";
    Text::new(
        header_text,
        Point::new(
            l.center_x(header_text.len() as i32 * Layout::glyph_w(l.font_header())),
            l.sy(10),
        ),
        style(l.font_header(), ACCENT),
    )
    .draw(d)
    .ok();
    Rectangle::new(
        Point::new(l.sx(0), l.sy(14)),
        Size::new(l.w as u32, l.s(1) as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(ACCENT))
    .draw(d)
    .ok();

    let available = l.w - l.sx(4);
    let title_font = if title.len() as i32 * Layout::glyph_w(l.font_large()) <= available {
        l.font_large()
    } else if title.len() as i32 * Layout::glyph_w(l.font_body()) <= available {
        l.font_body()
    } else {
        l.font_small()
    };
    Text::new(
        title,
        Point::new(
            l.center_x(title.len() as i32 * Layout::glyph_w(title_font)),
            l.sy(38),
        ),
        style(title_font, colour),
    )
    .draw(d)
    .ok();
    Text::new(
        hint,
        Point::new(
            l.center_x(hint.len() as i32 * Layout::glyph_w(l.font_small())),
            l.sy(53),
        ),
        style(l.font_small(), MUTED),
    )
    .draw(d)
    .ok();
}

fn draw_change_approval<D>(d: &mut D, remaining: u32)
where
    D: DrawTarget<Color = Rgb565> + Dimensions,
{
    let l = layout_of(d);
    d.clear(BG).ok();
    let header_text = "CONFIRM CHANGE";
    Text::new(
        header_text,
        Point::new(
            l.center_x(header_text.len() as i32 * Layout::glyph_w(l.font_header())),
            l.sy(10),
        ),
        style(l.font_header(), ACCENT),
    )
    .draw(d)
    .ok();
    Rectangle::new(
        Point::new(l.sx(0), l.sy(14)),
        Size::new(l.w as u32, l.s(1) as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(ACCENT))
    .draw(d)
    .ok();
    let title = "Set network config?";
    let title_font = if title.len() as i32 * Layout::glyph_w(l.font_body()) <= l.w - l.sx(4) {
        l.font_body()
    } else {
        l.font_small()
    };
    Text::new(
        title,
        Point::new(
            l.center_x(title.len() as i32 * Layout::glyph_w(title_font)),
            l.sy(36),
        ),
        style(title_font, WARN),
    )
    .draw(d)
    .ok();
    let hint = format!("Hold button - {remaining}s");
    Text::new(
        &hint,
        Point::new(
            l.center_x(hint.len() as i32 * Layout::glyph_w(l.font_small())),
            l.sy(57),
        ),
        style(l.font_small(), MUTED),
    )
    .draw(d)
    .ok();
}

fn draw_legacy_result_rules<D>(d: &mut D)
where
    D: DrawTarget<Color = Rgb565> + Dimensions,
{
    let l = layout_of(d);
    for y in [18, 44] {
        Rectangle::new(
            Point::new(l.sx(0), l.sy(y)),
            Size::new(l.w as u32, l.s(1) as u32),
        )
        .into_styled(PrimitiveStyle::with_fill(FG))
        .draw(d)
        .ok();
    }
}

fn assert_no_legacy_white_rules(d: &SimulatorDisplay<Rgb565>) {
    let l = layout_of(d);
    for y in [l.sy(18), l.sy(44)] {
        let white = (0..l.w)
            .filter(|x| d.get_pixel(Point::new(*x, y)) == FG)
            .count();
        assert!(
            white < l.w as usize / 2,
            "stale full-width white rule remained at y={y}"
        );
    }
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
        render(&format!("ready-{b}"), w, h, |d| draw_ready(d));
        render(&format!("idle-{b}"), w, h, |d| draw_idle(d, None, npub));
        render(&format!("idle-named-{b}"), w, h, |d| draw_idle(d, Some("TheCryptoDonkey"), npub));
        render(&format!("sign-{b}"), w, h, |d| {
            draw_sign(d, "primal", "sign_event", 30078, "Sync app settings", 18, 30)
        });
        render(&format!("sign-urgent-{b}"), w, h, |d| {
            draw_sign(d, "primal", "sign_event", 30078, "Sync app settings", 4, 30)
        });
        render(&format!("confirm-{b}"), w, h, |d| draw_confirm(d, 60));
        render(&format!("approved-{b}"), w, h, |d| draw_result(d, "APPROVED", OK));
        render(&format!("denied-{b}"), w, h, |d| draw_result(d, "DENIED", DANGER));
    }

    // Focused T-Display network-operation gallery. The transition case first
    // draws the old two-white-rule result frame, then the new status card; the
    // pixel assertion proves the full-frame clear removed both stale rules.
    render("network-approval-tdisplay", 240, 135, |d| {
        draw_change_approval(d, 24)
    });
    render("network-saving-tdisplay", 240, 135, |d| {
        draw_network_status(d, "Saving", "Storing network settings", WARN)
    });
    render("network-joining-tdisplay", 240, 135, |d| {
        draw_network_status(d, "Joining WiFi", "Please wait", WARN)
    });
    render("network-opening-relay-tdisplay", 240, 135, |d| {
        draw_network_status(d, "Opening relay", "Connecting securely", WARN)
    });
    render("network-online-tdisplay", 240, 135, |d| {
        draw_network_status(d, "Online", "Remote signing ready", OK)
    });
    render("network-radio-off-tdisplay", 240, 135, |d| {
        draw_network_status(d, "Saved", "Rebooting - radio off", OK)
    });
    render("network-update-failed-tdisplay", 240, 135, |d| {
        draw_network_status(d, "Update not confirmed", "Safety timeout reached", DANGER)
    });
    render("network-rollback-tdisplay", 240, 135, |d| {
        draw_legacy_result_rules(d);
        draw_network_status(d, "Rolling back", "Restoring last network", WARN);
        assert_no_legacy_white_rules(d);
    });
}
