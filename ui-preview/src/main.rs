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
#[path = "../../firmware/src/bigtext.rs"]
mod bigtext;

use embedded_graphics::{
    mono_font::{MonoFont, MonoTextStyle, MonoTextStyleBuilder},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{Circle, PrimitiveStyle, PrimitiveStyleBuilder, Rectangle, StrokeAlignment},
    text::Text,
};
use embedded_graphics_simulator::{OutputSettingsBuilder, SimulatorDisplay};
use heartwood_common::phone_unlock;
use layout::{Layout, TagSide};
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

/// Idle locker summary, mirroring `oled::show_info_notes`. It deliberately
/// has counts only: no note value, mint, sender or secret belongs on an idle
/// panel.
fn draw_notes<D: DrawTarget<Color = Rgb565>>(d: &mut D, held: usize, received: usize, pending: usize) {
    let l = layout_of(d);
    header(d, &l, "NOTES");
    Text::new(&format!("{held} held"), Point::new(l.sx(4), l.sy(28)), style(l.font_body(), FG))
        .draw(d)
        .ok();
    Text::new(&format!("received: {received}"), Point::new(l.sx(4), l.sy(41)), style(l.font_small(), MUTED))
        .draw(d)
        .ok();
    Text::new(&format!("pending: {pending}"), Point::new(l.sx(4), l.sy(52)), style(l.font_small(), MUTED))
        .draw(d)
        .ok();
    Text::new("4/4", Point::new(l.w - l.sx(4) - 3 * Layout::glyph_w(l.font_small()), l.sy(62)), style(l.font_small(), MUTED))
        .draw(d)
        .ok();
}

/// Signing request: hold-to-sign header, app label, friendly kind label, kind
/// number, and countdown bar (mirrors `oled::show_sign_request_as`).
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

    draw_countdown(d, &l, secs, total);
}

/// Countdown bar: muted track + proportional fill coloured by urgency
/// (mirrors `oled::draw_countdown_bar`).
fn draw_countdown<D: DrawTarget<Color = Rgb565>>(d: &mut D, l: &Layout, secs: u32, total: u32) {
    let small = style(l.font_small(), FG);
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

/// A board's button tags (mirrors `oled::draw_button_tags`): which edge they
/// sit on, whether there is a cancel button ("NO"), and whether approve is the
/// upper of the two.
#[derive(Clone, Copy)]
struct Tags {
    side: TagSide,
    cancel: bool,
    approve_on_top: bool,
}

const HELTEC_TAGS: Tags = Tags { side: TagSide::Left, cancel: false, approve_on_top: true };
const TDISPLAY_TAGS: Tags = Tags { side: TagSide::Right, cancel: true, approve_on_top: false };
/// The Heltec with its screen turned through 180 degrees (display_flip.rs):
/// the PRG tag moves to the right-hand edge, level with the lower row.
const HELTEC_FLIPPED_TAGS: Tags = Tags { side: TagSide::Right, cancel: false, approve_on_top: false };

/// Each tag as (text, colour, position).
fn tag_items(l: &Layout, tags: Tags) -> Vec<(String, Rgb565, Point)> {
    let font = l.font_small();
    let approve = if tags.cancel { "YES" } else { "PRG" };
    let mut list = vec![(approve, OK, tags.approve_on_top)];
    if tags.cancel {
        list.push(("NO", DANGER, !tags.approve_on_top));
    }
    list.into_iter()
        .map(|(word, colour, top)| {
            let on_right = tags.side == TagSide::Right;
            let text = if on_right { format!("{word}>") } else { format!("<{word}") };
            let w = text.len() as i32 * Layout::glyph_w(font);
            let x = if on_right { l.w - w - l.s(1) } else { l.s(1) };
            let y = if top { l.sy(10) } else { l.sy(48) };
            (text, colour, Point::new(x, y))
        })
        .collect()
}

/// One piece of text on a card: (text, font, integer scale, colour, baseline).
type Item = (String, &'static MonoFont<'static>, i32, Rgb565, Point);

/// Draw one [`Item`] (scaled through bigtext, as the firmware does).
fn draw_item<D: DrawTarget<Color = Rgb565>>(d: &mut D, (text, font, scale, colour, p): &Item) {
    bigtext::draw_text_scaled(d, text, *p, font, *scale, *colour);
}

/// The enrol card's text `elapsed` whole seconds after it opened, one entry
/// per line. Mirrors `oled::show_enrol_approval`: the top line and hint in
/// the small font, centred clear of the tags; the page's words (two, two,
/// one) with their place numbers, at the size `Layout::enrol_geometry`
/// picks; and the countdown row's page marker and seconds. The hint offers
/// no hold until the gate has passed (`armed`). The countdown bar is a
/// rectangle, drawn separately.
fn enrol_items(
    l: &Layout,
    tags: Option<Tags>,
    words: &[&str; phone_unlock::REQUEST_CODE_WORDS],
    label: &str,
    elapsed: u32,
    armed: bool,
) -> Vec<Item> {
    let side = tags.map(|t| t.side);
    let g = l.enrol_geometry(side);
    let page = phone_unlock::enrol_page(elapsed);
    let secs = phone_unlock::ENROL_CARD_SECS.saturating_sub(elapsed);
    let card = phone_unlock::enrol_card(words, label, l.span_chars(side, l.font_small()), page);
    let small = l.font_small();
    let centred = |text: &str, y: i32| Point::new(l.center_in_span(side, text.len() as i32 * Layout::glyph_w(small)), y);

    let mut items: Vec<Item> = vec![(card.top.clone(), small, 1, ACCENT, centred(&card.top, g.top_y))];
    for ((place, word), y) in card.lines.iter().zip(g.word_y) {
        items.push((place.to_string(), small, 1, MUTED, Point::new(g.number_x, y)));
        items.push((word.clone(), g.word_font, g.word_scale, WARN, Point::new(g.word_x, y)));
    }
    // A tagged board's cancel button is its second one (T-Display); the
    // untagged C6 is drawn as a single-button board.
    let hint = phone_unlock::enrol_hint(tags.map(|t| t.cancel), tags.is_some_and(|t| t.cancel), armed).to_string();
    let p = centred(&hint, g.hint_y);
    items.push((hint, small, 1, MUTED, p));
    items.push((phone_unlock::enrol_page_marker(page).into(), small, 1, MUTED, Point::new(g.marker_x, g.secs_y)));
    items.push((format!("{secs}s"), small, 1, FG, Point::new(g.secs_x, g.secs_y)));
    items
}

/// The enrol card's countdown bar: outline (drawn inside the bar, so a thick
/// stroke on a large panel cannot poke out of the span) and fill (mirrors
/// `oled::draw_enrol_countdown`).
fn draw_enrol_bar<D: DrawTarget<Color = Rgb565>>(d: &mut D, l: &Layout, side: Option<TagSide>, secs: u32, total: u32) {
    let (x, y, w, h) = l.enrol_geometry(side).bar;
    Rectangle::new(Point::new(x, y), Size::new(w as u32, h as u32))
        .into_styled(
            PrimitiveStyleBuilder::new()
                .stroke_color(MUTED)
                .stroke_width(l.s(1) as u32)
                .stroke_alignment(StrokeAlignment::Inside)
                .build(),
        )
        .draw(d)
        .ok();
    let pct_left = if total > 0 { secs * 100 / total } else { 0 };
    let urgency = if pct_left > 50 { OK } else if pct_left > 20 { WARN } else { DANGER };
    let inner = w - 2 * l.s(2);
    let fill = if total > 0 { secs as i32 * inner / total as i32 } else { 0 };
    if fill > 0 {
        Rectangle::new(Point::new(x + l.s(2), y + l.s(2)), Size::new(fill as u32, (h - 2 * l.s(2)).max(1) as u32))
            .into_styled(PrimitiveStyle::with_fill(urgency))
            .draw(d)
            .ok();
    }
}

/// Add-an-unlock-phone card `elapsed` seconds after it opened (mirrors
/// `oled::show_enrol_approval`).
fn draw_enrol_card<D: DrawTarget<Color = Rgb565> + Dimensions>(
    d: &mut D,
    tags: Option<Tags>,
    words: &[&str; phone_unlock::REQUEST_CODE_WORDS],
    label: &str,
    elapsed: u32,
) {
    let l = layout_of(d);
    d.clear(BG).ok();
    let total = phone_unlock::ENROL_CARD_SECS;
    let armed = u64::from(elapsed) * 1000 >= phone_unlock::ENROL_GATE_MS;
    for item in enrol_items(&l, tags, words, label, elapsed, armed) {
        draw_item(d, &item);
    }
    if let Some(tags) = tags {
        for (text, colour, p) in tag_items(&l, tags) {
            Text::new(&text, p, style(l.font_small(), colour)).draw(d).ok();
        }
    }
    draw_enrol_bar(d, &l, tags.map(|t| t.side), total.saturating_sub(elapsed), total);
}

/// PHONE ADDED's text (mirrors `oled::show_phone_added`): the header and its
/// rule as every status card has them, then "check code" small, the code
/// itself at the card words' size, and "else revoke N" small.
fn phone_added_items(l: &Layout, check: &str, id: u32) -> Vec<Item> {
    let (font, scale) = l.card_word_font(None);
    let small = l.font_small();
    let header = l.font_header();
    let centred = |text: &str, font: &MonoFont<'_>, scale: i32, y: i32| {
        Point::new(l.center_x(bigtext::scaled_text_width(text, font, scale)), l.sy(y))
    };
    let hint = format!("else revoke {id}");
    vec![
        ("PHONE ADDED".into(), header, 1, ACCENT, centred("PHONE ADDED", header, 1, 10)),
        ("check code".into(), small, 1, MUTED, centred("check code", small, 1, 24)),
        (check.into(), font, scale, OK, centred(check, font, scale, 43)),
        (hint.clone(), small, 1, MUTED, centred(&hint, small, 1, 56)),
    ]
}

/// PHONE ADDED (mirrors `oled::show_phone_added`).
fn draw_phone_added<D: DrawTarget<Color = Rgb565> + Dimensions>(d: &mut D, check: &str, id: u32) {
    let l = layout_of(d);
    d.clear(BG).ok();
    for item in phone_added_items(&l, check, id) {
        draw_item(d, &item);
    }
    Rectangle::new(Point::new(l.sx(0), l.sy(14)), Size::new(l.w as u32, l.s(1) as u32))
        .into_styled(PrimitiveStyle::with_fill(ACCENT))
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
    draw_status_card(d, "NETWORK", title, hint, colour);
}

/// Any `oled::show_status_card` screen.
fn draw_status_card<D>(d: &mut D, header_text: &str, title: &str, hint: &str, colour: Rgb565)
where
    D: DrawTarget<Color = Rgb565> + Dimensions,
{
    let l = layout_of(d);
    d.clear(BG).ok();

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

/// Recovery-word walkthrough, mirroring `oled::show_recovery_word`. The caption
/// between the rule and the word is the whole point of previewing this screen:
/// it must not collide with the FONT_10X20 word on any panel.
fn draw_recovery_word<D: DrawTarget<Color = Rgb565>>(
    d: &mut D,
    index: usize,
    total: usize,
    word: &str,
    role: &str,
) {
    let l = layout_of(d);
    header(d, &l, &format!("WORD {index} OF {total}"));

    if !role.is_empty() {
        Text::new(role, Point::new(l.sx(2), l.sy(26)), style(l.font_small(), ACCENT))
            .draw(d)
            .ok();
    }

    let scale = l.word_scale();
    let width = bigtext::scaled_text_width(word, l.font_large(), scale);
    let x = l.center_x(width);
    bigtext::draw_text_scaled(d, word, Point::new(x, l.sy(44)), l.font_large(), scale, FG);

    let footer = if index >= total { "tap PRG to finish" } else { "tap PRG for next" };
    Text::new(footer, Point::new(l.sx(2), l.sy(62)), style(l.font_small(), FG))
        .draw(d)
        .ok();
}

/// The one-off explainer shown before the walkthrough, mirroring
/// `oled::show_recovery_prefix_notice`.
fn draw_recovery_prefix_notice<D: DrawTarget<Color = Rgb565>>(d: &mut D) {
    let l = layout_of(d);
    header(d, &l, "BEFORE YOU WRITE");
    let body = style(l.font_body(), FG);
    Text::new("Words 1-7 are", Point::new(l.sx(4), l.sy(32)), body).draw(d).ok();
    Text::new("format, not key.", Point::new(l.sx(4), l.sy(46)), body).draw(d).ok();
    Text::new(
        "Same start every time",
        Point::new(l.sx(2), l.sy(60)),
        style(l.font_small(), FG),
    )
    .draw(d)
    .ok();
}

/// Restore word picker, mirroring `oled::show_word_entry`. Rendered here to
/// judge how the big word, the subtitle and the legend actually sit on each
/// panel — the legend is the widest fixed string on any Heartwood screen.
fn draw_word_entry<D: DrawTarget<Color = Rgb565>>(
    d: &mut D,
    word_index: usize,
    total: usize,
    big_text: &str,
    underline: bool,
    subtitle: &str,
    legend: &str,
) {
    let l = layout_of(d);
    header(d, &l, &format!("WORD {word_index}/{total}"));

    let scale = l.word_scale();
    let width = bigtext::scaled_text_width(big_text, l.font_large(), scale);
    let x = l.center_x(width);
    bigtext::draw_text_scaled(d, big_text, Point::new(x, l.sy(40)), l.font_large(), scale, FG);
    if underline {
        Rectangle::new(Point::new(x, l.sy(43)), Size::new(width as u32, l.s(1) as u32))
            .into_styled(PrimitiveStyle::with_fill(FG))
            .draw(d)
            .ok();
    }

    Text::new(subtitle, Point::new(l.sx(2), l.sy(54)), style(l.font_small(), FG)).draw(d).ok();
    Text::new(legend, Point::new(l.sx(2), l.sy(62)), style(l.font_small(), FG)).draw(d).ok();
}

/// Error card, mirroring `oled::show_error` — including its newline handling,
/// which is embedded-graphics' own. Rendered here because the RNG refusal
/// messages are the only two-line error strings on the device and nothing
/// checked they fit the narrowest panel.
fn draw_error<D: DrawTarget<Color = Rgb565>>(d: &mut D, msg: &str) {
    let l = layout_of(d);
    Text::new(msg, Point::new(l.sx(0), l.sy(30)), style(l.font_body(), DANGER))
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
    let boards = [("heltec", 128u32, 64u32), ("tdisplay", 240, 135), ("c6", 172, 320), ("c6-landscape", 320, 172)];

    for (b, w, h) in boards {
        render(&format!("ready-{b}"), w, h, |d| draw_ready(d));
        let tags = match b {
            "heltec" => Some(HELTEC_TAGS),
            "tdisplay" => Some(TDISPLAY_TAGS),
            _ => None,
        };
        let words = phone_unlock::request_words(&[0xAB; 32]);
        // One render per page, before the gate (0, 4 and 8 s), and page 1
        // again once it has passed (12 s), when the hint offers the hold.
        for (name, elapsed) in [("page1", 0), ("page2", 4), ("page3", 8), ("armed", 12)] {
            render(&format!("enrol-{b}-{name}"), w, h, |d| draw_enrol_card(d, tags, &words, "Pixel 8", elapsed));
            render(&format!("enrol-longest-{b}-{name}"), w, h, |d| {
                draw_enrol_card(d, tags, &["abstract", "accident", "acoustic", "absolute", "activity"], "WWWWWWWWWWWWWWWW", elapsed)
            });
        }
        if b == "heltec" {
            // The screen turned through 180 degrees: "PRG>" bottom right.
            render("enrol-heltec-flipped-armed", w, h, |d| draw_enrol_card(d, Some(HELTEC_FLIPPED_TAGS), &words, "Pixel 8", 12));
        }
        render(&format!("phone-added-{b}"), w, h, |d| draw_phone_added(d, "9B6 164", u32::MAX));
        render(&format!("idle-{b}"), w, h, |d| draw_idle(d, None, npub));
        render(&format!("idle-named-{b}"), w, h, |d| draw_idle(d, Some("TheCryptoDonkey"), npub));
        render(&format!("notes-{b}"), w, h, |d| draw_notes(d, 6, 2, 1));
        render(&format!("sign-{b}"), w, h, |d| {
            draw_sign(d, "primal", "sign_event", 30078, "Sync app settings", 18, 30)
        });
        render(&format!("sign-urgent-{b}"), w, h, |d| {
            draw_sign(d, "primal", "sign_event", 30078, "Sync app settings", 4, 30)
        });
        render(&format!("confirm-{b}"), w, h, |d| draw_confirm(d, 60));
        render(&format!("approved-{b}"), w, h, |d| draw_result(d, "APPROVED", OK));
        render(&format!("denied-{b}"), w, h, |d| draw_result(d, "DENIED", DANGER));
        // The recovery walkthrough at its three captions, on every panel: the
        // caption sits between the rule and the word and must clear both.
        render(&format!("recovery-notice-{b}"), w, h, |d| {
            draw_recovery_prefix_notice(d)
        });
        render(&format!("recovery-format-{b}"), w, h, |d| {
            draw_recovery_word(d, 1, 19, "edge", "SAME ON EVERY KEY")
        });
        render(&format!("recovery-header-{b}"), w, h, |d| {
            draw_recovery_word(d, 3, 19, "dolphin", "HEADER, NOT SECRET")
        });
        render(&format!("recovery-secret-{b}"), w, h, |d| {
            draw_recovery_word(d, 19, 19, "tomorrow", "SECRET")
        });
        render(&format!("entry-letter-{b}"), w, h, |d| {
            draw_word_entry(d, 3, 19, "dol", false, "14 words match", "tap=next   hold=back")
        });
        render(&format!("entry-word-{b}"), w, h, |d| {
            draw_word_entry(d, 3, 19, "dolphin", true, "use this word", "tap=pick   hold=back")
        });
        render(&format!("entry-twobutton-{b}"), w, h, |d| {
            let l = Layout::new(w as i32, h as i32);
            let legend = if l.chars_per_line(l.font_small()) >= 34 {
                "A/B move  holdB pick  holdA back"
            } else {
                "A/B move  holdA back"
            };
            draw_word_entry(d, 3, 19, "dolphin", true, "use this word", legend)
        });
        render(&format!("entry-longest-{b}"), w, h, |d| {
            draw_word_entry(d, 3, 19, "announce", true, "use this word", "tap=pick   hold=back")
        });
        render(&format!("error-rng-wipe-{b}"), w, h, |d| {
            draw_error(d, "Power-cycle once\nthen generate")
        });
        render(&format!("error-rng-failed-{b}"), w, h, |d| {
            draw_error(d, "RNG self-test failed\nrefusing to generate")
        });
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

#[cfg(test)]
mod error_card_tests {
    use super::layout::Layout;

    /// `oled::show_error` draws its message in `font_body` from `sx(0)` and does
    /// NOT wrap: embedded-graphics honours the `\n` and silently clips anything
    /// wider than the panel. On the 128x64 mono OLED that is 18 glyphs, and five
    /// cards were over it — including the two that tell an owner whether their
    /// signer's RNG is trustworthy, which read "RNG self-test faile / refusing
    /// to generat" on real hardware (2026-09-12).
    ///
    /// This scans the firmware sources rather than a list of constants kept in
    /// step by hand, so a card added in any module is covered the day it lands.
    /// Keep lines inside the budget or give the card its own screen; do not
    /// widen this test.
    #[test]
    fn no_show_error_card_is_clipped_on_the_narrowest_panel() {
        let l = Layout::new(Layout::BASE_W, Layout::BASE_H);
        let budget = l.chars_per_line(l.font_body());
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../firmware/src");

        let mut checked = 0usize;
        let mut offenders: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(dir).expect("firmware/src is readable") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let source = std::fs::read_to_string(&path).expect("source is readable");
            for call in source.match_indices("show_error(") {
                let rest = &source[call.0 + "show_error(".len()..];
                let region = &rest[..rest.find(");").map(|i| i.min(400)).unwrap_or(400.min(rest.len()))];
                for literal in string_literals(region) {
                    for line in literal.split("\\n") {
                        checked += 1;
                        if line.chars().count() > budget {
                            offenders.push(format!(
                                "{name}: {} chars (budget {budget}): {line:?}",
                                line.chars().count()
                            ));
                        }
                    }
                }
            }
        }

        assert!(checked > 0, "scan found no show_error literals — the parser has drifted");
        assert!(offenders.is_empty(), "clipped error cards:\n  {}", offenders.join("\n  "));
    }

    /// `oled::show_sign_request` dropped its `_content_preview` and drew "HOLD
    /// TO SIGN" over a kind name, so a destructive card built on it hides what
    /// the hold does. The factory reset card read "HOLD TO SIGN / Factory /
    /// Profile / kind 0" and never showed the word ERASE; the removal-journal
    /// wipe card made the same mistake and cost an owner every key
    /// (2026-08-19). The renderer is gone; this stops it, or a caller of the
    /// old name, coming back. Signing screens use `show_sign_request_as`.
    #[test]
    fn no_card_is_drawn_with_the_preview_dropping_sign_renderer() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../firmware/src");
        let mut offenders: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(dir).expect("firmware/src is readable") {
            let path = entry.expect("dir entry").path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") || name == "oled.rs" {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("source is readable");
            for (at, _) in source.match_indices("show_sign_request(") {
                let line = source[..at].lines().count() + 1;
                offenders.push(format!("{name}:{line}"));
            }
        }
        assert!(offenders.is_empty(), "cards drawn with show_sign_request:\n  {}", offenders.join("\n  "));
    }

    /// The factory reset card must say it erases, in words drawn on screen.
    #[test]
    fn factory_reset_card_says_erase() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../firmware/src/provision.rs");
        let source = std::fs::read_to_string(path).expect("provision.rs is readable");
        let start = source.find("pub fn handle_factory_reset(").expect("handle_factory_reset exists");
        let body = &source[start..];
        let card = &body[..body.find("match result").expect("approval result is matched")];
        assert!(card.contains("show_titled_approval("), "factory reset card must use a titled renderer");
        assert!(
            string_literals(card).iter().any(|l| l.contains("ERASE ALL KEYS")),
            "factory reset card must say ERASE ALL KEYS in a drawn string, not a comment"
        );
    }

    /// The identity removal card must say it erases, in words drawn on screen.
    #[test]
    fn identity_removal_card_says_erase() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../firmware/src/provision.rs");
        let source = std::fs::read_to_string(path).expect("provision.rs is readable");
        let start = source.find("pub fn handle_remove(").expect("handle_remove exists");
        let body = &source[start..];
        let region = &body[..body.find("if !matches!(approval").expect("approval result is checked")];
        assert!(region.contains("show_titled_approval("), "removal card must use a titled renderer");
        assert!(
            string_literals(region).iter().any(|l| l.starts_with("ERASE slot")),
            "removal card must say ERASE slot N in a drawn string"
        );
    }

    /// Every double-quoted literal in `region`, returned without its quotes.
    /// Escaped quotes are skipped so `\"` does not end a literal early.
    fn string_literals(region: &str) -> Vec<String> {
        let bytes: Vec<char> = region.chars().collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == '"' {
                let mut j = i + 1;
                let mut lit = String::new();
                while j < bytes.len() && bytes[j] != '"' {
                    if bytes[j] == '\\' && j + 1 < bytes.len() {
                        lit.push(bytes[j]);
                        j += 1;
                    }
                    lit.push(bytes[j]);
                    j += 1;
                }
                out.push(lit);
                i = j + 1;
            } else {
                i += 1;
            }
        }
        out
    }
}

#[cfg(test)]
mod cable_card_tests {
    use heartwood_common::phone_unlock::{cable_frame_claim, CableClaim};
    use heartwood_common::types::{cable_frame_card, CableCard, FRAME_TYPE_PHONE_UNLOCK_CMD};
    use std::collections::HashMap;

    /// relay.rs helpers that take the whole context but only look after the
    /// screen's ownership; any other call handed bare `ctx` could reach the
    /// buttons.
    const SCREEN_HELPERS: &[&str] = &[
        "cable_card_refused",
        "approval_card_open",
        "screen_busy",
        "release_card_screen_hold",
        "hold_card_screen",
        "interrupt_held_result",
    ];

    /// Whether an arm's text can reach the button: `ctx.buttons`, the
    /// button module's globals, or a call (other than a screen helper) that
    /// is handed the whole context.
    fn reaches_button(text: &str) -> Option<String> {
        if text.contains("ctx.buttons") {
            return Some("ctx.buttons".into());
        }
        if text.contains("crate::button::") {
            return Some("crate::button::".into());
        }
        let bytes = text.as_bytes();
        let mut from = 0;
        while let Some(at) = text[from..].find("ctx") {
            let i = from + at;
            from = i + 3;
            let before = text[..i].trim_end();
            let after = text[i + 3..].trim_start();
            let bare = (before.ends_with('(') || before.ends_with(','))
                && (after.starts_with(',') || after.starts_with(')'))
                && !(i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_'));
            if !bare {
                continue;
            }
            // The function this argument list belongs to.
            let mut depth = 0i32;
            let mut open = None;
            for (j, c) in text[..i].char_indices().rev() {
                match c {
                    ')' => depth += 1,
                    '(' if depth == 0 => {
                        open = Some(j);
                        break;
                    }
                    '(' => depth -= 1,
                    _ => {}
                }
            }
            let name: String = open
                .map(|j| {
                    text[..j]
                        .chars()
                        .rev()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect()
                })
                .unwrap_or_default();
            let short = name.rsplit("::").next().unwrap_or(&name);
            if !SCREEN_HELPERS.contains(&short) {
                return Some(format!("{name}(ctx)"));
            }
        }
        None
    }

    /// Every arm of the WiFi loop's USB dispatch (relay.rs `poll_usb_frame`)
    /// that can reach the button may raise a card of its own, and a card
    /// answered with a relay card waiting leaves a hold that card would read
    /// as its own approval. So each such frame must be classified as
    /// card-raising in `types::cable_frame_card`, which the loop refuses
    /// "approval on screen" (or, for recovery frames, takes the screen over
    /// from) while a relay card is up; and the fall-through arm must not
    /// reach the button at all. Scans the source, so a new arm is covered the
    /// day it lands.
    #[test]
    fn every_cable_frame_handed_the_buttons_is_refused_under_a_relay_card() {
        let types = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../common/src/types.rs")).unwrap();
        let consts: HashMap<String, u8> = types
            .lines()
            .filter_map(|l| {
                let rest = l.trim().strip_prefix("pub const ")?;
                let (name, value) = rest.split_once(": u8 = ")?;
                let hex = value.split(';').next()?.trim().strip_prefix("0x")?;
                Some((name.to_string(), u8::from_str_radix(hex, 16).ok()?))
            })
            .collect();
        let relay = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../firmware/src/relay.rs")).unwrap();
        let start = relay.find("fn poll_usb_frame(").expect("poll_usb_frame is in relay.rs");
        let body = &relay[start..start + relay[start..].find("\n}\n").unwrap()];
        let dispatch = &body[body.find("    match frame.frame_type {").expect("the dispatch match")..];
        // Arms start at eight spaces of indent with a frame name, or the
        // fall-through `other =>`; each runs to the next.
        let mut arms: Vec<String> = Vec::new();
        for line in dispatch.lines().skip(1) {
            if line.starts_with("        FRAME_TYPE_") || line.starts_with("        other =>") {
                arms.push(String::new());
            }
            if let Some(arm) = arms.last_mut() {
                arm.push_str(line);
                arm.push('\n');
            }
        }
        let mut checked = 0;
        let mut saw_fallthrough = false;
        for arm in &arms {
            let reach = reaches_button(arm);
            if arm.starts_with("        other =>") {
                saw_fallthrough = true;
                assert_eq!(reach, None, "the fall-through arm reaches the button");
                continue;
            }
            let pattern = &arm[..arm.find("=>").expect("an arm has =>")];
            for name in pattern
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|w| w.starts_with("FRAME_TYPE_"))
            {
                let value = *consts.get(name).unwrap_or_else(|| panic!("{name} not in types.rs"));
                checked += 1;
                if let Some(how) = &reach {
                    assert_ne!(cable_frame_card(value), CableCard::Never, "{name} reaches the button via {how}");
                }
            }
        }
        assert!(saw_fallthrough, "the fall-through arm was not found");
        assert!(checked >= 35, "scan found {checked} frames: the parser has drifted");

        // The phone commands split: only a valid enrolment raises a card.
        let pk = "ab".repeat(32);
        let enrol = format!(r#"{{"op":"enrol","enrol_pubkey":"{pk}"}}"#);
        assert_eq!(cable_frame_claim(FRAME_TYPE_PHONE_UNLOCK_CMD, enrol.as_bytes()), CableClaim::Card);
        for other in [r#"{"op":"list"}"#, r#"{"op":"revoke","id":1}"#, r#"{"op":"set_announce_operator","on":false}"#] {
            assert_eq!(cable_frame_claim(FRAME_TYPE_PHONE_UNLOCK_CMD, other.as_bytes()), CableClaim::Free, "{other}");
        }
    }

    #[test]
    fn the_scan_sees_every_way_to_the_button() {
        assert!(reaches_button("x(usb, ctx.nvs, ctx.buttons)").is_some());
        assert!(reaches_button("crate::net_config_store::handle_get_net_config(usb, ctx)").is_some());
        assert!(reaches_button("handle(ctx, usb)").is_some());
        assert!(reaches_button("if crate::button::hold_ms() > 0 {}").is_some());
        assert_eq!(reaches_button("if cable_card_refused(ctx) {}"), None);
        assert_eq!(reaches_button("release_card_screen_hold(ctx, None)"), None);
        assert_eq!(reaches_button("x(usb, ctx.nvs, ctx.network_runtime)"), None);
        assert_eq!(reaches_button("let ctxs = 1; f(my_ctx)"), None);
    }
}

#[cfg(test)]
mod enrol_card_tests {
    use super::*;
    use std::collections::HashSet;

    fn lit(draw: impl Fn(&mut SimulatorDisplay<Rgb565>), w: u32, h: u32) -> Vec<Point> {
        let mut d = SimulatorDisplay::<Rgb565>::new(Size::new(w, h));
        d.clear(BG).ok();
        draw(&mut d);
        d.bounding_box()
            .points()
            .filter(|p| d.get_pixel(*p) != BG)
            .collect()
    }

    /// Every piece of the enrol card, drawn alone, shares no pixel with any
    /// other or with a button tag, and stays inside the span clear of the
    /// tags, on every panel and orientation, on every page, with the longest
    /// label and the widest words. The countdown bar is one of the pieces.
    #[test]
    fn the_enrol_card_never_overprints_a_tag_or_itself() {
        let widest: [&str; phone_unlock::REQUEST_CODE_WORDS] =
            ["abstract", "accident", "acoustic", "absolute", "activity"];
        let boards = [
            (128u32, 64u32, Some(HELTEC_TAGS)),
            (128, 64, Some(HELTEC_FLIPPED_TAGS)),
            (240, 135, Some(TDISPLAY_TAGS)),
            (172, 320, None),
            (320, 172, None),
        ];
        for (w, h, tags) in boards {
            let l = Layout::new(w as i32, h as i32);
            let side = tags.map(|t| t.side);
            for label in ["phone", "Pixel 8", "WWWWWWWWWWWWWWWW"] {
                // Every page, before and after the gate (the hint differs).
                for (page, elapsed, armed) in [(0, 0, false), (1, 4, false), (2, 8, false), (0, 12, true), (2, 44, true)] {
                    assert_eq!(phone_unlock::enrol_page(elapsed), page);
                    let items = enrol_items(&l, tags, &widest, label, elapsed, armed);
                    let mut layers: Vec<(String, Vec<Point>)> = items
                        .into_iter()
                        .map(|item| (item.0.clone(), lit(move |d| draw_item(d, &item), w, h)))
                        .collect();
                    let bar_l = l;
                    layers.push(("countdown bar".into(), lit(move |d| draw_enrol_bar(d, &bar_l, side, 45, 45), w, h)));
                    let (left, right) = l.text_span(side);
                    for (text, points) in &layers {
                        assert!(!points.is_empty(), "{w}x{h}: {text:?} drew nothing");
                        assert!(
                            points.iter().all(|p| p.x >= left && p.x < right && p.y >= 0 && p.y < h as i32),
                            "{w}x{h}: {text:?} leaves the span clear of the tags"
                        );
                    }
                    if let Some(tags) = tags {
                        for (text, colour, p) in tag_items(&l, tags) {
                            let font = l.font_small();
                            let t = text.clone();
                            layers.push((text, lit(move |d| { Text::new(&t, p, style(font, colour)).draw(d).ok(); }, w, h)));
                        }
                    }
                    let sets: Vec<HashSet<Point>> = layers.iter().map(|(_, points)| points.iter().copied().collect()).collect();
                    for i in 0..layers.len() {
                        for j in i + 1..layers.len() {
                            let clash = layers[i].1.iter().find(|p| sets[j].contains(p));
                            assert!(
                                clash.is_none(),
                                "{w}x{h} label {label:?} page {page}: {:?} and {:?} meet at {clash:?}",
                                layers[i].0,
                                layers[j].0
                            );
                        }
                    }
                }
            }
        }
    }

    /// On the Heltec the words are 12 px letters (FONT_6X10 at 2x), twice
    /// the old card's, with a clear row between every piece of the card.
    #[test]
    fn the_heltec_enrol_words_are_twice_the_old_size() {
        let l = Layout::new(128, 64);
        let rows = |item: Item| {
            let ys: Vec<i32> = lit(move |d| draw_item(d, &item), 128, 64).iter().map(|p| p.y).collect();
            (*ys.iter().min().unwrap(), *ys.iter().max().unwrap())
        };
        let items = enrol_items(&l, Some(HELTEC_TAGS), &["bight", "jury", "ok", "ok", "ok"], "phone", 0, false);
        let word = items.iter().find(|i| i.0 == "bight").unwrap().clone();
        assert_eq!((word.1.character_size.width, word.2), (6, 2));
        // Ascender to descender: 18 rows, where the old card's words had 9.
        let (top, bottom) = rows(word);
        assert_eq!(bottom - top + 1, 18);
        // One piece per row band: the place numbers share their word's rows
        // and the marker shares the seconds' row.
        let mut spans: Vec<(i32, i32)> =
            items.into_iter().filter(|i| i.0 != "1" && i.0 != "2" && i.0 != "1-2 of 5").map(rows).collect();
        spans.sort();
        for pair in spans.windows(2) {
            assert!(pair[1].0 > pair[0].1 + 1, "no clear row between {pair:?}");
        }
    }

    /// PHONE ADDED: the check code at the card words' size, every line on
    /// the panel and apart from the others and the header's rule.
    #[test]
    fn phone_added_keeps_its_lines_apart_on_every_panel() {
        for (w, h) in [(128u32, 64u32), (240, 135), (172, 320), (320, 172)] {
            let l = Layout::new(w as i32, h as i32);
            let items = phone_added_items(&l, "9B6 164", u32::MAX);
            assert_eq!(items[2].2, l.card_word_font(None).1, "{w}x{h}");
            let mut layers: Vec<(String, Vec<Point>)> =
                items.into_iter().map(|item| (item.0.clone(), lit(move |d| draw_item(d, &item), w, h))).collect();
            let rule_y = l.sy(14);
            layers.push(("rule".into(), (0..w as i32).map(|x| Point::new(x, rule_y)).collect()));
            for (text, points) in &layers {
                assert!(points.iter().all(|p| p.x >= 0 && p.x < w as i32 && p.y >= 0 && p.y < h as i32), "{w}x{h} {text}");
            }
            let sets: Vec<HashSet<Point>> = layers.iter().map(|(_, points)| points.iter().copied().collect()).collect();
            for i in 0..layers.len() {
                for j in i + 1..layers.len() {
                    let near = layers[i].1.iter().find(|p| (-1..=1).any(|dy| sets[j].contains(&Point::new(p.x, p.y + dy))));
                    assert!(near.is_none(), "{w}x{h}: {:?} and {:?} touch at {near:?}", layers[i].0, layers[j].0);
                }
            }
        }
    }

    /// The Heltec's top line holds 20 small-font characters clear of "<PRG",
    /// the value common's enrol_card tests pin.
    #[test]
    fn the_heltec_top_line_width_is_what_common_pins() {
        let l = Layout::new(128, 64);
        assert_eq!(l.span_chars(Some(TagSide::Left), l.font_small()), 20);
        let card = phone_unlock::enrol_card(
            &phone_unlock::request_words(&[0xAB; 32]),
            "WWWWWWWWWWWWWWWW",
            l.span_chars(Some(TagSide::Left), l.font_small()),
            0,
        );
        assert_eq!(card.top.len(), 20);
    }

    /// The layout's longest word and marker are the word list's and the
    /// marker function's, so the card can never be sized for less than it
    /// draws.
    #[test]
    fn the_layout_is_sized_for_the_longest_word_and_marker() {
        assert_eq!(Layout::LONGEST_WORD as usize, heartwood_common::spoken_words::WORDLIST_MAX_LEN);
        assert_eq!(Layout::ENROL_MARKER_CHARS as usize, phone_unlock::ENROL_MARKER_MAX_CHARS);
        let longest = (0..phone_unlock::ENROL_PAGES).map(|p| phone_unlock::enrol_page_marker(p).len()).max();
        assert_eq!(longest, Some(phone_unlock::ENROL_MARKER_MAX_CHARS));
    }

    /// PHONE ADDED fits its longest id on the narrowest panel.
    #[test]
    fn phone_added_fits_the_narrowest_panel() {
        let l = Layout::new(128, 64);
        let hint = format!("else revoke {}", u32::MAX);
        assert!(hint.len() <= l.chars_per_line(l.font_small()), "{hint}");
        let (font, scale) = l.card_word_font(None);
        assert!(bigtext::scaled_text_width("9B6 164", font, scale) <= l.w - l.sx(4));
    }
}
