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
    primitives::{Circle, PrimitiveStyle, Rectangle},
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

/// The enrol card's text, one entry per line: (text, font, colour, position).
/// Mirrors `oled::show_enrol_approval`: the top line and hint in the small
/// font, the words in the header font, all centred clear of the tags.
fn enrol_items(
    l: &Layout,
    tags: Option<Tags>,
    words: &[&str; phone_unlock::REQUEST_CODE_WORDS],
    label: &str,
) -> Vec<(String, &'static MonoFont<'static>, Rgb565, Point)> {
    let side = tags.map(|t| t.side);
    let card = phone_unlock::enrol_card(words, label, l.span_chars(side, l.font_small()));

    let at = |text: &str, font: &MonoFont<'_>, y: i32| {
        Point::new(l.center_in_span(side, text.len() as i32 * Layout::glyph_w(font)), l.sy(y))
    };
    let mut items = vec![(card.top.clone(), l.font_small(), ACCENT, at(&card.top, l.font_small(), 7))];
    let (span_left, span_right) = l.text_span(side);
    let widest = card.words.iter().map(|w| w.len()).max().unwrap_or(0) as i32;
    let word_font = if widest * Layout::glyph_w(l.font_header()) <= span_right - span_left {
        l.font_header()
    } else {
        l.font_small()
    };
    for (line, y) in card.words.iter().zip([17, 28, 39]) {
        items.push((line.clone(), word_font, WARN, at(line, word_font, y)));
    }
    // A tagged board's cancel button is its second one (T-Display); the
    // untagged C6 is drawn as a single-button board.
    let hint = phone_unlock::enrol_hint(tags.map(|t| t.cancel), tags.is_some_and(|t| t.cancel)).to_string();
    let p = at(&hint, l.font_small(), 49);
    items.push((hint, l.font_small(), MUTED, p));
    items
}

/// Add-an-unlock-phone card (mirrors `oled::show_enrol_approval`).
fn draw_enrol_card<D: DrawTarget<Color = Rgb565> + Dimensions>(
    d: &mut D,
    tags: Option<Tags>,
    words: &[&str; phone_unlock::REQUEST_CODE_WORDS],
    label: &str,
    secs: u32,
) {
    let l = layout_of(d);
    d.clear(BG).ok();
    for (text, font, colour, p) in enrol_items(&l, tags, words, label) {
        Text::new(&text, p, style(font, colour)).draw(d).ok();
    }
    if let Some(tags) = tags {
        for (text, colour, p) in tag_items(&l, tags) {
            Text::new(&text, p, style(l.font_small(), colour)).draw(d).ok();
        }
    }
    draw_countdown(d, &l, secs, 30);
}

/// PHONE ADDED (mirrors `oled::show_phone_added` through `show_status_card`).
fn draw_phone_added<D: DrawTarget<Color = Rgb565> + Dimensions>(d: &mut D, check: &str, id: u32) {
    draw_status_card(d, "PHONE ADDED", &format!("check {check}"), &format!("else revoke {id}"), OK);
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
    let boards = [("heltec", 128u32, 64u32), ("tdisplay", 240, 135), ("c6", 172, 320)];

    for (b, w, h) in boards {
        render(&format!("ready-{b}"), w, h, |d| draw_ready(d));
        let tags = match b {
            "heltec" => Some(HELTEC_TAGS),
            "tdisplay" => Some(TDISPLAY_TAGS),
            _ => None,
        };
        let words = phone_unlock::request_words(&[0xAB; 32]);
        render(&format!("enrol-{b}"), w, h, |d| draw_enrol_card(d, tags, &words, "Pixel 8", 24));
        render(&format!("enrol-longest-{b}"), w, h, |d| {
            draw_enrol_card(d, tags, &["abstract", "accident", "acoustic", "absolute", "activity"], "WWWWWWWWWWWWWWWW", 24)
        });
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
mod enrol_card_tests {
    use super::*;

    fn lit(draw: impl Fn(&mut SimulatorDisplay<Rgb565>), w: u32, h: u32) -> Vec<Point> {
        let mut d = SimulatorDisplay::<Rgb565>::new(Size::new(w, h));
        d.clear(BG).ok();
        draw(&mut d);
        d.bounding_box()
            .points()
            .filter(|p| d.get_pixel(*p) != BG)
            .collect()
    }

    /// Every line of the enrol card, drawn alone, shares no pixel with any
    /// other line or with a button tag, and stays inside the span clear of
    /// the tags, on every panel, with the longest label and the widest words.
    #[test]
    fn the_enrol_card_never_overprints_a_tag_or_itself() {
        let widest: [&str; phone_unlock::REQUEST_CODE_WORDS] =
            ["abstract", "accident", "acoustic", "absolute", "activity"];
        let boards = [
            (128u32, 64u32, Some(HELTEC_TAGS)),
            (240, 135, Some(TDISPLAY_TAGS)),
            (172, 320, None),
        ];
        for (w, h, tags) in boards {
            let l = Layout::new(w as i32, h as i32);
            for label in ["phone", "Pixel 8", "WWWWWWWWWWWWWWWW"] {
                let items = enrol_items(&l, tags, &widest, label);
                let mut layers: Vec<(String, Vec<Point>)> = items
                    .iter()
                    .map(|(text, font, colour, p)| {
                        let (text, font, colour, p) = (text.clone(), *font, *colour, *p);
                        (text.clone(), lit(move |d| { Text::new(&text, p, style(font, colour)).draw(d).ok(); }, w, h))
                    })
                    .collect();
                let (left, right) = l.text_span(tags.map(|t| t.side));
                for (text, points) in &layers {
                    assert!(!points.is_empty(), "{w}x{h}: {text:?} drew nothing");
                    assert!(
                        points.iter().all(|p| p.x >= left && p.x < right),
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
                for i in 0..layers.len() {
                    for j in i + 1..layers.len() {
                        let clash = layers[i].1.iter().find(|p| layers[j].1.contains(p));
                        assert!(
                            clash.is_none(),
                            "{w}x{h} label {label:?}: {:?} and {:?} meet at {clash:?}",
                            layers[i].0,
                            layers[j].0
                        );
                    }
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
        );
        assert_eq!(card.top.len(), 20);
    }

    /// PHONE ADDED fits its longest id on the narrowest panel.
    #[test]
    fn phone_added_fits_the_narrowest_panel() {
        let l = Layout::new(128, 64);
        let hint = format!("else revoke {}", u32::MAX);
        assert!(hint.len() <= l.chars_per_line(l.font_small()), "{hint}");
        let title = "check 9B6 164";
        assert!(title.len() as i32 * Layout::glyph_w(l.font_body()) <= l.w - l.sx(4));
    }
}
