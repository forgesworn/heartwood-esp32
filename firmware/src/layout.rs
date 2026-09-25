// firmware/src/layout.rs
//
// Board-aware screen geometry.
//
// The screen-drawing code was written for the 128x64 mono OLED. To make the
// same code render well on the larger colour TFTs (T-Display 240x135, C6
// 172x320) without a bespoke layout per panel, every coordinate is expressed
// relative to a [`Layout`] derived from the live display size.
//
// The mapping scales positions per-axis and glyphs uniformly:
//
//   * `sx` scales x by width/128 and `sy` scales y by height/64, so the layout
//     fills BOTH dimensions of whatever panel it is on -- a tall portrait panel
//     spreads its rows down the full height rather than letterboxing;
//   * glyphs and square features (`s`) scale by the SMALLER of the two axis
//     factors, so text is never stretched, only repositioned -- and a larger
//     panel steps up to a bigger font tier so text is crisp at native
//     resolution (not upscaled);
//   * at 128x64 every factor is exactly 1, so `sx`/`sy`/`s` are the identity
//     and the baseline fonts are chosen -- the mono OLED renders pixel-for-pixel
//     as before, so the Heltec boards are unchanged by construction.
//
// This module has no esp-idf dependencies on purpose: it is shared verbatim by
// the host-side `ui-preview` tool so layouts can be rendered to PNG and checked
// visually.

use embedded_graphics::mono_font::{ascii, MonoFont};

/// Geometry for the active panel, derived from its pixel size.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    /// Panel width in pixels.
    pub w: i32,
    /// Panel height in pixels.
    pub h: i32,
    /// X-position scale from the 128-wide baseline, in percent (100 = 1.0x).
    fx: i32,
    /// Y-position scale from the 64-tall baseline, in percent.
    fy: i32,
    /// Glyph / square-feature scale = min(fx, fy), so text is never stretched.
    fs: i32,
}

impl Layout {
    /// The baseline canvas every screen was authored against.
    pub const BASE_W: i32 = 128;
    pub const BASE_H: i32 = 64;

    /// Build the layout for a panel of `w` x `h` pixels.
    pub fn new(w: i32, h: i32) -> Self {
        let fx = (w * 100 / Self::BASE_W).max(1);
        let fy = (h * 100 / Self::BASE_H).max(1);
        Self {
            w,
            h,
            fx,
            fy,
            fs: fx.min(fy),
        }
    }

    /// Map a baseline x-coordinate to a panel x-coordinate (width-scaled).
    /// Identity at 128 wide.
    pub fn sx(&self, x: i32) -> i32 {
        x * self.fx / 100
    }

    /// Map a baseline y-coordinate to a panel y-coordinate (height-scaled, so
    /// rows spread to fill the panel). Identity at 64 tall.
    pub fn sy(&self, y: i32) -> i32 {
        y * self.fy / 100
    }

    /// Scale a glyph-relative / square length (uniform, undistorted). Identity
    /// at the baseline. Never zero so 1px rules stay visible.
    pub fn s(&self, len: i32) -> i32 {
        (len * self.fs / 100).max(if len > 0 { 1 } else { 0 })
    }

    /// X for left-aligning content of pixel width `content_w` centred on the
    /// panel.
    pub fn center_x(&self, content_w: i32) -> i32 {
        ((self.w - content_w) / 2).max(0)
    }

    /// Whether the panel is large enough to justify the doubled font tier.
    /// Threshold chosen so the C6 (134%) and T-Display (187%) both step up,
    /// while the mono OLED (100%) keeps its original fonts.
    fn large_tier(&self) -> bool {
        self.fs >= 130
    }

    /// True on the colour TFTs (large font tier), false on the mono OLED. Lets
    /// screens choose a bigger font where the panel has room for it.
    pub fn is_large(&self) -> bool {
        self.large_tier()
    }

    /// Footer / fine-print font (baseline FONT_5X8).
    pub fn font_small(&self) -> &'static MonoFont<'static> {
        if self.large_tier() {
            &ascii::FONT_7X14
        } else {
            &ascii::FONT_5X8
        }
    }

    /// Section-header font (baseline FONT_6X10).
    pub fn font_header(&self) -> &'static MonoFont<'static> {
        if self.large_tier() {
            &ascii::FONT_10X20
        } else {
            &ascii::FONT_6X10
        }
    }

    /// Body font (baseline FONT_7X14).
    pub fn font_body(&self) -> &'static MonoFont<'static> {
        if self.large_tier() {
            &ascii::FONT_10X20
        } else {
            &ascii::FONT_7X14
        }
    }

    /// Headline font (baseline FONT_10X20 -- already the largest mono ascii
    /// font, so it does not grow further).
    pub fn font_large(&self) -> &'static MonoFont<'static> {
        &ascii::FONT_10X20
    }

    /// Integer magnification for the ONE word a screen exists to show — a
    /// recovery word being written down, or picked during a restore.
    ///
    /// The built-in ascii fonts stop at FONT_10X20, so [`Self::font_large`]
    /// cannot grow on a colour panel: the same 20px glyphs that fill a third of
    /// the 128x64 OLED occupy a fifteenth of the 172x320 C6. Scaling is bounded
    /// by WIDTH, not height — the longest BIP-39 English word is 8 characters
    /// and must still fit inside the side margins, which gives 1x on the mono
    /// OLED and 2x on both colour panels.
    pub fn word_scale(&self) -> i32 {
        const LONGEST_WORD: i32 = 8;
        let usable = self.w - self.sx(4) * 2;
        (usable / (LONGEST_WORD * Self::glyph_w(self.font_large()))).clamp(1, 3)
    }

    /// Glyph width of a mono font, for centring and character-fitting.
    pub fn glyph_w(font: &MonoFont) -> i32 {
        font.character_size.width as i32
    }

    /// How many glyphs of `font` fit across the panel.
    pub fn chars_per_line(&self, font: &MonoFont) -> usize {
        (self.w / Self::glyph_w(font)).max(1) as usize
    }

    /// Width the button tags ("<PRG", "YES>", "NO>": four small-font glyphs
    /// at most) take on their edge: the text, its inset from the edge, and a
    /// gap before anything else may start.
    pub fn tag_band(&self) -> i32 {
        4 * Self::glyph_w(self.font_small()) + self.s(1) + self.s(2)
    }

    /// The x span, `[left, right)`, that text may use on a card whose button
    /// tags sit on `side`, keeping clear of them at every height. With no tags,
    /// a small margin each side.
    pub fn text_span(&self, side: Option<TagSide>) -> (i32, i32) {
        let margin = self.s(2);
        match side {
            Some(TagSide::Left) => (self.tag_band(), self.w - margin),
            Some(TagSide::Right) => (margin, self.w - self.tag_band()),
            None => (margin, self.w - margin),
        }
    }

    /// How many glyphs of `font` fit in [`text_span`](Self::text_span).
    pub fn span_chars(&self, side: Option<TagSide>, font: &MonoFont) -> usize {
        let (left, right) = self.text_span(side);
        ((right - left) / Self::glyph_w(font)).max(0) as usize
    }

    /// X for content `content_w` wide, centred in [`text_span`](Self::text_span).
    pub fn center_in_span(&self, side: Option<TagSide>, content_w: i32) -> i32 {
        let (left, right) = self.text_span(side);
        left + ((right - left - content_w) / 2).max(0)
    }
}

/// Where the enrol card draws on a panel (oled.rs `show_enrol_approval`,
/// mirrored and pixel-checked in ui-preview). Rows are baselines on the
/// 128x64 canvas, spread by [`Layout::sy`]: on the Heltec the top line's ink
/// is rows 0-7, the two word lines 9-26 and 28-45, the hint 47-54 and the
/// countdown 57-62.
#[derive(Clone, Copy, Debug)]
pub struct EnrolGeometry {
    /// The words' font, drawn at `word_scale` (bigtext.rs).
    pub word_font: &'static MonoFont<'static>,
    pub word_scale: i32,
    /// Left edge of each line's place number (small font) and of its word:
    /// one block, a number column then the words left-aligned after it,
    /// centred in the span clear of the tags as wide as the longest word.
    pub number_x: i32,
    pub word_x: i32,
    /// Baselines: the top line, the two word lines, the hint.
    pub top_y: i32,
    pub word_y: [i32; 2],
    pub hint_y: i32,
    /// The countdown bar (x, y, width, height), and the baseline and left
    /// edge of its seconds, all inside the span.
    pub bar: (i32, i32, i32, i32),
    pub secs_x: i32,
    pub secs_y: i32,
}

impl Layout {
    /// Letters in the longest word a card may show (spoken-token's en-v1
    /// list: `heartwood_common::spoken_words::WORDLIST_MAX_LEN`).
    pub const LONGEST_WORD: i32 = 8;

    /// Width of a place number and the gap after it.
    fn number_band(&self) -> i32 {
        Self::glyph_w(self.font_small()) + self.s(2)
    }

    /// The largest word font for a card whose lines are a place number and
    /// one word, across `side`'s span: the header font at 3x or 2x, else the
    /// small font at 2x, else the header font as it is. On the Heltec that is
    /// FONT_6X10 at 2x (a place, a gap and eight letters fill its 103 px span
    /// exactly), 12 px letters with 2 px strokes where the old card drew
    /// 6 px ones two words a line.
    pub fn card_word_font(&self, side: Option<TagSide>) -> (&'static MonoFont<'static>, i32) {
        let (left, right) = self.text_span(side);
        let room = right - left - self.number_band();
        [(self.font_header(), 3), (self.font_header(), 2), (self.font_small(), 2)]
            .into_iter()
            .find(|(font, scale)| Self::LONGEST_WORD * Self::glyph_w(font) * scale <= room)
            .unwrap_or((self.font_header(), 1))
    }

    /// The enrol card's geometry with the button tags on `side`.
    pub fn enrol_geometry(&self, side: Option<TagSide>) -> EnrolGeometry {
        let (word_font, word_scale) = self.card_word_font(side);
        let block = self.number_band() + Self::LONGEST_WORD * Self::glyph_w(word_font) * word_scale;
        let number_x = self.center_in_span(side, block);
        let (left, right) = self.text_span(side);
        let secs_w = 3 * Self::glyph_w(self.font_small());
        let bar_h = self.s(6);
        let bar_y = self.sy(57);
        EnrolGeometry {
            word_font,
            word_scale,
            number_x,
            word_x: number_x + self.number_band(),
            top_y: self.sy(6),
            word_y: [self.sy(21), self.sy(40)],
            hint_y: self.sy(53),
            bar: (left, bar_y, right - left - secs_w - self.s(2), bar_h),
            secs_x: right - secs_w,
            secs_y: bar_y + bar_h,
        }
    }
}

/// Which edge of the panel carries the button tags (oled.rs
/// `draw_button_tags`), once the screen's orientation is taken into account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagSide {
    Left,
    Right,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_at_baseline() {
        // The Heltec non-regression guarantee: at 128x64 the mapping is the
        // identity and the original fonts are selected.
        let l = Layout::new(128, 64);
        for v in [0, 1, 2, 10, 14, 40, 63, 64, 100, 127, 128] {
            assert_eq!(l.sx(v), v, "sx must be identity at base");
        }
        for v in [0, 1, 10, 14, 30, 52, 62, 63, 64] {
            assert_eq!(l.sy(v), v, "sy must be identity at base");
        }
        assert_eq!(l.s(1), 1);
        assert_eq!(l.s(128), 128);
        assert_eq!(l.center_x(100), 14); // (128-100)/2, matches existing screens
        assert_eq!(l.font_small().character_size.width, 5);
        assert_eq!(l.font_header().character_size.width, 6);
        assert_eq!(l.font_body().character_size.width, 7);
        assert_eq!(l.font_large().character_size.width, 10);
    }

    #[test]
    fn tdisplay_fills_both_axes_and_steps_up_fonts() {
        let l = Layout::new(240, 135);
        assert_eq!(l.sx(128), 239, "fills the 240 width");
        assert_eq!(l.sy(64), 134, "fills the 135 height — no letterbox");
        assert!(l.large_tier(), "240x135 uses the large font tier");
        assert_eq!(l.font_header().character_size.width, 10);
    }

    #[test]
    fn word_scale_grows_on_colour_panels_and_always_fits_eight_glyphs() {
        // The mono OLED must stay exactly as it was; the colour panels must
        // grow. Whatever the scale, the longest BIP-39 word has to fit.
        for (w, h, expected) in [
            (128, 64, 1),
            (240, 135, 2),
            (172, 320, 2), // portrait C6: width-bound at 2x
            (320, 172, 3), // landscape C6: 320px of width affords 3x
        ] {
            let l = Layout::new(w, h);
            assert_eq!(l.word_scale(), expected, "{w}x{h} word scale");
            let widest = 8 * Layout::glyph_w(l.font_large()) * l.word_scale();
            assert!(widest <= w, "{w}x{h}: an 8-letter word ({widest}px) overflows");
        }
    }

    #[test]
    fn text_keeps_clear_of_the_button_tags() {
        // Heltec: "<PRG" on the left, 4 x 5 px + 1 inset + 2 gap.
        let heltec = Layout::new(128, 64);
        assert_eq!(heltec.tag_band(), 23);
        assert_eq!(heltec.text_span(Some(TagSide::Left)), (23, 126));
        assert_eq!(heltec.span_chars(Some(TagSide::Left), heltec.font_small()), 20);
        assert_eq!(heltec.span_chars(None, heltec.font_small()), 24);
        assert_eq!(heltec.center_in_span(Some(TagSide::Left), 100), 24);
        // T-Display: "NO>" and "YES>" on the right.
        let tdisplay = Layout::new(240, 135);
        let (left, right) = tdisplay.text_span(Some(TagSide::Right));
        assert_eq!(right, 240 - tdisplay.tag_band());
        assert!(left < right);
        // Whatever the panel and side, a centred line never reaches the band.
        for (w, h) in [(128, 64), (240, 135), (172, 320), (320, 172)] {
            let l = Layout::new(w, h);
            for side in [Some(TagSide::Left), Some(TagSide::Right), None] {
                let (left, right) = l.text_span(side);
                let chars = l.span_chars(side, l.font_small()) as i32;
                let width = chars * Layout::glyph_w(l.font_small());
                let x = l.center_in_span(side, width);
                assert!(x >= left && x + width <= right, "{w}x{h} {side:?}");
            }
        }
    }

    #[test]
    fn the_enrol_card_words_are_as_large_as_the_span_allows() {
        // Heltec, tags either side (the screen turns through 180 degrees):
        // FONT_6X10 at 2x, a place number, a gap and eight letters filling
        // the span exactly.
        let heltec = Layout::new(128, 64);
        for side in [Some(TagSide::Left), Some(TagSide::Right)] {
            let g = heltec.enrol_geometry(side);
            assert_eq!((g.word_font.character_size.width, g.word_scale), (6, 2));
            let (left, right) = heltec.text_span(side);
            assert_eq!(g.number_x, left);
            assert_eq!(g.word_x + 8 * 6 * 2, right);
        }
        assert_eq!(heltec.enrol_geometry(Some(TagSide::Left)).word_y, [21, 40]);
        // T-Display: the 10x20 font at 2x. Portrait C6: its 7x14 at 2x.
        let t = Layout::new(240, 135).enrol_geometry(Some(TagSide::Right));
        assert_eq!((t.word_font.character_size.width, t.word_scale), (10, 2));
        let c6 = Layout::new(172, 320).enrol_geometry(None);
        assert_eq!((c6.word_font.character_size.width, c6.word_scale), (7, 2));
        // Every panel and side: the block and the countdown stay in the span,
        // and the rows run down the screen inside it.
        for (w, h) in [(128, 64), (240, 135), (172, 320), (320, 172)] {
            let l = Layout::new(w, h);
            for side in [Some(TagSide::Left), Some(TagSide::Right), None] {
                let g = l.enrol_geometry(side);
                let (left, right) = l.text_span(side);
                let word_w = 8 * Layout::glyph_w(g.word_font) * g.word_scale;
                assert!(g.number_x >= left && g.word_x + word_w <= right, "{w}x{h} {side:?}");
                let (bx, by, bw, bh) = g.bar;
                assert!(bx >= left && bx + bw < g.secs_x && g.secs_x + 15 <= right, "{w}x{h} {side:?}");
                assert!(g.top_y < g.word_y[0] && g.word_y[0] < g.word_y[1] && g.word_y[1] < g.hint_y);
                assert!(g.hint_y < by && by + bh <= h && g.secs_y <= h, "{w}x{h} {side:?}");
            }
        }
    }

    #[test]
    fn c6_landscape_fills_both_axes() {
        let l = Layout::new(320, 172);
        // x scales 250%, y scales 268%: well-balanced landscape fill.
        // Glyphs scale by min(250, 268) = 250% — large font tier throughout.
        assert_eq!(l.sx(128), 320, "maps to the 320-wide edge (clipped by DrawTarget)");
        assert_eq!(l.sy(64), 171, "~fills the 172 height");
        assert!(l.large_tier(), "landscape steps fonts up (250% >= 130%)");
    }
}
