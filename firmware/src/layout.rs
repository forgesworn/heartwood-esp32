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

    /// Glyph width of a mono font, for centring and character-fitting.
    pub fn glyph_w(font: &MonoFont) -> i32 {
        font.character_size.width as i32
    }

    /// How many glyphs of `font` fit across the panel.
    pub fn chars_per_line(&self, font: &MonoFont) -> usize {
        (self.w / Self::glyph_w(font)).max(1) as usize
    }
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
    fn c6_landscape_fills_both_axes() {
        let l = Layout::new(320, 172);
        // x scales 250%, y scales 268%: well-balanced landscape fill.
        // Glyphs scale by min(250, 268) = 250% — large font tier throughout.
        assert_eq!(l.sx(128), 320, "maps to the 320-wide edge (clipped by DrawTarget)");
        assert_eq!(l.sy(64), 171, "~fills the 172 height");
        assert!(l.large_tier(), "landscape steps fonts up (250% >= 130%)");
    }
}
