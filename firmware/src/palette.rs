// firmware/src/palette.rs
//
// Semantic colour palette for the device UI.
//
// Shared *verbatim* by the firmware screens (`oled.rs`) and the host-side
// `ui-preview` tool (pulled in via `#[path]`, exactly like `layout.rs`), so the
// preview can never drift from what the device actually draws.
//
// Colours are `Rgb565` — the pixel format the colour panels (ST7789 / JD9853)
// store. On the mono SSD1306 boards the display backend thresholds every
// non-black colour to "on", so these semantics degrade to the existing
// white-on-black look with no per-screen changes. Keep `BG` the only black
// entry so that thresholding stays correct.
//
// Hues follow the ForgeSworn / Heartwood diagram palette (docs/architecture.md).
// Rgb565 channels are 5/6/5 bits, so each constant is the 8-bit hex right-
// shifted by 3 / 2 / 3.

// Not every colour is consumed by every board build (e.g. BG is only used by
// the mono threshold adapter) or every consumer (the host ui-preview uses all
// of them). This is a shared design palette, so allow unused constants.
#![allow(dead_code)]

use embedded_graphics::pixelcolor::Rgb565;

/// Background — always black. The mono threshold maps this (and only this) to
/// "off"; every other colour becomes "on" on the SSD1306 boards.
pub const BG: Rgb565 = Rgb565::new(0, 0, 0);

/// Default foreground: text, rules, outlines — soft near-white `#e8f4f8`.
pub const FG: Rgb565 = Rgb565::new(29, 61, 31);

/// Secondary / muted text and inactive tracks — grey `#737373`.
pub const MUTED: Rgb565 = Rgb565::new(14, 28, 14);

/// Brand accent for headers and identity — Heartwood green `#16a34a`.
pub const ACCENT: Rgb565 = Rgb565::new(2, 40, 9);

/// Success / approve / signed — green `#16a34a`.
pub const OK: Rgb565 = Rgb565::new(2, 40, 9);

/// Warning / caution — amber `#f59e0b`.
pub const WARN: Rgb565 = Rgb565::new(30, 39, 1);

/// Danger / deny / error — red `#ef4444`.
pub const DANGER: Rgb565 = Rgb565::new(29, 17, 8);

/// Deja-vu "ghost" cat in the boot animation — Bitcoin orange `#f7931a`.
pub const GHOST: Rgb565 = Rgb565::new(30, 36, 3);

/// Nostr brand purple `#8b5cf6` — the boot-animation cat.
pub const NOSTR: Rgb565 = Rgb565::new(17, 23, 30);
