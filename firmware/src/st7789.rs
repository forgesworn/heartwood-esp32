// firmware/src/st7789.rs
//
// Colour ST7789 TFT display backend.
//
// The Heltec boards drive a monochrome SSD1306 over I2C; the T-Display and
// ESP32-C6 boards drive a colour ST7789 over SPI. To keep the ~28 screen
// drawing functions in `oled.rs` completely backend-agnostic, this wrapper
// presents the *same* surface the SSD1306 buffered-graphics mode does:
//
//   * an embedded-graphics `DrawTarget<Color = BinaryColor>`, so the existing
//     mono drawing code (`Text`, `Rectangle`, `Pixel`, all in `BinaryColor`)
//     draws onto it untouched -- `On` maps to white, `Off`/cleared to black
//     (Phase A: a faithful mono look on a colour panel; semantic colour is a
//     later, additive change);
//   * `clear_buffer()` / `flush()` / `set_display_on()` inherent methods with
//     the same shapes the screens already call.
//
// Drawing goes into an in-RAM `Rgb565` framebuffer; `flush()` blits the whole
// frame to the panel in one sweep. That preserves the existing
// clear -> draw -> flush double-buffered model and avoids the flicker of
// clearing the panel directly before each redraw. RAM cost is `w * h * 2`
// bytes (240x135 -> 64.8 KB; 172x320 -> 110 KB), comfortably within the
// classic ESP32 / C6 SRAM budget.

use core::convert::Infallible;

use embedded_graphics::pixelcolor::{BinaryColor, Rgb565, RgbColor};
use embedded_graphics::prelude::*;

use esp_idf_hal::delay::Ets;
use esp_idf_hal::gpio::{Output, PinDriver};
use esp_idf_hal::spi::{SpiDeviceDriver, SpiDriver};

use mipidsi::interface::SpiInterface;
use mipidsi::models::ST7789;
use mipidsi::options::{ColorInversion, Orientation, Rotation};

/// The concrete SPI device the panel is driven through (bus + chip-select),
/// built from owned peripherals so it is `'a`-generic and instantiated
/// `'static` at bring-up.
type Spi<'a> = SpiDeviceDriver<'a, SpiDriver<'a>>;

/// mipidsi's 4-wire SPI command/data interface (SPI device + D/C pin + a
/// leaked scratch buffer it batches pixel writes through).
type Iface<'a> = SpiInterface<'a, Spi<'a>, PinDriver<'a, Output>>;

/// The fully-typed mipidsi ST7789 panel handle (interface + model + reset pin).
type Panel<'a> = mipidsi::Display<Iface<'a>, ST7789, PinDriver<'a, Output>>;

/// Error surfaced by [`St7789Display::flush`] / [`St7789Display::set_display_on`].
///
/// The SSD1306 backend's equivalent methods return their own driver error; the
/// screen code only ever `?`-discards or `{:?}`-logs these, so a small opaque
/// type with `Debug` is all that is needed to stay source-compatible.
#[derive(Debug)]
pub struct St7789Error;

/// Colour ST7789 display presented as a mono `DrawTarget` over an `Rgb565`
/// framebuffer. Drop-in for the SSD1306 `oled::Display` alias.
pub struct St7789Display<'a> {
    panel: Panel<'a>,
    /// Backlight pin (active high). Toggled for sleep/wake.
    backlight: PinDriver<'a, Output>,
    /// In-RAM frame, `w * h` pixels, blitted on `flush`.
    framebuffer: Vec<Rgb565>,
    width: i32,
    height: i32,
}

impl<'a> St7789Display<'a> {
    /// Initialise the panel and return a ready-to-draw display.
    ///
    /// `native_width`/`native_height` and the offsets are the panel's
    /// *unrotated* geometry (ST7789 controllers are 240x320; small panels
    /// expose a window into it via an offset); `rotation` then orients it.
    /// The logical drawing size (what the screens see) is taken from the
    /// initialised panel after rotation. `buffer` is mipidsi's SPI scratch
    /// space and must outlive the display (leak it at bring-up).
    ///
    /// Panics if the panel fails to initialise: a colour board with a dead
    /// panel is a dead device, and there is no `Display` to return otherwise.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        spi: Spi<'a>,
        dc: PinDriver<'a, Output>,
        rst: PinDriver<'a, Output>,
        mut backlight: PinDriver<'a, Output>,
        buffer: &'a mut [u8],
        native_width: u16,
        native_height: u16,
        x_offset: u16,
        y_offset: u16,
        rotation: Rotation,
    ) -> Self {
        let di = SpiInterface::new(spi, dc, buffer);
        let mut delay = Ets;
        let panel = mipidsi::Builder::new(ST7789, di)
            .reset_pin(rst)
            .display_size(native_width, native_height)
            .display_offset(x_offset, y_offset)
            .orientation(Orientation::new().rotate(rotation))
            // Most ST7789 panels (the T-Display included) ship with inverted
            // colours; without this whites read as blacks.
            .invert_colors(ColorInversion::Inverted)
            .init(&mut delay)
            .expect("ST7789 panel init failed");

        // Backlight on once the panel is initialised (avoids a flash of noise).
        backlight.set_high().ok();

        let size = panel.size();
        let (width, height) = (size.width as i32, size.height as i32);
        let framebuffer = vec![Rgb565::BLACK; (width * height) as usize];

        Self {
            panel,
            backlight,
            framebuffer,
            width,
            height,
        }
    }

    /// Clear the back buffer to black. Mirrors `Ssd1306::clear_buffer`.
    pub fn clear_buffer(&mut self) {
        self.framebuffer.fill(Rgb565::BLACK);
    }

    /// Blit the whole back buffer to the panel. Mirrors `Ssd1306::flush`.
    pub fn flush(&mut self) -> Result<(), St7789Error> {
        self.panel
            .set_pixels(
                0,
                0,
                (self.width - 1) as u16,
                (self.height - 1) as u16,
                self.framebuffer.iter().copied(),
            )
            .map_err(|_| St7789Error)
    }

    /// Turn the panel backlight on/off. Mirrors `Ssd1306::set_display_on` for
    /// the idle display-sleep path (cutting the backlight saves more power than
    /// the SSD1306 panel-off command and is instant).
    pub fn set_display_on(&mut self, on: bool) -> Result<(), St7789Error> {
        let r = if on {
            self.backlight.set_high()
        } else {
            self.backlight.set_low()
        };
        r.map_err(|_| St7789Error)
    }
}

impl OriginDimensions for St7789Display<'_> {
    fn size(&self) -> Size {
        Size::new(self.width as u32, self.height as u32)
    }
}

impl DrawTarget for St7789Display<'_> {
    type Color = BinaryColor;
    type Error = Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(p, colour) in pixels {
            // Clip to the panel; out-of-range pixels are silently dropped, as
            // the `DrawTarget` contract requires.
            if p.x >= 0 && p.y >= 0 && p.x < self.width && p.y < self.height {
                let idx = (p.y * self.width + p.x) as usize;
                self.framebuffer[idx] = match colour {
                    BinaryColor::On => Rgb565::WHITE,
                    BinaryColor::Off => Rgb565::BLACK,
                };
            }
        }
        Ok(())
    }
}
