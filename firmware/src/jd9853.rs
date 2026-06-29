// firmware/src/jd9853.rs
//
// Raw SPI driver for the Jadard JD9853 display controller used on the
// Waveshare ESP32-C6-Touch-LCD-1.47 (172×320 IPS panel).
//
// The JD9853 is not supported by mipidsi, so this driver sends the vendor
// init sequence directly and then uses standard MIPI DCS commands (CASET /
// RASET / RAMWR) for pixel writes. The public interface mirrors St7789Display
// so oled.rs can use it unchanged.

use core::convert::Infallible;

use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;

use esp_idf_hal::delay::FreeRtos;
use esp_idf_hal::gpio::{Output, PinDriver};
use esp_idf_hal::ledc::LedcDriver;
use esp_idf_hal::spi::{SpiDeviceDriver, SpiDriver};

// Panel dimensions (visible window into the 240×320 controller).
const W: u16 = 172;
const H: u16 = 320;
const X_OFFSET: u16 = 34; // (240 - 172) / 2
const Y_OFFSET: u16 = 0;

type Spi<'a> = SpiDeviceDriver<'a, SpiDriver<'a>>;

#[derive(Debug)]
pub struct Jd9853Error;

/// JD9853 display presented as a mono DrawTarget over a big-endian RGB565
/// byte framebuffer. Drop-in for St7789Display on the Waveshare C6 board.
pub struct Jd9853Display<'a> {
    spi: Spi<'a>,
    dc: PinDriver<'a, Output>,
    backlight: LedcDriver<'a>,
    // Framebuffer: W*H pixels stored as big-endian RGB565 bytes (2 bytes/pixel).
    framebuffer: Vec<u8>,
}

impl<'a> Jd9853Display<'a> {
    pub fn new(
        spi: Spi<'a>,
        dc: PinDriver<'a, Output>,
        mut rst: PinDriver<'a, Output>,
        mut backlight: LedcDriver<'a>,
    ) -> Self {
        // Hardware reset: RST=GPIO22, active-low pulse.
        rst.set_low().ok();
        FreeRtos::delay_ms(10);
        rst.set_high().ok();
        FreeRtos::delay_ms(120);
        // RST is leaked: must stay HIGH for the display's lifetime.
        core::mem::forget(rst);

        let mut disp = Self {
            spi,
            dc,
            backlight,
            framebuffer: vec![0u8; (W as usize) * (H as usize) * 2],
        };

        disp.send_init();

        // Backlight on at full brightness via LEDC PWM (GPIO23).
        let max = disp.backlight.get_max_duty();
        disp.backlight.set_duty(max).ok();

        // Diagnostic: fill red — shows as cyan with INVON active.
        disp.framebuffer.chunks_exact_mut(2).for_each(|b| {
            b[0] = 0xF8;
            b[1] = 0x00;
        });
        disp.flush().ok();

        disp
    }

    fn cmd(&mut self, c: u8) {
        self.dc.set_low().ok();
        self.spi.write(&[c]).ok();
    }

    fn data(&mut self, d: &[u8]) {
        if d.is_empty() { return; }
        self.dc.set_high().ok();
        // 512-byte chunks: matches mipidsi's scratch-buffer size and is known
        // to work with the ESP-IDF SPI FIFO without requiring an explicit DMA
        // channel (writes larger than the FIFO hang on C6 without DMA).
        for chunk in d.chunks(512) {
            self.spi.write(chunk).ok();
        }
    }

    fn cd(&mut self, c: u8, d: &[u8]) {
        self.cmd(c);
        self.data(d);
    }

    fn send_init(&mut self) {
        // JD9853 vendor-specific init sequence (from Waveshare reference BSP).
        self.cd(0x11, &[]);                                     // Sleep out
        FreeRtos::delay_ms(120);

        self.cd(0xDF, &[0x98, 0x53]);                          // Unlock (×2)
        self.cd(0xDF, &[0x98, 0x53]);
        self.cd(0xB2, &[0x23]);
        self.cd(0xB7, &[0x00, 0x47, 0x00, 0x6F]);
        self.cd(0xBB, &[0x1C, 0x1A, 0x55, 0x73, 0x63, 0xF0]);
        self.cd(0xC0, &[0x44, 0xA4]);
        self.cd(0xC1, &[0x16]);
        self.cd(0xC3, &[0x7D, 0x07, 0x14, 0x06, 0xCF, 0x71, 0x72, 0x77]);
        self.cd(0xC4, &[0x00, 0x00, 0xA0, 0x79, 0x0B, 0x0A, 0x16,
                         0x79, 0x0B, 0x0A, 0x16, 0x82]);
        // Gamma (positive + negative, 16 bytes each).
        self.cd(0xC8, &[
            0x3F, 0x32, 0x29, 0x29, 0x27, 0x2B, 0x27, 0x28,
            0x28, 0x26, 0x25, 0x17, 0x12, 0x0D, 0x04, 0x00,
            0x3F, 0x32, 0x29, 0x29, 0x27, 0x2B, 0x27, 0x28,
            0x28, 0x26, 0x25, 0x17, 0x12, 0x0D, 0x04, 0x00,
        ]);
        self.cd(0xD0, &[0x04, 0x06, 0x6B, 0x0F, 0x00]);
        self.cd(0xD7, &[0x00, 0x30]);
        self.cd(0xE6, &[0x14]);

        // Page 1 registers.
        self.cd(0xDE, &[0x01]);
        self.cd(0xB7, &[0x03, 0x13, 0xEF, 0x35, 0x35]);
        self.cd(0xC1, &[0x14, 0x15, 0xC0]);
        self.cd(0xC2, &[0x06, 0x3A]);
        self.cd(0xC4, &[0x72, 0x12]);
        self.cd(0xBE, &[0x00]);

        // Page 2 registers.
        self.cd(0xDE, &[0x02]);
        self.cd(0xE5, &[0x00, 0x02, 0x00]);
        self.cd(0xE5, &[0x01, 0x02, 0x00]);

        // Back to page 0.
        self.cd(0xDE, &[0x00]);

        self.cd(0x35, &[0x00]);             // Tearing effect line on
        self.cd(0x3A, &[0x05]);             // Interface pixel format: RGB565
        // Column address set: 34–205 (172 px wide).
        self.cd(0x2A, &[0x00, X_OFFSET as u8,
                         0x00, (X_OFFSET + W - 1) as u8]);
        // Row address set: 0–319.
        self.cd(0x2B, &[0x00, Y_OFFSET as u8,
                         ((Y_OFFSET + H - 1) >> 8) as u8,
                         ((Y_OFFSET + H - 1) & 0xFF) as u8]);

        // Page 2 again (reference firmware repeats this after 2A/2B).
        self.cd(0xDE, &[0x02]);
        self.cd(0xE5, &[0x00, 0x02, 0x00]);
        self.cd(0xDE, &[0x00]);

        // Color inversion on (matches reference BSP invert_color=true).
        // Without this command the panel shows near-zero contrast (invisible content).
        self.cd(0x21, &[]);

        self.cd(0x29, &[]);                 // Display on
    }

    /// Clear the back-buffer to black.
    pub fn clear_buffer(&mut self) {
        self.framebuffer.fill(0x00);
    }

    /// Blit the back-buffer to the panel.
    pub fn flush(&mut self) -> Result<(), Jd9853Error> {
        // Set column window.
        self.cd(0x2A, &[0x00, X_OFFSET as u8,
                         0x00, (X_OFFSET + W - 1) as u8]);
        // Set row window.
        self.cd(0x2B, &[0x00, Y_OFFSET as u8,
                         ((Y_OFFSET + H - 1) >> 8) as u8,
                         ((Y_OFFSET + H - 1) & 0xFF) as u8]);
        // RAM write command byte (DC low), then pixel data (DC high).
        // Inline the pixel send to allow split borrows: the borrow checker
        // rejects self.data(&self.framebuffer.clone()) because the clone()
        // immutably borrows self while data() needs &mut self simultaneously.
        self.dc.set_low().ok();
        self.spi.write(&[0x2C]).ok();
        self.dc.set_high().ok();
        for chunk in self.framebuffer.chunks(512) {
            self.spi.write(chunk).ok();
        }
        Ok(())
    }

    /// Turn the backlight on (full brightness) or off via LEDC.
    pub fn set_display_on(&mut self, on: bool) -> Result<(), Jd9853Error> {
        if on {
            let max = self.backlight.get_max_duty();
            self.backlight.set_duty(max).ok();
        } else {
            self.backlight.set_duty(0).ok();
        }
        Ok(())
    }
}

impl OriginDimensions for Jd9853Display<'_> {
    fn size(&self) -> Size {
        Size::new(W as u32, H as u32)
    }
}

impl DrawTarget for Jd9853Display<'_> {
    type Color = BinaryColor;
    type Error = Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        let (w, h) = (W as i32, H as i32);
        for Pixel(p, colour) in pixels {
            if p.x >= 0 && p.y >= 0 && p.x < w && p.y < h {
                let idx = (p.y * w + p.x) as usize * 2;
                // BinaryColor::On → white (0xFFFF), Off → black (0x0000).
                let (hi, lo) = match colour {
                    BinaryColor::On => (0xFF, 0xFF),
                    BinaryColor::Off => (0x00, 0x00),
                };
                self.framebuffer[idx] = hi;
                self.framebuffer[idx + 1] = lo;
            }
        }
        Ok(())
    }
}
