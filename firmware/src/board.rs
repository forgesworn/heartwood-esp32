// firmware/src/board.rs
//
// Board hardware-abstraction seam.
//
// Each supported board fills in one cfg-gated `bringup()` body that wires up
// the display, the host serial transport, the button(s) and any housekeeping
// pins (LED, display power), and returns a uniform [`Hw`] the rest of the
// firmware drives without caring which board it is running on.
//
// Today's boards -- the Heltec WiFi LoRa 32 V3 and V4, both ESP32-S3 -- share
// an identical pin map and differ only in how USB-C reaches the chip (V4:
// native USB-Serial-JTAG on GPIO19/20; V3: a CP2102 bridge to UART0 on
// GPIO43/44). That one difference is normalised by `serial::SerialPort`.
//
// Adding a new board (e.g. the T-Display, classic ESP32 + ST7789, or the
// ESP32-C6) means adding one `#[cfg]` block here. `main.rs` never changes:
// it calls `board::bringup` once and consumes the returned handles.

use esp_idf_hal::gpio::{Input, PinDriver};
use esp_idf_hal::modem::Modem;
use esp_idf_hal::peripherals::Peripherals;

use crate::oled;
use crate::serial::SerialPort;

/// Board identifier, reported in `FIRMWARE_INFO` so the manager can match the
/// right firmware asset and version to the hardware in front of it.
#[cfg(feature = "heltec-v4")]
pub const BOARD: &str = "heltec-v4";
#[cfg(feature = "heltec-v3")]
pub const BOARD: &str = "heltec-v3";
#[cfg(feature = "tdisplay")]
pub const BOARD: &str = "tdisplay";
#[cfg(feature = "c6")]
pub const BOARD: &str = "esp32c6";

/// Initialised, board-agnostic hardware handles.
///
/// Every driver is built from the owned (`'static`) peripheral singletons, so
/// they outlive `bringup` and can be handed back here. Housekeeping pins that
/// must stay driven for the device's lifetime but are never read again (the
/// LED, the OLED power rail, the display reset) are leaked with
/// `core::mem::forget` inside `bringup`/`oled::init` rather than parked here,
/// so `Hw` holds only handles the firmware actively drives.
pub struct Hw {
    /// The display, ready to draw on (mono SSD1306 on the Heltec boards).
    pub display: oled::Display<'static>,
    /// Host transport carrying the binary frame protocol.
    pub serial: SerialPort<'static>,
    /// Primary / approval button (active-low, internal pull-up).
    pub button_a: PinDriver<'static, Input>,
    /// Second physical button where the board has one (e.g. the T-Display).
    /// `None` on single-button boards (Heltec, C6).
    pub button_b: Option<PinDriver<'static, Input>>,
    /// Radio modem, carried through untouched for the WiFi-standalone relay
    /// path. The radio stays off until a WiFi-configured device deliberately
    /// enters relay mode.
    pub modem: Modem<'static>,
}

/// Initialise all board hardware and return uniform handles.
///
/// Consumes the whole `Peripherals` bundle: constructs the display, transport
/// and button(s) from the pins this board uses, keeps the LED and
/// display-power pins driven, and carries the radio modem through for the
/// relay path. Peripherals this board does not use are simply dropped.
#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
pub fn bringup(p: Peripherals) -> Hw {
    use esp_idf_hal::delay::FreeRtos;
    use esp_idf_hal::gpio::Pull;
    use esp_idf_hal::i2c::{I2cConfig, I2cDriver};
    use esp_idf_hal::units::FromValueType;

    // White LED (GPIO35, active high).
    let mut led = PinDriver::output(p.pins.gpio35).expect("LED pin");
    led.set_high().ok();

    // Vext (GPIO36, active low) powers the OLED. It must be enabled before the
    // I2C bus is touched, with a short settle.
    let mut vext = PinDriver::output(p.pins.gpio36).expect("Vext pin");
    vext.set_low().ok();
    FreeRtos::delay_ms(50);

    // OLED on I2C0 (SDA GPIO17 / SCL GPIO18), reset on GPIO21.
    log::info!("Initialising OLED...");
    let i2c = I2cDriver::new(
        p.i2c0,
        p.pins.gpio17,
        p.pins.gpio18,
        &I2cConfig::new().baudrate(400.kHz().into()),
    )
    .expect("I2C init failed");
    let display = oled::init(i2c, p.pins.gpio21.into());
    log::info!("OLED init complete");

    // PRG button (GPIO0, active low, internal pull-up).
    let button_a = PinDriver::input(p.pins.gpio0, Pull::Up).expect("button pin");

    // Host transport. V4 drives the ESP32-S3 native USB-Serial-JTAG peripheral
    // (GPIO19 D- / GPIO20 D+, wired to the USB-C connector). V3 routes USB-C
    // through a CP2102 bridge to UART0 (GPIO43 TX / GPIO44 RX). The frame
    // protocol is identical -- `SerialPort` normalises the read/write API.
    #[cfg(feature = "heltec-v4")]
    let serial = {
        use esp_idf_hal::usb_serial::{UsbSerialConfig, UsbSerialDriver};
        let driver = UsbSerialDriver::new(
            p.usb_serial,
            p.pins.gpio19,
            p.pins.gpio20,
            &UsbSerialConfig::new().rx_buffer_size(4096).tx_buffer_size(4096),
        )
        .expect("USB serial driver init failed");
        SerialPort::from_usb(driver)
    };

    #[cfg(feature = "heltec-v3")]
    let serial = {
        use esp_idf_hal::gpio::AnyIOPin;
        use esp_idf_hal::uart::{config::Config as UartConfig, UartDriver};
        use esp_idf_hal::units::Hertz;
        let driver = UartDriver::new(
            p.uart0,
            p.pins.gpio43, // CP2102 RX (ESP32 TX)
            p.pins.gpio44, // CP2102 TX (ESP32 RX)
            None::<AnyIOPin>, // CTS -- unused
            None::<AnyIOPin>, // RTS -- unused
            &UartConfig::new().baudrate(Hertz(115_200)),
        )
        .expect("UART0 driver init failed");
        SerialPort::from_uart(driver)
    };

    // Keep the LED lit and the OLED power rail enabled for the device's
    // lifetime by leaking their drivers, exactly as `oled::init` leaks the
    // display reset pin. `main` never returns, so this is equivalent to
    // holding them in a never-dropped local; the leak just states the intent
    // and keeps `Hw` to handles the firmware actively drives.
    core::mem::forget(led);
    core::mem::forget(vext);

    Hw {
        display,
        serial,
        button_a,
        button_b: None,
        modem: p.modem,
    }
}

/// Bring up the LilyGO / TENSTAR T-Display: classic ESP32-D0WD, an ST7789
/// 240x135 colour TFT over SPI, two buttons, and a CH9102 USB-to-UART bridge
/// on UART0.
#[cfg(feature = "tdisplay")]
pub fn bringup(p: Peripherals) -> Hw {
    use esp_idf_hal::gpio::{AnyIOPin, Pull};
    use esp_idf_hal::spi::config::{Config as SpiConfig, DriverConfig as SpiDriverConfig};
    use esp_idf_hal::spi::SpiDeviceDriver;
    use esp_idf_hal::uart::{config::Config as UartConfig, UartDriver};
    use esp_idf_hal::units::{FromValueType, Hertz};
    use mipidsi::options::{ColorInversion, Rotation};

    // --- ST7789 colour TFT on SPI2 ---
    // SCLK=18, MOSI(SDA)=19, CS=5, DC=16, RST=23, backlight=4. The panel is
    // write-only, so there is no MISO.
    //
    // GPIO18/19/5 are the VSPI (SPI3) IO_MUX pins, not the SPI2 (HSPI) defaults,
    // so all three route through the GPIO matrix. ESP-IDF's SPI master rejects
    // full-duplex operation above 26.7 MHz (80 MHz ÷ 3) on matrix-routed pins.
    // 26 MHz rounds down to 80/3 = 26.67 MHz — the fastest the matrix allows —
    // and is still very fast for a write-only 240×135 panel.
    let spi = SpiDeviceDriver::new_single(
        p.spi2,
        p.pins.gpio18,      // SCLK
        p.pins.gpio19,      // MOSI / SDA
        None::<AnyIOPin>,   // MISO unused
        Some(p.pins.gpio5), // CS
        &SpiDriverConfig::new(),
        &SpiConfig::new().baudrate(26.MHz().into()),
    )
    .expect("ST7789 SPI init failed");
    let dc = PinDriver::output(p.pins.gpio16).expect("DC pin");
    let rst = PinDriver::output(p.pins.gpio23).expect("RST pin");
    let backlight = PinDriver::output(p.pins.gpio4).expect("backlight pin");

    // mipidsi's SPI scratch buffer must outlive the display; leak it (a one-off,
    // device-lifetime allocation, same rationale as the LED/Vext pins above).
    let spi_buffer: &'static mut [u8] = Box::leak(vec![0u8; 512].into_boxed_slice());

    // The ST7789 controller addresses 240x320; the T-Display panel is a 135x240
    // window into it (offsets 52,40) rotated 90 degrees to a 240x135 landscape
    // surface. Offsets/inversion are the canonical T-Display values; verify on
    // the actual TENSTAR clone.
    let display = crate::st7789::St7789Display::new(
        spi,
        dc,
        rst,
        backlight,
        spi_buffer,
        135, // native portrait width
        240, // native portrait height
        52,  // x offset
        40,  // y offset
        Rotation::Deg90,
        false,                    // T-Display backlight: active-high (direct drive)
        ColorInversion::Inverted, // T-Display panel ships with inverted colours
    );

    // --- Host transport: CH9102 USB-UART bridge on classic-ESP32 UART0 ---
    // (TX0 = GPIO1, RX0 = GPIO3).
    let serial = {
        let driver = UartDriver::new(
            p.uart0,
            p.pins.gpio1,     // TX0
            p.pins.gpio3,     // RX0
            None::<AnyIOPin>, // CTS unused
            None::<AnyIOPin>, // RTS unused
            &UartConfig::new().baudrate(Hertz(115_200)),
        )
        .expect("UART0 driver init failed");
        SerialPort::from_uart(driver)
    };

    // --- Buttons ---
    // A = GPIO0 (BOOT, has an internal pull-up; the approval/select button).
    // B = GPIO35 (input-only on the classic ESP32 -- no internal pull, relies on
    // the board's external pull-up; the cancel/back button).
    let button_a = PinDriver::input(p.pins.gpio0, Pull::Up).expect("button A");
    let button_b = PinDriver::input(p.pins.gpio35, Pull::Floating).expect("button B");

    Hw {
        display,
        serial,
        button_a,
        button_b: Some(button_b),
        modem: p.modem,
    }
}

/// Bring up the Waveshare ESP32-C6-LCD-1.47 (also sold as ESP32-C6-Touch-LCD-1.47):
/// ESP32-C6 (RISC-V rv32imac), a JD9853 172×320 portrait IPS panel over SPI, a
/// single BOOT button, and the chip's native USB-Serial-JTAG host transport.
///
/// Confirmed pin assignments (waveshare schematic + two independent community drivers):
///   SCLK=GPIO1, MOSI=GPIO2, CS=GPIO14, DC=GPIO15, RST=GPIO22, BL=GPIO23 (LEDC PWM)
///
/// The backlight IC requires LEDC PWM (5 kHz); plain GPIO HIGH does not enable it.
/// The display controller is JD9853 — NOT ST7789. See jd9853.rs for the init sequence.
#[cfg(feature = "c6")]
pub fn bringup(p: Peripherals) -> Hw {
    use esp_idf_hal::gpio::{AnyIOPin, Pull};
    use esp_idf_hal::ledc::{config::TimerConfig, LedcDriver, LedcTimerDriver};
    use esp_idf_hal::spi::config::{Config as SpiConfig, DriverConfig as SpiDriverConfig};
    use esp_idf_hal::spi::SpiDeviceDriver;
    use esp_idf_hal::units::FromValueType;

    // --- JD9853 IPS panel on SPI2 ---
    // GPIO1 (SCLK) and GPIO2 (MOSI) route through the GPIO matrix; 10 MHz is
    // a safe cap for matrix-routed pins during initial bring-up.
    let spi = SpiDeviceDriver::new_single(
        p.spi2,
        p.pins.gpio1,        // SCLK (LCD_CLK)
        p.pins.gpio2,        // MOSI (LCD_DIN)
        None::<AnyIOPin>,    // MISO unused (write-only panel)
        Some(p.pins.gpio14), // CS
        &SpiDriverConfig::new(),
        &SpiConfig::new().baudrate(10.MHz().into()),
    )
    .expect("JD9853 SPI init failed");
    let dc  = PinDriver::output(p.pins.gpio15).expect("DC pin");
    let rst = PinDriver::output(p.pins.gpio22).expect("RST pin");

    // Backlight on GPIO23 via LEDC PWM at 5 kHz.
    // Plain GPIO HIGH does not enable the backlight driver IC on this board.
    let timer = LedcTimerDriver::new(
        p.ledc.timer0,
        &TimerConfig::default().frequency(5_000.Hz().into()),
    ).expect("LEDC timer init");
    let bl = LedcDriver::new(p.ledc.channel0, timer, p.pins.gpio23)
        .expect("LEDC backlight init");

    let display = crate::jd9853::Jd9853Display::new(spi, dc, rst, bl);

    // --- Host transport: ESP32-C6 native USB-Serial-JTAG (GPIO12 D- / GPIO13 D+) ---
    let serial = {
        use esp_idf_hal::usb_serial::{UsbSerialConfig, UsbSerialDriver};
        let driver = UsbSerialDriver::new(
            p.usb_serial,
            p.pins.gpio12, // D-
            p.pins.gpio13, // D+
            &UsbSerialConfig::new().rx_buffer_size(4096).tx_buffer_size(4096),
        )
        .expect("USB serial driver init failed");
        SerialPort::from_usb(driver)
    };

    // GPIO9 is the BOOT strapping pin and the user PRG button on this board.
    let button_a = PinDriver::input(p.pins.gpio9, Pull::Up).expect("button A");

    Hw {
        display,
        serial,
        button_a,
        button_b: None,
        modem: p.modem,
    }
}
