// firmware/src/main.rs
//
// Heartwood ESP32 — boot flow.
// Checks NVS for a stored root secret. If found, derives master npub and
// displays it. If not found, enters provisioning mode and waits for the
// secret over USB serial.

mod nvs;
mod oled;
mod provision;
mod sign;

use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::i2c::{I2cConfig, I2cDriver};
use esp_idf_hal::units::FromValueType;
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_hal::usb_serial::{UsbSerialConfig, UsbSerialDriver};
use esp_idf_svc::nvs::EspDefaultNvsPartition;

use zeroize::Zeroize;
use heartwood_common::derive;

fn main() {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("Heartwood ESP32 — Phase 2 (provisioning)");

    let peripherals = Peripherals::take().expect("failed to take peripherals");

    // Turn on white LED (GPIO 35)
    let mut led = PinDriver::output(peripherals.pins.gpio35).expect("LED pin");
    led.set_high().ok();

    // Enable Vext (GPIO 36, active low) — powers the OLED
    let mut vext = PinDriver::output(peripherals.pins.gpio36).expect("Vext pin");
    vext.set_low().ok();
    esp_idf_hal::delay::FreeRtos::delay_ms(50);

    // --- OLED init ---
    log::info!("Initialising OLED...");
    let i2c_config = I2cConfig::new().baudrate(400.kHz().into());
    let i2c = I2cDriver::new(
        peripherals.i2c0,
        peripherals.pins.gpio17, // SDA
        peripherals.pins.gpio18, // SCL
        &i2c_config,
    )
    .expect("I2C init failed");
    log::info!("I2C driver created");

    let mut display = oled::init(i2c, peripherals.pins.gpio21.into());
    log::info!("OLED init complete");

    // --- NVS: check for stored secret ---
    let nvs_partition = EspDefaultNvsPartition::take().expect("failed to take NVS partition");
    let (mut nvs, stored_secret) = nvs::read_root_secret(nvs_partition)
        .expect("NVS read failed");

    let root_secret = match stored_secret {
        Some(secret) => {
            log::info!("Booted with stored identity");
            secret
        }
        None => {
            log::info!("No stored secret — entering provisioning mode");
            oled::show_awaiting(&mut display);

            // Only install USB serial driver when we need it for provisioning.
            let mut usb = UsbSerialDriver::new(
                peripherals.usb_serial,
                peripherals.pins.gpio19,
                peripherals.pins.gpio20,
                &UsbSerialConfig::new().rx_buffer_size(512),
            )
            .expect("USB serial driver init failed");

            let secret = provision::wait_for_secret(&mut usb);

            // Store in NVS
            match nvs::write_root_secret(&mut nvs, &secret) {
                Ok(()) => log::info!("Provisioned — identity stored in NVS"),
                Err(e) => {
                    log::error!("NVS write failed: {e}");
                    oled::show_error(&mut display, "NVS write failed");
                    loop {
                        esp_idf_hal::delay::FreeRtos::delay_ms(1000);
                    }
                }
            }

            // Drop the USB serial driver to restore console logging
            drop(usb);

            secret
        }
    };

    // --- Display identity ---
    // TODO: k256 create_tree_root crashes with LoadStoreAlignment on Xtensa
    // on the stored-identity boot path. Works during provisioning boot.
    // Needs investigation — likely k256 unaligned access on Xtensa LX7.
    // For now, show confirmation that the identity is stored.
    oled::show_error(&mut display, "Identity stored");

    log::info!("Idle — display on");

    // Idle loop — display stays on
    loop {
        esp_idf_hal::delay::FreeRtos::delay_ms(1000);
    }
}
