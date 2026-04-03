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

use esp_idf_hal::i2c::{I2cConfig, I2cDriver};
use esp_idf_hal::prelude::*;
use esp_idf_svc::nvs::EspDefaultNvsPartition;

use heartwood_common::derive;

fn main() {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("Heartwood ESP32 — Phase 2 (provisioning)");

    let peripherals = Peripherals::take().expect("failed to take peripherals");

    // --- OLED init ---
    let i2c_config = I2cConfig::new().baudrate(400.kHz().into());
    let i2c = I2cDriver::new(
        peripherals.i2c0,
        peripherals.pins.gpio17, // SDA
        peripherals.pins.gpio18, // SCL
        &i2c_config,
    )
    .expect("I2C init failed");

    let mut display = oled::init(i2c, peripherals.pins.gpio21.into());

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

            // Read from stdin — ESP-IDF maps this to USB-Serial-JTAG on the Heltec V4.
            // No UART driver or GPIO pins needed.
            let secret = provision::wait_for_secret();

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

            secret
        }
    };

    // --- Derive and display master npub ---
    let root = derive::create_tree_root(&root_secret).expect("root creation failed");
    log::info!("Master npub: {}", root.master_npub);

    oled::show_npub(&mut display, &root.master_npub);

    root.destroy();

    // Idle loop — display stays on
    loop {
        esp_idf_hal::delay::FreeRtos::delay_ms(1000);
    }
}
