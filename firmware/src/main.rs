// firmware/src/main.rs
//
// Heartwood ESP32 — Phase 3 boot flow.
//
// Boot sequence:
//   1. Initialise peripherals (LED, Vext, OLED, button, USB serial, NVS)
//   2. Check NVS for a stored root secret
//   3. If none: show "Awaiting secret...", wait for a valid provision frame
//   4. Derive master npub and display it (libsecp256k1)
//   5. Enter frame dispatch loop — route by frame type indefinitely

mod button;
mod masters;
mod nip46_handler;
mod nvs;
mod oled;
mod policy;
mod protocol;
mod provision;
mod session;
mod sign;

use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::i2c::{I2cConfig, I2cDriver};
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_hal::units::FromValueType;
use esp_idf_hal::usb_serial::{UsbSerialConfig, UsbSerialDriver};
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use std::sync::Arc;

use heartwood_common::types::{
    FRAME_TYPE_NACK, FRAME_TYPE_NIP46_REQUEST, FRAME_TYPE_PROVISION,
    FRAME_TYPE_PROVISION_LIST, FRAME_TYPE_PROVISION_REMOVE,
};
use secp256k1::Secp256k1;

fn main() {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("Heartwood ESP32 — Phase 3 (signing oracle)");

    let peripherals = Peripherals::take().expect("failed to take peripherals");

    // Turn on white LED (GPIO 35, active high)
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

    // --- Button pin (GPIO 0, active low, internal pull-up) ---
    let button_pin = PinDriver::input(peripherals.pins.gpio0, esp_idf_hal::gpio::Pull::Up).expect("button pin");

    // --- NVS: check for stored secret ---
    let nvs_partition = EspDefaultNvsPartition::take().expect("failed to take NVS partition");
    let (mut nvs, stored_secret) = nvs::read_root_secret(nvs_partition).expect("NVS read failed");

    // Create the secp256k1 context once — ~130KB. Shared via Arc with
    // signing threads to avoid repeated heap allocations on ESP32.
    let secp = Arc::new(Secp256k1::signing_only());

    // Obtain the root secret — either from NVS or by waiting for a provision frame.
    // The USB serial driver is created inside each branch because:
    // - For provisioning: the host must connect BEFORE we take over USB-Serial-JTAG
    // - For stored identity: we create it after NVS read for the dispatch loop
    let (root_secret, mut usb): ([u8; 32], UsbSerialDriver<'_>) = match stored_secret {
        Some(secret) => {
            log::info!("Booted with stored identity");
            let usb = UsbSerialDriver::new(
                peripherals.usb_serial,
                peripherals.pins.gpio19,
                peripherals.pins.gpio20,
                &UsbSerialConfig::new().rx_buffer_size(512).tx_buffer_size(1024),
            )
            .expect("USB serial driver init failed");
            (secret, usb)
        }
        None => {
            log::info!("No stored secret — entering provisioning mode");
            oled::show_awaiting(&mut display);

            // Create USB serial driver — host is expected to connect after seeing
            // "Awaiting secret..." on the OLED.
            let mut usb = UsbSerialDriver::new(
                peripherals.usb_serial,
                peripherals.pins.gpio19,
                peripherals.pins.gpio20,
                &UsbSerialConfig::new().rx_buffer_size(512).tx_buffer_size(1024),
            )
            .expect("USB serial driver init failed");

            // Wait until we receive a valid provision frame.
            let secret = loop {
                let frame = protocol::read_frame(&mut usb);
                if frame.frame_type == FRAME_TYPE_PROVISION {
                    if let Some(master) =
                        provision::handle_add(&mut usb, &frame, &mut nvs, &secp, &mut display)
                    {
                        break master.secret;
                    }
                    // handle_add sent a NACK; loop back and wait again.
                } else {
                    log::warn!(
                        "Expected provision frame, got type 0x{:02x}",
                        frame.frame_type
                    );
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                }
            };
            (secret, usb)
        }
    };

    // Derive master npub at boot and show it on the OLED.
    let keypair = secp256k1::Keypair::from_seckey_slice(&secp, &root_secret)
        .expect("stored secret is invalid");
    let (xonly, _) = keypair.x_only_public_key();
    let master_npub = heartwood_common::encoding::encode_npub(&xonly.serialize());
    log::info!("Master npub: {master_npub}");
    oled::show_npub(&mut display, &master_npub);

    // Load all provisioned masters from NVS into memory.
    let mut loaded_masters = masters::load_all(&nvs);
    log::info!("Loaded {} master(s) from NVS", loaded_masters.len());

    log::info!("Identity loaded — ready for signing requests");

    // --- Frame dispatch loop ---
    log::info!("Entering frame dispatch loop");
    loop {
        let frame = protocol::read_frame(&mut usb);
        match frame.frame_type {
            FRAME_TYPE_NIP46_REQUEST => {
                nip46_handler::handle_request(
                    &mut usb,
                    &frame,
                    &root_secret,
                    &secp,
                    &mut display,
                    &button_pin,
                );
                oled::show_error(&mut display, "Heartwood ready");
            }
            FRAME_TYPE_PROVISION => {
                if let Some(master) = provision::handle_add(
                    &mut usb,
                    &frame,
                    &mut nvs,
                    &secp,
                    &mut display,
                ) {
                    loaded_masters.push(master);
                }
            }
            FRAME_TYPE_PROVISION_REMOVE => {
                provision::handle_remove(
                    &mut usb,
                    &frame,
                    &mut nvs,
                    &mut loaded_masters,
                    &mut display,
                );
            }
            FRAME_TYPE_PROVISION_LIST => {
                provision::handle_list(&mut usb, &loaded_masters);
            }
            _ => {
                log::warn!("Unknown frame type: 0x{:02x}", frame.frame_type);
                protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
            }
        }
    }
}
