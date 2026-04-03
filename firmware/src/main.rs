// firmware/src/main.rs
//
// Heartwood ESP32 — Phase 3 boot flow.
//
// Boot sequence:
//   1. Initialise peripherals (LED, Vext, OLED, button, USB serial, NVS)
//   2. Check NVS for a stored root secret
//   3. If none: show "Awaiting secret...", wait for a valid provision frame
//   4. Derive master npub and display it (k256 in aligned thread)
//   5. Enter frame dispatch loop — route by frame type indefinitely

mod button;
mod nip46_handler;
mod nvs;
mod oled;
mod protocol;
mod provision;
mod sign;

use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::i2c::{I2cConfig, I2cDriver};
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_hal::units::FromValueType;
use esp_idf_hal::usb_serial::{UsbSerialConfig, UsbSerialDriver};
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use heartwood_common::derive;
use heartwood_common::types::{
    FRAME_TYPE_NACK, FRAME_TYPE_NIP46_REQUEST, FRAME_TYPE_PROVISION,
};

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

    // --- USB serial driver — created early, stays alive for the dispatch loop ---
    let mut usb = UsbSerialDriver::new(
        peripherals.usb_serial,
        peripherals.pins.gpio19,
        peripherals.pins.gpio20,
        &UsbSerialConfig::new().rx_buffer_size(512),
    )
    .expect("USB serial driver init failed");

    // --- NVS: check for stored secret ---
    let nvs_partition = EspDefaultNvsPartition::take().expect("failed to take NVS partition");
    let (mut nvs, stored_secret) = nvs::read_root_secret(nvs_partition).expect("NVS read failed");

    // Obtain the root secret — either from NVS or by waiting for a provision frame.
    let root_secret: [u8; 32] = match stored_secret {
        Some(secret) => {
            log::info!("Booted with stored identity");
            secret
        }
        None => {
            log::info!("No stored secret — entering provisioning mode");
            oled::show_awaiting(&mut display);

            // Wait until we receive a valid provision frame.
            loop {
                let frame = protocol::read_frame(&mut usb);
                if frame.frame_type == FRAME_TYPE_PROVISION {
                    if let Some(secret) =
                        provision::handle_provision(&mut usb, &frame, &mut nvs, &mut display)
                    {
                        break secret;
                    }
                    // handle_provision sent a NACK; loop back and wait again.
                } else {
                    log::warn!(
                        "Expected provision frame, got type 0x{:02x}",
                        frame.frame_type
                    );
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                }
            }
        }
    };

    // --- Derive master npub and display it ---
    //
    // k256 field arithmetic does unaligned memory accesses that crash on
    // Xtensa LX7 (EXCCAUSE: 0x00000005 LoadStoreAlignment). Running in a
    // dedicated thread with a fresh aligned stack sidesteps this — the main
    // task's stack/heap layout happens to misalign k256's internal structures.
    //
    // We keep root_secret for the dispatch loop below; secret_copy is a
    // separate copy moved into the thread.
    let secret_copy = root_secret;

    let npub_result = std::thread::Builder::new()
        .name("derive".into())
        .stack_size(32768)
        .spawn(move || {
            #[repr(align(16))]
            struct Aligned([u8; 32]);
            let aligned = Aligned(secret_copy);
            derive::create_tree_root(&aligned.0)
        })
        .expect("thread spawn failed")
        .join()
        .expect("derivation panicked");

    match &npub_result {
        Ok(tree_root) => {
            log::info!("Identity: {}", tree_root.master_npub);
            oled::show_npub(&mut display, &tree_root.master_npub);
        }
        Err(e) => {
            log::error!("Key derivation failed: {e}");
            oled::show_error(&mut display, "Derivation failed");
        }
    }

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
                    &mut display,
                    &button_pin,
                );
                // Return to idle npub display after handling the request.
                if let Ok(ref tree_root) = npub_result {
                    oled::show_npub(&mut display, &tree_root.master_npub);
                }
            }
            FRAME_TYPE_PROVISION => {
                log::warn!("Already provisioned — ignoring provision frame");
                protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
            }
            _ => {
                log::warn!("Unknown frame type: 0x{:02x}", frame.frame_type);
                protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
            }
        }
    }
}
