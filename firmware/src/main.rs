// firmware/src/main.rs
//
// Heartwood ESP32 — Phase 4 boot flow (multi-master).
//
// Boot sequence:
//   1. Initialise peripherals (LED, Vext, OLED, button, USB serial, NVS)
//   2. Load all masters from NVS via masters::load_all
//   3. If no masters: show "No masters — provision me", wait for provision frame
//   4. Create secp256k1 context (shared Arc)
//   5. Show boot screen (single master → npub, multiple → count)
//   6. Create PolicyEngine (empty until bridge authenticates)
//   7. Enter frame dispatch loop

mod button;
mod identity_cache;
mod masters;
mod nip46_handler;
mod nvs;
mod oled;
mod policy;
mod protocol;
mod provision;
mod session;
mod sign;
mod transport;

use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::i2c::{I2cConfig, I2cDriver};
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_hal::units::FromValueType;
use esp_idf_hal::usb_serial::{UsbSerialConfig, UsbSerialDriver};
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs};
use std::sync::Arc;

use heartwood_common::encoding::encode_npub;
use heartwood_common::types::{
    FRAME_TYPE_ENCRYPTED_REQUEST, FRAME_TYPE_NACK, FRAME_TYPE_NIP46_REQUEST,
    FRAME_TYPE_NIP46_RESPONSE, FRAME_TYPE_POLICY_PUSH, FRAME_TYPE_PROVISION,
    FRAME_TYPE_PROVISION_LIST, FRAME_TYPE_PROVISION_REMOVE, FRAME_TYPE_SESSION_AUTH,
};
use secp256k1::Secp256k1;

fn main() {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("Heartwood ESP32 — Phase 4 (multi-master)");

    let peripherals = Peripherals::take().expect("failed to take peripherals");

    // Turn on white LED (GPIO 35, active high).
    let mut led = PinDriver::output(peripherals.pins.gpio35).expect("LED pin");
    led.set_high().ok();

    // Enable Vext (GPIO 36, active low) — powers the OLED.
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
    let button_pin =
        PinDriver::input(peripherals.pins.gpio0, esp_idf_hal::gpio::Pull::Up).expect("button pin");

    // --- NVS init ---
    let nvs_partition = EspDefaultNvsPartition::take().expect("failed to take NVS partition");
    let mut nvs = EspNvs::new(nvs_partition, "heartwood", true).expect("NVS namespace init failed");

    // --- USB serial (unconditional — created before the provision wait loop) ---
    let mut usb = UsbSerialDriver::new(
        peripherals.usb_serial,
        peripherals.pins.gpio19,
        peripherals.pins.gpio20,
        &UsbSerialConfig::new().rx_buffer_size(512).tx_buffer_size(1024),
    )
    .expect("USB serial driver init failed");

    // --- Load masters ---
    let mut loaded_masters = masters::load_all(&nvs);
    log::info!("Loaded {} master(s) from NVS", loaded_masters.len());

    // If no masters are provisioned, wait for a provision frame before continuing.
    if loaded_masters.is_empty() {
        log::info!("No masters provisioned — entering provision-wait mode");
        oled::show_error(&mut display, "No masters --\nprovision me");

        loop {
            let frame = protocol::read_frame(&mut usb);
            match frame.frame_type {
                FRAME_TYPE_PROVISION => {
                    if let Some(master) = provision::handle_add(
                        &mut usb,
                        &frame,
                        &mut nvs,
                        // secp context not yet created — build a temporary one for
                        // the provision handler to validate the key.
                        &Arc::new(Secp256k1::signing_only()),
                        &mut display,
                    ) {
                        loaded_masters.push(master);
                        log::info!("First master provisioned — continuing boot");
                        break;
                    }
                    // handle_add sent a NACK; wait for the next frame.
                }
                _ => {
                    log::warn!(
                        "Expected provision frame, got type 0x{:02x}",
                        frame.frame_type
                    );
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                }
            }
        }
    }

    // --- secp256k1 context — created once and shared via Arc ---
    // ~130 KB on the heap. Shared with signing threads to avoid repeated
    // allocations on the ESP32's constrained heap.
    let secp = Arc::new(Secp256k1::signing_only());

    // --- Per-master identity caches ---
    // Created here, populated on demand by heartwood extension methods
    // (heartwood_derive, heartwood_switch, heartwood_list_identities,
    // heartwood_recover). Not yet wired into the handler — that happens in
    // Task 5 when the heartwood methods are implemented.
    let mut identity_caches: Vec<identity_cache::IdentityCache> = loaded_masters
        .iter()
        .map(|m| identity_cache::IdentityCache::new(m.slot))
        .collect();

    // --- Boot screen ---
    // Single master: show its npub. Multiple masters: show the count.
    if loaded_masters.len() == 1 {
        let master = &loaded_masters[0];
        let npub = encode_npub(&master.pubkey);
        log::info!("Boot with master[0]: label={} npub={}", master.label, npub);
        oled::show_npub(&mut display, &npub);
    } else {
        log::info!("Boot with {} masters", loaded_masters.len());
        oled::show_boot(&mut display, loaded_masters.len() as u8);
    }

    // --- Policy engine (empty; populated when bridge authenticates) ---
    let mut policy_engine = policy::PolicyEngine::new();

    // --- Frame dispatch loop ---
    log::info!("Entering frame dispatch loop");
    loop {
        let frame = protocol::read_frame(&mut usb);
        match frame.frame_type {
            // 0x01 — add a master
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

            // 0x02 — plaintext NIP-46 request (only if bridge NOT authenticated)
            FRAME_TYPE_NIP46_REQUEST => {
                if policy_engine.bridge_authenticated {
                    log::warn!("Plaintext NIP-46 rejected — bridge is authenticated; use encrypted channel");
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                } else if loaded_masters.is_empty() {
                    log::warn!("NIP-46 request with no masters loaded");
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                } else {
                    // Use the first loaded master for plaintext requests.
                    let master = &loaded_masters[0];
                    if let Some(response_json) = nip46_handler::handle_request(
                        &mut usb,
                        &frame,
                        &master.secret,
                        &master.label,
                        master.mode,
                        master.slot,
                        &secp,
                        &mut display,
                        &button_pin,
                        &mut policy_engine,
                        &mut identity_caches,
                    ) {
                        protocol::write_frame(
                            &mut usb,
                            FRAME_TYPE_NIP46_RESPONSE,
                            response_json.as_bytes(),
                        );
                    }
                    // None means sign_event already wrote its own frame.
                    oled::show_boot(&mut display, loaded_masters.len() as u8);
                }
            }

            // 0x04 — remove a master
            FRAME_TYPE_PROVISION_REMOVE => {
                provision::handle_remove(
                    &mut usb,
                    &frame,
                    &mut nvs,
                    &mut loaded_masters,
                    &mut display,
                );
            }

            // 0x05 — list masters
            FRAME_TYPE_PROVISION_LIST => {
                provision::handle_list(&mut usb, &loaded_masters);
            }

            // 0x10 — encrypted NIP-46 request (NIP-44 transport layer)
            FRAME_TYPE_ENCRYPTED_REQUEST => {
                if !policy_engine.bridge_authenticated {
                    log::warn!("Encrypted request rejected — bridge not authenticated");
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                } else {
                    transport::handle_encrypted_request(
                        &mut usb,
                        &frame,
                        &loaded_masters,
                        &secp,
                        &mut display,
                        &button_pin,
                        &mut policy_engine,
                        &mut identity_caches,
                    );
                }
            }

            // 0x20 — push client policies
            FRAME_TYPE_POLICY_PUSH => {
                session::handle_policy_push(
                    &mut usb,
                    &frame.payload,
                    &loaded_masters,
                    &mut policy_engine,
                );
            }

            // 0x21 — bridge authentication
            FRAME_TYPE_SESSION_AUTH => {
                session::handle_auth(
                    &mut usb,
                    &frame.payload,
                    &nvs,
                    &mut policy_engine,
                );
            }

            // Unknown frame — NACK
            _ => {
                log::warn!("Unknown frame type: 0x{:02x}", frame.frame_type);
                protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
            }
        }
    }
}
