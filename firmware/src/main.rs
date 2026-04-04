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

mod approval;
mod button;
mod identity_cache;
mod masters;
mod nip46_handler;
mod nvs;
mod oled;
mod ota;
mod pin;
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
use std::time::{Duration, Instant};

/// How long the display stays on after the last activity before sleeping.
const DISPLAY_TIMEOUT: Duration = Duration::from_secs(30);

/// Polling interval for the idle loop — short enough for responsive button
/// wake, long enough not to busy-spin the CPU.
const IDLE_POLL_MS: u32 = 50;

use heartwood_common::encoding::encode_npub;
use heartwood_common::types::{
    FRAME_TYPE_ACK, FRAME_TYPE_ENCRYPTED_REQUEST, FRAME_TYPE_FACTORY_RESET, FRAME_TYPE_NACK,
    FRAME_TYPE_NIP46_REQUEST, FRAME_TYPE_NIP46_RESPONSE, FRAME_TYPE_OTA_BEGIN,
    FRAME_TYPE_OTA_CHUNK, FRAME_TYPE_OTA_FINISH, FRAME_TYPE_PIN_UNLOCK,
    FRAME_TYPE_BUNKER_URI_REQUEST, FRAME_TYPE_BUNKER_URI_RESPONSE,
    FRAME_TYPE_POLICY_LIST_REQUEST, FRAME_TYPE_POLICY_LIST_RESPONSE,
    FRAME_TYPE_POLICY_PUSH, FRAME_TYPE_POLICY_REVOKE, FRAME_TYPE_POLICY_UPDATE,
    FRAME_TYPE_PROVISION, FRAME_TYPE_PROVISION_LIST, FRAME_TYPE_PROVISION_REMOVE,
    FRAME_TYPE_SESSION_AUTH, FRAME_TYPE_SET_BRIDGE_SECRET, FRAME_TYPE_SET_PIN,
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

    // --- Boot animation ---
    oled::show_boot_animation(&mut display);

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
        &UsbSerialConfig::new().rx_buffer_size(4096).tx_buffer_size(4096),
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

    // --- PIN lock ---
    // If a PIN is set, the device stays locked until the correct PIN is
    // provided via a PIN_UNLOCK frame. All other frames are rejected,
    // except PROVISION_LIST which is safe (no secret material exposed).
    if pin::has_pin(&nvs) {
        log::info!("PIN protection active — waiting for unlock");
        oled::show_error(&mut display, "PIN locked\nAwait unlock...");

        let mut failed_attempts: u8 = 0;
        loop {
            let frame = protocol::read_frame(&mut usb);
            match frame.frame_type {
                FRAME_TYPE_PIN_UNLOCK => {
                    if pin::handle_pin_unlock(
                        &mut usb,
                        &frame.payload,
                        &nvs,
                        &mut failed_attempts,
                        &mut display,
                    ) {
                        break; // Unlocked — continue boot.
                    }
                }
                FRAME_TYPE_PROVISION_LIST => {
                    // Allow listing masters even when locked — no secrets exposed,
                    // only public npubs, which is acceptable.
                    provision::handle_list(&mut usb, &loaded_masters);
                }
                _ => {
                    log::warn!("Device locked — rejecting frame type 0x{:02x}", frame.frame_type);
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
    // Populated on demand by heartwood extension methods
    // (heartwood_derive, heartwood_switch, heartwood_list_identities,
    // heartwood_recover).
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

    // --- Policy engine (load persisted TOFU policies from NVS) ---
    let mut policy_engine = policy::PolicyEngine::load_from_nvs(&nvs, loaded_masters.len() as u8);

    // --- OTA rollback guard ---
    // If this boot was triggered by an OTA update, mark the firmware as valid
    // so the rollback safety net is cancelled.  If this is a normal (non-OTA)
    // boot the call is a no-op and the error code is ignored.
    unsafe {
        let err = esp_idf_svc::sys::esp_ota_mark_app_valid_cancel_rollback();
        if err == esp_idf_svc::sys::ESP_OK {
            log::info!("OTA: firmware marked as valid (rollback cancelled)");
        } else {
            log::info!("OTA: not an OTA boot or already confirmed ({})", err);
        }
    }

    // --- OTA session state ---
    let mut ota_session: Option<ota::OtaSession> = None;

    // --- Display power management ---
    // Track the timestamp of the last activity (frame received or button press).
    // After DISPLAY_TIMEOUT of inactivity the OLED panel is switched off to
    // prevent burn-in and save power.  Any frame arriving or a short PRG
    // button press will wake it again.
    let mut last_activity = Instant::now();
    let mut display_on = true;

    // --- Frame dispatch loop ---
    log::info!("Entering frame dispatch loop");
    loop {
        // Poll for an incoming frame with a short timeout so we can also check
        // the button state and display timeout while idle.
        let frame = loop {
            match protocol::try_read_frame(&mut usb, IDLE_POLL_MS) {
                Some(f) => {
                    // A frame arrived — mark activity and ensure the display is on.
                    last_activity = Instant::now();
                    if !display_on {
                        oled::wake_display(&mut display);
                        display_on = true;
                        log::info!("Display woken by incoming frame");
                    }
                    break f;
                }
                None => {
                    // No frame this tick — check for display timeout and button.

                    // Signing requests always wake the display (handled above when
                    // the frame arrives).  Between frames, check elapsed idle time.
                    if display_on && last_activity.elapsed() >= DISPLAY_TIMEOUT {
                        oled::sleep_display(&mut display);
                        display_on = false;
                        log::info!("Display slept after {}s idle", DISPLAY_TIMEOUT.as_secs());
                    }

                    // Short PRG button press (active-low GPIO 0) wakes the display.
                    // A 2-second hold is reserved for signing approval inside the
                    // signing handler — we only act on a complete short press here
                    // (press detected AND released before 2 s).
                    if button_pin.is_low() {
                        let press_start = Instant::now();
                        // Wait for release, capping at 2 s to avoid consuming a
                        // long-hold that belongs to a signing request.
                        while button_pin.is_low()
                            && press_start.elapsed() < Duration::from_millis(1900)
                        {
                            esp_idf_hal::delay::FreeRtos::delay_ms(20);
                        }

                        if button_pin.is_high() {
                            // Button released — treat as a short press (wake).
                            last_activity = Instant::now();
                            if !display_on {
                                oled::wake_display(&mut display);
                                display_on = true;
                                log::info!("Display woken by button short press");
                            }
                            // Show the idle status screen so the user can see
                            // the current state after waking.
                            oled::show_boot(&mut display, loaded_masters.len() as u8);
                        }
                        // If still held at 1.9 s, a signing frame is expected
                        // imminently — let the signing handler deal with it.
                    }
                }
            }
        };

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
                    let response_json = nip46_handler::handle_request(
                        &frame,
                        &master.secret,
                        &master.label,
                        master.mode,
                        master.slot,
                        &master.connect_secret,
                        &secp,
                        &mut display,
                        &button_pin,
                        &mut policy_engine,
                        &mut identity_caches,
                        None,
                    );
                    protocol::write_frame(
                        &mut usb,
                        FRAME_TYPE_NIP46_RESPONSE,
                        response_json.as_bytes(),
                    );
                    // Persist policies if TOFU may have added one.
                    if !loaded_masters.is_empty() {
                        policy_engine.persist_policies(&mut nvs, loaded_masters[0].slot);
                    }
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
                        &mut nvs,
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
                    &mut nvs,
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

            // 0x23 — set bridge secret
            FRAME_TYPE_SET_BRIDGE_SECRET => {
                session::handle_set_bridge_secret(
                    &mut usb,
                    &frame.payload,
                    &mut nvs,
                    &policy_engine,
                    &mut display,
                    &button_pin,
                );
            }

            // 0x24 — factory reset
            FRAME_TYPE_FACTORY_RESET => {
                provision::handle_factory_reset(
                    &mut usb,
                    &mut nvs,
                    &mut display,
                    &button_pin,
                );
            }

            // 0x25 — set/change/clear boot PIN
            FRAME_TYPE_SET_PIN => {
                pin::handle_set_pin(
                    &mut usb,
                    &frame.payload,
                    &mut nvs,
                    &mut display,
                    &button_pin,
                );
            }

            // 0x27 — list TOFU-approved clients for a master slot
            FRAME_TYPE_POLICY_LIST_REQUEST => {
                if frame.payload.is_empty() {
                    log::warn!("POLICY_LIST_REQUEST missing master_slot byte");
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                } else {
                    let slot = frame.payload[0];
                    let policies = policy_engine.list_policies(slot);
                    match serde_json::to_vec(policies) {
                        Ok(json) => {
                            protocol::write_frame(&mut usb, FRAME_TYPE_POLICY_LIST_RESPONSE, &json);
                        }
                        Err(e) => {
                            log::error!("Failed to serialise policy list: {e}");
                            protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                        }
                    }
                }
            }

            // 0x29 — revoke a TOFU-approved client
            FRAME_TYPE_POLICY_REVOKE => {
                // Payload: master_slot (1 byte) + client_pubkey_hex (64 bytes ASCII)
                if frame.payload.len() < 65 {
                    log::warn!("POLICY_REVOKE payload too short ({} bytes)", frame.payload.len());
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                } else {
                    let slot = frame.payload[0];
                    let pubkey_hex = match std::str::from_utf8(&frame.payload[1..65]) {
                        Ok(s) => s,
                        Err(_) => {
                            log::warn!("POLICY_REVOKE invalid UTF-8 in client pubkey");
                            protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                            continue;
                        }
                    };
                    if policy_engine.revoke_policy(slot, pubkey_hex) {
                        policy_engine.persist_policies(&mut nvs, slot);
                        log::info!("Revoked client policy for {}", &pubkey_hex[..8]);
                        protocol::write_frame(&mut usb, FRAME_TYPE_ACK, &[]);
                    } else {
                        log::warn!("POLICY_REVOKE: no policy found for client");
                        protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                    }
                }
            }

            // 0x2A — update/add a client policy
            FRAME_TYPE_POLICY_UPDATE => {
                // Payload: master_slot (1 byte) + JSON ClientPolicy
                if frame.payload.len() < 2 {
                    log::warn!("POLICY_UPDATE payload too short");
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                } else {
                    let slot = frame.payload[0];
                    match serde_json::from_slice::<heartwood_common::policy::ClientPolicy>(&frame.payload[1..]) {
                        Ok(policy) => {
                            log::info!("Upserted client policy for {}", &policy.client_pubkey[..policy.client_pubkey.len().min(8)]);
                            policy_engine.upsert_policy(slot, policy);
                            policy_engine.persist_policies(&mut nvs, slot);
                            protocol::write_frame(&mut usb, FRAME_TYPE_ACK, &[]);
                        }
                        Err(e) => {
                            log::warn!("POLICY_UPDATE: invalid JSON: {e}");
                            protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                        }
                    }
                }
            }

            // 0x2B -- bunker URI request (bridge asks for the full URI with secret)
            FRAME_TYPE_BUNKER_URI_REQUEST => {
                if frame.payload.is_empty() {
                    log::warn!("BUNKER_URI_REQUEST missing master_slot byte");
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                } else {
                    let slot = frame.payload[0] as usize;
                    if slot >= loaded_masters.len() {
                        log::warn!("BUNKER_URI_REQUEST invalid slot {slot}");
                        protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                    } else {
                        let master = &loaded_masters[slot];
                        let npub_hex = heartwood_common::hex::hex_encode(&master.pubkey);
                        let secret_hex = heartwood_common::hex::hex_encode(&master.connect_secret);

                        // Parse relay URLs from the rest of the payload (JSON string array).
                        let relay_params = if frame.payload.len() > 1 {
                            if let Ok(relays) = serde_json::from_slice::<Vec<String>>(&frame.payload[1..]) {
                                relays.iter()
                                    .map(|r| format!("relay={}", r))
                                    .collect::<Vec<_>>()
                                    .join("&")
                            } else {
                                String::new()
                            }
                        } else {
                            String::new()
                        };

                        let uri = if relay_params.is_empty() {
                            format!("bunker://{}?secret={}", npub_hex, secret_hex)
                        } else {
                            format!("bunker://{}?{}&secret={}", npub_hex, relay_params, secret_hex)
                        };

                        protocol::write_frame(&mut usb, FRAME_TYPE_BUNKER_URI_RESPONSE, uri.as_bytes());
                    }
                }
            }

            // 0x30 -- OTA begin (sends size + expected SHA-256, triggers approval)
            FRAME_TYPE_OTA_BEGIN => {
                ota::handle_ota_begin(
                    &mut usb,
                    &frame.payload,
                    &mut display,
                    &button_pin,
                    &mut ota_session,
                );
            }

            // 0x31 — OTA chunk (offset + data)
            FRAME_TYPE_OTA_CHUNK => {
                ota::handle_ota_chunk(
                    &mut usb,
                    &frame.payload,
                    &mut display,
                    &mut ota_session,
                );
            }

            // 0x32 — OTA finish (verify hash, reboot)
            FRAME_TYPE_OTA_FINISH => {
                ota::handle_ota_finish(
                    &mut usb,
                    &mut display,
                    &mut ota_session,
                );
            }

            // Unknown frame — NACK
            _ => {
                log::warn!("Unknown frame type: 0x{:02x}", frame.frame_type);
                protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
            }
        }

        // Reset activity timestamp after every handler returns.  This is
        // especially important after sign_event, which can hold the button
        // loop for up to 30 seconds — without this reset the display would
        // sleep immediately after the user finishes approving a request.
        last_activity = Instant::now();
    }
}
