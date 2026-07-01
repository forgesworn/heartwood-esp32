// firmware/src/main.rs
//
// Heartwood ESP32 -- Phase 4 boot flow (multi-master).
//
// Boot sequence:
//   1. Initialise peripherals (LED, Vext, OLED, button, serial port, NVS)
//   2. Load all masters from NVS via masters::load_all
//   3. If no masters: show "No masters -- provision me", wait for provision frame
//   4. Create secp256k1 context (shared Arc)
//   5. Show boot screen (single master -> npub, multiple -> count)
//   6. Create PolicyEngine (empty until bridge authenticates)
//   7. Enter frame dispatch loop
//
// Board selection: exactly one of the `heltec-v3` or `heltec-v4` cargo
// features must be active. The Heltec V4 routes USB-C to the ESP32-S3 native
// USB pins (GPIO19/20) and we use the USB-Serial-JTAG peripheral. The Heltec
// V3 routes USB-C through a CP2102 bridge chip to UART0 (GPIO43 TX /
// GPIO44 RX). Both boards expose the same frame protocol through the
// `serial::SerialPort` wrapper.

#[cfg(not(any(feature = "heltec-v3", feature = "heltec-v4", feature = "tdisplay", feature = "c6")))]
compile_error!(
    "heartwood-esp32 requires exactly one board feature: `heltec-v3`, \
     `heltec-v4`, `tdisplay`, or `c6`. Did you build with `--no-default-features` \
     and forget to pick a board?"
);

#[cfg(any(
    all(feature = "heltec-v3", feature = "heltec-v4"),
    all(feature = "heltec-v3", feature = "tdisplay"),
    all(feature = "heltec-v3", feature = "c6"),
    all(feature = "heltec-v4", feature = "tdisplay"),
    all(feature = "heltec-v4", feature = "c6"),
    all(feature = "tdisplay", feature = "c6"),
))]
compile_error!(
    "board features `heltec-v3`, `heltec-v4`, `tdisplay` and `c6` are mutually \
     exclusive -- enable exactly one."
);

mod approval;
mod backup;
mod board;
mod button;
mod connslot;
mod identity_cache;
mod layout;
mod palette;
mod masters;
mod nip46_handler;
mod personas;
mod nvs;
mod cat_sprites;
mod oled;
mod ota;
mod pin;
mod policy;
mod protocol;
mod provision;
mod serial;
mod net_config_store;
mod boot_config;
#[cfg(feature = "st7789")]
mod st7789;
#[cfg(feature = "c6")]
mod jd9853;
mod relay;
mod session;
mod sign;
mod transport;

use esp_idf_hal::peripherals::Peripherals;
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
    FRAME_TYPE_ENCRYPTED_REQUEST, FRAME_TYPE_FACTORY_RESET, FRAME_TYPE_NACK,
    FRAME_TYPE_SIGN_ENVELOPE,
    FRAME_TYPE_NIP46_REQUEST, FRAME_TYPE_NIP46_RESPONSE, FRAME_TYPE_OTA_BEGIN,
    FRAME_TYPE_OTA_CHUNK, FRAME_TYPE_OTA_FINISH, FRAME_TYPE_PIN_UNLOCK,
    FRAME_TYPE_PROVISION, FRAME_TYPE_PROVISION_LIST, FRAME_TYPE_PROVISION_REMOVE,
    FRAME_TYPE_GENERATE_IDENTITY, FRAME_TYPE_RESTORE_IDENTITY,
    FRAME_TYPE_FIRMWARE_INFO, FRAME_TYPE_FIRMWARE_INFO_RESPONSE,
    FRAME_TYPE_SESSION_AUTH, FRAME_TYPE_SET_BRIDGE_SECRET, FRAME_TYPE_SET_PIN,
    FRAME_TYPE_CONNSLOT_CREATE, FRAME_TYPE_CONNSLOT_LIST, FRAME_TYPE_CONNSLOT_UPDATE,
    FRAME_TYPE_CONNSLOT_REVOKE, FRAME_TYPE_CONNSLOT_URI,
    FRAME_TYPE_BACKUP_EXPORT_REQUEST, FRAME_TYPE_BACKUP_IMPORT_REQUEST,
    FRAME_TYPE_SET_NET_CONFIG,
};
use secp256k1::Secp256k1;

/// JSON for a FIRMWARE_INFO_RESPONSE — the running firmware version and board.
/// Read-only and secret-free, so it is answered over USB in any mode.
pub fn firmware_info_json() -> String {
    format!(
        "{{\"version\":\"{}\",\"board\":\"{}\"}}",
        env!("CARGO_PKG_VERSION"),
        board::BOARD
    )
}

/// Fill `buf` with hardware-RNG bytes, guaranteeing a true entropy source for
/// the draw.
///
/// `esp_random()`/`esp_fill_random()` are only a true RNG while a hardware
/// entropy source is live — the RF radio (Wi-Fi/BT) or the SAR-ADC noise
/// source. Key material is generated at provision time, *before* the Wi-Fi
/// stack starts, so the radio is still off; without this the master seed and
/// connection-slot secrets would come from output ESP-IDF classifies as merely
/// pseudo-random. `bootloader_random_enable()` switches the ADC noise source on
/// for the draw; we disable it again so it can't clash with a later ADC/Wi-Fi
/// user. Safe here because nothing else touches the SAR ADC during provisioning.
pub fn fill_random_strong(buf: &mut [u8]) {
    unsafe {
        esp_idf_svc::sys::bootloader_random_enable();
        esp_idf_svc::sys::esp_fill_random(buf.as_mut_ptr() as *mut core::ffi::c_void, buf.len());
        esp_idf_svc::sys::bootloader_random_disable();
    }
}

fn main() {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("Heartwood ESP32 — Phase 4 (multi-master)");

    let peripherals = Peripherals::take().expect("failed to take peripherals");

    // --- Board hardware bring-up ---
    // All board-specific pin/peripheral wiring (LED, display power, display,
    // host transport, button(s)) lives in `board::bringup`; everything below
    // is board-agnostic. Housekeeping pins (LED, OLED power) are kept driven
    // inside `bringup`, so only handles the firmware actively uses come back.
    let board::Hw {
        mut display,
        serial: mut usb,
        button_a: button_pin,
        button_b: _button_b,
        modem,
    } = board::bringup(peripherals);
    log::info!("Board bring-up complete ({})", board::BOARD);

    // --- Boot animation ---
    oled::show_boot_animation(&mut display);

    // --- NVS init ---
    let nvs_partition = EspDefaultNvsPartition::take().expect("failed to take NVS partition");
    let mut nvs = EspNvs::new(nvs_partition, "heartwood", true).expect("NVS namespace init failed");

    // --- Load masters ---
    let mut loaded_masters = masters::load_all(&nvs);
    log::info!("Loaded {} master(s) from NVS", loaded_masters.len());

    // --- Load personas (per-identity registry; signing keys re-derived on use) ---
    let mut loaded_personas = personas::load_all(&nvs);
    log::info!("Loaded {} persona(s) from NVS", loaded_personas.len());

    // --- Flash-time config seed (web flasher — Raspberry Pi Imager model) ---
    // Seed NVS from the `config` partition whenever the flashed blob differs from
    // what we last seeded (CRC changed) — so re-flashing is authoritative (e.g.
    // adding an operator key). USB `SET_NET_CONFIG` changes NVS but not the
    // partition, so its CRC is unchanged and those edits persist across reboots.
    // Missing/blank/invalid partition → no-op.
    if let Some((json, crc)) = boot_config::read_flash_config() {
        if net_config_store::read_seeded_crc(&nvs) != Some(crc) {
            if heartwood_common::net_config::parse_net_config(&json).is_ok() {
                match net_config_store::write_net_config(&mut nvs, &json) {
                    Ok(()) => {
                        net_config_store::write_seeded_crc(&mut nvs, crc);
                        log::info!("Seeded net config from `config` partition (crc {crc:08x})");
                    }
                    Err(e) => log::warn!("Flash-config seed failed: {e}"),
                }
            } else {
                log::warn!("Flash-time config partition holds invalid NetConfig JSON — ignoring");
            }
        }
    }

    // --- Boot-time network config read ---
    let net_cfg = net_config_store::read_net_config(&nvs)
        .and_then(|raw| heartwood_common::net_config::parse_net_config(&raw).ok());
    if let Some(cfg) = &net_cfg {
        log::info!(
            "net config present: mode={:?}, {} relay(s)",
            cfg.device_mode(),
            cfg.relays.len()
        );
    }

    // If no masters are provisioned, wait for a provision frame before continuing.
    if loaded_masters.is_empty() {
        log::info!("No masters provisioned — entering provision-wait mode");
        oled::show_error(&mut display, "No masters --\nprovision me");

        loop {
            let frame = protocol::read_frame(&mut usb);
            match frame.frame_type {
                FRAME_TYPE_FIRMWARE_INFO => {
                    protocol::write_frame(
                        &mut usb,
                        FRAME_TYPE_FIRMWARE_INFO_RESPONSE,
                        firmware_info_json().as_bytes(),
                    );
                }
                FRAME_TYPE_PROVISION | FRAME_TYPE_GENERATE_IDENTITY | FRAME_TYPE_RESTORE_IDENTITY => {
                    // Show the "working" screen before the (one-time, slowish)
                    // secp context build so generation feedback covers it too.
                    if frame.frame_type == FRAME_TYPE_GENERATE_IDENTITY {
                        oled::show_generating(&mut display);
                    }
                    // secp context not yet created — build a temporary one for the
                    // provision/generate/restore handler to validate/derive the key.
                    let secp = Arc::new(Secp256k1::signing_only());
                    let provisioned = match frame.frame_type {
                        FRAME_TYPE_GENERATE_IDENTITY => {
                            provision::handle_generate(&mut usb, &frame, &mut nvs, &secp, &mut display, &button_pin)
                        }
                        FRAME_TYPE_RESTORE_IDENTITY => {
                            provision::handle_restore(&mut usb, &frame, &mut nvs, &secp, &mut display, &button_pin)
                        }
                        _ => provision::handle_add(&mut usb, &frame, &mut nvs, &secp, &mut display),
                    };
                    if let Some(master) = provisioned {
                        loaded_masters.push(master);
                        log::info!("First master provisioned — continuing boot");
                        // A wifi-configured device leaves the USB path the moment
                        // it has a master and runs the relay loop instead. Reboot
                        // cleanly so the wifi/relay stack initialises from a fresh
                        // boot rather than a half-set-up transition — this removes
                        // the manual reset the operator otherwise had to do, and
                        // the "USB stopped responding" confusion. The provision
                        // ACK was already sent by handle_add; delay briefly so it
                        // flushes to the host before we restart.
                        let wifi_armed = net_cfg
                            .as_ref()
                            .map(|c| {
                                c.device_mode()
                                    == heartwood_common::net_config::DeviceMode::Wifi
                            })
                            .unwrap_or(false);
                        if wifi_armed {
                            log::info!("Wifi-standalone configured — rebooting into signer mode");
                            oled::show_result(&mut display, "Provisioned!\nStarting wifi...");
                            esp_idf_hal::delay::FreeRtos::delay_ms(800);
                            unsafe { esp_idf_svc::sys::esp_restart() };
                        }
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

        // Load the persisted failed-attempt counter so the wipe threshold
        // survives power cycles (attacker cannot reset by rebooting).
        let mut failed_attempts: u8 = pin::read_failed_attempts(&nvs);
        if failed_attempts > 0 {
            log::warn!("PIN: {} failed attempt(s) carried over from previous boot", failed_attempts);
        }
        loop {
            let frame = protocol::read_frame(&mut usb);
            match frame.frame_type {
                FRAME_TYPE_PIN_UNLOCK => {
                    if pin::handle_pin_unlock(
                        &mut usb,
                        &frame.payload,
                        &mut nvs,
                        &mut failed_attempts,
                        &mut display,
                    ) {
                        break; // Unlocked — continue boot.
                    }
                }
                FRAME_TYPE_PROVISION_LIST => {
                    // Allow listing masters even when locked — no secrets exposed,
                    // only public npubs, which is acceptable.
                    provision::handle_list(&mut usb, &loaded_masters, &loaded_personas);
                }
                FRAME_TYPE_FIRMWARE_INFO => {
                    protocol::write_frame(
                        &mut usb,
                        FRAME_TYPE_FIRMWARE_INFO_RESPONSE,
                        firmware_info_json().as_bytes(),
                    );
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
    let mut policy_engine = policy::PolicyEngine::load_from_nvs(&mut nvs, loaded_masters.len() as u8);

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

    // --- WiFi-standalone (Plan 2): relay signing loop ---
    // In wifi mode the device handles NIP-46 over its own outbound relay
    // connection AND serves the full USB command set over the cable (see
    // relay::poll_usb) — so the cable stays completely usable without any mode
    // switch. The old "hold PRG at boot to force USB" escape hatch is therefore
    // gone: USB is always live, even while wifi is down (a bad SSID/relay can be
    // fixed over the cable). `mode=usb` remains the explicit radio-off tier and
    // falls through to the dispatch loop below. Never returns once entered.
    if let Some(cfg) = &net_cfg {
        if cfg.device_mode() == heartwood_common::net_config::DeviceMode::Wifi
            && !loaded_masters.is_empty()
        {
            log::info!("WiFi-standalone mode — entering relay loop");
            let op_mgmt = cfg.op_mgmt_pubkey();
            relay::run_wifi_standalone(
                modem,
                cfg,
                &loaded_masters,
                &mut loaded_personas,
                &secp,
                &mut display,
                &button_pin,
                &mut policy_engine,
                &mut identity_caches,
                &mut nvs,
                op_mgmt,
                &mut usb,
            );
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
            // 0x01 — add a master (host-derived) / 0x57 — self-generate on-device
            // / 0x58 — restore an existing 12-word phrase via the on-device picker
            FRAME_TYPE_PROVISION | FRAME_TYPE_GENERATE_IDENTITY | FRAME_TYPE_RESTORE_IDENTITY => {
                let provisioned = match frame.frame_type {
                    FRAME_TYPE_GENERATE_IDENTITY => {
                        provision::handle_generate(&mut usb, &frame, &mut nvs, &secp, &mut display, &button_pin)
                    }
                    FRAME_TYPE_RESTORE_IDENTITY => {
                        provision::handle_restore(&mut usb, &frame, &mut nvs, &secp, &mut display, &button_pin)
                    }
                    _ => provision::handle_add(&mut usb, &frame, &mut nvs, &secp, &mut display),
                };
                if let Some(master) = provisioned {
                    loaded_masters.push(master);
                }
            }

            // 0x59 — firmware version query (read-only, no secrets)
            FRAME_TYPE_FIRMWARE_INFO => {
                protocol::write_frame(
                    &mut usb,
                    FRAME_TYPE_FIRMWARE_INFO_RESPONSE,
                    firmware_info_json().as_bytes(),
                );
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
                    // Persist slots if TOFU may have added one.
                    if !loaded_masters.is_empty() {
                        policy_engine.persist_slots(&mut nvs, loaded_masters[0].slot);
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

            // 0x05 — list masters (and personas)
            FRAME_TYPE_PROVISION_LIST => {
                provision::handle_list(&mut usb, &loaded_masters, &loaded_personas);
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
                        &mut loaded_personas,
                        &secp,
                        &mut display,
                        &button_pin,
                        &mut policy_engine,
                        &mut identity_caches,
                        &mut nvs,
                    );
                }
            }

            // 0x34 — SIGN_ENVELOPE (deprecated: envelope signing now happens
            // inline during handle_encrypted_request). Kept as a NACK handler
            // so stale daemon versions get an explicit rejection.
            FRAME_TYPE_SIGN_ENVELOPE => {
                log::warn!("SIGN_ENVELOPE is deprecated — envelope signing is now inline");
                protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
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

            // 0x54 — set WiFi-standalone network config
            FRAME_TYPE_SET_NET_CONFIG => {
                net_config_store::handle_set_net_config(
                    &mut usb,
                    &frame.payload,
                    &mut nvs,
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

            // 0x40 -- create a connection slot
            FRAME_TYPE_CONNSLOT_CREATE => {
                connslot::handle_create(&mut usb, &frame, &mut policy_engine, &loaded_masters, &mut nvs);
            }

            // 0x42 -- list connection slots (secrets redacted)
            FRAME_TYPE_CONNSLOT_LIST => {
                connslot::handle_list(&mut usb, &frame, &mut policy_engine);
            }

            // 0x44 -- update a connection slot (requires button confirmation)
            FRAME_TYPE_CONNSLOT_UPDATE => {
                connslot::handle_update(&mut usb, &frame, &mut policy_engine, &mut nvs, &mut display, &button_pin);
            }

            // 0x46 -- revoke a connection slot
            FRAME_TYPE_CONNSLOT_REVOKE => {
                connslot::handle_revoke(&mut usb, &frame, &mut policy_engine, &mut nvs);
            }

            // 0x48 -- get bunker URI for a connection slot
            FRAME_TYPE_CONNSLOT_URI => {
                connslot::handle_uri(&mut usb, &frame, &mut policy_engine, &loaded_masters);
            }

            // 0x50 -- backup export (dump all slots + bridge secret)
            FRAME_TYPE_BACKUP_EXPORT_REQUEST => {
                if !policy_engine.bridge_authenticated {
                    log::warn!("Backup export rejected -- bridge not authenticated");
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                    continue;
                }
                backup::handle_export(
                    &mut usb,
                    &loaded_masters,
                    &policy_engine,
                    &nvs,
                    &mut display,
                    &button_pin,
                );
            }

            // 0x52 -- backup import (restore slots + bridge secret)
            FRAME_TYPE_BACKUP_IMPORT_REQUEST => {
                backup::handle_import(
                    &mut usb,
                    &frame.payload,
                    &loaded_masters,
                    &mut policy_engine,
                    &mut nvs,
                    &mut display,
                    &button_pin,
                );
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
        // loop for up to 30 seconds -- without this reset the display would
        // sleep immediately after the user finishes approving a request.
        last_activity = Instant::now();

        // Return to the idle screen after non-OTA requests so the OLED doesn't
        // stay stuck on "SIGNED" or other transient confirmation screens.
        // Skip for OTA frames -- the OTA handler manages its own progress display,
        // and redrawing between chunks slows the transfer and generates log noise.
        if !matches!(frame.frame_type,
            FRAME_TYPE_OTA_BEGIN | FRAME_TYPE_OTA_CHUNK | FRAME_TYPE_OTA_FINISH
        ) {
            oled::show_awaiting(&mut display);
        }
    }
}
