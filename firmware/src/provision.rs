// firmware/src/provision.rs
//
// Multi-master provisioning handler.
//
// Frame 0x01 (PROVISION_ADD): [mode_u8][label_len_u8][label...][secret_32]
//   - Legacy compat: if payload is exactly 32 bytes, treat as tree-mnemonic with label "default".
// Frame 0x04 (PROVISION_REMOVE): [slot_u8]
// Frame 0x05 (PROVISION_LIST): (empty) → responds with 0x07 (PROVISION_LIST_RESPONSE)

use crate::serial::SerialPort;
use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use secp256k1::Secp256k1;
use std::sync::Arc;

use heartwood_common::encoding::encode_npub;
use heartwood_common::frame::Frame;
use heartwood_common::types::{
    MasterMode, FRAME_TYPE_ACK, FRAME_TYPE_NACK, FRAME_TYPE_PROVISION_LIST_RESPONSE,
};

use crate::masters::{self, LoadedMaster};
use crate::oled::{self, Display};
use crate::protocol;

/// Handle a PROVISION_ADD frame (0x01). Returns the new `LoadedMaster` on success.
pub fn handle_add(
    usb: &mut SerialPort<'_>,
    frame: &Frame,
    nvs: &mut EspNvs<NvsDefault>,
    secp: &Arc<Secp256k1<secp256k1::SignOnly>>,
    display: &mut Display<'_>,
) -> Option<LoadedMaster> {
    // Legacy format: exactly 32 bytes = tree-mnemonic with label "default".
    let (mode, label, secret) = if frame.payload.len() == 32 {
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&frame.payload);
        (MasterMode::TreeMnemonic, "default".to_string(), secret)
    } else if frame.payload.len() >= 2 + 32 {
        let mode_byte = frame.payload[0];
        let mode = match MasterMode::from_u8(mode_byte) {
            Some(m) => m,
            None => {
                log::warn!("Unknown provision mode byte: 0x{:02x}", mode_byte);
                protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
                return None;
            }
        };

        let label_len = frame.payload[1] as usize;
        if frame.payload.len() < 2 + label_len + 32 {
            log::warn!("Provision payload too short for label ({} bytes) + secret", label_len);
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return None;
        }

        let label = String::from_utf8_lossy(&frame.payload[2..2 + label_len]).to_string();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&frame.payload[2 + label_len..2 + label_len + 32]);

        (mode, label, secret)
    } else {
        log::warn!(
            "Provision payload is {} bytes, expected exactly 32 or >= 34",
            frame.payload.len()
        );
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return None;
    };

    match store_master(nvs, secret, label, mode, secp) {
        Ok(master) => {
            let npub = encode_npub(&master.pubkey);
            log::info!("Provisioned slot {}: {} ({npub})", master.slot, master.label);
            oled::show_npub(display, &npub);
            protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
            Some(master)
        }
        Err(e) => {
            log::error!("Provision add failed: {e}");
            oled::show_error(display, "Provision failed");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            None
        }
    }
}

/// Derive the x-only pubkey from a 32-byte root secret and persist the master to
/// NVS. No display, no ACK — the caller decides what to show (the npub for an
/// import, the recovery phrase for a self-generated identity).
fn store_master(
    nvs: &mut EspNvs<NvsDefault>,
    secret: [u8; 32],
    label: String,
    mode: MasterMode,
    secp: &Arc<Secp256k1<secp256k1::SignOnly>>,
) -> Result<LoadedMaster, String> {
    let keypair = secp256k1::Keypair::from_seckey_slice(secp, &secret)
        .map_err(|_| "invalid secret key".to_string())?;
    let (xonly, _) = keypair.x_only_public_key();
    let pubkey = xonly.serialize();
    let slot = masters::add_master(nvs, &secret, &label, mode, &pubkey)?;
    Ok(LoadedMaster { slot, secret, label, mode, pubkey })
}

/// Handle a GENERATE_IDENTITY frame (0x57). The device generates its OWN seed
/// from the hardware RNG, derives the tree root, stores it, and shows the
/// 12-word recovery phrase on its OLED for the owner to write down. The phrase
/// is NEVER sent to the host — only the public npub is discoverable (via
/// PROVISION_LIST). Payload is optional `[label_len][label]`; empty ⇒ "default".
pub fn handle_generate(
    usb: &mut SerialPort<'_>,
    frame: &Frame,
    nvs: &mut EspNvs<NvsDefault>,
    secp: &Arc<Secp256k1<secp256k1::SignOnly>>,
    display: &mut Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> Option<LoadedMaster> {
    let label = if frame.payload.is_empty() {
        "default".to_string()
    } else {
        let label_len = frame.payload[0] as usize;
        if frame.payload.len() < 1 + label_len {
            log::warn!("GENERATE_IDENTITY label length overruns payload");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return None;
        }
        String::from_utf8_lossy(&frame.payload[1..1 + label_len]).to_string()
    };

    // Entropy from the hardware RNG — 128 bits → a 12-word phrase.
    let mut entropy = [0u8; 16];
    unsafe {
        esp_idf_svc::sys::esp_fill_random(entropy.as_mut_ptr() as *mut core::ffi::c_void, 16);
    }

    let (phrase, root) = match heartwood_common::mnemonic::generate(&entropy) {
        Ok(pair) => pair,
        Err(e) => {
            entropy.iter_mut().for_each(|b| *b = 0);
            log::error!("on-device generate failed: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return None;
        }
    };
    entropy.iter_mut().for_each(|b| *b = 0);

    let mut root = root; // own it so we can zeroize after storing
    let result = store_master(nvs, root, label, MasterMode::TreeMnemonic, secp);
    root.iter_mut().for_each(|b| *b = 0);

    match result {
        Ok(master) => {
            let npub = encode_npub(&master.pubkey);
            log::info!("Self-generated identity slot {}: {} ({npub})", master.slot, master.label);
            // Show the phrase on the device's own screen — the one place it ever
            // appears.
            oled::show_mnemonic(display, &phrase, "Hold button when saved");
            // ACK carries the public npub (only the public key leaves the device)
            // so the host can address it over the relay without a separate fetch.
            // Sent now so the host advances to its "write it down" step while the
            // owner copies the words.
            protocol::write_frame(usb, FRAME_TYPE_ACK, npub.as_bytes());
            // Hold the phrase up until the owner confirms with a button hold. The
            // caller redraws (or, for a wifi device, reboots) the instant we
            // return, so without this the phrase would flash and vanish — exactly
            // the "no words shown" failure this guards against.
            wait_for_writedown_ack(display, button_pin, &phrase);
            drop(phrase);
            Some(master)
        }
        Err(e) => {
            drop(phrase);
            log::error!("Generate-identity store failed: {e}");
            oled::show_error(display, "Generate failed");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            None
        }
    }
}

/// Keep the freshly-generated recovery phrase on screen until the owner
/// confirms they've written it down with a deliberate 2-second button hold.
///
/// This is the only moment the phrase is ever visible, and a wifi-standalone
/// device reboots within a second of provisioning, so we must NOT return (and
/// let the caller redraw or reboot) until the owner acknowledges. There is no
/// timeout: an unacknowledged phrase staying on screen is the safe failure
/// mode — dismissing it early would lose the key for good. The footer line
/// reflects the hold state, and we wait for release before returning so the
/// confirm hold isn't re-read by the post-reboot "hold PRG = USB" prompt.
fn wait_for_writedown_ack(
    display: &mut Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
    phrase: &str,
) {
    use esp_idf_hal::delay::FreeRtos;
    use std::time::Instant;

    const HOLD_MS: u128 = 2000;
    const POLL_MS: u32 = 20;

    let mut pressed = false;
    let mut press_start = Instant::now();

    loop {
        let low = button_pin.is_low();
        if low && !pressed {
            pressed = true;
            press_start = Instant::now();
            oled::show_mnemonic(display, phrase, "Keep holding...");
        } else if low && pressed {
            if press_start.elapsed().as_millis() >= HOLD_MS {
                oled::show_mnemonic(display, phrase, "Saved - release");
                // Wait for release so the held button isn't immediately re-read
                // by the post-reboot USB-mode escape hatch.
                while button_pin.is_low() {
                    FreeRtos::delay_ms(POLL_MS);
                }
                return;
            }
        } else if !low && pressed {
            // Released before the hold completed — reset and keep the phrase up.
            pressed = false;
            oled::show_mnemonic(display, phrase, "Hold button when saved");
        }
        FreeRtos::delay_ms(POLL_MS);
    }
}

/// Handle a PROVISION_REMOVE frame (0x04). Removes the named slot and
/// re-numbers the in-memory list to stay consistent with NVS.
pub fn handle_remove(
    usb: &mut SerialPort<'_>,
    frame: &Frame,
    nvs: &mut EspNvs<NvsDefault>,
    loaded: &mut Vec<LoadedMaster>,
    display: &mut Display<'_>,
) {
    if frame.payload.len() != 1 {
        log::warn!(
            "PROVISION_REMOVE payload is {} bytes, expected 1",
            frame.payload.len()
        );
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    let slot = frame.payload[0];
    match masters::remove_master(nvs, slot) {
        Ok(()) => {
            // Remove from the in-memory list and re-number to match NVS order.
            loaded.retain(|m| m.slot != slot);
            for (i, m) in loaded.iter_mut().enumerate() {
                m.slot = i as u8;
            }
            let msg = format!("Removed slot {slot}");
            oled::show_error(display, &msg);
            protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
        }
        Err(e) => {
            log::error!("Remove master slot {slot} failed: {e}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        }
    }
}

/// Handle a PROVISION_LIST frame (0x05). Responds with frame 0x07 containing
/// a JSON array of `{slot, label, mode, npub}` objects.
pub fn handle_list(usb: &mut SerialPort<'_>, loaded: &[LoadedMaster]) {
    let infos: Vec<serde_json::Value> = loaded
        .iter()
        .map(|m| {
            serde_json::json!({
                "slot": m.slot,
                "label": m.label,
                "mode": m.mode as u8,
                "npub": encode_npub(&m.pubkey),
            })
        })
        .collect();

    let json = serde_json::to_string(&infos).unwrap_or_else(|_| "[]".to_string());
    protocol::write_frame(usb, FRAME_TYPE_PROVISION_LIST_RESPONSE, json.as_bytes());
}

/// Handle a FACTORY_RESET frame (0x24).
///
/// Erases all NVS keys in the `heartwood` namespace and reboots the device.
/// Requires physical button approval (2-second hold) — this is irreversible.
pub fn handle_factory_reset(
    usb: &mut SerialPort<'_>,
    nvs: &mut EspNvs<NvsDefault>,
    display: &mut Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) {
    let result = crate::approval::run_approval_loop(
        display,
        button_pin,
        30,
        |d, remaining| {
            crate::oled::show_sign_request(d, "FACTORY", 0, "ERASE ALL DATA?", remaining);
        },
    );

    match result {
        crate::approval::ApprovalResult::Approved => {
            log::warn!("Factory reset approved — erasing NVS");
            crate::oled::show_error(display, "Erasing...");

            // Erase all master keys by removing slot 0 repeatedly (they shift down).
            let count = masters::read_master_count(nvs);
            for _ in 0..count {
                let _ = masters::remove_master(nvs, 0);
            }

            // Erase bridge secret and policy keys.
            let _ = nvs.remove("bridge_secret");
            for i in 0..8u8 {
                let key = format!("policy_{i}");
                let _ = nvs.remove(&key);
            }

            crate::oled::show_error(display, "Reset complete\nRebooting...");
            protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
            esp_idf_hal::delay::FreeRtos::delay_ms(1000);

            unsafe { esp_idf_svc::sys::esp_restart(); }
        }
        crate::approval::ApprovalResult::Denied => {
            log::info!("Factory reset denied");
            crate::oled::show_result(display, "Reset cancelled");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        }
        crate::approval::ApprovalResult::TimedOut => {
            log::info!("Factory reset timed out");
            crate::oled::show_result(display, "Timed out");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        }
    }
}
