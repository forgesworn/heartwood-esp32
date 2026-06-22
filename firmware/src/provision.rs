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

use crate::button::Gesture;
use crate::masters::{self, LoadedMaster};
use crate::oled::{self, Display};
use crate::protocol;
use heartwood_common::restore::{restore_root, Choice, WordEntry};

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

    // Feedback while the (multi-second) entropy draw + PBKDF2 + derivation +
    // NVS write run, so the device isn't silently stuck on the previous screen.
    oled::show_generating(display);

    // Entropy from the hardware RNG — 128 bits → a 12-word phrase. Drawn with a
    // guaranteed entropy source: provisioning runs before the Wi-Fi radio is up,
    // so esp_random alone would be only pseudo-random here.
    let mut entropy = [0u8; 16];
    crate::fill_random_strong(&mut entropy);

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
            // ACK carries the public npub (only the public key leaves the device)
            // so the host can address it over the relay without a separate fetch.
            // Sent now so the host advances to its "write it down" step while the
            // owner steps through the words on the device.
            protocol::write_frame(usb, FRAME_TYPE_ACK, npub.as_bytes());
            // Walk the owner through the phrase one big word at a time and block
            // the caller from redrawing (or, for a wifi device, rebooting) until
            // they confirm with a hold. The phrase only ever appears here.
            walk_recovery_phrase(display, button_pin, &phrase);
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

/// Walk the owner through the freshly-generated recovery phrase one large word
/// at a time, advancing on a PRG tap, then gate completion behind a deliberate
/// hold on a final confirm screen.
///
/// This is the only moment the phrase is ever visible, and a wifi-standalone
/// device reboots within a second of provisioning, so we must NOT return (and
/// let the caller redraw or reboot) until the owner confirms. There is no
/// timeout: an unconfirmed phrase staying on screen is the safe failure mode —
/// dismissing it early would lose the key for good. A short tap on the confirm
/// screen restarts the walkthrough so the owner can re-check; only a hold
/// (which `wait_for_press` returns once the button is released) ends it, so the
/// confirm hold can't be re-read by the post-reboot "hold PRG = USB" prompt.
fn walk_recovery_phrase(
    display: &mut Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
    phrase: &str,
) {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let total = words.len();

    loop {
        // Step through every word; any press advances to the next.
        for (i, word) in words.iter().enumerate() {
            oled::show_recovery_word(display, i + 1, total, word);
            let _ = press_blocking(button_pin);
        }

        // Confirm with the same 0–100% hold bar used for signing: a full hold
        // saves, a short tap restarts the review.
        if confirm_recovery_save(display, button_pin) {
            oled::show_result(display, "SAVED");
            return;
        }
    }
}

/// Final save gate for the recovery walkthrough. Mirrors the signing approval:
/// a press fills a 0–100% bar over two seconds (the shared `show_hold_progress`
/// screen), completing the save; releasing early restarts the review. Waits for
/// release before returning so the confirm hold isn't re-read by the post-reboot
/// "hold PRG = USB" prompt. Returns true to save, false to show the words again.
fn confirm_recovery_save(
    display: &mut Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> bool {
    oled::show_recovery_done(display);
    hold_to_confirm(display, button_pin)
}

/// Run a 0–100% hold-to-confirm over the shared `show_hold_progress` bar,
/// returning true once a full two-second hold completes (draining to release so
/// the hold can't be re-read), or false if the button is released early. The
/// caller must have already drawn the prompt screen this overlays — used by
/// both the recovery-save and restore-save confirmations.
fn hold_to_confirm(
    display: &mut Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> bool {
    use esp_idf_hal::delay::FreeRtos;
    use std::time::Instant;

    const HOLD_MS: u32 = 2000;
    const POLL_MS: u32 = 20;

    let mut pressed = false;
    let mut press_start = Instant::now();
    let mut last_pct = 101u32; // force first bar draw

    loop {
        let low = button_pin.is_low();
        if low && !pressed {
            pressed = true;
            press_start = Instant::now();
            last_pct = 101;
        } else if low && pressed {
            let held = press_start.elapsed().as_millis() as u32;
            if held >= HOLD_MS {
                oled::show_hold_progress(display, 100);
                while button_pin.is_low() {
                    FreeRtos::delay_ms(POLL_MS);
                }
                return true;
            }
            let pct = (held * 100 / HOLD_MS).min(100);
            if pct / 5 != last_pct / 5 {
                oled::show_hold_progress(display, pct);
                last_pct = pct;
            }
        } else if !low && pressed {
            return false; // released before the hold completed
        }
        FreeRtos::delay_ms(POLL_MS);
    }
}

/// Block until the PRG button is pressed and released, reporting whether it was
/// a long hold (`Approve`) or a short tap (`Deny`). Re-arms on the (deliberately
/// long) timeout so it never returns on its own.
fn press_blocking(
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> crate::button::ButtonResult {
    loop {
        if let Some(r) = crate::button::wait_for_press(button_pin, std::time::Duration::from_secs(3600)) {
            return r;
        }
    }
}

/// Handle a RESTORE_IDENTITY frame (0x58). The owner re-enters an EXISTING
/// 12-word recovery phrase on the device itself via the single PRG button — the
/// phrase is never typed into or sent from the host (the host only triggers the
/// flow and learns the resulting public npub). The device drives an on-screen
/// one-button picker (tap = next, double-tap = choose, hold = delete),
/// validates the BIP-39 checksum, shows the derived npub for the owner to
/// confirm it is the right account, then stores it as a `TreeMnemonic` master.
/// Payload is optional `[label_len][label]`; empty ⇒ "default".
pub fn handle_restore(
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
            log::warn!("RESTORE_IDENTITY label length overruns payload");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return None;
        }
        String::from_utf8_lossy(&frame.payload[1..1 + label_len]).to_string()
    };

    oled::show_restore_intro(display);
    esp_idf_hal::delay::FreeRtos::delay_ms(2200);

    // Words accepted so far. Survives across validation attempts so a checksum
    // failure can drop just the last word and resume entry rather than restart.
    let mut words: Vec<&'static str> = Vec::with_capacity(12);

    loop {
        if !enter_words(display, button_pin, &mut words) {
            log::info!("restore cancelled by operator");
            oled::show_result(display, "Cancelled");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            return None;
        }

        let phrase = words.join(" ");
        match restore_root(&phrase) {
            Ok(mut root) => {
                let npub = match npub_from_secret(&root, secp) {
                    Some(n) => n,
                    None => {
                        root.iter_mut().for_each(|b| *b = 0);
                        log::error!("restore: derived secret rejected by secp");
                        oled::show_error(display, "Restore failed");
                        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
                        return None;
                    }
                };

                // Show the resulting npub and gate the save behind a hold so the
                // owner can verify it is the account they meant to restore.
                oled::show_restore_confirm(display, &npub);
                if !hold_to_confirm(display, button_pin) {
                    // "Not this account" — let them fix the last word.
                    root.iter_mut().for_each(|b| *b = 0);
                    words.pop();
                    continue;
                }

                let result = store_master(nvs, root, label, MasterMode::TreeMnemonic, secp);
                root.iter_mut().for_each(|b| *b = 0);
                return match result {
                    Ok(master) => {
                        log::info!("Restored identity slot {}: {} ({npub})", master.slot, master.label);
                        protocol::write_frame(usb, FRAME_TYPE_ACK, npub.as_bytes());
                        oled::show_result(display, "RESTORED");
                        Some(master)
                    }
                    Err(e) => {
                        log::error!("Restore store failed: {e}");
                        oled::show_error(display, "Restore failed");
                        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
                        None
                    }
                };
            }
            Err(_) => {
                // Valid words but a failed checksum — a mistyped word. Offer to
                // fix the last word (tap) or abandon the restore (hold).
                oled::show_restore_invalid(display);
                match gesture_blocking(button_pin) {
                    Gesture::Long => {
                        log::info!("restore abandoned after invalid phrase");
                        oled::show_result(display, "Cancelled");
                        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
                        return None;
                    }
                    _ => {
                        words.pop();
                    }
                }
            }
        }
    }
}

/// Drive the one-button picker to fill `words` to twelve. Each word is entered
/// letter by letter, the wordlist autocompleting as the prefix narrows: a tap
/// cycles the highlighted choice, a double-tap commits it (a letter, or a whole
/// word once it is uniquely determined), and a hold backspaces — stepping back
/// to the previous word when the current one is empty. Returns false if the
/// owner holds past the very first word (cancelling the whole restore).
fn enter_words(
    display: &mut Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
    words: &mut Vec<&'static str>,
) -> bool {
    const TOTAL: usize = 12;

    while words.len() < TOTAL {
        let word_index = words.len() + 1;
        let mut entry = WordEntry::new();
        let mut sel = 0usize;

        loop {
            let choices = entry.choices();
            if choices.is_empty() {
                // Defensive: a prefix that matches nothing cannot arise from the
                // picker (it only commits offered letters), but never wedge.
                entry = WordEntry::new();
                sel = 0;
                continue;
            }
            if sel >= choices.len() {
                sel = 0;
            }

            let (text, is_word) = match choices[sel] {
                Choice::Letter(c) => {
                    let mut t = entry.prefix().to_string();
                    t.push(c);
                    (t, false)
                }
                Choice::Word(w) => (w.to_string(), true),
            };
            oled::show_word_entry(display, word_index, TOTAL, &text, is_word, entry.candidate_count());

            match gesture_blocking(button_pin) {
                Gesture::Single => sel = (sel + 1) % choices.len(),
                Gesture::Double => match choices[sel] {
                    Choice::Letter(c) => {
                        entry.push(c);
                        sel = 0;
                    }
                    Choice::Word(w) => {
                        words.push(w);
                        break; // on to the next word
                    }
                },
                Gesture::Long => {
                    if !entry.backspace() {
                        // Empty prefix: step back a word, or cancel at word one.
                        if words.pop().is_none() {
                            return false;
                        }
                        break; // re-enter the previous slot from scratch
                    }
                    sel = 0;
                }
            }
        }
    }
    true
}

/// Block until one classified button gesture is read, re-arming on the long
/// idle timeout so it never returns on its own (mirrors `press_blocking`).
fn gesture_blocking(
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> Gesture {
    loop {
        if let Some(g) = crate::button::read_gesture(button_pin, std::time::Duration::from_secs(3600)) {
            return g;
        }
    }
}

/// Derive the npub for a root secret without storing it, so the owner can
/// confirm the restored identity before it is persisted. Returns None only if
/// the secret is not a valid secp256k1 key (a derived BIP-32 root always is).
fn npub_from_secret(secret: &[u8; 32], secp: &Arc<Secp256k1<secp256k1::SignOnly>>) -> Option<String> {
    let keypair = secp256k1::Keypair::from_seckey_slice(secp, secret).ok()?;
    let (xonly, _) = keypair.x_only_public_key();
    Some(encode_npub(&xonly.serialize()))
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
