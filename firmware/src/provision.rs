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
            oled::show_npub(display, None, &npub, None);
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

/// Two-button save confirm: **B** saves (returns `true`), **A** returns to
/// review (`false`). The confirm screen (the derived npub) is already drawn by
/// the caller; this only reads the choice. No hold, so nothing can be re-read
/// by a later prompt.
fn confirm_two_button(
    button_a: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
    button_b: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) -> bool {
    matches!(
        crate::button::read_two_button(button_a, button_b),
        crate::button::TwoButton::Select
    )
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
/// one-button picker (tap = next choice, double-tap = pick, hold = go back),
/// lets the owner review and edit all 12 words, validates the BIP-39
/// checksum, shows the derived npub to confirm the account, then stores it as a
/// `TreeMnemonic` master. Payload is optional `[label_len][label]`; empty ⇒ "default".
pub fn handle_restore(
    usb: &mut SerialPort<'_>,
    frame: &Frame,
    nvs: &mut EspNvs<NvsDefault>,
    secp: &Arc<Secp256k1<secp256k1::SignOnly>>,
    display: &mut Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
    // Second button, present on boards that have one (the T-Display). When set,
    // word entry runs the two-button picker (A = move, B = pick, no timing);
    // single-button boards (Heltec, C6) pass `None` and keep the gesture picker.
    button_b: Option<&esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>>,
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

    oled::show_restore_intro(display, button_b.is_some());
    esp_idf_hal::delay::FreeRtos::delay_ms(2200);

    const TOTAL: usize = 12;
    let mut words: Vec<&'static str> = Vec::with_capacity(TOTAL);

    // Sequential entry of all 12 words. Holding "back" past the start of an empty
    // word steps to the previous one; stepping back past word 1 cancels the restore.
    while words.len() < TOTAL {
        let idx = words.len() + 1;
        match enter_one_word(display, button_pin, button_b, idx, TOTAL) {
            WordResult::Accepted(w) => words.push(w),
            WordResult::Back => {
                if words.pop().is_none() {
                    return cancel_restore(usb, display);
                }
            }
        }
    }

    // Review + save loop. The owner can page through every word and re-edit any
    // one before committing; SAVE validates the checksum (a failure marks the
    // list so they can hunt the wrong word) and then confirms the derived npub.
    let mut invalid = false;
    loop {
        match review_phrase(display, button_pin, button_b, &mut words, invalid) {
            ReviewOutcome::Cancel => return cancel_restore(usb, display),
            ReviewOutcome::Save => {
                let phrase = words.join(" ");
                let mut root = match restore_root(&phrase) {
                    Ok(r) => r,
                    Err(_) => {
                        invalid = true; // back to review, banner on
                        continue;
                    }
                };
                invalid = false;

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

                // Verify the account before committing; a "back" returns to
                // review (e.g. right checksum, wrong account). Two-button boards
                // confirm with B (A = back); single-button boards use the
                // deliberate 2-second save hold.
                oled::show_restore_confirm(display, &npub, button_b.is_some());
                let confirmed = match button_b {
                    Some(b) => confirm_two_button(button_pin, b),
                    None => hold_to_confirm(display, button_pin),
                };
                if !confirmed {
                    root.iter_mut().for_each(|b| *b = 0);
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
        }
    }
}

/// NACK + acknowledge a cancelled restore on screen.
fn cancel_restore(usb: &mut SerialPort<'_>, display: &mut Display<'_>) -> Option<LoadedMaster> {
    log::info!("restore cancelled by operator");
    oled::show_result(display, "Cancelled");
    protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
    None
}

/// The result of entering (or editing) a single word.
enum WordResult {
    /// A BIP-39 word was accepted.
    Accepted(&'static str),
    /// Hold "back" past the first choice on an empty prefix — the caller decides
    /// what "back" means (step to the previous word, or abandon an edit keeping
    /// the old word).
    Back,
}

/// Entry of a single word. Two input styles share one draw loop:
///
/// * **Two-button** (T-Display, `button_b = Some`): the ring is the valid next
///   letters, the whole word once it resolves, and a trailing **⌫ back** item.
///   Button A moves the highlight, button B picks it. No timing — no
///   double-taps, no holds. Picking a letter extends the prefix, the word
///   accepts, ⌫ removes the last letter (or, on an empty prefix, returns
///   [`WordResult::Back`]).
/// * **One-button** (`button_b = None`): a single tap moves, a double-tap
///   picks, and a hold goes back one step (from the first choice it deletes the
///   last letter, or on an empty prefix returns [`WordResult::Back`]). Once the
///   prefix resolves to the sole word, a single tap accepts it.
fn enter_one_word(
    display: &mut Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
    button_b: Option<&esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>>,
    index: usize,
    total: usize,
) -> WordResult {
    let two = button_b.is_some();
    let mut entry = WordEntry::new();
    let mut sel = 0usize;

    loop {
        let choices = entry.choices();
        let n = choices.len();
        // Two-button boards get a trailing ⌫ back slot in the ring; one-button
        // boards reach "back" through a hold instead.
        let ring = if two { n + 1 } else { n };
        if ring == 0 || sel >= ring {
            sel = 0;
        }
        let back_slot = two && sel == n;
        // One-button only: the sole resolved word accepts on a single tap.
        let sole_word = !two && n == 1 && matches!(choices[0], Choice::Word(_));

        if back_slot {
            oled::show_word_entry(display, index, total, "back", oled::Highlight::Delete, "delete a letter", false, true);
        } else {
            match choices[sel] {
                Choice::Letter(c) => {
                    let mut text = entry.prefix().to_string();
                    text.push(c);
                    let sub = if two {
                        format!("{} left", entry.candidate_count())
                    } else {
                        format!("{} left   2tap=pick", entry.candidate_count())
                    };
                    oled::show_word_entry(display, index, total, &text, oled::Highlight::Letter, &sub, false, two);
                }
                Choice::Word(w) => {
                    let sub = if two {
                        "B = use this word"
                    } else if sole_word {
                        "tap = use this word"
                    } else {
                        "2tap = use this word"
                    };
                    oled::show_word_entry(display, index, total, w, oled::Highlight::Word, sub, sole_word, two);
                }
            }
        }

        if let Some(b) = button_b {
            match crate::button::read_two_button(button_pin, b) {
                crate::button::TwoButton::Advance => sel = (sel + 1) % ring,
                crate::button::TwoButton::Select => {
                    if back_slot {
                        if !entry.backspace() {
                            return WordResult::Back;
                        }
                        sel = 0;
                    } else {
                        match choices[sel] {
                            Choice::Letter(c) => {
                                entry.push(c);
                                sel = 0;
                            }
                            Choice::Word(w) => return WordResult::Accepted(w),
                        }
                    }
                }
            }
            continue;
        }

        match next_gesture(button_pin) {
            Gesture::Single => {
                if sole_word {
                    if let Choice::Word(w) = choices[0] {
                        return WordResult::Accepted(w);
                    }
                }
                sel = (sel + 1) % n;
            }
            Gesture::Double => match choices[sel] {
                Choice::Letter(c) => {
                    entry.push(c);
                    sel = 0;
                }
                Choice::Word(w) => return WordResult::Accepted(w),
            },
            Gesture::Long => {
                if sel > 0 {
                    sel -= 1;
                } else if !entry.backspace() {
                    return WordResult::Back;
                } else {
                    sel = 0;
                }
            }
        }
    }
}

/// What the review screen returns.
enum ReviewOutcome {
    Save,
    Cancel,
}

/// Page through the 12 entered words (plus SAVE / CANCEL items) and act on one.
/// Two-button boards move with A and act with B; one-button boards tap to move,
/// hold to move back, and double-tap to act. Acting on a word re-enters that one
/// slot in place. `invalid` shows a banner when the phrase last failed its
/// checksum, so the owner knows a wrong word is still hiding in the list.
fn review_phrase(
    display: &mut Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
    button_b: Option<&esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>>,
    words: &mut [&'static str],
    invalid: bool,
) -> ReviewOutcome {
    let two = button_b.is_some();
    let n = words.len();
    let total_items = n + 2; // words + SAVE + CANCEL
    let mut sel = 0usize;

    loop {
        if sel < n {
            oled::show_review_word(display, sel + 1, n, words[sel], invalid);
        } else if sel == n {
            oled::show_review_action(display, "SAVE", if two { "B = save" } else { "2tap = save" });
        } else {
            oled::show_review_action(display, "CANCEL", if two { "B = discard" } else { "2tap = discard" });
        }

        // `act` is set when the highlighted item should be actioned (B, or a
        // double-tap). Movement is handled inline.
        let act = if let Some(b) = button_b {
            match crate::button::read_two_button(button_pin, b) {
                crate::button::TwoButton::Advance => {
                    sel = (sel + 1) % total_items;
                    false
                }
                crate::button::TwoButton::Select => true,
            }
        } else {
            match next_gesture(button_pin) {
                Gesture::Single => {
                    sel = (sel + 1) % total_items;
                    false
                }
                Gesture::Long => {
                    sel = (sel + total_items - 1) % total_items;
                    false
                }
                Gesture::Double => true,
            }
        };

        if act {
            if sel < n {
                // Re-enter this slot; a Back keeps the existing word.
                if let WordResult::Accepted(w) = enter_one_word(display, button_pin, button_b, sel + 1, n) {
                    words[sel] = w;
                }
            } else if sel == n {
                return ReviewOutcome::Save;
            } else {
                return ReviewOutcome::Cancel;
            }
        }
    }
}

/// Block until one gesture is read, re-arming on the (deliberately long) idle
/// timeout so it never returns on its own. (Distinct from `press_blocking`,
/// which reports the approve/deny `ButtonResult` used by the generate walkthrough.)
fn next_gesture(
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
pub fn handle_list(
    usb: &mut SerialPort<'_>,
    loaded: &[LoadedMaster],
    personas: &[crate::personas::LoadedPersona],
) {
    let mut infos: Vec<serde_json::Value> = loaded
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

    // Derived personas are each addressable by their own bunker URI. The bridge
    // subscribes to every npub reported here, so listing them makes persona
    // connections reachable (and they survive reboot via the NVS registry).
    for p in personas {
        infos.push(serde_json::json!({
            "slot": p.master_slot,
            "label": p.name.clone().unwrap_or_else(|| p.purpose.clone()),
            "npub": encode_npub(&p.pubkey),
            "persona": true,
        }));
    }

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
