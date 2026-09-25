// firmware/src/phone_unlock_cmd.rs
//
// Managing the phones that can unlock this board
// (docs/specs/2026-09-24-phone-unlock-design.md section 3). One JSON command
// set, served over the cable (frame 0x64 -> 0x65, authenticated bridge
// session required) and, except for enrolment, over the relay management
// channel:
//
//   enrol                   adds authority to unlock: needs the board
//                           unlocked, at-rest encryption on (so a data key
//                           exists to wrap), relays configured, and a press.
//                           On the cable the card blocks, as every cable card
//                           does. Over the relay (`enrol_unlock_phone`, device
//                           operator only) relay.rs holds it as a deferred
//                           card (#64) and completes it here once pressed:
//                           [`check_enrol`] before the card, [`complete_enrol`]
//                           after it. Both cards lead with the request code's
//                           five words (`phone_unlock::request_words`), which
//                           the owner compares with the phone that made the
//                           key, and the board shows the check code once the
//                           phone is added.
//   list                    ids and labels; nothing that unlocks.
//   revoke                  deletes a phone's record, and with it its
//                           authority. No press: removing authority is always
//                           allowed. Revoking the last phone also forgets the
//                           relays the phones were told (relay.rs RelayUpdate).
//   set_announce_operator   whether the locked board still publishes the
//                           operator's announcement, the one stable `p` tag.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use heartwood_common::data_key::{self, PhoneSet};
use heartwood_common::phone_unlock::{
    self, EnrolError, EnrolFacts, EnrolRefusal, Enrolment, PhoneCmd, UsedEnrolKeys,
};
use heartwood_common::types::{FRAME_TYPE_NACK, FRAME_TYPE_PHONE_UNLOCK_RESP};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::data_key_store::{self, NvsBlobs};
use crate::masters::LoadedMaster;
use crate::serial::SerialPort;

/// Enrolment keys already answered this boot, shared by the cable and the
/// relay (`phone_unlock::UsedEnrolKeys`). Refused before any card is shown.
static USED_ENROL_KEYS: Mutex<Option<UsedEnrolKeys>> = Mutex::new(None);

/// Mark an enrolment key used, or refuse it as already used.
pub fn claim_enrol_key(key: &[u8; 32]) -> Result<(), String> {
    let mut used = USED_ENROL_KEYS.lock().unwrap_or_else(|e| e.into_inner());
    if used.get_or_insert_with(UsedEnrolKeys::default).claim(key) {
        Ok(())
    } else {
        Err(EnrolRefusal::KeyUsed.message())
    }
}

/// Set by a revoke or an enrolment, so a relay update under way (relay.rs
/// RelayUpdate) checks its record on its next pass instead of its next round.
static PHONES_CHANGED: AtomicBool = AtomicBool::new(false);

/// Whether the phones changed since the last call.
pub fn take_phones_changed() -> bool {
    PHONES_CHANGED.swap(false, Ordering::AcqRel)
}

/// The PHONE ADDED screen an enrolment drew, kept so a caller can hold it
/// until a press (`phone_unlock::ResultHold`) and draw it again after
/// anything that interrupts it.
#[derive(Clone, Debug)]
pub struct Added {
    pub check: String,
    pub id: u32,
}

impl Added {
    fn of(enrolment: &Enrolment) -> Self {
        Added { check: phone_unlock::check_code(&enrolment.ephemeral_pubkey), id: enrolment.id }
    }

    /// Draw the screen again.
    pub fn show(&self, display: &mut crate::oled::Display<'_>) {
        crate::oled::show_phone_added(display, &self.check, self.id);
    }
}

/// What a PHONE_UNLOCK_CMD frame did to the screen.
pub enum Screen {
    /// No card went up: another command, or an enrolment refused before its
    /// card (bad auth, a used key, a board that cannot enrol). Whatever was
    /// on screen is still there.
    Untouched,
    /// An enrol card went up and ended with nothing added: declined or
    /// expired ("Denied", "Cancelled" or "Expired" is on screen), or refused
    /// after the press (the board full or locked by then, a storage or
    /// memory failure: "No phone added" is on screen).
    NothingAdded,
    /// A phone was added and PHONE ADDED drawn, for the caller to hold until
    /// a press (main.rs in USB mode, relay.rs in WiFi mode).
    Added(Added),
}

/// Handle a PHONE_UNLOCK_CMD frame (0x64), and say what it left on screen.
pub fn handle_frame(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    nvs: &mut EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
    bridge_authenticated: bool,
    display: &mut crate::oled::Display<'_>,
    buttons: &crate::button::Buttons<'_>,
) -> Screen {
    if !bridge_authenticated {
        crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"bridge auth required");
        return Screen::Untouched;
    }
    let mut screen = Screen::Untouched;
    let outcome = PhoneCmd::parse(payload).map_err(str::to_string).and_then(|cmd| match cmd {
        PhoneCmd::Enrol { enrol_pubkey, label } => {
            let (outcome, card_shown) = enrol_on_cable(&enrol_pubkey, label, nvs, masters, display, buttons);
            if card_shown {
                screen = Screen::NothingAdded;
            }
            outcome.map(|(answer, added)| {
                screen = Screen::Added(added);
                answer
            })
        }
        cmd => run(cmd, nvs),
    });
    match outcome {
        Ok(answer) => {
            crate::protocol::write_frame(usb, FRAME_TYPE_PHONE_UNLOCK_RESP, answer.to_string().as_bytes());
        }
        Err(e) => {
            log::warn!("phone unlock: {e}");
            crate::protocol::write_frame(usb, FRAME_TYPE_NACK, e.as_bytes());
        }
    }
    screen
}

fn load(nvs: &mut EspNvs<NvsDefault>) -> Result<PhoneSet, String> {
    data_key::load_phones(&NvsBlobs(nvs)).map_err(|_| "phone records unreadable".to_string())
}

fn save(nvs: &mut EspNvs<NvsDefault>, phones: &PhoneSet) -> Result<(), String> {
    data_key::save_phones(&mut NvsBlobs(nvs), phones)
        .map_err(|_| "phone storage full or failing: nothing was changed".to_string())
}

fn configured_relays(nvs: &EspNvs<NvsDefault>) -> Vec<String> {
    crate::net_config_store::read_net_config(nvs)
        .and_then(|raw| heartwood_common::net_config::parse_net_config(&raw).ok())
        .map(|cfg| {
            cfg.relays
                .iter()
                .map(|r| r.trim().to_string())
                .filter(|r| !r.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Run one command. Enrolment is not run here: the cable's goes through
/// [`enrol_on_cable`] (`handle_frame`), and the relay holds its own on a
/// deferred card (relay.rs).
pub fn run(cmd: PhoneCmd, nvs: &mut EspNvs<NvsDefault>) -> Result<serde_json::Value, String> {
    match cmd {
        PhoneCmd::List => {
            let phones = load(nvs)?;
            Ok(phone_unlock::list_json(&phones, data_key_store::announce_operator(nvs)))
        }
        PhoneCmd::Revoke { id } => {
            let mut phones = load(nvs)?;
            phones.revoke(id).map_err(|_| format!("no phone with id {id}"))?;
            save(nvs, &phones)?;
            PHONES_CHANGED.store(true, Ordering::Release);
            log::info!("phone unlock: revoked phone {id}");
            // No phone listens anywhere now; the next enrolment records afresh.
            if phones.is_empty() && heartwood_common::phone_relays::forget_told(&mut NvsBlobs(nvs)).is_err() {
                log::warn!("phone unlock: relay record not cleared");
            }
            Ok(serde_json::json!({ "revoked": id }))
        }
        PhoneCmd::SetAnnounceOperator { on } => {
            data_key_store::set_announce_operator(nvs, on)
                .map_err(|_| "could not save the setting".to_string())?;
            Ok(serde_json::json!({ "announce_operator": on }))
        }
        PhoneCmd::Enrol { .. } => {
            // relay.rs holds a relay enrolment on a deferred card instead.
            Err("enrolling a phone over the relay waits on a card: use enrol_unlock_phone".into())
        }
    }
}

/// Enrol over the cable: the blocking card, for `phone_unlock::ENROL_CARD_SECS`
/// (45 s, for the five words to be read a page at a time and compared), gated
/// until every page has been shown (`approval::run_enrol_approval_loop`), then
/// PHONE ADDED. Returns the answer and what PHONE ADDED showed, and whether
/// the card went up at all (false when refused before it).
fn enrol_on_cable(
    enrol_pubkey: &[u8; 32],
    label: String,
    nvs: &mut EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
    display: &mut crate::oled::Display<'_>,
    buttons: &crate::button::Buttons<'_>,
) -> (Result<(serde_json::Value, Added), String>, bool) {
    // One attempt per enrolment key, whatever its outcome: marked before
    // anything can fail, so a resend queued behind this command (or one
    // after a decline) is refused rather than raising another card.
    if let Err(e) = claim_enrol_key(enrol_pubkey) {
        return (Err(e), false);
    }
    let label = default_label(label);
    if let Err(e) = check_enrol(nvs, masters, &label) {
        return (Err(e), false);
    }

    let words = phone_unlock::request_words(enrol_pubkey);
    let window = phone_unlock::ENROL_CARD_SECS;
    // No hold counts until every page has been on screen its full dwell
    // (EnrolGate); a tap before then does nothing, so it cannot decline and
    // spend the key.
    let approved = crate::approval::run_enrol_approval_loop(
        display,
        buttons,
        u64::from(window),
        |d, remaining, page, armed| {
            crate::oled::show_enrol_approval(d, &words, &label, remaining, window, page, armed);
        },
    );
    if !matches!(approved, crate::approval::ApprovalResult::Approved) {
        return (Err("declined on the board".into()), true);
    }

    let enrolment =
        match complete_enrol(nvs, masters, enrol_pubkey, &label, phone_unlock::enrol_refusal, |_| true) {
            Ok(enrolment) => enrolment,
            Err(e) => {
                // The approval loop left APPROVED up; say plainly that no
                // phone was added, as the relay card does.
                crate::oled::show_not_done(display, "No phone added", "see Sapwood");
                wait_for_release(buttons);
                return (Err(e), true);
            }
        };
    let added = Added::of(&enrolment);
    added.show(display);
    // The approving hold usually still has the button down here. Let
    // it go before returning, or the cable-only loop takes the same
    // press for a carousel page and wipes the check code at once.
    wait_for_release(buttons);
    (Ok((phone_unlock::enrolment_json(&enrolment), added)), true)
}

/// The label the board keeps when the requester sent none.
pub fn default_label(label: String) -> String {
    if label.is_empty() {
        "phone".to_string()
    } else {
        label
    }
}

/// What the board knows about whether an enrolment of `label` can go ahead,
/// and the phone set it counted, decoded once. A locked board refuses as
/// locked before its phone blob is read.
fn read_board(
    nvs: &mut EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
    label: &str,
) -> Result<(EnrolFacts, Option<PhoneSet>, Vec<String>), String> {
    let unlocked = !masters.is_empty() && !crate::pin::is_locked(masters);
    let data_key = data_key_store::current()
        .map(|mut dk| dk.iter_mut().for_each(|b| *b = 0))
        .is_some();
    let relays = configured_relays(nvs);
    let phones = if unlocked { Some(load(nvs)?) } else { None };
    let facts = EnrolFacts {
        label_len: label.len(),
        unlocked,
        data_key,
        relays: !relays.is_empty(),
        phones: phones.as_ref().map_or(0, |p| p.records().len()),
    };
    Ok((facts, phones, relays))
}

/// Whether an enrolment of `label` could go ahead now. Asked before a card
/// goes up, so a board that cannot enrol never asks for a press.
pub fn check_enrol(nvs: &mut EspNvs<NvsDefault>, masters: &[LoadedMaster], label: &str) -> Result<(), String> {
    match phone_unlock::enrol_refusal(&read_board(nvs, masters, label)?.0) {
        Some(refusal) => Err(refusal.message()),
        None => Ok(()),
    }
}

/// Add the phone, once pressed. The board is read again (the phone set
/// decoded once) and `gate` decides on what it says: the cable passes
/// `enrol_refusal`, the relay `relay_enrol_completion` with its operator and
/// relay checks. Then the slot secret is drawn and the hand-off sealed in
/// RAM; `fits` says whether the answer carrying it can be sent (the relay's
/// heap check), and only then is the record persisted, so a phone is never
/// handed a secret the board did not keep, and a board short of memory
/// refuses before any NVS write. A full NVS refuses at the save, cleanly.
pub fn complete_enrol(
    nvs: &mut EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
    enrol_pubkey: &[u8; 32],
    label: &str,
    gate: impl FnOnce(&EnrolFacts) -> Option<EnrolRefusal>,
    fits: impl FnOnce(&Enrolment) -> bool,
) -> Result<Enrolment, String> {
    let (facts, phones, relays) = read_board(nvs, masters, label)?;
    if let Some(refusal) = gate(&facts) {
        return Err(refusal.message());
    }
    let (Some(mut phones), Some(mut dk)) = (phones, data_key_store::current()) else {
        return Err(EnrolRefusal::NoDataKey.message());
    };
    let had_phones = !phones.is_empty();
    let enrolment = phone_unlock::enrol(
        &mut phones,
        &dk,
        enrol_pubkey,
        label,
        &relays,
        &mut |buf: &mut [u8]| crate::fill_random(buf),
    );
    dk.iter_mut().for_each(|b| *b = 0);
    let enrolment = enrolment.map_err(|e| match e {
        EnrolError::BadEnrolmentKey => "enrol_pubkey is not a valid key".to_string(),
        EnrolError::NoRelays => EnrolRefusal::NoRelays.message(),
        EnrolError::Phone(data_key::PhoneError::Full) => EnrolRefusal::Full.message(),
        EnrolError::Phone(e) => format!("could not add the phone: {e:?}"),
        EnrolError::Crypto(e) => format!("enrolment failed: {e}"),
    })?;
    if !fits(&enrolment) {
        return Err(EnrolRefusal::LowMemory.message());
    }
    save(nvs, &phones)?;
    PHONES_CHANGED.store(true, Ordering::Release);
    log::info!("phone unlock: enrolled phone {} ({label})", enrolment.id);
    // The phone was handed `relays`. As the only phone, whatever the
    // record said belonged to phones that are gone, so it is replaced;
    // beside others it is written only if missing, so an update they
    // are still owed is not cut short. A failed write is repaired at
    // the next boot, which records the live list when there is none.
    if heartwood_common::phone_relays::record_told_at_enrolment(&mut NvsBlobs(nvs), had_phones, &relays).is_err() {
        log::warn!("phone unlock: relay record not saved");
    }
    Ok(enrolment)
}

/// Wait, feeding the watchdog, until the button that approved a card is let
/// go. Bounded: a serial bridge can pin GPIO 0 low after a web flash, and a
/// pinned button must not hold the board here.
fn wait_for_release(buttons: &crate::button::Buttons<'_>) {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while buttons.a.is_low() && std::time::Instant::now() < until {
        crate::wdt::feed();
        esp_idf_hal::delay::FreeRtos::delay_ms(20);
    }
}

