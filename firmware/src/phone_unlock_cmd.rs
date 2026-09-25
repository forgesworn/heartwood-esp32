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
//                           after it. Both cards lead with the request code
//                           (`phone_unlock::request_code`), and the board
//                           shows the check code once the phone is added.
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

/// Handle a PHONE_UNLOCK_CMD frame (0x64).
pub fn handle_frame(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    nvs: &mut EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
    bridge_authenticated: bool,
    display: &mut crate::oled::Display<'_>,
    buttons: &crate::button::Buttons<'_>,
) {
    if !bridge_authenticated {
        crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"bridge auth required");
        return;
    }
    let outcome = PhoneCmd::parse(payload)
        .map_err(str::to_string)
        .and_then(|cmd| run(cmd, nvs, masters, display, Some(buttons)));
    match outcome {
        Ok(answer) => crate::protocol::write_frame(
            usb,
            FRAME_TYPE_PHONE_UNLOCK_RESP,
            answer.to_string().as_bytes(),
        ),
        Err(e) => {
            log::warn!("phone unlock: {e}");
            crate::protocol::write_frame(usb, FRAME_TYPE_NACK, e.as_bytes());
        }
    }
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

/// Run one command. `buttons` is `None` on the relay path, which holds an
/// enrolment on a deferred card (relay.rs) instead of running it here.
pub fn run(
    cmd: PhoneCmd,
    nvs: &mut EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
    display: &mut crate::oled::Display<'_>,
    buttons: Option<&crate::button::Buttons<'_>>,
) -> Result<serde_json::Value, String> {
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
        PhoneCmd::Enrol { enrol_pubkey, label } => {
            let Some(buttons) = buttons else {
                // relay.rs holds a relay enrolment on a deferred card instead.
                return Err("enrolling a phone over the relay waits on a card: use enrol_unlock_phone".into());
            };
            // One attempt per enrolment key, whatever its outcome: marked before
            // anything can fail, so a resend queued behind this command (or one
            // after a decline) is refused rather than raising another card.
            claim_enrol_key(&enrol_pubkey)?;
            let label = default_label(label);
            check_enrol(nvs, masters, &label)?;

            let title = phone_unlock::enrol_card_title(&phone_unlock::request_code(&enrol_pubkey), &label);
            let approved = crate::approval::run_approval_loop(display, buttons, 30, |d, remaining| {
                crate::oled::show_titled_approval(d, ENROL_CARD_HEADER, &title, remaining, 30);
            });
            if !matches!(approved, crate::approval::ApprovalResult::Approved) {
                return Err("declined on the board".into());
            }

            let enrolment = complete_enrol(nvs, masters, &enrol_pubkey, &label)?;
            show_enrolled(display, &enrolment);
            Ok(phone_unlock::enrolment_json(&enrolment))
        }
    }
}

/// The enrol card's header, on the cable and the relay alike.
pub const ENROL_CARD_HEADER: &str = "ADD UNLOCK PHONE";

/// The label the board keeps when the requester sent none.
pub fn default_label(label: String) -> String {
    if label.is_empty() {
        "phone".to_string()
    } else {
        label
    }
}

/// What the board knows about whether an enrolment of `label` can go ahead.
/// A relay card's press is checked against these again: anything may have
/// changed while the card was up.
pub fn enrol_facts(nvs: &mut EspNvs<NvsDefault>, masters: &[LoadedMaster], label: &str) -> Result<EnrolFacts, String> {
    let unlocked = !masters.is_empty() && !crate::pin::is_locked(masters);
    let data_key = data_key_store::current()
        .map(|mut dk| dk.iter_mut().for_each(|b| *b = 0))
        .is_some();
    let relays = !configured_relays(nvs).is_empty();
    // A locked board refuses as locked before its phone blob is read.
    let phones = if unlocked { load(nvs)?.records().len() } else { 0 };
    Ok(EnrolFacts { label_len: label.len(), unlocked, data_key, relays, phones })
}

/// Whether an enrolment of `label` could go ahead now. Asked before a card
/// goes up, so a board that cannot enrol never asks for a press.
pub fn check_enrol(nvs: &mut EspNvs<NvsDefault>, masters: &[LoadedMaster], label: &str) -> Result<(), String> {
    match phone_unlock::enrol_refusal(&enrol_facts(nvs, masters, label)?) {
        Some(refusal) => Err(refusal.message()),
        None => Ok(()),
    }
}

/// Add the phone, once pressed: re-check the board, draw the slot secret,
/// persist the record, and only then return the hand-off, so a phone is never
/// handed a secret the board did not keep. A full NVS refuses here, cleanly.
pub fn complete_enrol(
    nvs: &mut EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
    enrol_pubkey: &[u8; 32],
    label: &str,
) -> Result<Enrolment, String> {
    check_enrol(nvs, masters, label)?;
    let Some(mut dk) = data_key_store::current() else {
        return Err(EnrolRefusal::NoDataKey.message());
    };
    let relays = configured_relays(nvs);
    let mut phones = match load(nvs) {
        Ok(p) => p,
        Err(e) => {
            dk.iter_mut().for_each(|b| *b = 0);
            return Err(e);
        }
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

/// The DONE screen after an enrolment: the check code the phone and Sapwood
/// show, so the owner can see the phone holds this board's hand-off.
pub fn show_enrolled(display: &mut crate::oled::Display<'_>, enrolment: &Enrolment) {
    crate::oled::show_change_done(
        display,
        "Phone added",
        &format!("check {}", phone_unlock::check_code(&enrolment.ephemeral_pubkey)),
    );
}
