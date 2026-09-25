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
//                           Cable only for now: the relay loop must not block
//                           on a card (#64), and enrolment has not been moved
//                           onto the deferred approval path.
//   list                    ids and labels; nothing that unlocks.
//   revoke                  deletes a phone's record, and with it its
//                           authority. No press: removing authority is always
//                           allowed. Revoking the last phone also forgets the
//                           relays the phones were told (relay.rs RelayUpdate).
//                           Then zeroes the deleted bytes (nvs_scrub.rs) and
//                           says how that went in the answer's `scrub`.
//   set_announce_operator   whether the locked board still publishes the
//                           operator's announcement, the one stable `p` tag.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use heartwood_common::data_key::{self, PhoneSet, LABEL_MAX};
use heartwood_common::phone_unlock::{self, EnrolError, PhoneCmd};
use heartwood_common::types::{FRAME_TYPE_NACK, FRAME_TYPE_PHONE_UNLOCK_RESP};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::data_key_store::{self, NvsBlobs};
use crate::masters::LoadedMaster;
use crate::serial::SerialPort;

/// Enrolment keys already answered this boot. A phone makes a fresh one-off
/// key per enrolment, so the same key again is a host resending a command it
/// has already sent (a retrying request helper queued three extra enrols
/// behind one press on 2026-09-24, and the secrets of the three records they
/// made were never read). Refused before any card is shown.
static USED_ENROL_KEYS: Mutex<Vec<[u8; 32]>> = Mutex::new(Vec::new());
const USED_ENROL_KEYS_MAX: usize = 16;

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

/// Save after a revocation, and say truthfully what is on flash if that
/// fails. On a partition with no room for a second copy the records are
/// erased before the rewrite, so a failure can leave none at all.
fn save_revoked(nvs: &mut EspNvs<NvsDefault>, phones: &PhoneSet, id: u32) -> Result<(), String> {
    if save(nvs, phones).is_ok() {
        return Ok(());
    }
    match load(nvs) {
        Ok(stored) if stored.records().iter().any(|r| r.id == id) => Err(format!(
            "phone storage failing: phone {id} is still enrolled on flash, try again"
        )),
        Ok(stored) if stored.is_empty() && !phones.is_empty() => Err(format!(
            "phone storage full: phone {id} is revoked, but so are the other phones; re-enrol them"
        )),
        Ok(_) => Ok(()),
        Err(e) => Err(format!("phone storage failing after revoking phone {id}: {e}")),
    }
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

/// Run one command. `buttons` is `None` on the relay path, where enrolment
/// is refused.
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
            let saved = save_revoked(nvs, &phones, id);
            // Whatever the outcome, the records on flash may have changed
            // (a failed rewrite can leave none), so the relay loop re-reads.
            PHONES_CHANGED.store(true, Ordering::Release);
            // No phone listens anywhere now; the next enrolment records afresh.
            let none_left = matches!(load(nvs), Ok(stored) if stored.is_empty());
            if none_left && heartwood_common::phone_relays::forget_told(&mut NvsBlobs(nvs)).is_err() {
                log::warn!("phone unlock: relay record not cleared");
            }
            // Deleting the record only marks its entries erased; its bytes
            // (which the revoked phone's secret opens) stay on flash until
            // this zeroes them. Run whatever the save did: a failed rewrite
            // can still have erased the old records.
            let scrub = crate::nvs_scrub::run("phone revoke");
            saved?;
            log::info!("phone unlock: revoked phone {id}");
            Ok(phone_unlock::revoke_json(id, &scrub))
        }
        PhoneCmd::SetAnnounceOperator { on } => {
            data_key_store::set_announce_operator(nvs, on)
                .map_err(|_| "could not save the setting".to_string())?;
            Ok(serde_json::json!({ "announce_operator": on }))
        }
        PhoneCmd::Enrol { enrol_pubkey, label } => {
            let Some(buttons) = buttons else {
                return Err("enrolling a phone needs the cable and a press on the board".into());
            };
            // One attempt per enrolment key, whatever its outcome: marked before
            // anything can fail, so a resend queued behind this command (or one
            // after a decline) is refused rather than raising another card.
            {
                let mut used = USED_ENROL_KEYS.lock().unwrap_or_else(|e| e.into_inner());
                if used.contains(&enrol_pubkey) {
                    return Err("this enrolment key was already used: start again on the phone".into());
                }
                if used.len() >= USED_ENROL_KEYS_MAX {
                    used.remove(0);
                }
                used.push(enrol_pubkey);
            }
            let label = if label.is_empty() { "phone".to_string() } else { label };
            if label.len() > LABEL_MAX {
                return Err(format!("label longer than {LABEL_MAX} bytes"));
            }
            if masters.is_empty() || crate::pin::is_locked(masters) {
                return Err("unlock the board first".into());
            }
            let Some(mut dk) = data_key_store::current() else {
                return Err(
                    "phone unlock opens encrypted storage: set a PIN or vault key first".into(),
                );
            };
            let relays = configured_relays(nvs);
            if relays.is_empty() {
                dk.iter_mut().for_each(|b| *b = 0);
                return Err("phone unlock needs WiFi relays configured".into());
            }
            let mut phones = match load(nvs) {
                Ok(p) => p,
                Err(e) => {
                    dk.iter_mut().for_each(|b| *b = 0);
                    return Err(e);
                }
            };
            if phones.records().len() >= data_key::MAX_PHONES {
                dk.iter_mut().for_each(|b| *b = 0);
                return Err(format!("{} phones already enrolled; revoke one first", data_key::MAX_PHONES));
            }
            // Leave room to rewrite the records (and the pairing tables) in
            // place afterwards, so a later revocation is cut-safe.
            let grown = phones.encode().len() + data_key::MAX_RECORD_LEN;
            if !crate::nvs::growth_allowed(nvs, data_key::PHONES_KEY, grown) {
                dk.iter_mut().for_each(|b| *b = 0);
                return Err("not enough storage left to add a phone: remove an unused pairing, persona or avatar first".into());
            }

            let title = format!("Add unlock phone?\n{label}");
            let approved = crate::approval::run_approval_loop(display, buttons, 30, |d, remaining| {
                crate::oled::show_change_approval(d, &title, remaining, 30);
            });
            if !matches!(approved, crate::approval::ApprovalResult::Approved) {
                dk.iter_mut().for_each(|b| *b = 0);
                return Err("declined on the board".into());
            }

            let had_phones = !phones.is_empty();
            let enrolment = phone_unlock::enrol(
                &mut phones,
                &dk,
                &enrol_pubkey,
                &label,
                &relays,
                &mut |buf: &mut [u8]| crate::fill_random(buf),
            );
            dk.iter_mut().for_each(|b| *b = 0);
            let enrolment = enrolment.map_err(|e| match e {
                EnrolError::BadEnrolmentKey => "enrol_pubkey is not a valid key".to_string(),
                EnrolError::NoRelays => "phone unlock needs WiFi relays configured".to_string(),
                EnrolError::Phone(e) => format!("could not add the phone: {e:?}"),
                EnrolError::Crypto(e) => format!("enrolment failed: {e}"),
            })?;
            // Persist before answering: a phone is never handed a secret the
            // board did not keep. A full NVS refuses here, cleanly.
            save(nvs, &phones)?;
            PHONES_CHANGED.store(true, Ordering::Release);
            log::info!("phone unlock: enrolled phone {} ({label})", enrolment.id);
            // The phone was handed `relays`. As the only phone, whatever the
            // record said belonged to phones that are gone, so it is replaced;
            // beside others it is written only if missing, so an update they
            // are still owed is not cut short. A failed write is repaired at
            // the next boot, which records the live list when there is none.
            if heartwood_common::phone_relays::record_told_at_enrolment(&mut NvsBlobs(nvs), had_phones, &relays)
                .is_err()
            {
                log::warn!("phone unlock: relay record not saved");
            }
            crate::oled::show_change_done(display, "Phone added", &label);
            Ok(phone_unlock::enrolment_json(&enrolment))
        }
    }
}
