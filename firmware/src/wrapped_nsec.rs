//! Owner recovery over the authenticated cable only. Never a NIP-46 method.
use crate::{
    approval::{self, ApprovalResult},
    button::Buttons,
    masters::{self, LoadedMaster},
    oled::{self, Display},
    protocol,
    serial::SerialPort,
};
use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use heartwood_common::types::{MasterMode, FRAME_TYPE_NACK, FRAME_TYPE_WRAPPED_NSEC_RESP};
use heartwood_common::{
    encoding::encode_npub,
    wrapped_command::{parse_command, SlotReference, WrappedCommand},
    wrapped_nsec::{unwrap_nsec, verify_slot_key, wrap_nsec},
};

fn selected<'a>(
    masters: &'a [LoadedMaster],
    reference: &SlotReference,
) -> Result<&'a LoadedMaster, &'static str> {
    let master = masters
        .iter()
        .find(|m| {
            m.slot == reference.slot
                && m.mode as u8 == reference.mode
                && encode_npub(&m.pubkey) == reference.npub
                && !m.locked
        })
        .ok_or("identity changed or locked: refresh the signer")?;
    verify_slot_key(&master.secret, &reference.npub)
        .map_err(|_| "stored identity key does not match its npub")?;
    Ok(master)
}

fn confirm(
    display: &mut Display<'_>,
    buttons: &Buttons<'_>,
    op: &str,
    root: &LoadedMaster,
    target_npub: &str,
    destination: Option<u8>,
) -> Result<(), &'static str> {
    // Reuse the tested three-page dwell/release gate. All three pages must be
    // visible before a fresh hold can approve; a pre-held button never counts.
    let root_npub = encode_npub(&root.pubkey);
    let root_title = format!("ROOT {} MODE {}", root.slot, root.mode as u8);
    let action = match destination {
        Some(slot) => format!("RESTORE RAW SLOT {slot}"),
        None => format!("{} RAW ACCOUNT", op.to_uppercase()),
    };
    let approved = approval::run_full_access_approval_loop(
        display,
        buttons,
        60,
        |d, remaining, page, armed| {
            oled::show_wrapped_approval(
                d,
                &action,
                &root_title,
                &root_npub,
                target_npub,
                remaining,
                page,
                armed,
            )
        },
        oled::show_hold_progress,
    );
    match approved {
        ApprovalResult::Approved => Ok(()),
        _ => Err("wrapped operation not approved"),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn handle(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    authenticated: bool,
    nvs: &mut EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
    personas: &[crate::personas::LoadedPersona],
    display: &mut Display<'_>,
    buttons: &Buttons<'_>,
) -> Option<LoadedMaster> {
    let result = execute(
        payload,
        authenticated,
        nvs,
        masters,
        personas,
        display,
        buttons,
    );
    match result {
        Ok((receipt, added)) => {
            protocol::write_frame(
                usb,
                FRAME_TYPE_WRAPPED_NSEC_RESP,
                receipt.to_string().as_bytes(),
            );
            added
        }
        Err(reason) => {
            protocol::write_frame(usb, FRAME_TYPE_NACK, reason.as_bytes());
            None
        }
    }
}

fn execute(
    payload: &[u8],
    authenticated: bool,
    nvs: &mut EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
    personas: &[crate::personas::LoadedPersona],
    display: &mut Display<'_>,
    buttons: &Buttons<'_>,
) -> Result<(serde_json::Value, Option<LoadedMaster>), &'static str> {
    if !authenticated {
        return Err("bridge auth required");
    }
    let command = parse_command(payload)?;
    let root = selected(masters, command.root())?;
    let root_secret = crate::nip46_handler::derivation_secret(&root.secret, root.mode)?;
    heartwood_common::derive::public_key_xonly(&root_secret).map_err(|_| "invalid tree root")?;
    match &command {
        WrappedCommand::Wrap { target, .. } => {
            let target = selected(masters, target)?;
            if target.mode != MasterMode::Bunker {
                return Err("only raw-key slots can be wrapped");
            }
            if !crate::entropy::rng_ok() {
                return Err(crate::entropy::rng_refusal());
            }
            let npub = encode_npub(&target.pubkey);
            confirm(display, buttons, "wrap", root, &npub, None)?;
            let record = wrap_nsec(&root_secret, &target.secret, |bytes| {
                crate::fill_random_strong(bytes);
                Ok(())
            })?;
            // Verify the exact encrypted result on-chip before returning it.
            let _checked = unwrap_nsec(&root_secret, &record, Some(&npub))?;
            Ok((
                serde_json::json!({ "op": "wrap", "npub": npub, "record": record }),
                None,
            ))
        }
        WrappedCommand::Check {
            record,
            expected_npub,
            ..
        } => {
            let checked = unwrap_nsec(&root_secret, record, Some(expected_npub))?;
            confirm(display, buttons, "check", root, &checked.npub, None)?;
            Ok((
                serde_json::json!({ "op": "check", "npub": checked.npub }),
                None,
            ))
        }
        WrappedCommand::Restore {
            record,
            expected_npub,
            destination,
            label,
            ..
        } => {
            let restored = unwrap_nsec(&root_secret, record, Some(expected_npub))?;
            if masters.iter().any(|m| m.pubkey == restored.public_key)
                || personas.iter().any(|p| p.pubkey == restored.public_key)
            {
                return Err("identity already exists; no slot was overwritten");
            }
            if masters.len() != masters::read_master_count(nvs) as usize
                || *destination as usize != masters.len()
                || *destination >= masters::MAX_MASTERS
            {
                return Err("destination changed: refresh the signer");
            }
            confirm(
                display,
                buttons,
                "restore",
                root,
                &restored.npub,
                Some(*destination),
            )?;
            masters::add_wrapped_master(
                nvs,
                *destination,
                &restored.private_key,
                label,
                &restored.public_key,
            )?;
            let added = LoadedMaster {
                slot: *destination,
                secret: *restored.private_key,
                label: label.clone(),
                mode: MasterMode::Bunker,
                derivation_version: 0,
                pubkey: restored.public_key,
                locked: false,
                operator: None,
            };
            Ok((
                serde_json::json!({ "op": "restore", "npub": restored.npub, "slot": destination, "mode": 0, "derivation_version": 0 }),
                Some(added),
            ))
        }
    }
}
