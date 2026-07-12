// firmware/src/net_config_store.rs
//
//! NVS persistence for the WiFi-standalone network config (JSON blob).
//! Mirrors the bridge_secret pattern in session.rs.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};

use heartwood_common::net_config::{
    activate_network_trial_record, apply_local_net_config_patch, commit_network_trial_record,
    effective_network_revision, mark_network_trial_attempt, network_revision_matches,
    network_trial_boot_action, new_network_trial_record, valid_network_transaction_id,
    validate_remote_net_config, LocalNetConfigPatchParams, NetConfig, NetworkTerminalOutcome,
    NetworkTerminalRecord, NetworkTrialBootAction, NetworkTrialPhase, NetworkTrialRecord,
};
use heartwood_common::types::{
    FRAME_TYPE_ACK, FRAME_TYPE_GET_NET_CONFIG_RESPONSE, FRAME_TYPE_NACK,
};
use secp256k1::XOnlyPublicKey;

use crate::protocol;
use crate::serial::SerialPort;

const NVS_NET_CONFIG_KEY: &str = "net_config";
/// A single versioned transaction blob contains the candidate, id, activation
/// phase, and boot-attempt marker. Replacing one NVS blob avoids torn state.
const NVS_TRIAL_KEY: &str = "net_trial";
/// Monotonic network mutation revision. A stage request must name the current
/// value and consumes the next value immediately, even if the trial rolls back.
const NVS_REVISION_KEY: &str = "net_rev";
/// Durable terminal outcome for recovery after a lost commit/abort response.
const NVS_LAST_KEY: &str = "net_last";
/// CRC32 of the config-partition blob last seeded into NVS. Lets `main`
/// re-seed on a genuine re-flash (CRC changed) while leaving USB
/// `SET_NET_CONFIG` changes (which don't touch the partition) untouched.
const NVS_SEEDED_CRC_KEY: &str = "ncfg_crc";

/// Maximum stored config size. The read buffer is fixed at this size, so the
/// write must reject anything larger — otherwise the blob writes but every
/// subsequent boot read returns None (ESP_ERR_NVS_INVALID_LENGTH swallowed).
const NET_CONFIG_MAX_LEN: usize = 512;
const NET_TRIAL_MAX_LEN: usize = 1024;
const NET_LAST_MAX_LEN: usize = 192;

#[derive(Debug, Clone)]
pub struct BootNetConfig {
    pub config: Option<NetConfig>,
    /// Present only when `config` is the one-shot candidate selected for this
    /// boot. The relay loop uses it to enforce a commit timeout.
    pub trial_transaction_id: Option<String>,
}

/// Write the network config blob to NVS.
pub fn write_net_config(nvs: &mut EspNvs<NvsDefault>, json: &[u8]) -> Result<(), &'static str> {
    if json.len() > NET_CONFIG_MAX_LEN {
        return Err("net config too large");
    }
    nvs.set_blob(NVS_NET_CONFIG_KEY, json)
        .map_err(|_| "nvs write failed")?;
    if read_net_config(nvs).as_deref() != Some(json) {
        return Err("net config read-back verification failed");
    }
    Ok(())
}

/// Read the network config blob from NVS. Returns None if not provisioned.
pub fn read_net_config(nvs: &EspNvs<NvsDefault>) -> Option<Vec<u8>> {
    let mut buf = [0u8; NET_CONFIG_MAX_LEN];
    match nvs.get_blob(NVS_NET_CONFIG_KEY, &mut buf) {
        Ok(Some(b)) => Some(b.to_vec()),
        _ => None,
    }
}

fn read_trial_blob(nvs: &EspNvs<NvsDefault>) -> Option<Vec<u8>> {
    let mut buf = [0u8; NET_TRIAL_MAX_LEN];
    match nvs.get_blob(NVS_TRIAL_KEY, &mut buf) {
        Ok(Some(b)) => Some(b.to_vec()),
        _ => None,
    }
}

fn valid_transaction_id(transaction_id: &str) -> bool {
    valid_network_transaction_id(transaction_id)
}

/// Return the pending trial only when the versioned blob and candidate are
/// intact. A corrupt record is never used for boot or commit.
pub fn read_trial(nvs: &EspNvs<NvsDefault>) -> Option<NetworkTrialRecord> {
    let raw = read_trial_blob(nvs)?;
    let record: NetworkTrialRecord = serde_json::from_slice(&raw).ok()?;
    if record.version != 1
        || !valid_transaction_id(&record.transaction_id)
        || validate_remote_net_config(&record.candidate).is_err()
    {
        return None;
    }
    Some(record)
}

fn write_trial(
    nvs: &mut EspNvs<NvsDefault>,
    record: &NetworkTrialRecord,
) -> Result<(), &'static str> {
    let json = serde_json::to_vec(record).map_err(|_| "network trial encode failed")?;
    if json.len() > NET_TRIAL_MAX_LEN {
        return Err("network trial too large");
    }
    nvs.set_blob(NVS_TRIAL_KEY, &json)
        .map_err(|_| "network trial nvs write failed")
}

/// Best-effort removal followed by a read-back check. Removing an absent NVS
/// key reports an ESP error, so the verification is the authoritative result.
pub fn clear_trial(nvs: &mut EspNvs<NvsDefault>) -> Result<(), &'static str> {
    let _ = nvs.remove(NVS_TRIAL_KEY);
    if read_trial_blob(nvs).is_some() {
        Err("could not clear network trial")
    } else {
        Ok(())
    }
}

pub fn read_terminal(nvs: &EspNvs<NvsDefault>) -> Option<NetworkTerminalRecord> {
    let mut buf = [0u8; NET_LAST_MAX_LEN];
    let raw = match nvs.get_blob(NVS_LAST_KEY, &mut buf) {
        Ok(Some(raw)) => raw,
        _ => return None,
    };
    let record: NetworkTerminalRecord = serde_json::from_slice(raw).ok()?;
    (record.version == 1 && valid_transaction_id(&record.transaction_id)).then_some(record)
}

fn write_terminal(
    nvs: &mut EspNvs<NvsDefault>,
    trial: &NetworkTrialRecord,
    outcome: NetworkTerminalOutcome,
) -> Result<(), &'static str> {
    let record = NetworkTerminalRecord {
        version: 1,
        transaction_id: trial.transaction_id.clone(),
        revision: trial.accepted_revision,
        outcome,
    };
    let json = serde_json::to_vec(&record).map_err(|_| "network outcome encode failed")?;
    if json.len() > NET_LAST_MAX_LEN {
        return Err("network outcome too large");
    }
    nvs.set_blob(NVS_LAST_KEY, &json)
        .map_err(|_| "network outcome nvs write failed")
}

fn finalize_committed(
    nvs: &mut EspNvs<NvsDefault>,
    trial: &NetworkTrialRecord,
) -> Result<(), &'static str> {
    if trial.phase != NetworkTrialPhase::Committed {
        return Err("network transaction has no committed marker");
    }
    ensure_network_revision(nvs, trial.accepted_revision)?;
    let json = serde_json::to_vec(&trial.candidate).map_err(|_| "net config encode failed")?;
    write_net_config(nvs, &json)?;
    write_terminal(nvs, trial, NetworkTerminalOutcome::Committed)?;
    // Once active B and the committed terminal record are both durable, stale
    // trial cleanup is no longer safety-critical. A later boot/get retries it.
    let _ = clear_trial(nvs);
    Ok(())
}

/// Finish promotion/terminal cleanup after the one-blob Committed marker made B
/// authoritative. Every operation is idempotent and may be retried by get/boot.
pub fn reconcile_terminal_state(
    nvs: &mut EspNvs<NvsDefault>,
) -> Result<Option<NetworkTerminalRecord>, &'static str> {
    if let Some(trial) = read_trial(nvs) {
        if trial.phase == NetworkTrialPhase::Committed {
            finalize_committed(nvs, &trial)?;
        } else if read_terminal(nvs)
            .map(|last| {
                last.transaction_id == trial.transaction_id
                    && last.revision == trial.accepted_revision
                    && last.outcome != NetworkTerminalOutcome::Committed
            })
            .unwrap_or(false)
        {
            // The terminal rollback/abort is already durable; retry only the
            // stale transaction-blob cleanup and never expose it as pending.
            let _ = clear_trial(nvs);
        }
    }
    Ok(read_terminal(nvs))
}

/// A physical USB change or changed flash seed is authoritative and cancels a
/// pending remote transaction without forgetting its terminal outcome.
pub fn cancel_trial(nvs: &mut EspNvs<NvsDefault>) -> Result<(), &'static str> {
    if let Some(trial) = read_trial(nvs) {
        if trial.phase == NetworkTrialPhase::Committed {
            finalize_committed(nvs, &trial)?;
        } else {
            ensure_network_revision(nvs, trial.accepted_revision)?;
            write_terminal(nvs, &trial, NetworkTerminalOutcome::Aborted)?;
        }
    }
    clear_trial(nvs)
}

pub fn read_network_revision(nvs: &EspNvs<NvsDefault>) -> u32 {
    nvs.get_u32(NVS_REVISION_KEY).ok().flatten().unwrap_or(0)
}

fn ensure_network_revision(
    nvs: &mut EspNvs<NvsDefault>,
    accepted_revision: u32,
) -> Result<(), &'static str> {
    if read_network_revision(nvs) < accepted_revision {
        nvs.set_u32(NVS_REVISION_KEY, accepted_revision)
            .map_err(|_| "network revision nvs write failed")?;
    }
    if read_network_revision(nvs) < accepted_revision {
        return Err("network revision verification failed");
    }
    Ok(())
}

/// Reconcile the separate monotonic counter after a power cut between the
/// atomic trial write and revision write. The transaction carries the accepted
/// revision, so recovery can only move the counter forward.
pub fn reconcile_network_revision(nvs: &mut EspNvs<NvsDefault>) -> u32 {
    let stored = read_network_revision(nvs);
    let accepted = read_trial(nvs).map(|trial| trial.accepted_revision);
    let terminal = read_terminal(nvs).map(|last| last.revision);
    let revision = effective_network_revision(stored, accepted, terminal);
    if revision != stored && nvs.set_u32(NVS_REVISION_KEY, revision).is_err() {
        log::error!("Could not reconcile network revision to {revision}");
    }
    revision
}

/// Consume a new revision for a physical/flash-time network replacement. The
/// revision is advanced before the active write, so a power cut can at worst
/// create a harmless skipped number, never leave a stale base revision valid.
pub fn bump_network_revision(nvs: &mut EspNvs<NvsDefault>) -> Result<u32, &'static str> {
    let current = reconcile_network_revision(nvs);
    let next = current.checked_add(1).ok_or("network revision exhausted")?;
    nvs.set_u32(NVS_REVISION_KEY, next)
        .map_err(|_| "network revision nvs write failed")?;
    Ok(next)
}

/// Persist an inert STAGED candidate without touching the active config.
/// A retry with the same transaction id and exact candidate is idempotent.
pub fn stage_trial(
    nvs: &mut EspNvs<NvsDefault>,
    base_revision: u32,
    transaction_id: &str,
    config: &NetConfig,
) -> Result<u32, &'static str> {
    if !valid_transaction_id(transaction_id) {
        return Err("invalid network transaction id");
    }
    validate_remote_net_config(config)?;
    let json = serde_json::to_vec(config).map_err(|_| "net config encode failed")?;
    if json.len() > NET_CONFIG_MAX_LEN {
        return Err("net config too large");
    }

    let _ = reconcile_terminal_state(nvs)?;

    if let Some(existing) = read_trial(nvs) {
        if existing.transaction_id == transaction_id && existing.candidate == *config {
            ensure_network_revision(nvs, existing.accepted_revision)?;
            return Ok(existing.accepted_revision);
        }
        return Err("a different network trial is already pending");
    } else if read_trial_blob(nvs).is_some() {
        return Err("corrupt network trial must be aborted first");
    }
    if read_terminal(nvs)
        .map(|last| last.transaction_id == transaction_id)
        .unwrap_or(false)
    {
        return Err("network transaction id was already used");
    }

    let current = reconcile_network_revision(nvs);
    if !network_revision_matches(base_revision, current) {
        return Err("network base revision mismatch");
    }
    let accepted_revision = current.checked_add(1).ok_or("network revision exhausted")?;
    let record = new_network_trial_record(
        transaction_id.to_string(),
        accepted_revision,
        config.clone(),
    );
    // Record first. If power fails before the revision write, boot reconciliation
    // recovers the accepted revision from this atomic blob.
    write_trial(nvs, &record)?;
    ensure_network_revision(nvs, accepted_revision)?;
    match read_trial(nvs) {
        Some(stored) if stored == record => Ok(accepted_revision),
        _ => Err("network trial verification failed"),
    }
}

/// Move STAGED to TRYING. The following reboot is the only boot allowed to use
/// the candidate; merely staging and then rebooting continues with active A.
pub fn activate_trial(
    nvs: &mut EspNvs<NvsDefault>,
    transaction_id: &str,
    revision: u32,
) -> Result<(), &'static str> {
    let trial = read_trial(nvs).ok_or("no network trial pending")?;
    let activated = activate_network_trial_record(&trial, transaction_id, revision)?;
    write_trial(nvs, &activated)
}

/// Select the network config for this boot.
///
/// STAGED is inert. TRYING is marked as attempted *before* its candidate is
/// returned. Therefore any reset, panic, watchdog event, or power cycle before
/// commit sees attempt >= 1 on the next boot and falls back to active A.
pub fn prepare_boot_net_config(nvs: &mut EspNvs<NvsDefault>) -> BootNetConfig {
    reconcile_network_revision(nvs);
    let active = read_net_config(nvs)
        .and_then(|raw| heartwood_common::net_config::parse_net_config(&raw).ok());

    let mut trial = match read_trial(nvs) {
        Some(trial) => trial,
        None => {
            if read_trial_blob(nvs).is_some() {
                log::warn!(
                    "Network trial state incomplete/corrupt — rolling back to active config"
                );
                let _ = clear_trial(nvs);
            }
            return BootNetConfig {
                config: active,
                trial_transaction_id: None,
            };
        }
    };

    match network_trial_boot_action(&trial) {
        NetworkTrialBootAction::UseActive => {
            log::info!(
                "Network trial {} staged but not activated; using active config",
                trial.transaction_id
            );
            BootNetConfig {
                config: active,
                trial_transaction_id: None,
            }
        }
        NetworkTrialBootAction::RollBack => {
            log::warn!(
                "Network trial {} rebooted before commit — rolling back to active config",
                trial.transaction_id
            );
            if ensure_network_revision(nvs, trial.accepted_revision).is_ok()
                && write_terminal(nvs, &trial, NetworkTerminalOutcome::RolledBack).is_ok()
            {
                let _ = clear_trial(nvs);
            } else {
                log::error!("Could not persist rolled-back network outcome; retaining trial proof");
            }
            BootNetConfig {
                config: active,
                trial_transaction_id: None,
            }
        }
        NetworkTrialBootAction::FinalizeCommitted => {
            let candidate = trial.candidate.clone();
            let _ = finalize_committed(nvs, &trial);
            BootNetConfig {
                // Committed is the atomic decision: B is selected even if NVS
                // promotion/terminal cleanup must be retried later.
                config: Some(candidate),
                trial_transaction_id: None,
            }
        }
        NetworkTrialBootAction::TryCandidate => {
            trial = match mark_network_trial_attempt(&trial) {
                Ok(attempted) => attempted,
                Err(e) => {
                    log::error!("Could not prepare network trial attempt: {e}");
                    return BootNetConfig {
                        config: active,
                        trial_transaction_id: None,
                    };
                }
            };
            if write_trial(nvs, &trial).is_err()
                || read_trial(nvs).map(|stored| stored.attempts) != Some(1)
            {
                log::error!("Could not persist network trial attempt — refusing candidate boot");
                if ensure_network_revision(nvs, trial.accepted_revision).is_ok()
                    && write_terminal(nvs, &trial, NetworkTerminalOutcome::RolledBack).is_ok()
                {
                    let _ = clear_trial(nvs);
                }
                return BootNetConfig {
                    config: active,
                    trial_transaction_id: None,
                };
            }
            log::info!("Booting one-shot network trial {}", trial.transaction_id);
            BootNetConfig {
                config: Some(trial.candidate),
                trial_transaction_id: Some(trial.transaction_id),
            }
        }
    }
}

/// Atomically decide commit by replacing the one transaction blob with phase
/// Committed. From that point B is authoritative; active-key promotion and the
/// compact terminal record are idempotent cleanup, never a reason to select A.
pub fn commit_trial(
    nvs: &mut EspNvs<NvsDefault>,
    transaction_id: &str,
    revision: u32,
) -> Result<NetConfig, &'static str> {
    let trial = read_trial(nvs).ok_or("no network trial pending")?;
    let committed = commit_network_trial_record(&trial, transaction_id, revision)?;
    ensure_network_revision(nvs, trial.accepted_revision)?;
    write_trial(nvs, &committed)?;
    if read_trial(nvs).map(|stored| stored.phase) != Some(NetworkTrialPhase::Committed) {
        return Err("network committed marker verification failed");
    }
    // Marker durability is the commit point. Cleanup failure is recoverable by
    // get/boot and must not turn a committed transaction into an error/rollback.
    let _ = finalize_committed(nvs, &committed);
    Ok(trial.candidate)
}

pub fn abort_trial(
    nvs: &mut EspNvs<NvsDefault>,
    transaction_id: &str,
    revision: u32,
) -> Result<bool, &'static str> {
    let trial = read_trial(nvs).ok_or("no network trial pending")?;
    if trial.transaction_id != transaction_id {
        return Err("network transaction id mismatch");
    }
    if !network_revision_matches(revision, trial.accepted_revision) {
        return Err("network transaction revision mismatch");
    }
    if trial.phase == NetworkTrialPhase::Committed {
        let _ = finalize_committed(nvs, &trial);
        return Err("network transaction is already committed");
    }
    ensure_network_revision(nvs, trial.accepted_revision)?;
    let was_trying = trial.phase == NetworkTrialPhase::Trying;
    write_terminal(nvs, &trial, NetworkTerminalOutcome::Aborted)?;
    clear_trial(nvs)?;
    Ok(was_trying)
}

pub fn rollback_trial(
    nvs: &mut EspNvs<NvsDefault>,
    transaction_id: &str,
) -> Result<bool, &'static str> {
    let trial = read_trial(nvs).ok_or("no network trial pending")?;
    if trial.transaction_id != transaction_id {
        return Err("network transaction id mismatch");
    }
    if trial.phase == NetworkTrialPhase::Committed {
        finalize_committed(nvs, &trial)?;
        return Ok(true);
    }
    ensure_network_revision(nvs, trial.accepted_revision)?;
    write_terminal(nvs, &trial, NetworkTerminalOutcome::RolledBack)?;
    clear_trial(nvs)?;
    Ok(false)
}

/// CRC of the config-partition blob last seeded into NVS (`None` if never).
pub fn read_seeded_crc(nvs: &EspNvs<NvsDefault>) -> Option<u32> {
    nvs.get_u32(NVS_SEEDED_CRC_KEY).ok().flatten()
}

/// Record the CRC of the config-partition blob just seeded into NVS.
pub fn write_seeded_crc(nvs: &mut EspNvs<NvsDefault>, crc: u32) {
    if nvs.set_u32(NVS_SEEDED_CRC_KEY, crc).is_err() {
        log::warn!("Failed to persist seeded config CRC");
    }
}

fn redacted_state(nvs: &mut EspNvs<NvsDefault>) -> serde_json::Value {
    // Completing an already-durable committed marker is idempotent recovery,
    // not a new management mutation. It ensures USB reports B once commit made
    // B authoritative, even if power failed during cleanup.
    let recovery_error = reconcile_terminal_state(nvs).err();
    let revision = reconcile_network_revision(nvs);
    let active = read_net_config(nvs)
        .and_then(|raw| heartwood_common::net_config::parse_net_config(&raw).ok());
    let trial = read_trial(nvs).map(|pending| {
        serde_json::json!({
            "transaction_id": pending.transaction_id,
            "revision": pending.accepted_revision,
            "phase": pending.phase,
            "mode": pending.candidate.mode,
            "ssid": pending.candidate.ssid,
            "relays": pending.candidate.relays,
            "password_set": !pending.candidate.password.is_empty(),
            "attempted": pending.attempts > 0,
        })
    });
    let last_result = read_terminal(nvs).map(|last| {
        serde_json::json!({
            "transaction_id": last.transaction_id,
            "revision": last.revision,
            "outcome": last.outcome,
        })
    });

    match active {
        Some(cfg) => serde_json::json!({
            "version": 1,
            "configured": true,
            "revision": revision,
            "mode": cfg.mode,
            "ssid": cfg.ssid,
            "relays": cfg.relays,
            "password_set": !cfg.password.is_empty(),
            "op_mgmt": cfg.op_mgmt,
            "trial": trial,
            "last_result": last_result,
            "recovery_ok": recovery_error.is_none(),
        }),
        None => serde_json::json!({
            "version": 1,
            "configured": false,
            "revision": revision,
            "trial": trial,
            "last_result": last_result,
            "recovery_ok": recovery_error.is_none(),
        }),
    }
}

/// Read-only, password-redacted USB network/operator state (0x5C → 0x5D).
pub fn handle_get_net_config(usb: &mut SerialPort<'_>, nvs: &mut EspNvs<NvsDefault>) {
    let json = redacted_state(nvs).to_string();
    protocol::write_frame(usb, FRAME_TYPE_GET_NET_CONFIG_RESPONSE, json.as_bytes());
}

fn current_config(nvs: &mut EspNvs<NvsDefault>) -> Result<(Vec<u8>, NetConfig, u32), &'static str> {
    reconcile_terminal_state(nvs)?;
    let revision = reconcile_network_revision(nvs);
    let raw = read_net_config(nvs).ok_or("network config unavailable")?;
    let cfg = heartwood_common::net_config::parse_net_config(&raw)?;
    Ok((raw, cfg, revision))
}

fn persist_local_replacement(
    nvs: &mut EspNvs<NvsDefault>,
    previous_raw: &[u8],
    replacement_raw: &[u8],
) -> Result<u32, &'static str> {
    let revision = bump_network_revision(nvs)?;
    cancel_trial(nvs)?;
    if let Err(error) = write_net_config(nvs, replacement_raw) {
        if write_net_config(nvs, previous_raw).is_err() {
            return Err("fatal net config storage error; previous state could not be restored");
        }
        return Err(error);
    }
    Ok(revision)
}

fn approved(
    display: &mut crate::oled::Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
    title: &str,
) -> bool {
    matches!(
        crate::approval::run_approval_loop(display, button_pin, 30, |d, remaining| {
            let msg = format!("{title}\nHold to confirm\n{remaining}s");
            crate::oled::show_error(d, &msg);
        }),
        crate::approval::ApprovalResult::Approved
    )
}

fn ack_and_reboot(usb: &mut SerialPort<'_>, display: &mut crate::oled::Display<'_>, result: &str) -> ! {
    crate::oled::show_result(display, result);
    protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
    esp_idf_hal::delay::FreeRtos::delay_ms(500);
    unsafe { esp_idf_svc::sys::esp_restart() }
}

/// Physically confirmed partial USB network update. Password `keep` never
/// exposes or resends the stored credential, and `op_mgmt` is not part of this
/// request type.
pub fn handle_patch_net_config(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    nvs: &mut EspNvs<NvsDefault>,
    display: &mut crate::oled::Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) {
    let params: LocalNetConfigPatchParams = match serde_json::from_slice(payload) {
        Ok(params) => params,
        Err(_) => {
            protocol::write_frame(usb, FRAME_TYPE_NACK, b"invalid patch");
            return;
        }
    };
    let (previous_raw, active, revision) = match current_config(nvs) {
        Ok(state) => state,
        Err(error) => {
            protocol::write_frame(usb, FRAME_TYPE_NACK, error.as_bytes());
            return;
        }
    };
    if params.base_revision != revision {
        protocol::write_frame(usb, FRAME_TYPE_NACK, b"stale network revision");
        return;
    }
    let replacement = match apply_local_net_config_patch(&active, &params.patch) {
        Ok(candidate) => candidate,
        Err(error) => {
            protocol::write_frame(usb, FRAME_TYPE_NACK, error.as_bytes());
            return;
        }
    };
    let replacement_raw = match serde_json::to_vec(&replacement) {
        Ok(raw) if raw.len() <= NET_CONFIG_MAX_LEN => raw,
        _ => {
            protocol::write_frame(usb, FRAME_TYPE_NACK, b"network config too large");
            return;
        }
    };
    if !approved(display, button_pin, "Change network?") {
        protocol::write_frame(usb, FRAME_TYPE_NACK, b"denied");
        return;
    }
    match persist_local_replacement(nvs, &previous_raw, &replacement_raw) {
        Ok(_) => ack_and_reboot(usb, display, "Network changed\nRebooting..."),
        Err(error) => protocol::write_frame(usb, FRAME_TYPE_NACK, error.as_bytes()),
    }
}

/// Physically confirmed management trust-root replacement. Payload is the
/// caller's observed network revision followed by one valid x-only pubkey.
pub fn handle_set_operator(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    nvs: &mut EspNvs<NvsDefault>,
    display: &mut crate::oled::Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
    radio_active: bool,
) {
    if payload.len() != 36 {
        protocol::write_frame(usb, FRAME_TYPE_NACK, b"invalid operator request");
        return;
    }
    let requested_revision = u32::from_be_bytes(payload[..4].try_into().unwrap());
    let canonical = match XOnlyPublicKey::from_slice(&payload[4..]) {
        Ok(key) => key.serialize(),
        Err(_) => {
            protocol::write_frame(usb, FRAME_TYPE_NACK, b"invalid operator pubkey");
            return;
        }
    };
    let (previous_raw, mut active, revision) = match current_config(nvs) {
        Ok(state) => state,
        Err(error) => {
            protocol::write_frame(usb, FRAME_TYPE_NACK, error.as_bytes());
            return;
        }
    };
    if requested_revision != revision {
        protocol::write_frame(usb, FRAME_TYPE_NACK, b"stale network revision");
        return;
    }
    let operator_hex = heartwood_common::hex::hex_encode(&canonical);
    let prompt = format!("Replace operator?\n{}...", &operator_hex[..8]);
    if !approved(display, button_pin, &prompt) {
        protocol::write_frame(usb, FRAME_TYPE_NACK, b"denied");
        return;
    }

    let entropy = if radio_active {
        crate::management_challenge::EntropySource::RadioActive
    } else {
        crate::management_challenge::EntropySource::RadioOff
    };
    if let Err(error) = crate::management_challenge::rotate_boundary(nvs, entropy) {
        log::error!("Operator rotation stopped at replay boundary: {error}");
        protocol::write_frame(usb, FRAME_TYPE_NACK, b"challenge persistence failed");
        return;
    }

    active.op_mgmt = operator_hex;
    let replacement_raw = match serde_json::to_vec(&active) {
        Ok(raw) if raw.len() <= NET_CONFIG_MAX_LEN => raw,
        _ => {
            protocol::write_frame(usb, FRAME_TYPE_NACK, b"network config too large");
            return;
        }
    };
    match persist_local_replacement(nvs, &previous_raw, &replacement_raw) {
        Ok(_) => ack_and_reboot(usb, display, "Operator changed\nRebooting..."),
        Err(error) => {
            log::error!("Operator rotation storage failed: {error}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, error.as_bytes());
        }
    }
}

/// Handle a SET_NET_CONFIG frame (0x54).
///
/// Parses and validates the JSON payload, requires a 30-second button-hold
/// confirmation on the OLED, then persists the config to NVS.
/// Mirrors handle_set_bridge_secret in session.rs exactly.
pub fn handle_set_net_config(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    nvs: &mut EspNvs<NvsDefault>,
    display: &mut crate::oled::Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) {
    match heartwood_common::net_config::parse_net_config(payload) {
        Ok(cfg) if cfg.validate().is_ok() => {
            let result =
                crate::approval::run_approval_loop(display, button_pin, 30, |d, remaining| {
                    let msg = format!("Set network\nconfig? {}s", remaining);
                    crate::oled::show_error(d, &msg);
                });

            if !matches!(result, crate::approval::ApprovalResult::Approved) {
                log::info!("SET_NET_CONFIG denied by user");
                protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
                return;
            }

            match bump_network_revision(nvs)
                .and_then(|_| cancel_trial(nvs))
                .and_then(|_| write_net_config(nvs, payload))
            {
                Ok(()) => {
                    log::info!("Network config written to NVS");
                    // WiFi-standalone is entered at boot from this config, so a
                    // wifi save applies by rebooting straight into the relay loop
                    // — no manual power-cycle. USB (radio-off) saves just persist
                    // and take effect immediately in the running dispatch loop.
                    let wifi = cfg.device_mode() == heartwood_common::net_config::DeviceMode::Wifi;
                    crate::oled::show_result(
                        display,
                        if wifi {
                            "Network config set\nStarting wifi..."
                        } else {
                            "Network config\nset"
                        },
                    );
                    esp_idf_hal::delay::FreeRtos::delay_ms(1500);
                    protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
                    if wifi {
                        // Brief delay so the ACK flushes to the host before the
                        // USB CDC drops on restart.
                        esp_idf_hal::delay::FreeRtos::delay_ms(300);
                        log::info!("WiFi config saved — rebooting into signer mode");
                        unsafe { esp_idf_svc::sys::esp_restart() };
                    }
                }
                Err(e) => {
                    log::error!("Failed to write network config: {e}");
                    protocol::write_frame(usb, FRAME_TYPE_NACK, b"nvs");
                }
            }
        }
        _ => {
            log::warn!("SET_NET_CONFIG rejected — invalid payload");
            protocol::write_frame(usb, FRAME_TYPE_NACK, b"invalid config");
        }
    }
}
