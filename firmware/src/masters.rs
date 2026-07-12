// firmware/src/masters.rs
//
// Multi-master NVS storage. Each master occupies a numbered slot (0-7)
// with a secret, label, mode, and cached pubkey.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use heartwood_common::persistent_state::{
    remap_master_slot, RemovalJournal, RemovalPhase, NO_PERSONA_IN_FLIGHT,
    REMOVAL_JOURNAL_LEN,
};
use heartwood_common::types::MasterMode;
use zeroize::Zeroize;

/// Maximum number of masters the device can hold.
pub const MAX_MASTERS: u8 = 8;

/// Power-loss journal for the multi-key master-removal transaction.
const REMOVAL_JOURNAL_KEY: &str = "rm_journal";
const REMOVAL_PINNED_SHADOW_KEY: &str = "rm_pinned";
const MAX_MIGRATION_BLOB: usize = 12 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
struct PinnedRelayRecord {
    url: String,
    ms: u8,
    si: u8,
}

/// A loaded master identity.
///
/// When PIN-derived seed encryption is on (P5), a slot's seed is stored as an
/// encrypted blob (`m<slot>_seed_enc`). Such a slot loads as `locked`
/// with `secret` left zeroed — the real seed is filled in only after the PIN
/// decrypts it at boot (see `pin::try_unlock`). Nothing must read `.secret`
/// while `locked` is true.
pub struct LoadedMaster {
    pub slot: u8,
    pub secret: [u8; 32],
    pub label: String,
    pub mode: MasterMode,
    pub pubkey: [u8; 32],
    /// True when the seed is encrypted at rest and not yet decrypted.
    pub locked: bool,
}

impl Drop for LoadedMaster {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Compact encrypted-seed key. ESP-IDF limits NVS keys to 15 characters; the
/// older `master_<slot>_secret_enc` spelling exceeded that limit and could
/// never be stored by NVS.
fn secret_enc_key(slot: u8) -> String {
    format!("m{slot}_seed_enc")
}

/// Read a slot's encrypted seed blob, if present and well-formed.
pub fn read_secret_enc(nvs: &EspNvs<NvsDefault>, slot: u8) -> Option<[u8; SEED_ENC_LEN]> {
    let key = secret_enc_key(slot);
    let mut buf = [0u8; SEED_ENC_LEN];
    match nvs.get_blob(&key, &mut buf) {
        Ok(Some(b)) if b.len() == SEED_ENC_LEN => Some(buf),
        _ => None,
    }
}

/// Whether a reboot would stop in the local USB PIN-unlock loop before WiFi
/// and relay management start. Runtime `LoadedMaster::locked` is false after a
/// successful unlock, so the durable encrypted-seed blobs are the source of
/// truth for deciding whether a remote reboot is safe unattended. Storage
/// errors and malformed blobs stay distinct from definite absence so callers
/// can fail closed rather than accidentally authorise a remote reboot.
pub fn pin_unlock_required_after_reboot(
    nvs: &EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
) -> Result<bool, &'static str> {
    for master in masters {
        let key = secret_enc_key(master.slot);
        let mut buf = [0u8; SEED_ENC_LEN];
        match nvs.get_blob(&key, &mut buf) {
            Ok(Some(blob)) if blob.len() == SEED_ENC_LEN => return Ok(true),
            Ok(Some(_)) => return Err("malformed encrypted seed state"),
            Ok(None) => {}
            Err(_) => return Err("could not read encrypted seed state"),
        }
    }
    Ok(false)
}

/// Length of an encrypted seed blob.
pub const SEED_ENC_LEN: usize = heartwood_common::seed_cipher::BLOB_LEN;

/// Store a slot's encrypted seed blob and remove its plaintext secret. Used when
/// enabling a PIN — after the caller has verified the blob decrypts.
pub fn store_secret_enc(
    nvs: &mut EspNvs<NvsDefault>,
    slot: u8,
    blob: &[u8],
) -> Result<(), &'static str> {
    let prefix = format!("master_{slot}");
    nvs.set_blob(&secret_enc_key(slot), blob)
        .map_err(|_| "failed to write encrypted secret")?;
    // The plaintext must not linger next to the ciphertext.
    let _ = nvs.remove(&format!("{prefix}_secret"));
    Ok(())
}

/// Store a slot's seed as plaintext and remove any encrypted blob. Used when a
/// PIN is cleared (opt-out of at-rest encryption).
pub fn store_secret_plain(
    nvs: &mut EspNvs<NvsDefault>,
    slot: u8,
    secret: &[u8; 32],
) -> Result<(), &'static str> {
    let prefix = format!("master_{slot}");
    nvs.set_blob(&format!("{prefix}_secret"), secret)
        .map_err(|_| "failed to write secret")?;
    let _ = nvs.remove(&secret_enc_key(slot));
    Ok(())
}

/// Read the master count from NVS.
pub fn read_master_count(nvs: &EspNvs<NvsDefault>) -> u8 {
    let mut buf = [0u8; 1];
    match nvs.get_blob("master_count", &mut buf) {
        Ok(Some(b)) if b.len() == 1 => buf[0],
        _ => 0,
    }
}

/// Write the master count to NVS.
fn write_master_count(nvs: &mut EspNvs<NvsDefault>, count: u8) -> Result<(), &'static str> {
    nvs.set_blob("master_count", &[count])
        .map_err(|_| "failed to write master_count")
}

/// Load all masters from NVS into memory.
pub fn load_all(nvs: &EspNvs<NvsDefault>) -> Vec<LoadedMaster> {
    let count = read_master_count(nvs);
    let mut masters = Vec::with_capacity(count as usize);

    for slot in 0..count {
        match load_one(nvs, slot) {
            Some(m) => masters.push(m),
            None => log::warn!("Failed to load master slot {slot}"),
        }
    }

    masters
}

/// Load a single master from NVS.
fn load_one(nvs: &EspNvs<NvsDefault>, slot: u8) -> Option<LoadedMaster> {
    let prefix = format!("master_{slot}");

    // An encrypted slot loads its metadata but leaves the seed locked (zeroed)
    // until the PIN decrypts it. A plaintext slot loads its seed directly.
    let mut secret = [0u8; 32];
    let locked = if read_secret_enc(nvs, slot).is_some() {
        true
    } else {
        let secret_key = format!("{prefix}_secret");
        match nvs.get_blob(&secret_key, &mut secret) {
            Ok(Some(b)) if b.len() == 32 => false,
            _ => return None,
        }
    };

    let mut label_buf = [0u8; 32];
    let label_key = format!("{prefix}_label");
    let label = match nvs.get_blob(&label_key, &mut label_buf) {
        Ok(Some(b)) => String::from_utf8_lossy(b).to_string(),
        _ => "default".to_string(),
    };

    let mut mode_buf = [0u8; 1];
    let mode_key = format!("{prefix}_mode");
    let mode = match nvs.get_blob(&mode_key, &mut mode_buf) {
        Ok(Some(b)) if b.len() == 1 => {
            MasterMode::from_u8(b[0]).unwrap_or(MasterMode::TreeMnemonic)
        }
        _ => MasterMode::TreeMnemonic,
    };

    let mut pubkey = [0u8; 32];
    let pubkey_key = format!("{prefix}_pubkey");
    match nvs.get_blob(&pubkey_key, &mut pubkey) {
        Ok(Some(b)) if b.len() == 32 => {}
        _ => return None,
    }

    Some(LoadedMaster {
        slot,
        secret,
        label,
        mode,
        pubkey,
        locked,
    })
}

/// Add a new master to NVS. Returns the assigned slot number.
pub fn add_master(
    nvs: &mut EspNvs<NvsDefault>,
    secret: &[u8; 32],
    label: &str,
    mode: MasterMode,
    pubkey: &[u8; 32],
) -> Result<u8, &'static str> {
    let count = read_master_count(nvs);
    if count >= MAX_MASTERS {
        return Err("maximum masters reached");
    }

    let slot = count;
    let prefix = format!("master_{slot}");

    nvs.set_blob(&format!("{prefix}_secret"), secret)
        .map_err(|_| "failed to write secret")?;
    nvs.set_blob(&format!("{prefix}_label"), label.as_bytes())
        .map_err(|_| "failed to write label")?;
    nvs.set_blob(&format!("{prefix}_mode"), &[mode as u8])
        .map_err(|_| "failed to write mode")?;
    nvs.set_blob(&format!("{prefix}_pubkey"), pubkey)
        .map_err(|_| "failed to write pubkey")?;

    write_master_count(nvs, count + 1)?;

    log::info!("Added master slot {slot}: label={label}");
    Ok(slot)
}

/// Remove a master and shift every associated slot-indexed record down with it.
/// A durable cursor is written before the first mutation and after every
/// idempotent step. Boot calls `resume_pending_removal` before loading any
/// signer state, so a power cut can never expose a half-shifted authority map.
pub fn remove_master(nvs: &mut EspNvs<NvsDefault>, slot: u8) -> Result<(), &'static str> {
    resume_pending_removal(nvs)?;
    let count = read_master_count_strict(nvs)?;
    let persona_count = read_persona_count_strict(nvs)?;
    let journal = RemovalJournal::new(slot, count, persona_count).ok_or("slot out of range")?;
    persist_removal_journal(nvs, &journal)?;
    resume_pending_removal(nvs)
}

/// Whether a removal journal exists. Callers use this to reboot rather than
/// continue serving if a storage error interrupted a destructive transaction.
pub fn removal_pending(nvs: &EspNvs<NvsDefault>) -> bool {
    match nvs.blob_len(REMOVAL_JOURNAL_KEY) {
        Ok(None) => false,
        Ok(Some(_)) | Err(_) => true,
    }
}

/// Resume (or complete) an interrupted master removal. This must run before
/// `load_all`, persona loading, policy loading, or any signing path.
pub fn resume_pending_removal(nvs: &mut EspNvs<NvsDefault>) -> Result<(), &'static str> {
    let Some(mut journal) = read_removal_journal(nvs)? else {
        return Ok(());
    };
    // Preserve the original master-slot mapping before any slot mutation. The
    // shadow makes the later JSON rewrite idempotent across a cut.
    ensure_pinned_shadow(nvs)?;

    loop {
        match journal.phase {
            RemovalPhase::ShiftSlots => {
                if journal.next_master_destination + 1 < journal.original_master_count {
                    let dst = journal.next_master_destination;
                    copy_slot_bundle(nvs, dst + 1, dst)?;
                    journal.next_master_destination += 1;
                    persist_removal_journal(nvs, &journal)?;
                } else {
                    journal.phase = RemovalPhase::RewritePersonas;
                    persist_removal_journal(nvs, &journal)?;
                }
            }
            RemovalPhase::RewritePersonas => {
                if journal.persona_read < journal.original_persona_count {
                    if journal.persona_inflight_master_slot == NO_PERSONA_IN_FLIGHT {
                        let owner = read_persona_master_slot(nvs, journal.persona_read)?;
                        if owner >= journal.original_master_count {
                            return Err("persona references invalid master slot");
                        }
                        // Persist the original owner before any in-place rewrite.
                        // A retry then remaps from this byte, never from already
                        // decremented NVS data.
                        journal.persona_inflight_master_slot = owner;
                        persist_removal_journal(nvs, &journal)?;
                        continue;
                    }

                    if let Some(mapped_owner) = remap_master_slot(
                        journal.persona_inflight_master_slot,
                        journal.target,
                    ) {
                        copy_persona_entry(
                            nvs,
                            journal.persona_read,
                            journal.persona_write,
                            mapped_owner,
                        )?;
                        journal.persona_write += 1;
                    }
                    journal.persona_read += 1;
                    journal.persona_inflight_master_slot = NO_PERSONA_IN_FLIGHT;
                    persist_removal_journal(nvs, &journal)?;
                } else {
                    journal.persona_clear = journal.persona_write;
                    journal.phase = RemovalPhase::ClearPersonaTail;
                    persist_removal_journal(nvs, &journal)?;
                }
            }
            RemovalPhase::ClearPersonaTail => {
                if journal.persona_clear < journal.original_persona_count {
                    clear_persona_entry(nvs, journal.persona_clear)?;
                    journal.persona_clear += 1;
                    persist_removal_journal(nvs, &journal)?;
                } else {
                    write_persona_count(nvs, journal.persona_write)?;
                    journal.phase = RemovalPhase::ClearLastSlot;
                    persist_removal_journal(nvs, &journal)?;
                }
            }
            RemovalPhase::ClearLastSlot => {
                clear_slot_bundle(nvs, journal.original_master_count - 1)?;
                journal.phase = RemovalPhase::ClearGlobalSlotState;
                persist_removal_journal(nvs, &journal)?;
            }
            RemovalPhase::ClearGlobalSlotState => {
                // Pinned relay entries carry (master slot, client slot): drop
                // target-owned entries and shift higher owners, while keeping
                // reachability for every surviving master. Rebuild from the
                // pre-mutation shadow on every retry to avoid double-shifting.
                rewrite_pinned_relays_from_shadow(
                    nvs,
                    journal.target,
                    journal.original_master_count,
                )?;
                // Legacy single-master firmware used this global seed key.
                clear_blob(nvs, "root_secret")?;
                journal.phase = RemovalPhase::CommitMasterCount;
                persist_removal_journal(nvs, &journal)?;
            }
            RemovalPhase::CommitMasterCount => {
                write_master_count(nvs, journal.original_master_count - 1)?;
                if read_master_count_strict(nvs)? != journal.original_master_count - 1 {
                    return Err("master_count verification failed");
                }
                journal.phase = RemovalPhase::Complete;
                persist_removal_journal(nvs, &journal)?;
            }
            RemovalPhase::Complete => {
                clear_blob(nvs, REMOVAL_PINNED_SHADOW_KEY)?;
                clear_blob(nvs, REMOVAL_JOURNAL_KEY)?;
                log::info!("Removed master slot {} with associated state", journal.target);
                return Ok(());
            }
        }
    }
}

fn read_master_count_strict(nvs: &EspNvs<NvsDefault>) -> Result<u8, &'static str> {
    let mut buf = [0u8; 1];
    match nvs.get_blob("master_count", &mut buf) {
        Ok(Some(bytes)) if bytes.len() == 1 && bytes[0] <= MAX_MASTERS => Ok(bytes[0]),
        Ok(Some(_)) => Err("invalid master_count"),
        Ok(None) => Ok(0),
        Err(_) => Err("failed to read master_count"),
    }
}

fn read_persona_count_strict(nvs: &EspNvs<NvsDefault>) -> Result<u8, &'static str> {
    let mut buf = [0u8; 1];
    match nvs.get_blob("persona_count", &mut buf) {
        Ok(Some(bytes)) if bytes.len() == 1 && bytes[0] <= crate::personas::MAX_PERSONAS => {
            Ok(bytes[0])
        }
        Ok(Some(_)) => Err("invalid persona_count"),
        Ok(None) => Ok(0),
        Err(_) => Err("failed to read persona_count"),
    }
}

fn write_persona_count(
    nvs: &mut EspNvs<NvsDefault>,
    count: u8,
) -> Result<(), &'static str> {
    nvs.set_blob("persona_count", &[count])
        .map_err(|_| "failed to write persona_count")?;
    if read_persona_count_strict(nvs)? == count {
        Ok(())
    } else {
        Err("persona_count verification failed")
    }
}

fn read_removal_journal(
    nvs: &EspNvs<NvsDefault>,
) -> Result<Option<RemovalJournal>, &'static str> {
    let mut buf = [0u8; REMOVAL_JOURNAL_LEN];
    match nvs.get_blob(REMOVAL_JOURNAL_KEY, &mut buf) {
        Ok(Some(bytes)) => RemovalJournal::decode(bytes)
            .map(Some)
            .ok_or("invalid master-removal journal"),
        Ok(None) => Ok(None),
        Err(_) => Err("failed to read master-removal journal"),
    }
}

fn persist_removal_journal(
    nvs: &mut EspNvs<NvsDefault>,
    journal: &RemovalJournal,
) -> Result<(), &'static str> {
    let encoded = journal.encode();
    nvs.set_blob(REMOVAL_JOURNAL_KEY, &encoded)
        .map_err(|_| "failed to write master-removal journal")?;
    match read_removal_journal(nvs)? {
        Some(stored) if stored == *journal => Ok(()),
        _ => Err("master-removal journal verification failed"),
    }
}

fn ensure_pinned_shadow(nvs: &mut EspNvs<NvsDefault>) -> Result<(), &'static str> {
    if read_blob(nvs, REMOVAL_PINNED_SHADOW_KEY)?.is_some() {
        return Ok(());
    }
    let mut shadow = vec![0u8];
    let current = match nvs.blob_len("pinned_rly") {
        Ok(Some(len)) if len <= MAX_MIGRATION_BLOB => read_blob(nvs, "pinned_rly")?,
        Ok(Some(_)) => {
            log::warn!("Discarding oversized pinned-relay cache during master removal");
            clear_blob(nvs, "pinned_rly")?;
            None
        }
        Ok(None) => None,
        Err(_) => return Err("failed to inspect pinned relay state"),
    };
    if let Some(current) = current {
        shadow[0] = 1;
        shadow.extend_from_slice(&current);
    }
    nvs.set_blob(REMOVAL_PINNED_SHADOW_KEY, &shadow)
        .map_err(|_| "failed to shadow pinned relay state")?;
    if read_blob(nvs, REMOVAL_PINNED_SHADOW_KEY)?.as_deref() == Some(shadow.as_slice()) {
        Ok(())
    } else {
        Err("pinned relay shadow verification failed")
    }
}

fn rewrite_pinned_relays_from_shadow(
    nvs: &mut EspNvs<NvsDefault>,
    target: u8,
    original_master_count: u8,
) -> Result<(), &'static str> {
    let shadow = read_blob(nvs, REMOVAL_PINNED_SHADOW_KEY)?
        .ok_or("pinned relay shadow missing")?;
    if shadow.first() == Some(&0) && shadow.len() == 1 {
        return clear_blob(nvs, "pinned_rly");
    }
    if shadow.first() != Some(&1) {
        log::warn!("Discarding malformed pinned-relay shadow during master removal");
        return clear_blob(nvs, "pinned_rly");
    }
    let original: Vec<PinnedRelayRecord> = match serde_json::from_slice(&shadow[1..]) {
        Ok(records) => records,
        Err(_) => {
            // Reachability cache only: malformed data carries no signing
            // authority and must not brick an authoritative key removal.
            log::warn!("Discarding malformed pinned-relay cache during master removal");
            return clear_blob(nvs, "pinned_rly");
        }
    };
    let shifted: Vec<PinnedRelayRecord> = original
        .into_iter()
        .filter_map(|mut relay| {
            if relay.ms >= original_master_count {
                return None;
            }
            relay.ms = remap_master_slot(relay.ms, target)?;
            Some(relay)
        })
        .collect();
    if shifted.is_empty() {
        return clear_blob(nvs, "pinned_rly");
    }
    let encoded = serde_json::to_vec(&shifted).map_err(|_| "failed to encode pinned relays")?;
    nvs.set_blob("pinned_rly", &encoded)
        .map_err(|_| "failed to shift pinned relays")?;
    let stored = read_blob(nvs, "pinned_rly")?.ok_or("shifted pinned relays missing")?;
    let verified: Vec<PinnedRelayRecord> =
        serde_json::from_slice(&stored).map_err(|_| "shifted pinned relays invalid")?;
    if verified == shifted {
        Ok(())
    } else {
        Err("shifted pinned relay verification failed")
    }
}

fn slot_keys(slot: u8) -> [String; 10] {
    let master = format!("master_{slot}");
    [
        format!("{master}_secret"),
        secret_enc_key(slot),
        format!("{master}_label"),
        format!("{master}_mode"),
        format!("{master}_pubkey"),
        format!("{master}_conn"),
        format!("connslots_{slot}"),
        format!("policy_{slot}"),
        format!("iman{slot}"),
        format!("imav{slot}"),
    ]
}

fn copy_slot_bundle(
    nvs: &mut EspNvs<NvsDefault>,
    source: u8,
    destination: u8,
) -> Result<(), &'static str> {
    let source_keys = slot_keys(source);
    let destination_keys = slot_keys(destination);
    for (src, dst) in source_keys.iter().zip(destination_keys.iter()) {
        copy_optional_blob(nvs, src, dst)?;
    }
    Ok(())
}

fn clear_slot_bundle(nvs: &mut EspNvs<NvsDefault>, slot: u8) -> Result<(), &'static str> {
    for key in slot_keys(slot) {
        clear_blob(nvs, &key)?;
    }
    Ok(())
}

fn persona_key(entry: u8, suffix: &str) -> String {
    format!("p{entry}_{suffix}")
}

fn read_persona_master_slot(
    nvs: &EspNvs<NvsDefault>,
    entry: u8,
) -> Result<u8, &'static str> {
    let mut buf = [0u8; 1];
    match nvs.get_blob(&persona_key(entry, "ms"), &mut buf) {
        Ok(Some(bytes)) if bytes.len() == 1 => Ok(bytes[0]),
        _ => Err("failed to read persona master slot"),
    }
}

fn copy_persona_entry(
    nvs: &mut EspNvs<NvsDefault>,
    source: u8,
    destination: u8,
    mapped_owner: u8,
) -> Result<(), &'static str> {
    for suffix in ["ix", "pk", "pp"] {
        copy_required_blob(
            nvs,
            &persona_key(source, suffix),
            &persona_key(destination, suffix),
        )?;
    }
    copy_optional_blob(
        nvs,
        &persona_key(source, "nm"),
        &persona_key(destination, "nm"),
    )?;

    let owner_key = persona_key(destination, "ms");
    nvs.set_blob(&owner_key, &[mapped_owner])
        .map_err(|_| "failed to write remapped persona owner")?;
    if read_persona_master_slot(nvs, destination)? != mapped_owner {
        return Err("remapped persona owner verification failed");
    }
    Ok(())
}

fn clear_persona_entry(nvs: &mut EspNvs<NvsDefault>, entry: u8) -> Result<(), &'static str> {
    for suffix in ["ms", "ix", "pk", "pp", "nm"] {
        clear_blob(nvs, &persona_key(entry, suffix))?;
    }
    Ok(())
}

fn copy_required_blob(
    nvs: &mut EspNvs<NvsDefault>,
    source: &str,
    destination: &str,
) -> Result<(), &'static str> {
    if read_blob(nvs, source)?.is_none() {
        return Err("required slot state missing");
    }
    copy_optional_blob(nvs, source, destination)
}

fn copy_optional_blob(
    nvs: &mut EspNvs<NvsDefault>,
    source: &str,
    destination: &str,
) -> Result<(), &'static str> {
    match read_blob(nvs, source)? {
        Some(value) => {
            nvs.set_blob(destination, &value)
                .map_err(|_| "failed to shift slot state")?;
            if read_blob(nvs, destination)?.as_deref() != Some(value.as_slice()) {
                return Err("shifted slot state verification failed");
            }
            Ok(())
        }
        None => clear_blob(nvs, destination),
    }
}

fn read_blob(nvs: &EspNvs<NvsDefault>, key: &str) -> Result<Option<Vec<u8>>, &'static str> {
    let len = match nvs.blob_len(key) {
        Ok(Some(len)) if len <= MAX_MIGRATION_BLOB => len,
        Ok(Some(_)) => return Err("slot state exceeds migration bound"),
        Ok(None) => return Ok(None),
        Err(_) => return Err("failed to inspect slot state"),
    };
    // Give the C API a real destination even for a deliberately empty blob.
    let mut value = vec![0u8; core::cmp::max(len, 1)];
    match nvs.get_blob(key, &mut value) {
        Ok(Some(bytes)) if bytes.len() == len => Ok(Some(bytes.to_vec())),
        _ => Err("failed to read slot state"),
    }
}

fn clear_blob(nvs: &mut EspNvs<NvsDefault>, key: &str) -> Result<(), &'static str> {
    nvs.remove(key)
        .map_err(|_| "failed to clear slot state")?;
    match nvs.blob_len(key) {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err("cleared slot state still present"),
        Err(_) => Err("failed to verify cleared slot state"),
    }
}

/// Find a master by x-only public key (32 bytes).
pub fn find_by_pubkey(masters: &[LoadedMaster], pubkey: &[u8; 32]) -> Option<usize> {
    masters.iter().position(|m| &m.pubkey == pubkey)
}
