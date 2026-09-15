//! Durable replay boundary for relay-management mutations.
//!
//! Shared by the relay dispatcher and the physically confirmed USB operator
//! rotation path. Persistence is read back exactly before callers may cross an
//! authority boundary.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};

use heartwood_common::mgmt;

const MGMT_CHALLENGE_KEY: &str = "mgmt_nonce";

/// Which authority owns a management replay boundary. The legacy device
/// operator keeps its existing NVS key so upgrades preserve outstanding
/// challenges. A delegated identity operator gets a separate public-key-bound
/// record and can therefore never invalidate the owner's pending mutation.
#[derive(Clone, Copy)]
pub enum Scope {
    Device,
    Operator([u8; 32]),
}

#[derive(Clone, Copy)]
pub enum EntropySource {
    /// WiFi is started, so ESP-IDF's RNG has an RF entropy source.
    RadioActive,
    /// Radio-off USB tier: temporarily use the SAR-ADC entropy source.
    RadioOff,
}

fn random_challenge(source: EntropySource) -> [u8; 32] {
    let mut challenge = [0u8; 32];
    match source {
        EntropySource::RadioActive => unsafe {
            esp_idf_svc::sys::esp_fill_random(
                challenge.as_mut_ptr() as *mut core::ffi::c_void,
                challenge.len(),
            );
        },
        EntropySource::RadioOff => crate::fill_random_strong(&mut challenge),
    }
    challenge
}

fn persist(nvs: &mut EspNvs<NvsDefault>, challenge: &[u8; 32]) -> Result<(), String> {
    nvs.set_blob(MGMT_CHALLENGE_KEY, challenge)
        .map_err(|e| format!("persist management challenge: {e:?}"))?;

    let mut verify = [0u8; 32];
    match nvs.get_blob(MGMT_CHALLENGE_KEY, &mut verify) {
        Ok(stored) if mgmt::persisted_challenge_matches(challenge, stored) => Ok(()),
        Ok(Some(stored)) => Err(format!(
            "management challenge read-back mismatch ({} bytes)",
            stored.len()
        )),
        Ok(None) => Err("management challenge missing after persistence".into()),
        Err(e) => Err(format!("verify management challenge persistence: {e:?}")),
    }
}

/// Load the current challenge, creating one when upgrading older firmware.
pub fn current(
    nvs: &mut EspNvs<NvsDefault>,
    source: EntropySource,
) -> Result<[u8; 32], String> {
    let mut buf = [0u8; 64];
    match nvs.get_blob(MGMT_CHALLENGE_KEY, &mut buf) {
        Ok(Some(data)) if data.len() == 32 => {
            let mut current = [0u8; 32];
            current.copy_from_slice(data);
            return Ok(current);
        }
        Ok(Some(data)) => {
            log::warn!(
                "replacing malformed management challenge ({} bytes)",
                data.len()
            );
        }
        Ok(None) => {}
        Err(e) => return Err(format!("read management challenge: {e:?}")),
    }

    let challenge = random_challenge(source);
    persist(nvs, &challenge)?;
    Ok(challenge)
}

/// Durably consume `current` by replacing it with a fresh challenge.
pub fn rotate(
    nvs: &mut EspNvs<NvsDefault>,
    current: &[u8; 32],
    source: EntropySource,
) -> Result<(), String> {
    let mut next = random_challenge(source);
    while &next == current {
        next = random_challenge(source);
    }
    persist(nvs, &next)
}

fn current_operator(
    nvs: &mut EspNvs<NvsDefault>,
    operator: &[u8; 32],
    source: EntropySource,
) -> Result<[u8; 32], String> {
    let key = mgmt::operator_challenge_nvs_key(operator);
    let mut buf = [0u8; mgmt::OPERATOR_CHALLENGE_RECORD_LEN + 32];
    match nvs.get_blob(&key, &mut buf) {
        Ok(stored) => match mgmt::classify_operator_challenge_record(operator, stored) {
            mgmt::OperatorChallengeRecord::Current(challenge) => return Ok(challenge),
            // A shortened key collision is extremely unlikely, but treating
            // another public key's record as ours would couple authorities.
            mgmt::OperatorChallengeRecord::ScopeMismatch => {
                return Err("management challenge scope collision".into())
            }
            mgmt::OperatorChallengeRecord::Malformed => {
                log::warn!("replacing malformed scoped management challenge");
            }
            mgmt::OperatorChallengeRecord::Missing => {}
        },
        Err(e) => return Err(format!("read scoped management challenge: {e:?}")),
    }

    let challenge = random_challenge(source);
    persist_operator(nvs, operator, &challenge)?;
    Ok(challenge)
}

fn persist_operator(
    nvs: &mut EspNvs<NvsDefault>,
    operator: &[u8; 32],
    challenge: &[u8; 32],
) -> Result<(), String> {
    let key = mgmt::operator_challenge_nvs_key(operator);
    let record = mgmt::encode_operator_challenge_record(operator, challenge);
    nvs.set_blob(&key, &record)
        .map_err(|e| format!("persist scoped management challenge: {e:?}"))?;

    let mut verify = [0u8; mgmt::OPERATOR_CHALLENGE_RECORD_LEN];
    match nvs.get_blob(&key, &mut verify) {
        Ok(Some(stored)) if stored == record.as_slice() => Ok(()),
        Ok(Some(stored)) => Err(format!(
            "scoped management challenge read-back mismatch ({} bytes)",
            stored.len()
        )),
        Ok(None) => Err("scoped management challenge missing after persistence".into()),
        Err(e) => Err(format!("verify scoped management challenge persistence: {e:?}")),
    }
}

fn rotate_operator(
    nvs: &mut EspNvs<NvsDefault>,
    operator: &[u8; 32],
    current: &[u8; 32],
    source: EntropySource,
) -> Result<(), String> {
    let mut next = random_challenge(source);
    while &next == current {
        next = random_challenge(source);
    }
    persist_operator(nvs, operator, &next)
}

/// Read the challenge belonging to one authenticated management authority.
pub fn current_scoped(
    nvs: &mut EspNvs<NvsDefault>,
    scope: Scope,
    source: EntropySource,
) -> Result<[u8; 32], String> {
    match scope {
        Scope::Device => current(nvs, source),
        Scope::Operator(operator) => current_operator(nvs, &operator, source),
    }
}

/// Persist a fresh challenge for exactly the authority that supplied `current`.
pub fn rotate_scoped(
    nvs: &mut EspNvs<NvsDefault>,
    scope: Scope,
    current: &[u8; 32],
    source: EntropySource,
) -> Result<(), String> {
    match scope {
        Scope::Device => rotate(nvs, current, source),
        Scope::Operator(operator) => rotate_operator(nvs, &operator, current, source),
    }
}

/// Rotate whatever challenge is currently authoritative.
pub fn rotate_boundary(
    nvs: &mut EspNvs<NvsDefault>,
    source: EntropySource,
) -> Result<(), String> {
    let current = current(nvs, source)?;
    rotate(nvs, &current, source)
}
