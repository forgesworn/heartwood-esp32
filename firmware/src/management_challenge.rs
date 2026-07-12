//! Durable replay boundary for relay-management mutations.
//!
//! Shared by the relay dispatcher and the physically confirmed USB operator
//! rotation path. Persistence is read back exactly before callers may cross an
//! authority boundary.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};

use heartwood_common::mgmt;

const MGMT_CHALLENGE_KEY: &str = "mgmt_nonce";

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

/// Rotate whatever challenge is currently authoritative.
pub fn rotate_boundary(
    nvs: &mut EspNvs<NvsDefault>,
    source: EntropySource,
) -> Result<(), String> {
    let current = current(nvs, source)?;
    rotate(nvs, &current, source)
}
