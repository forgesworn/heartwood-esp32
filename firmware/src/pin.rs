// firmware/src/pin.rs
//
// PIN-derived seed encryption at rest (P5) — the eFuse-free device-theft
// mitigation. When a PIN is set, each master seed is stored ENCRYPTED
// (`master_<slot>_secret_enc`, see heartwood_common::seed_cipher) and the
// plaintext is removed. On boot the device is locked until a PIN_UNLOCK frame
// decrypts the seeds into RAM. After 5 failed attempts the NVS is wiped.
//
// There is deliberately NO stored hash of the PIN. A fast hash would let an
// attacker who owns the flash brute-force the PIN against it (instant),
// bypassing the slow KDF entirely — so the encrypted blob's AEAD tag is the
// SOLE PIN check, and every guess must pay the PBKDF2 cost.
//
// Limitation (see docs/2026-07-02-pin-seed-encryption-design.md): with no
// secure element the key derives only from the PIN, so a flash dump is
// offline-brute-forceable — a real uplift, not hardware-wallet-grade.

use crate::masters::{self, LoadedMaster};
use crate::serial::SerialPort;
use esp_idf_svc::nvs::{EspNvs, NvsDefault};

use crate::protocol;
use heartwood_common::seed_cipher::{decrypt_seed, encrypt_seed, NONCE_LEN, SALT_LEN};
use heartwood_common::types::{FRAME_TYPE_ACK, FRAME_TYPE_NACK};

const NVS_PIN_ATTEMPTS_KEY: &str = "pin_attempts";
const MAX_FAILED_ATTEMPTS: u8 = 5;

/// True if any loaded master's seed is encrypted and not yet decrypted — i.e.
/// the device is PIN-locked and must be unlocked before its seeds are usable.
pub fn is_locked(masters: &[LoadedMaster]) -> bool {
    masters.iter().any(|m| m.locked)
}

/// Fill a buffer with hardware RNG bytes for a salt/nonce. Plain
/// `esp_fill_random` (a true RNG while the system runs, RF/SAR-ADC active) —
/// matches the nonce generation elsewhere; the salt/nonce need uniqueness, not
/// the pre-Wi-Fi bracket the seed draw uses.
fn fill_random(buf: &mut [u8]) {
    unsafe {
        esp_idf_svc::sys::esp_fill_random(buf.as_mut_ptr() as *mut core::ffi::c_void, buf.len());
    }
}

/// Read the persisted failed-attempt counter from NVS (0 if unset).
pub fn read_failed_attempts(nvs: &EspNvs<NvsDefault>) -> u8 {
    let mut buf = [0u8; 1];
    match nvs.get_blob(NVS_PIN_ATTEMPTS_KEY, &mut buf) {
        Ok(Some(b)) if b.len() == 1 => buf[0],
        _ => 0,
    }
}

fn write_failed_attempts(nvs: &mut EspNvs<NvsDefault>, count: u8) {
    let _ = nvs.set_blob(NVS_PIN_ATTEMPTS_KEY, &[count]);
}

fn clear_failed_attempts(nvs: &mut EspNvs<NvsDefault>) {
    let _ = nvs.remove(NVS_PIN_ATTEMPTS_KEY);
}

/// Encrypt every (unlocked, in-RAM) master seed under `pin` and remove its
/// plaintext. VERIFY-AFTER-ENCRYPT: each blob is decrypted with the same PIN
/// and checked against the original seed BEFORE the plaintext is dropped, so a
/// bad blob can never lose the seed. The seeds stay usable in RAM this session;
/// they load locked on the next boot.
fn enable_encryption(
    nvs: &mut EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
    pin: &[u8],
) -> Result<(), &'static str> {
    for m in masters.iter() {
        if m.locked {
            continue; // already encrypted (defensive)
        }
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut salt);
        fill_random(&mut nonce);

        let blob = encrypt_seed(pin, &m.secret, &salt, &nonce);
        match decrypt_seed(pin, &blob) {
            Ok(check) if check == m.secret => {}
            _ => return Err("encrypt self-check failed"),
        }
        masters::store_secret_enc(nvs, m.slot, &blob)?;
    }
    Ok(())
}

/// Re-store every master seed as plaintext and drop its encrypted blob (opt-out
/// of at-rest encryption). Requires the seeds to be in RAM (device unlocked).
fn disable_encryption(
    nvs: &mut EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
) -> Result<(), &'static str> {
    for m in masters.iter() {
        masters::store_secret_plain(nvs, m.slot, &m.secret)?;
    }
    Ok(())
}

/// Try to unlock: decrypt every locked slot with `pin`, filling `.secret` in
/// RAM. All-or-nothing — a wrong PIN fails the AEAD tag on the first slot and
/// nothing is filled. Returns true only if every locked slot decrypted.
pub fn try_unlock(
    nvs: &EspNvs<NvsDefault>,
    masters: &mut [LoadedMaster],
    pin: &[u8],
) -> bool {
    // Decrypt all first; only commit to `masters` once every slot succeeds.
    let mut decrypted: Vec<(usize, [u8; 32])> = Vec::new();
    for (i, m) in masters.iter().enumerate() {
        if !m.locked {
            continue;
        }
        let blob = match masters::read_secret_enc(nvs, m.slot) {
            Some(b) => b,
            None => return false, // marked locked but no blob — inconsistent
        };
        match decrypt_seed(pin, &blob) {
            Ok(seed) => decrypted.push((i, seed)),
            Err(_) => return false, // wrong PIN (or tampered blob)
        }
    }
    for (i, seed) in decrypted {
        masters[i].secret = seed;
        masters[i].locked = false;
    }
    true
}

/// Handle a PIN_UNLOCK frame (0x26). Payload: ASCII PIN digits (4–8 bytes).
/// Decrypts the seeds into RAM on success. The failed-attempt counter is
/// persisted, so an attacker cannot dodge the wipe threshold by rebooting.
pub fn handle_pin_unlock(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    nvs: &mut EspNvs<NvsDefault>,
    masters: &mut [LoadedMaster],
    failed_attempts: &mut u8,
    display: &mut crate::oled::Display<'_>,
) -> bool {
    if payload.is_empty() || payload.len() > 8 {
        log::warn!("PIN_UNLOCK: invalid PIN length {}", payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return false;
    }

    if try_unlock(nvs, masters, payload) {
        log::info!("PIN verified — seeds decrypted, device unlocked");
        *failed_attempts = 0;
        clear_failed_attempts(nvs);
        crate::oled::show_error(display, "Unlocked!");
        esp_idf_hal::delay::FreeRtos::delay_ms(500);
        protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
        true
    } else {
        *failed_attempts += 1;
        write_failed_attempts(nvs, *failed_attempts);
        log::warn!("PIN incorrect — attempt {}/{}", failed_attempts, MAX_FAILED_ATTEMPTS);

        if *failed_attempts >= MAX_FAILED_ATTEMPTS {
            log::error!("Too many failed PIN attempts — factory reset!");
            crate::oled::show_error(display, "PIN LOCKED\nWIPING...");
            esp_idf_hal::delay::FreeRtos::delay_ms(2000);
            wipe_and_reboot();
        }

        let remaining = MAX_FAILED_ATTEMPTS - *failed_attempts;
        let msg = format!("Wrong PIN\n{} left", remaining);
        crate::oled::show_error(display, &msg);
        esp_idf_hal::delay::FreeRtos::delay_ms(1000);
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        false
    }
}

/// Handle a SET_PIN frame (0x25). Payload: ASCII PIN digits (4–8), or empty to
/// clear. Requires physical button confirmation. Encrypts (or, on clear,
/// decrypts) the in-RAM master seeds — so it needs the device unlocked, with a
/// master present.
pub fn handle_set_pin(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    nvs: &mut EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
    display: &mut crate::oled::Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) {
    if payload.len() > 8 {
        log::warn!("SET_PIN: PIN too long ({} bytes, max 8)", payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }
    if !payload.is_empty() && !payload.iter().all(|b| b.is_ascii_digit()) {
        log::warn!("SET_PIN: PIN contains non-digit characters");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }
    if !payload.is_empty() && payload.len() < 4 {
        log::warn!("SET_PIN: PIN too short ({} digits, min 4)", payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    // There must be a seed in RAM to encrypt/decrypt: refuse if no master, or
    // if the device is still locked (seeds not decrypted this session).
    if masters.is_empty() {
        log::warn!("SET_PIN: no identity to protect");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }
    if is_locked(masters) {
        log::warn!("SET_PIN: device is locked — unlock before changing the PIN");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    let action = if payload.is_empty() { "Remove PIN?" } else { "Set PIN?" };
    let result = crate::approval::run_approval_loop(display, button_pin, 30, |d, remaining| {
        crate::oled::show_error(d, &format!("{}\n{}s", action, remaining));
    });
    if !matches!(result, crate::approval::ApprovalResult::Approved) {
        log::info!("SET_PIN denied by user");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    let outcome = if payload.is_empty() {
        disable_encryption(nvs, masters).map(|()| "PIN removed!")
    } else {
        enable_encryption(nvs, masters, payload).map(|()| "PIN set!")
    };

    match outcome {
        Ok(msg) => {
            log::info!("SET_PIN: {msg}");
            crate::oled::show_error(display, msg);
            esp_idf_hal::delay::FreeRtos::delay_ms(1000);
            protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
        }
        Err(e) => {
            log::error!("SET_PIN failed: {e}");
            crate::oled::show_error(display, "PIN change failed");
            esp_idf_hal::delay::FreeRtos::delay_ms(1500);
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        }
    }
}

/// Erase the entire NVS partition and reboot — the automatic security wipe
/// after too many failed PIN attempts. No button confirmation: reaching the
/// threshold is already a hostile event.
fn wipe_and_reboot() -> ! {
    unsafe {
        let part = esp_idf_svc::sys::esp_partition_find_first(
            esp_idf_svc::sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
            esp_idf_svc::sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_DATA_NVS,
            std::ptr::null(),
        );
        if !part.is_null() {
            esp_idf_svc::sys::esp_partition_erase_range(part, 0, (*part).size as usize);
        }
        esp_idf_svc::sys::esp_restart();
    }
}
