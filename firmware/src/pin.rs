// firmware/src/pin.rs
//
// PIN-derived seed encryption at rest (P5) — the eFuse-free device-theft
// mitigation. When a PIN is set, each master seed is stored ENCRYPTED
// (`m<slot>_seed_enc`, see heartwood_common::seed_cipher) and the
// plaintext is removed. On boot the device is locked until a PIN_UNLOCK frame
// decrypts the seeds into RAM. After 5 failed attempts both the flash-time
// config source and the complete NVS partition are wiped.
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
pub const MAX_FAILED_ATTEMPTS: u8 = 5;

/// True if any loaded master's seed is encrypted and not yet decrypted — i.e.
/// the device is PIN-locked and must be unlocked before its seeds are usable.
pub fn is_locked(masters: &[LoadedMaster]) -> bool {
    masters.iter().any(|m| m.locked)
}

/// Fill a buffer with hardware RNG bytes for a salt/nonce, via the shared
/// `fill_random` helper — guaranteed true entropy in both tiers (RF source
/// when the radio is up, SAR-ADC bracket in the radio-off USB tier).
fn fill_random(buf: &mut [u8]) {
    crate::fill_random(buf);
}

/// Read the persisted failed-attempt counter from NVS. Malformed/unreadable
/// state stays distinct from absence so boot can fail closed into a wipe.
pub fn read_failed_attempts(nvs: &EspNvs<NvsDefault>) -> Result<u8, &'static str> {
    let mut buf = [0u8; 1];
    match nvs.get_blob(NVS_PIN_ATTEMPTS_KEY, &mut buf) {
        Ok(Some(b)) if b.len() == 1 => Ok(buf[0]),
        Ok(Some(_)) => Err("malformed PIN-attempt state"),
        Ok(None) => Ok(0),
        Err(_) => Err("could not read PIN-attempt state"),
    }
}

fn write_failed_attempts(
    nvs: &mut EspNvs<NvsDefault>,
    count: u8,
) -> Result<(), &'static str> {
    nvs.set_blob(NVS_PIN_ATTEMPTS_KEY, &[count])
        .map_err(|_| "could not persist PIN-attempt state")?;
    if read_failed_attempts(nvs)? == count {
        Ok(())
    } else {
        Err("PIN-attempt state verification failed")
    }
}

pub(crate) fn clear_failed_attempts(nvs: &mut EspNvs<NvsDefault>) {
    let _ = nvs.remove(NVS_PIN_ATTEMPTS_KEY);
}

/// Encrypt every (unlocked, in-RAM) master seed under `pin` and remove its
/// plaintext. VERIFY-AFTER-ENCRYPT: each blob is decrypted with the same PIN
/// and checked against the original seed BEFORE the plaintext is dropped, so a
/// bad blob can never lose the seed. The seeds stay usable in RAM this session;
/// they load locked on the next boot.
///
/// Two-phase, because the S3 resets when a host reconnects the USB CDC: the
/// slow PBKDF2 work happens entirely in phase 1 with storage untouched, and
/// phase 2 is a fast commit of prepared blobs. A reset during phase 1 leaves
/// the device fully plaintext; a reset during the (millisecond) phase 2 could
/// still tear per-slot, but every committed blob decrypts under the same key,
/// so re-running the operation converges — observed in the field 2026-08-08
/// (slot 0 sealed, slots 1–2 plaintext after a mid-enable reset).
fn enable_encryption(
    nvs: &mut EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
    pin: &[u8],
) -> Result<(), &'static str> {
    let mut prepared: Vec<(u8, Vec<u8>)> = Vec::new();
    for m in masters.iter() {
        // Each slot pays two 100k-round PBKDF2 runs (encrypt + self-check);
        // with several masters this phase runs for tens of seconds.
        crate::wdt::feed();
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
        prepared.push((m.slot, blob));
    }
    for (slot, blob) in prepared {
        masters::store_secret_enc(nvs, slot, &blob)?;
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
        // Yield so IDLE0 runs between per-slot KDF stretches (its watchdog
        // aborts after 60 s of unbroken compute), then feed our own.
        esp_idf_hal::delay::FreeRtos::delay_ms(20);
        crate::wdt::feed(); // 100k-round PBKDF2 per locked slot
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
    // A power cycle after the threshold must not offer a sixth guess, even if
    // the previous erase attempt failed. Retry the complete wipe first.
    if *failed_attempts >= MAX_FAILED_ATTEMPTS {
        log::error!("PIN wipe threshold already reached — retrying persistent wipe");
        crate::oled::show_error(display, "PIN LOCKED\nWIPING...");
        wipe_and_reboot(usb, display);
    }

    // Reject out-of-policy PINs BEFORE they can burn a wipe-counter attempt
    // (FW-L4): SET_PIN only ever stores 4–8 ASCII digits, so anything else
    // can never be the PIN — refusing it here costs the owner nothing and
    // keeps the counter for genuine mistakes.
    if payload.len() < 4 || payload.len() > 8 || !payload.iter().all(|b| b.is_ascii_digit()) {
        log::warn!("PIN_UNLOCK: out-of-policy PIN ({} bytes)", payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return false;
    }

    if try_unlock(nvs, masters, payload) {
        log::info!("PIN verified — seeds decrypted, device unlocked");
        *failed_attempts = 0;
        clear_failed_attempts(nvs);
        crate::oled::show_change_done(display, "Unlocked", "");
        esp_idf_hal::delay::FreeRtos::delay_ms(500);
        protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
        true
    } else {
        *failed_attempts = failed_attempts.saturating_add(1);
        if let Err(e) = write_failed_attempts(nvs, *failed_attempts) {
            // If the durable counter cannot be trusted, do not grant further
            // guesses that a reboot could reset.
            log::error!("PIN attempt persistence failed ({e}) — wiping fail-closed");
            crate::oled::show_error(display, "PIN STATE ERROR\nWIPING...");
            esp_idf_hal::delay::FreeRtos::delay_ms(1000);
            wipe_and_reboot(usb, display);
        }
        log::warn!("PIN incorrect — attempt {}/{}", failed_attempts, MAX_FAILED_ATTEMPTS);

        if *failed_attempts >= MAX_FAILED_ATTEMPTS {
            log::error!("Too many failed PIN attempts — factory reset!");
            crate::oled::show_error(display, "PIN LOCKED\nWIPING...");
            esp_idf_hal::delay::FreeRtos::delay_ms(2000);
            wipe_and_reboot(usb, display);
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
    buttons: &crate::button::Buttons<'_>,
) -> bool {
    if payload.len() > 8 {
        log::warn!("SET_PIN: PIN too long ({} bytes, max 8)", payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return false;
    }
    if !payload.is_empty() && !payload.iter().all(|b| b.is_ascii_digit()) {
        log::warn!("SET_PIN: PIN contains non-digit characters");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return false;
    }
    if !payload.is_empty() && payload.len() < 4 {
        log::warn!("SET_PIN: PIN too short ({} digits, min 4)", payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return false;
    }

    // There must be a seed in RAM to encrypt/decrypt: refuse if no master, or
    // if the device is still locked (seeds not decrypted this session).
    if masters.is_empty() {
        log::warn!("SET_PIN: no identity to protect");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return false;
    }
    if is_locked(masters) {
        log::warn!("SET_PIN: device is locked — unlock before changing the PIN");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return false;
    }

    let action = if payload.is_empty() { "Remove PIN?" } else { "Set PIN?" };
    let result = crate::approval::run_approval_loop(display, buttons, 30, |d, remaining| {
        crate::oled::show_change_approval(d, action, remaining, 30);
    });
    if !matches!(result, crate::approval::ApprovalResult::Approved) {
        log::info!("SET_PIN denied by user");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return false;
    }

    let outcome = if payload.is_empty() {
        disable_encryption(nvs, masters).map(|()| "PIN removed")
    } else {
        enable_encryption(nvs, masters, payload).map(|()| "PIN set")
    };

    match outcome {
        Ok(msg) => {
            log::info!("SET_PIN: {msg}");
            crate::oled::show_change_done(display, msg, "");
            esp_idf_hal::delay::FreeRtos::delay_ms(1000);
            protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
            true
        }
        Err(e) => {
            log::error!("SET_PIN failed: {e}");
            crate::oled::show_error(display, "PIN change failed");
            esp_idf_hal::delay::FreeRtos::delay_ms(1500);
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            false
        }
    }
}

/// Erase both persistent state sources and reboot — the automatic security
/// wipe after too many failed PIN attempts. No button confirmation: reaching
/// the threshold is already a hostile event. Any erase/verification failure is
/// reported and retried without returning to unlock or signing.
pub fn wipe_and_reboot(
    usb: &mut SerialPort<'_>,
    display: &mut crate::oled::Display<'_>,
) -> ! {
    let mut failure_reported = false;
    loop {
        crate::wdt::feed();
        match crate::persistent_wipe::erase_all() {
            Ok(()) => {
                crate::oled::show_error(display, "Wipe complete\nRebooting...");
                esp_idf_hal::delay::FreeRtos::delay_ms(500);
                unsafe { esp_idf_svc::sys::esp_restart() }
            }
            Err(e) => {
                log::error!("PIN-threshold persistent wipe failed: {e}");
                crate::oled::show_error(display, "ERASE FAILED\nRetrying...");
                if !failure_reported {
                    protocol::write_frame(usb, FRAME_TYPE_NACK, b"erase_failed");
                    failure_reported = true;
                }
                esp_idf_hal::delay::FreeRtos::delay_ms(2000);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Vault key (Pi/Sapwood-assisted unlock)
// ---------------------------------------------------------------------------
//
// The vault key is a 32-byte random secret generated and held by the host
// (heartwoodd's encrypted keyfile, or Sapwood's browser storage) — never on
// the device. Seeds are wrapped with exactly the same `encrypt_seed` AEAD as
// the human PIN path; only the caller and payload shape differ. Because the
// key is a 256-bit bearer credential (not a knowledge factor), VAULT_UNLOCK
// requires an authenticated bridge session, and a wrong key is a plain NACK —
// it must NOT feed the PIN wipe counter, or a buggy/malicious host could
// trick the device into wiping itself.
//
// Design: docs/specs/2026-08-08-encrypted-at-rest-unlock-design.md

pub const VAULT_KEY_LEN: usize = 32;

/// Handle a VAULT_SET frame (0x62). Payload: 32-byte binary vault key, or
/// empty to disable at-rest encryption (back to plaintext). Requires the
/// device unlocked with a master present, an authenticated bridge session,
/// and physical button confirmation.
pub fn handle_vault_set(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    nvs: &mut EspNvs<NvsDefault>,
    masters: &[LoadedMaster],
    bridge_authenticated: bool,
    display: &mut crate::oled::Display<'_>,
    buttons: &crate::button::Buttons<'_>,
) -> bool {
    if !bridge_authenticated {
        log::warn!("VAULT_SET rejected — bridge not authenticated");
        protocol::write_frame(usb, FRAME_TYPE_NACK, b"bridge auth required");
        return false;
    }
    if !payload.is_empty() && payload.len() != VAULT_KEY_LEN {
        log::warn!("VAULT_SET: payload is {} bytes, expected 0 or 32", payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return false;
    }
    if masters.is_empty() {
        log::warn!("VAULT_SET: no identity to protect");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return false;
    }
    if is_locked(masters) {
        log::warn!("VAULT_SET: device is locked — unlock before changing the vault key");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return false;
    }

    let action = if payload.is_empty() {
        "Disable vault?\n(plaintext at rest)"
    } else {
        "Enable vault?\n(host-held key)"
    };
    let result = crate::approval::run_approval_loop(display, buttons, 30, |d, remaining| {
        crate::oled::show_change_approval(d, action, remaining, 30);
    });
    if !matches!(result, crate::approval::ApprovalResult::Approved) {
        log::info!("VAULT_SET denied by user");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return false;
    }

    let outcome = if payload.is_empty() {
        disable_encryption(nvs, masters).map(|()| "Vault disabled")
    } else {
        enable_encryption(nvs, masters, payload).map(|()| "Vault enabled")
    };

    match outcome {
        Ok(msg) => {
            log::info!("VAULT_SET: {msg}");
            crate::oled::show_change_done(display, msg, "");
            esp_idf_hal::delay::FreeRtos::delay_ms(1000);
            protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
            true
        }
        Err(e) => {
            log::error!("VAULT_SET failed: {e}");
            crate::oled::show_error(display, "Vault change failed");
            esp_idf_hal::delay::FreeRtos::delay_ms(1500);
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            false
        }
    }
}

/// Handle a VAULT_UNLOCK frame (0x63). Payload: 32-byte binary vault key.
/// Caller must have verified bridge authentication first. Returns true when
/// the device unlocked. A wrong key is a plain NACK — no wipe counter, no
/// OLED drama (the host may legitimately retry with a corrected key).
pub fn handle_vault_unlock(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    nvs: &mut EspNvs<NvsDefault>,
    masters: &mut [LoadedMaster],
    display: &mut crate::oled::Display<'_>,
) -> bool {
    if payload.len() != VAULT_KEY_LEN {
        log::warn!("VAULT_UNLOCK: payload is {} bytes, expected 32", payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return false;
    }

    if try_unlock(nvs, masters, payload) {
        log::info!("Vault key accepted — seeds decrypted, device unlocked");
        // A prior PIN-attempt counter is meaningless after a successful
        // vault unlock — clear it so a later PIN attempt starts fresh.
        clear_failed_attempts(nvs);
        crate::oled::show_change_done(display, "Unlocked", "");
        esp_idf_hal::delay::FreeRtos::delay_ms(500);
        protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
        true
    } else {
        log::warn!("VAULT_UNLOCK: wrong key (AEAD check failed)");
        protocol::write_frame(usb, FRAME_TYPE_NACK, b"wrong vault key");
        false
    }
}
