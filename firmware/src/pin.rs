// firmware/src/pin.rs
//
// Boot PIN protection. When a PIN is set, the device enters a locked
// state on boot and refuses all requests until the correct PIN is
// provided via a PIN_UNLOCK frame. After 5 failed attempts the device
// performs a factory reset (erases all NVS keys and reboots).

use esp_idf_hal::usb_serial::UsbSerialDriver;
use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use sha2::{Digest, Sha256};

use heartwood_common::types::{FRAME_TYPE_ACK, FRAME_TYPE_NACK};
use crate::protocol;

const NVS_PIN_HASH_KEY: &str = "pin_hash";
const MAX_FAILED_ATTEMPTS: u8 = 5;

/// Check whether a PIN hash is stored in NVS.
pub fn has_pin(nvs: &EspNvs<NvsDefault>) -> bool {
    let mut buf = [0u8; 32];
    matches!(nvs.get_blob(NVS_PIN_HASH_KEY, &mut buf), Ok(Some(b)) if b.len() == 32)
}

/// Verify a PIN against the stored hash. Returns true if correct.
pub fn verify_pin(nvs: &EspNvs<NvsDefault>, pin: &[u8]) -> bool {
    let mut stored = [0u8; 32];
    let stored = match nvs.get_blob(NVS_PIN_HASH_KEY, &mut stored) {
        Ok(Some(b)) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            arr
        }
        _ => return false,
    };

    let computed = hash_pin(pin);

    // Constant-time comparison — prevent timing-based PIN oracle.
    let mut diff = 0u8;
    for (a, b) in stored.iter().zip(computed.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Hash a PIN using SHA-256 with a domain prefix to prevent rainbow table
/// attacks against common 4-8 digit PINs.
fn hash_pin(pin: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"heartwood-pin\0");
    hasher.update(pin);
    hasher.finalize().into()
}

/// Handle a PIN_UNLOCK frame (0x26).
///
/// Payload: ASCII PIN digits (4–8 bytes).
/// Returns true if the device is now unlocked.
pub fn handle_pin_unlock(
    usb: &mut UsbSerialDriver<'_>,
    payload: &[u8],
    nvs: &EspNvs<NvsDefault>,
    failed_attempts: &mut u8,
    display: &mut crate::oled::Display<'_>,
) -> bool {
    if payload.is_empty() || payload.len() > 8 {
        log::warn!("PIN_UNLOCK: invalid PIN length {}", payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return false;
    }

    if verify_pin(nvs, payload) {
        log::info!("PIN verified — device unlocked");
        *failed_attempts = 0;
        crate::oled::show_error(display, "Unlocked!");
        esp_idf_hal::delay::FreeRtos::delay_ms(500);
        protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
        true
    } else {
        *failed_attempts += 1;
        log::warn!("PIN incorrect — attempt {}/{}", failed_attempts, MAX_FAILED_ATTEMPTS);

        if *failed_attempts >= MAX_FAILED_ATTEMPTS {
            log::error!("Too many failed PIN attempts — factory reset!");
            crate::oled::show_error(display, "PIN LOCKED\nWIPING...");
            esp_idf_hal::delay::FreeRtos::delay_ms(2000);
            // Wipe all NVS data and reboot. No button confirmation needed —
            // this is an automatic security response to repeated failed attempts.
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

/// Handle a SET_PIN frame (0x25).
///
/// Payload: ASCII PIN digits (4–8 bytes). Empty payload clears the PIN.
/// Requires physical button confirmation before the change takes effect.
pub fn handle_set_pin(
    usb: &mut UsbSerialDriver<'_>,
    payload: &[u8],
    nvs: &mut EspNvs<NvsDefault>,
    display: &mut crate::oled::Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) {
    if payload.len() > 8 {
        log::warn!("SET_PIN: PIN too long ({} bytes, max 8)", payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    // Non-empty payload must be all ASCII digits.
    if !payload.is_empty() && !payload.iter().all(|b| b.is_ascii_digit()) {
        log::warn!("SET_PIN: PIN contains non-digit characters");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    // Non-empty PINs must be at least 4 digits.
    if !payload.is_empty() && payload.len() < 4 {
        log::warn!("SET_PIN: PIN too short ({} digits, min 4)", payload.len());
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    let action = if payload.is_empty() { "Clear PIN?" } else { "Set PIN?" };

    let result = crate::approval::run_approval_loop(
        display,
        button_pin,
        30,
        |d, remaining| {
            let msg = format!("{}\n{}s", action, remaining);
            crate::oled::show_error(d, &msg);
        },
    );

    if !matches!(result, crate::approval::ApprovalResult::Approved) {
        log::info!("SET_PIN denied by user");
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }

    if payload.is_empty() {
        // Clear the PIN — device will boot without lock from now on.
        let _ = nvs.remove(NVS_PIN_HASH_KEY);
        log::info!("PIN cleared");
        crate::oled::show_error(display, "PIN cleared!");
    } else {
        // Store the hashed PIN.
        let hash = hash_pin(payload);
        match nvs.set_blob(NVS_PIN_HASH_KEY, &hash) {
            Ok(()) => {
                log::info!("PIN set ({} digits)", payload.len());
                crate::oled::show_error(display, "PIN set!");
            }
            Err(e) => {
                log::error!("Failed to write PIN hash: {e:?}");
                protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
                return;
            }
        }
    }
    esp_idf_hal::delay::FreeRtos::delay_ms(1000);
    protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
}

/// Erase the entire NVS partition and reboot. Used for the automatic security
/// wipe after too many failed PIN attempts — no button confirmation is needed
/// because the threshold being reached already represents a hostile event.
fn wipe_and_reboot() -> ! {
    unsafe {
        // Find the NVS data partition and erase it entirely.
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
