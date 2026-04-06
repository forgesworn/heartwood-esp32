// firmware/src/ota.rs
//
// OTA firmware update handler.
//
// Receives firmware chunks over serial, writes them to the inactive OTA
// partition, verifies SHA-256, and reboots into the new firmware.
//
// Frame flow:
//   Host → OTA_BEGIN  [total_size_u32_be][sha256_32]
//   Device → OTA_STATUS(READY)
//   Host → OTA_CHUNK  [offset_u32_be][data...]  (repeated)
//   Device → OTA_STATUS(CHUNK_OK)  (after each chunk)
//   Host → OTA_FINISH
//   Device → OTA_STATUS(VERIFIED) + reboot
//
// On any error the device sends OTA_STATUS(ERR_*) and the session is aborted.

use esp_idf_hal::gpio::{Input, PinDriver};
use esp_idf_hal::usb_serial::UsbSerialDriver;
use sha2::{Digest, Sha256};

use crate::oled::Display;
use heartwood_common::types::{
    FRAME_TYPE_OTA_STATUS, OTA_STATUS_CHUNK_OK, OTA_STATUS_ERR_HASH, OTA_STATUS_ERR_NOT_STARTED,
    OTA_STATUS_ERR_SIZE, OTA_STATUS_ERR_WRITE, OTA_STATUS_READY, OTA_STATUS_VERIFIED,
};

/// Active OTA session state, held in `Option` in the dispatch loop.
///
/// Created by `handle_ota_begin`, consumed by `handle_ota_finish`.
pub struct OtaSession {
    pub total_size: u32,
    pub expected_hash: [u8; 32],
    pub bytes_received: u32,
    pub hasher: Sha256,
    pub ota_handle: esp_idf_svc::sys::esp_ota_handle_t,
    pub partition: *const esp_idf_svc::sys::esp_partition_t,
}

// SAFETY: OtaSession is only ever accessed from the single-threaded dispatch
// loop.  The raw pointer is valid for the duration of the OTA session and is
// never aliased from another thread.
unsafe impl Send for OtaSession {}

// ---------------------------------------------------------------------------
// OTA_BEGIN (0x30)
// ---------------------------------------------------------------------------

/// Handle an `OTA_BEGIN` frame.
///
/// Payload: `[total_size: u32 BE][sha256: 32 bytes]` — 36 bytes total.
///
/// Shows the firmware size on the OLED and runs the 30-second approval loop
/// (hold button 2 seconds to confirm).  On approval, opens the inactive OTA
/// partition and initialises an `OtaSession`.  Sends `OTA_STATUS(READY)` on
/// success or an appropriate error code on failure.
pub fn handle_ota_begin(
    usb: &mut UsbSerialDriver<'_>,
    payload: &[u8],
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, Input>,
    session: &mut Option<OtaSession>,
) {
    // Validate payload length: 4 bytes size + 32 bytes hash.
    if payload.len() != 36 {
        log::warn!(
            "OTA_BEGIN: invalid payload length {} (expected 36)",
            payload.len()
        );
        send_ota_status(usb, OTA_STATUS_ERR_SIZE, "Bad payload length");
        return;
    }

    let total_size = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(&payload[4..36]);

    log::info!(
        "OTA_BEGIN: firmware size {} bytes, awaiting approval",
        total_size
    );

    // Show firmware size and run the approval loop (30 s, 2 s hold).
    let size_kb = (total_size + 1023) / 1024;
    let approval_result =
        crate::approval::run_approval_loop(display, button_pin, 30, |d, remaining| {
            let msg = format!("OTA update\n{}KB\nHold 2s ({remaining}s)", size_kb);
            crate::oled::show_error(d, &msg);
        });

    match approval_result {
        crate::approval::ApprovalResult::Approved => {
            log::info!("OTA_BEGIN: approved — opening update partition");
        }
        crate::approval::ApprovalResult::Denied => {
            log::info!("OTA_BEGIN: denied by user");
            send_ota_status(usb, OTA_STATUS_ERR_NOT_STARTED, "Denied");
            return;
        }
        crate::approval::ApprovalResult::TimedOut => {
            log::info!("OTA_BEGIN: timed out waiting for approval");
            send_ota_status(usb, OTA_STATUS_ERR_NOT_STARTED, "Timed out");
            return;
        }
    }

    // Locate the inactive OTA partition and begin the update.
    let (ota_handle, partition) = unsafe {
        let partition =
            esp_idf_svc::sys::esp_ota_get_next_update_partition(core::ptr::null());
        if partition.is_null() {
            log::error!("OTA_BEGIN: no update partition found");
            send_ota_status(usb, OTA_STATUS_ERR_WRITE, "No OTA partition");
            return;
        }

        let mut handle: esp_idf_svc::sys::esp_ota_handle_t = 0;
        let err = esp_idf_svc::sys::esp_ota_begin(partition, total_size as usize, &mut handle);
        if err != esp_idf_svc::sys::ESP_OK {
            log::error!("OTA_BEGIN: esp_ota_begin failed ({})", err);
            send_ota_status(usb, OTA_STATUS_ERR_WRITE, "esp_ota_begin failed");
            return;
        }

        (handle, partition)
    };

    *session = Some(OtaSession {
        total_size,
        expected_hash,
        bytes_received: 0,
        hasher: Sha256::new(),
        ota_handle,
        partition,
    });

    log::info!("OTA_BEGIN: session created, ready for chunks");
    send_ota_status(usb, OTA_STATUS_READY, "Ready");
}

// ---------------------------------------------------------------------------
// OTA_CHUNK (0x31)
// ---------------------------------------------------------------------------

/// Handle an `OTA_CHUNK` frame.
///
/// Payload: `[offset: u32 BE][data...]`.
///
/// Verifies that the offset matches `bytes_received` (sequential chunks only),
/// writes the data to the inactive partition, feeds the SHA-256 hasher, and
/// updates the OLED progress bar.  Sends `OTA_STATUS(CHUNK_OK)` on success.
pub fn handle_ota_chunk(
    usb: &mut UsbSerialDriver<'_>,
    payload: &[u8],
    display: &mut Display<'_>,
    session: &mut Option<OtaSession>,
) {
    let s = match session.as_mut() {
        Some(s) => s,
        None => {
            log::warn!("OTA_CHUNK: no active session");
            send_ota_status(usb, OTA_STATUS_ERR_NOT_STARTED, "No session");
            return;
        }
    };

    // Minimum payload: 4 bytes offset + at least 1 byte data.
    if payload.len() < 5 {
        log::warn!("OTA_CHUNK: payload too short ({})", payload.len());
        send_ota_status(usb, OTA_STATUS_ERR_SIZE, "Chunk too short");
        return;
    }

    let offset = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let data = &payload[4..];

    // Sequential chunks only — offset must match bytes received so far.
    if offset != s.bytes_received {
        log::warn!(
            "OTA_CHUNK: offset mismatch — expected {}, got {}",
            s.bytes_received,
            offset
        );
        send_ota_status(usb, OTA_STATUS_ERR_WRITE, "Offset mismatch");
        return;
    }

    // Write to the partition.
    let err = unsafe {
        esp_idf_svc::sys::esp_ota_write(s.ota_handle, data.as_ptr() as *const _, data.len())
    };
    if err != esp_idf_svc::sys::ESP_OK {
        log::error!("OTA_CHUNK: esp_ota_write failed ({})", err);
        send_ota_status(usb, OTA_STATUS_ERR_WRITE, "Write failed");
        // Abort the session on write error.
        unsafe {
            esp_idf_svc::sys::esp_ota_abort(s.ota_handle);
        }
        *session = None;
        return;
    }

    // Update hash and byte counter.
    s.hasher.update(data);
    s.bytes_received += data.len() as u32;

    // Show progress on OLED.
    let percent = if s.total_size > 0 {
        (s.bytes_received as u64 * 100 / s.total_size as u64) as u32
    } else {
        0
    };
    let progress_msg = format!("OTA {percent}%\n{}/{}B", s.bytes_received, s.total_size);
    crate::oled::show_error(display, &progress_msg);

    // NOTE: no log::info! here -- ESP-IDF VFS logging and UsbSerialDriver
    // both write to the USB-Serial-JTAG peripheral via different APIs.
    // Interleaving log output with frame data corrupts the frame protocol
    // after ~245 chunks. The OLED shows progress; serial logging is not needed.

    send_ota_status(usb, OTA_STATUS_CHUNK_OK, "OK");
}

// ---------------------------------------------------------------------------
// OTA_FINISH (0x32)
// ---------------------------------------------------------------------------

/// Handle an `OTA_FINISH` frame.
///
/// Verifies that all bytes have been received, finalises the SHA-256 digest,
/// and compares it against the expected hash supplied in `OTA_BEGIN`.
///
/// On success: calls `esp_ota_end`, sets the boot partition, sends
/// `OTA_STATUS(VERIFIED)`, and reboots.
///
/// On hash mismatch: calls `esp_ota_abort` and sends `OTA_STATUS(ERR_HASH)`.
pub fn handle_ota_finish(
    usb: &mut UsbSerialDriver<'_>,
    display: &mut Display<'_>,
    session: &mut Option<OtaSession>,
) {
    let s = match session.take() {
        Some(s) => s,
        None => {
            log::warn!("OTA_FINISH: no active session");
            send_ota_status(usb, OTA_STATUS_ERR_NOT_STARTED, "No session");
            return;
        }
    };

    // Verify total bytes written.
    if s.bytes_received != s.total_size {
        log::error!(
            "OTA_FINISH: size mismatch — received {} of {} bytes",
            s.bytes_received,
            s.total_size
        );
        unsafe {
            esp_idf_svc::sys::esp_ota_abort(s.ota_handle);
        }
        send_ota_status(usb, OTA_STATUS_ERR_SIZE, "Size mismatch");
        return;
    }

    // Finalise the SHA-256 digest.
    let actual_hash: [u8; 32] = s.hasher.finalize().into();

    if actual_hash != s.expected_hash {
        log::error!("OTA_FINISH: SHA-256 mismatch — firmware rejected");
        unsafe {
            esp_idf_svc::sys::esp_ota_abort(s.ota_handle);
        }
        send_ota_status(usb, OTA_STATUS_ERR_HASH, "Hash mismatch");
        return;
    }

    log::info!("OTA_FINISH: SHA-256 verified — finalising update");
    crate::oled::show_error(display, "OTA verified\nRebooting...");

    // Finalise the OTA write and set the new boot partition.
    let err = unsafe { esp_idf_svc::sys::esp_ota_end(s.ota_handle) };
    if err != esp_idf_svc::sys::ESP_OK {
        log::error!("OTA_FINISH: esp_ota_end failed ({})", err);
        send_ota_status(usb, OTA_STATUS_ERR_WRITE, "esp_ota_end failed");
        return;
    }

    let err = unsafe { esp_idf_svc::sys::esp_ota_set_boot_partition(s.partition) };
    if err != esp_idf_svc::sys::ESP_OK {
        log::error!("OTA_FINISH: esp_ota_set_boot_partition failed ({})", err);
        send_ota_status(usb, OTA_STATUS_ERR_WRITE, "Set boot partition failed");
        return;
    }

    // Notify the host before rebooting.
    send_ota_status(usb, OTA_STATUS_VERIFIED, "Verified");
    esp_idf_hal::delay::FreeRtos::delay_ms(200);

    log::info!("OTA_FINISH: rebooting into new firmware");
    unsafe {
        esp_idf_svc::sys::esp_restart();
    }
}

// ---------------------------------------------------------------------------
// Helper: send OTA_STATUS frame
// ---------------------------------------------------------------------------

/// Send an `OTA_STATUS` frame with a single status code byte, followed by an
/// optional ASCII message (truncated to 63 bytes to fit within the frame).
///
/// Payload layout: `[status_code: u8][message: ASCII...]`
pub fn send_ota_status(usb: &mut UsbSerialDriver<'_>, code: u8, message: &str) {
    let msg_bytes = message.as_bytes();
    let msg_len = msg_bytes.len().min(63);
    let mut payload = Vec::with_capacity(1 + msg_len);
    payload.push(code);
    payload.extend_from_slice(&msg_bytes[..msg_len]);
    crate::protocol::write_frame(usb, FRAME_TYPE_OTA_STATUS, &payload);
}
