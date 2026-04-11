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
use crate::serial::SerialPort;
use sha2::{Digest, Sha256};

use crate::oled::Display;
use heartwood_common::types::{
    FRAME_TYPE_OTA_STATUS, OTA_STATUS_CHUNK_OK, OTA_STATUS_ERR_HASH, OTA_STATUS_ERR_NOT_STARTED,
    OTA_STATUS_ERR_SIZE, OTA_STATUS_ERR_WRITE, OTA_STATUS_READY, OTA_STATUS_VERIFIED,
};

/// Expected chunk data size for progress display (host OTA tool default).
const CHUNK_DATA_MAX: usize = 4088;

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
    usb: &mut SerialPort<'_>,
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

    // NOTE: no log::info! here -- VFS logging interleaves with framed
    // serial data and corrupts OTA_STATUS responses on the host side.
    // The OLED shows the firmware size instead.

    // Show firmware size and run the approval loop (30 s, 2 s hold).
    let size_kb = (total_size + 1023) / 1024;
    let approval_result =
        crate::approval::run_approval_loop(display, button_pin, 30, |d, remaining| {
            crate::oled::show_ota_approval(d, size_kb, remaining, 30);
        });

    match approval_result {
        crate::approval::ApprovalResult::Approved => {}
        crate::approval::ApprovalResult::Denied => {
            send_ota_status(usb, OTA_STATUS_ERR_NOT_STARTED, "Denied");
            return;
        }
        crate::approval::ApprovalResult::TimedOut => {
            send_ota_status(usb, OTA_STATUS_ERR_NOT_STARTED, "Timed out");
            return;
        }
    }

    // Suppress ALL logging (including ESP-IDF internal) during partition
    // setup and status frame send.  esp_ota_begin erases flash and emits
    // log lines through VFS which share the USB serial with framed data.
    unsafe {
        esp_idf_svc::sys::esp_log_level_set(
            b"*\0".as_ptr() as *const core::ffi::c_char,
            esp_idf_svc::sys::esp_log_level_t_ESP_LOG_NONE,
        );
    }

    // Locate the inactive OTA partition and begin the update.
    let (ota_handle, partition) = unsafe {
        let partition =
            esp_idf_svc::sys::esp_ota_get_next_update_partition(core::ptr::null());
        if partition.is_null() {
            restore_logging();
            send_ota_status(usb, OTA_STATUS_ERR_WRITE, "No OTA partition");
            return;
        }

        let mut handle: esp_idf_svc::sys::esp_ota_handle_t = 0;
        let err = esp_idf_svc::sys::esp_ota_begin(partition, total_size as usize, &mut handle);
        if err != esp_idf_svc::sys::ESP_OK {
            restore_logging();
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

    send_ota_status(usb, OTA_STATUS_READY, "Ready");
    restore_logging();
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
    usb: &mut SerialPort<'_>,
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
    let chunk_num = (s.bytes_received + CHUNK_DATA_MAX as u32 - 1) / CHUNK_DATA_MAX as u32;
    let total_chunks = (s.total_size + CHUNK_DATA_MAX as u32 - 1) / CHUNK_DATA_MAX as u32;
    crate::oled::show_ota_progress(
        display,
        percent,
        s.bytes_received,
        s.total_size,
        chunk_num,
        total_chunks,
    );

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
    usb: &mut SerialPort<'_>,
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

    log::info!("OTA_FINISH: SHA-256 verified -- finalising update");
    crate::oled::show_ota_verifying(display);
    esp_idf_hal::delay::FreeRtos::delay_ms(300);

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
    crate::oled::show_ota_complete(display);
    esp_idf_hal::delay::FreeRtos::delay_ms(1500);

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
pub fn send_ota_status(usb: &mut SerialPort<'_>, code: u8, message: &str) {
    // Flush any pending VFS log output before writing the frame.
    unsafe { esp_idf_svc::sys::fsync(1); }
    std::thread::sleep(std::time::Duration::from_millis(50));

    let msg_bytes = message.as_bytes();
    let msg_len = msg_bytes.len().min(63);
    let mut payload = Vec::with_capacity(1 + msg_len);
    payload.push(code);
    payload.extend_from_slice(&msg_bytes[..msg_len]);
    crate::protocol::write_frame(usb, FRAME_TYPE_OTA_STATUS, &payload);
}

/// Restore ESP-IDF logging to INFO level after OTA operations.
fn restore_logging() {
    unsafe {
        esp_idf_svc::sys::esp_log_level_set(
            b"*\0".as_ptr() as *const core::ffi::c_char,
            esp_idf_svc::sys::esp_log_level_t_ESP_LOG_INFO,
        );
    }
}
