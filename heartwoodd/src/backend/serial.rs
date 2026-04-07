// heartwoodd/src/backend/serial.rs
//
// Hard mode: ESP32 serial backend implementing SigningBackend.
//
// Wraps the raw serial port and translates each trait method into the
// appropriate frame exchange defined in heartwood-common/src/types.rs.
// All blocking serial I/O runs synchronously -- callers are expected to
// wrap calls in tokio::task::spawn_blocking if they run from async context.
//
// There is intentional duplication of serial helper code that also lives in
// main.rs / api.rs. That duplication is temporary and will be resolved when
// those files are refactored (Tasks 7-9) to go through this backend.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::sync::broadcast;
use serde_json::Value;

use heartwood_common::frame;
use heartwood_common::types::*;

use crate::serial::RawSerial;
use super::{BackendError, SigningBackend, Tier};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const OTA_CHUNK_SIZE: usize = 4096;

/// Number of retries when trying to acquire the serial mutex.
const LOCK_RETRIES: usize = 10;
/// Pause between retries.
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(50);

// ---------------------------------------------------------------------------
// SerialBackend
// ---------------------------------------------------------------------------

/// Hard-mode signing backend. Owns the shared serial port handle and a
/// broadcast sender for forwarding device log lines to the Sapwood log panel.
pub struct SerialBackend {
    serial: Arc<Mutex<RawSerial>>,
    log_tx: broadcast::Sender<String>,
}

impl SerialBackend {
    /// Construct a new SerialBackend.
    pub fn new(serial: Arc<Mutex<RawSerial>>, log_tx: broadcast::Sender<String>) -> Self {
        Self { serial, log_tx }
    }

    /// Access the underlying serial mutex (needed by the log poller task).
    pub fn serial(&self) -> &Arc<Mutex<RawSerial>> {
        &self.serial
    }

    /// Access the log broadcast sender.
    pub fn log_tx(&self) -> &broadcast::Sender<String> {
        &self.log_tx
    }

    // -- Private helpers -----------------------------------------------------

    /// Attempt to acquire the serial mutex, retrying up to LOCK_RETRIES times
    /// with LOCK_RETRY_DELAY between attempts. Returns DeviceBusy if the lock
    /// cannot be obtained after all retries.
    fn acquire(&self) -> Result<MutexGuard<'_, RawSerial>, BackendError> {
        for _ in 0..LOCK_RETRIES {
            if let Ok(guard) = self.serial.try_lock() {
                return Ok(guard);
            }
            std::thread::sleep(LOCK_RETRY_DELAY);
        }
        Err(BackendError::DeviceBusy)
    }

    /// Send a frame and wait for a response whose type is one of `expected_types`.
    ///
    /// Non-frame bytes (device log output interleaved on the USB-CDC port) are
    /// forwarded line-by-line to `self.log_tx` so they reach the Sapwood log panel
    /// even during long frame exchanges.
    ///
    /// Management operations (list_slots, create_slot, etc.) use this helper.
    /// For NIP-46 signing operations use `read_any_response` instead, which
    /// accepts a wider set of response types.
    fn send_and_receive(
        &self,
        port: &mut RawSerial,
        frame_bytes: &[u8],
        expected_types: &[u8],
        timeout_secs: u64,
    ) -> Result<frame::Frame, BackendError> {
        port.file.write_all(frame_bytes)
            .map_err(|e| BackendError::Internal(format!("serial write failed: {e}")))?;
        port.file.flush()
            .map_err(|e| BackendError::Internal(format!("serial flush failed: {e}")))?;

        let deadline = Instant::now() + Duration::from_secs(timeout_secs);

        loop {
            if Instant::now() > deadline {
                return Err(BackendError::DeviceTimeout);
            }

            let mut byte = [0u8; 1];
            match port.file.read(&mut byte) {
                Ok(1) => {
                    if byte[0] != 0x48 { continue; }
                    match port.file.read(&mut byte) {
                        Ok(1) if byte[0] == 0x57 => {}
                        _ => continue,
                    }
                    // Got magic -- read header (type + length_u16_be).
                    let mut header = [0u8; 3];
                    self.read_exact_deadline(&mut port.file, &mut header, deadline)?;
                    let resp_type = header[0];
                    let length = u16::from_be_bytes([header[1], header[2]]) as usize;
                    if length > MAX_PAYLOAD_SIZE {
                        continue;
                    }
                    let mut body = vec![0u8; length + 4]; // payload + CRC32
                    self.read_exact_deadline(&mut port.file, &mut body, deadline)?;

                    // Reassemble into a complete frame buffer for parse_frame.
                    let mut buf = Vec::with_capacity(5 + length + 4);
                    buf.extend_from_slice(&[0x48, 0x57]);
                    buf.push(resp_type);
                    buf.extend_from_slice(&header[1..3]);
                    buf.extend_from_slice(&body);

                    match frame::parse_frame(&buf) {
                        Ok(f) => {
                            if expected_types.contains(&f.frame_type) {
                                return Ok(f);
                            }
                            if f.frame_type == FRAME_TYPE_NACK {
                                return Err(BackendError::Internal("ESP32 sent NACK".into()));
                            }
                            // Unexpected frame type -- keep hunting.
                        }
                        Err(_) => continue,
                    }
                }
                Ok(_) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => {
                    return Err(BackendError::Internal(format!("serial read error: {e}")));
                }
            }
        }
    }

    /// Read exactly `buf.len()` bytes from `file`, respecting `deadline`.
    fn read_exact_deadline(
        &self,
        file: &mut std::fs::File,
        buf: &mut [u8],
        deadline: Instant,
    ) -> Result<(), BackendError> {
        let mut pos = 0;
        while pos < buf.len() {
            if Instant::now() > deadline {
                return Err(BackendError::DeviceTimeout);
            }
            match file.read(&mut buf[pos..]) {
                Ok(n) if n > 0 => pos += n,
                Ok(_) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => {
                    return Err(BackendError::Internal(format!("serial read failed: {e}")));
                }
            }
        }
        Ok(())
    }

    /// Read a response frame from the ESP32, accepting any of the NIP-46 response
    /// types (NIP46_RESPONSE, ENCRYPTED_RESPONSE, PROVISION_LIST_RESPONSE,
    /// SIGN_ENVELOPE_RESPONSE).
    ///
    /// Non-frame bytes (device log output) are forwarded line-by-line to
    /// `self.log_tx`. This is the only way device logs reach Sapwood during a
    /// long-running frame exchange (e.g. waiting for a button press) because the
    /// background log_poller task cannot access the serial mutex while it is held
    /// here.
    ///
    /// Returns the payload as a UTF-8 string (raw JSON or NIP-44 ciphertext).
    fn read_any_response(
        &self,
        port: &mut RawSerial,
    ) -> Result<String, BackendError> {
        let deadline = Instant::now() + Duration::from_secs(60);
        let log_tx = &self.log_tx;
        let mut log_line_buf: Vec<u8> = Vec::with_capacity(256);

        let flush_log_line = |buf: &mut Vec<u8>| {
            if buf.is_empty() { return; }
            if let Ok(s) = std::str::from_utf8(buf) {
                let trimmed = s.trim_end_matches(|c: char| c == '\r' || c == '\n');
                if !trimmed.is_empty() {
                    let _ = log_tx.send(trimmed.to_string());
                }
            }
            buf.clear();
        };

        loop {
            if Instant::now() > deadline {
                flush_log_line(&mut log_line_buf);
                return Err(BackendError::DeviceTimeout);
            }

            let mut byte = [0u8; 1];
            match port.read(&mut byte) {
                Ok(1) => {
                    if byte[0] != 0x48 {
                        // Accumulate for line-based log forwarding.
                        log_line_buf.push(byte[0]);
                        if byte[0] == b'\n' || log_line_buf.len() > 512 {
                            flush_log_line(&mut log_line_buf);
                        }
                        continue;
                    }
                    match port.read(&mut byte) {
                        Ok(1) if byte[0] == 0x57 => {}
                        _ => {
                            // 0x48 not followed by 0x57 -- treat as log noise.
                            log_line_buf.push(0x48);
                            log_line_buf.push(byte[0]);
                            continue;
                        }
                    }
                    // Found a real frame boundary -- flush any partial log line.
                    flush_log_line(&mut log_line_buf);

                    let mut header = [0u8; 3];
                    self.read_exact_deadline(&mut port.file, &mut header, deadline)?;
                    let resp_type = header[0];
                    let length = u16::from_be_bytes([header[1], header[2]]) as usize;
                    let mut body = vec![0u8; length + 4];
                    self.read_exact_deadline(&mut port.file, &mut body, deadline)?;

                    let mut buf = Vec::with_capacity(5 + length + 4);
                    buf.extend_from_slice(&MAGIC_BYTES);
                    buf.push(resp_type);
                    buf.extend_from_slice(&header[1..3]);
                    buf.extend_from_slice(&body);

                    match frame::parse_frame(&buf) {
                        Ok(f) => {
                            match f.frame_type {
                                FRAME_TYPE_NIP46_RESPONSE
                                | FRAME_TYPE_PROVISION_LIST_RESPONSE
                                | FRAME_TYPE_SIGN_ENVELOPE_RESPONSE => {
                                    return String::from_utf8(f.payload)
                                        .map_err(|e| BackendError::Internal(
                                            format!("invalid UTF-8 in response: {e}")
                                        ));
                                }
                                FRAME_TYPE_ENCRYPTED_RESPONSE => {
                                    // Payload layout: [client_pubkey_32][ciphertext_b64_ascii...]
                                    // The pubkey prefix is raw bytes -- strip it and return
                                    // only the base64 ciphertext that the relay loop needs.
                                    if f.payload.len() < 32 {
                                        return Err(BackendError::Internal(
                                            "encrypted response too short".into()
                                        ));
                                    }
                                    return String::from_utf8(f.payload[32..].to_vec())
                                        .map_err(|e| BackendError::Internal(
                                            format!("invalid UTF-8 in encrypted response: {e}")
                                        ));
                                }
                                FRAME_TYPE_NACK => {
                                    return Err(BackendError::Denied);
                                }
                                _ => {
                                    // Unknown frame type -- keep hunting.
                                }
                            }
                        }
                        Err(_) => continue,
                    }
                }
                Ok(_) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => {
                    return Err(BackendError::Internal(format!("serial read error: {e}")));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SigningBackend implementation
// ---------------------------------------------------------------------------

impl SigningBackend for SerialBackend {
    // -- Tier / lock ---------------------------------------------------------

    fn tier(&self) -> Tier {
        Tier::Hard
    }

    fn is_locked(&self) -> bool {
        // The ESP32 manages its own lock state (button-required). The Pi-side
        // concept of "locked" does not apply in Hard mode.
        false
    }

    fn unlock(&self, _passphrase: &str) -> Result<(), BackendError> {
        Err(BackendError::NotSupported)
    }

    fn lock(&self) -> Result<(), BackendError> {
        Err(BackendError::NotSupported)
    }

    // -- NIP-46 signing ------------------------------------------------------

    fn handle_encrypted_request(
        &self,
        master_pubkey: &[u8; 32],
        client_pubkey: &[u8; 32],
        ciphertext: &str,
    ) -> Result<String, BackendError> {
        let mut payload = Vec::with_capacity(64 + ciphertext.len());
        payload.extend_from_slice(master_pubkey);
        payload.extend_from_slice(client_pubkey);
        payload.extend_from_slice(ciphertext.as_bytes());

        let frame_bytes = frame::build_frame(FRAME_TYPE_ENCRYPTED_REQUEST, &payload)
            .map_err(|e| BackendError::Internal(format!("frame build failed: {e:?}")))?;

        let mut port = self.acquire()?;
        port.write_all(&frame_bytes)
            .map_err(|e| BackendError::Internal(format!("serial write failed: {e}")))?;
        port.flush()
            .map_err(|e| BackendError::Internal(format!("serial flush failed: {e}")))?;

        self.read_any_response(&mut port)
    }

    fn sign_envelope(
        &self,
        master_pubkey: &[u8; 32],
        client_pubkey: &[u8; 32],
        created_at: u64,
        ciphertext: &str,
    ) -> Result<String, BackendError> {
        let mut payload = Vec::with_capacity(72 + ciphertext.len());
        payload.extend_from_slice(master_pubkey);
        payload.extend_from_slice(client_pubkey);
        payload.extend_from_slice(&created_at.to_be_bytes());
        payload.extend_from_slice(ciphertext.as_bytes());

        let frame_bytes = frame::build_frame(FRAME_TYPE_SIGN_ENVELOPE, &payload)
            .map_err(|e| BackendError::Internal(format!("frame build failed: {e:?}")))?;

        let mut port = self.acquire()?;
        port.write_all(&frame_bytes)
            .map_err(|e| BackendError::Internal(format!("serial write failed: {e}")))?;
        port.flush()
            .map_err(|e| BackendError::Internal(format!("serial flush failed: {e}")))?;

        self.read_any_response(&mut port)
    }

    // -- Master management ---------------------------------------------------

    fn list_masters(&self) -> Result<Vec<Value>, BackendError> {
        let frame_bytes = frame::build_frame(FRAME_TYPE_PROVISION_LIST, &[])
            .map_err(|e| BackendError::Internal(format!("frame build failed: {e:?}")))?;

        let mut port = self.acquire()?;
        let resp = self.send_and_receive(
            &mut port,
            &frame_bytes,
            &[FRAME_TYPE_PROVISION_LIST_RESPONSE],
            10,
        )?;

        let json: Value = serde_json::from_slice(&resp.payload)
            .map_err(|e| BackendError::Internal(format!("JSON parse failed: {e}")))?;
        match json {
            Value::Array(arr) => Ok(arr),
            _ => Err(BackendError::Internal("provision list was not a JSON array".into())),
        }
    }

    // -- Connection slot management ------------------------------------------

    fn list_slots(&self, master: u8) -> Result<Value, BackendError> {
        let frame_bytes = frame::build_frame(FRAME_TYPE_CONNSLOT_LIST, &[master])
            .map_err(|e| BackendError::Internal(format!("frame build failed: {e:?}")))?;

        let mut port = self.acquire()?;
        let resp = self.send_and_receive(
            &mut port,
            &frame_bytes,
            &[FRAME_TYPE_CONNSLOT_LIST_RESP],
            10,
        )?;

        serde_json::from_slice(&resp.payload)
            .map_err(|e| BackendError::Internal(format!("JSON parse failed: {e}")))
    }

    fn create_slot(&self, master: u8, label: &str) -> Result<Value, BackendError> {
        // Payload: master_slot (1 byte) + label (plain UTF-8 string).
        let mut payload = Vec::with_capacity(1 + label.len());
        payload.push(master);
        payload.extend_from_slice(label.as_bytes());

        let frame_bytes = frame::build_frame(FRAME_TYPE_CONNSLOT_CREATE, &payload)
            .map_err(|e| BackendError::Internal(format!("frame build failed: {e:?}")))?;

        let mut port = self.acquire()?;
        let resp = self.send_and_receive(
            &mut port,
            &frame_bytes,
            &[FRAME_TYPE_CONNSLOT_CREATE_RESP],
            10,
        )?;

        serde_json::from_slice(&resp.payload)
            .map_err(|e| BackendError::Internal(format!("JSON parse failed: {e}")))
    }

    fn update_slot(&self, master: u8, index: u8, mut patch: Value) -> Result<Value, BackendError> {
        // Inject slot_index into the patch -- the firmware reads it from the JSON body.
        patch["slot_index"] = Value::Number(index.into());
        let json = serde_json::to_vec(&patch)
            .map_err(|e| BackendError::Internal(format!("JSON serialise failed: {e}")))?;

        // Payload: master_slot (1 byte) + JSON (includes slot_index).
        let mut payload = Vec::with_capacity(1 + json.len());
        payload.push(master);
        payload.extend_from_slice(&json);

        let frame_bytes = frame::build_frame(FRAME_TYPE_CONNSLOT_UPDATE, &payload)
            .map_err(|e| BackendError::Internal(format!("frame build failed: {e:?}")))?;

        let mut port = self.acquire()?;
        let resp = self.send_and_receive(
            &mut port,
            &frame_bytes,
            &[FRAME_TYPE_CONNSLOT_UPDATE_RESP],
            10,
        )?;

        // Firmware responds with "ok" or "not found" as plain text.
        let text = String::from_utf8_lossy(&resp.payload);
        if text == "not found" {
            return Err(BackendError::Internal("slot not found".into()));
        }
        Ok(serde_json::json!({"ok": true}))
    }

    fn revoke_slot(&self, master: u8, index: u8) -> Result<Value, BackendError> {
        let payload = [master, index];
        let frame_bytes = frame::build_frame(FRAME_TYPE_CONNSLOT_REVOKE, &payload)
            .map_err(|e| BackendError::Internal(format!("frame build failed: {e:?}")))?;

        let mut port = self.acquire()?;
        let resp = self.send_and_receive(
            &mut port,
            &frame_bytes,
            &[FRAME_TYPE_CONNSLOT_REVOKE_RESP],
            10,
        )?;

        // Firmware responds with "ok" or "not found" as plain text.
        let text = String::from_utf8_lossy(&resp.payload);
        if text == "not found" {
            return Err(BackendError::Internal("slot not found".into()));
        }
        Ok(serde_json::json!({"ok": true}))
    }

    fn get_slot_uri(&self, master: u8, index: u8, relays: &[String]) -> Result<String, BackendError> {
        let relay_json = serde_json::to_vec(relays)
            .map_err(|e| BackendError::Internal(format!("relay serialisation failed: {e}")))?;

        // Payload: master_slot (1) + slot_index (1) + relay_urls (JSON).
        let mut payload = Vec::with_capacity(2 + relay_json.len());
        payload.push(master);
        payload.push(index);
        payload.extend_from_slice(&relay_json);

        let frame_bytes = frame::build_frame(FRAME_TYPE_CONNSLOT_URI, &payload)
            .map_err(|e| BackendError::Internal(format!("frame build failed: {e:?}")))?;

        let mut port = self.acquire()?;
        let resp = self.send_and_receive(
            &mut port,
            &frame_bytes,
            &[FRAME_TYPE_CONNSLOT_URI_RESP],
            10,
        )?;

        String::from_utf8(resp.payload)
            .map_err(|e| BackendError::Internal(format!("invalid UTF-8 in URI response: {e}")))
    }

    // -- Device management ---------------------------------------------------

    fn factory_reset(&self) -> Result<(), BackendError> {
        let frame_bytes = frame::build_frame(FRAME_TYPE_FACTORY_RESET, &[])
            .map_err(|e| BackendError::Internal(format!("frame build failed: {e:?}")))?;

        let mut port = self.acquire()?;
        // 60-second timeout -- user must press the physical confirmation button.
        let resp = self.send_and_receive(
            &mut port,
            &frame_bytes,
            &[FRAME_TYPE_ACK, FRAME_TYPE_NACK],
            60,
        )?;

        if resp.frame_type == FRAME_TYPE_NACK {
            return Err(BackendError::Denied);
        }
        Ok(())
    }

    fn ota_upload(&self, firmware: &[u8]) -> Result<(), BackendError> {
        if firmware.is_empty() {
            return Err(BackendError::Internal("empty firmware binary".into()));
        }

        // Compute SHA-256 hash of the firmware image.
        let hash: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(firmware);
            let result = hasher.finalize();
            let mut h = [0u8; 32];
            h.copy_from_slice(&result);
            h
        };

        // OTA_BEGIN: [size_u32_be (4)][sha256 (32)]
        let size = firmware.len() as u32;
        let mut begin_payload = Vec::with_capacity(36);
        begin_payload.extend_from_slice(&size.to_be_bytes());
        begin_payload.extend_from_slice(&hash);

        let begin_frame = frame::build_frame(FRAME_TYPE_OTA_BEGIN, &begin_payload)
            .map_err(|e| BackendError::Internal(format!("frame build failed: {e:?}")))?;

        let mut port = self.acquire()?;

        // 60-second timeout for button approval.
        let begin_resp = self.send_and_receive(&mut port, &begin_frame, &[FRAME_TYPE_OTA_STATUS], 60)?;
        if begin_resp.payload.first().copied() != Some(OTA_STATUS_READY) {
            let code = begin_resp.payload.first().copied().unwrap_or(0xff);
            return Err(BackendError::Internal(
                format!("OTA begin rejected (status 0x{code:02x})")
            ));
        }

        // Stream firmware in 4096-byte chunks.
        let mut offset: usize = 0;
        while offset < firmware.len() {
            let end = (offset + OTA_CHUNK_SIZE).min(firmware.len());
            let chunk = &firmware[offset..end];

            let mut chunk_payload = Vec::with_capacity(4 + chunk.len());
            chunk_payload.extend_from_slice(&(offset as u32).to_be_bytes());
            chunk_payload.extend_from_slice(chunk);

            let chunk_frame = frame::build_frame(FRAME_TYPE_OTA_CHUNK, &chunk_payload)
                .map_err(|e| BackendError::Internal(format!("chunk frame build failed: {e:?}")))?;

            // 10-second timeout per chunk.
            let chunk_resp = self.send_and_receive(&mut port, &chunk_frame, &[FRAME_TYPE_OTA_STATUS], 10)?;
            if chunk_resp.payload.first().copied() != Some(OTA_STATUS_CHUNK_OK) {
                let code = chunk_resp.payload.first().copied().unwrap_or(0xff);
                return Err(BackendError::Internal(
                    format!("chunk at offset {offset} rejected (0x{code:02x})")
                ));
            }

            offset = end;
        }

        // OTA_FINISH -- 30-second timeout for hash verification.
        let finish_frame = frame::build_frame(FRAME_TYPE_OTA_FINISH, &[])
            .map_err(|e| BackendError::Internal(format!("finish frame build failed: {e:?}")))?;

        let finish_resp = self.send_and_receive(&mut port, &finish_frame, &[FRAME_TYPE_OTA_STATUS], 30)?;
        if finish_resp.payload.first().copied() != Some(OTA_STATUS_VERIFIED) {
            let code = finish_resp.payload.first().copied().unwrap_or(0xff);
            return Err(BackendError::Internal(
                format!("OTA verification failed (0x{code:02x}) -- automatic rollback")
            ));
        }

        Ok(())
    }
}
