// firmware/src/nip46_handler.rs
//
// NIP-46 request dispatcher for the Heartwood HSM.
//
// Handles two methods:
//   sign_event      — shows event on OLED, waits for button approval, signs
//   get_public_key  — returns the hex public key immediately (no approval needed)
//
// All k256 operations run in a dedicated thread with a 32 KiB aligned stack
// to work around the LoadStoreAlignment fault (EXCCAUSE: 0x05) on Xtensa LX7.

use std::time::Duration;

use esp_idf_hal::gpio::{AnyInputPin, Input, PinDriver};
use esp_idf_hal::usb_serial::UsbSerialDriver;

use heartwood_common::derive;
use heartwood_common::frame::Frame;
use heartwood_common::hex::hex_encode;
use heartwood_common::nip46::{
    self, HeartwoodContext, SignedEvent, UnsignedEvent,
};
use heartwood_common::types::{FRAME_TYPE_NACK, FRAME_TYPE_NIP46_RESPONSE};
use zeroize::Zeroize;

use crate::button::{wait_for_press, ButtonResult};
use crate::oled::Display;
use crate::protocol::write_frame;

/// Timeout in seconds shown on the OLED countdown bar.
const APPROVAL_TIMEOUT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Dispatch an incoming NIP-46 frame to the appropriate handler.
///
/// If the payload cannot be parsed as a NIP-46 JSON-RPC request a NACK is
/// sent and the function returns immediately. Unknown methods receive an error
/// response.
pub fn handle_request(
    usb: &mut UsbSerialDriver<'_>,
    frame: &Frame,
    master_secret: &[u8; 32],
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, AnyInputPin, Input>,
) {
    // Parse the JSON payload into a Nip46Request.
    let request = match nip46::parse_request(&frame.payload) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("Failed to parse NIP-46 request: {e}");
            write_frame(usb, FRAME_TYPE_NACK, &[]);
            return;
        }
    };

    log::info!("NIP-46 request: method={} id={}", request.method, request.id);

    match request.method.as_str() {
        "sign_event" => handle_sign_event(usb, master_secret, display, button_pin, &request),
        "get_public_key" => handle_get_public_key(usb, master_secret, &request),
        other => {
            log::warn!("Unknown NIP-46 method: {other}");
            send_error(usb, &request.id, -2, "unknown method");
        }
    }
}

// ---------------------------------------------------------------------------
// sign_event
// ---------------------------------------------------------------------------

fn handle_sign_event(
    usb: &mut UsbSerialDriver<'_>,
    master_secret: &[u8; 32],
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, AnyInputPin, Input>,
    request: &nip46::Nip46Request,
) {
    // Parse the unsigned event from params.
    let event = match nip46::parse_unsigned_event(&request.params) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("sign_event: bad event format: {e}");
            send_error(usb, &request.id, -3, "bad event format");
            return;
        }
    };

    // Extract a brief summary for the OLED.
    let (kind, content_preview) = nip46::event_display_summary(&event, 50);

    // Determine the signing context label shown on the display.
    let purpose = request
        .heartwood
        .as_ref()
        .map(|h| h.purpose.as_str())
        .unwrap_or("master");

    // Show the signing request and wait for the user to approve or deny.
    crate::oled::show_sign_request(
        display,
        purpose,
        kind,
        &content_preview,
        APPROVAL_TIMEOUT_SECS as u32,
    );

    let button_result =
        wait_for_press(button_pin, Duration::from_secs(APPROVAL_TIMEOUT_SECS));

    match button_result {
        Some(ButtonResult::Approve) => {
            log::info!("sign_event: approved");
            match do_sign(&event, master_secret, request.heartwood.as_ref()) {
                Ok(signed) => {
                    match nip46::build_sign_response(&request.id, &signed) {
                        Ok(json) => {
                            write_frame(usb, FRAME_TYPE_NIP46_RESPONSE, json.as_bytes());
                        }
                        Err(e) => {
                            log::error!("Failed to build sign response: {e}");
                            send_error(usb, &request.id, -4, "signing failed");
                        }
                    }
                    crate::oled::show_result(display, "Signed!");
                }
                Err(e) => {
                    log::error!("Signing failed: {e}");
                    send_error(usb, &request.id, -4, "signing/derivation failure");
                    crate::oled::show_result(display, "Sign error");
                }
            }
        }
        Some(ButtonResult::Deny) => {
            log::info!("sign_event: denied by user");
            send_error(usb, &request.id, -1, "user denied");
            crate::oled::show_result(display, "Denied");
        }
        None => {
            log::info!("sign_event: timed out");
            send_error(usb, &request.id, -1, "timeout");
            crate::oled::show_result(display, "Timed out");
        }
    }
}

// ---------------------------------------------------------------------------
// do_sign — runs k256 in an aligned thread to avoid Xtensa crash
// ---------------------------------------------------------------------------

fn do_sign(
    event: &UnsignedEvent,
    master_secret: &[u8; 32],
    heartwood: Option<&HeartwoodContext>,
) -> Result<SignedEvent, String> {
    // Step 1: compute event ID using sha2 only — safe on the main thread.
    let event_id_bytes = nip46::compute_event_id(event);

    // Step 2: derive signing key in an aligned thread.
    // The thread returns (private_key_bytes, hex_pubkey_string).
    let secret_copy = *master_secret;
    let heartwood_owned = heartwood.cloned();

    let (mut signing_secret, hex_pubkey) = std::thread::Builder::new()
        .name("derive".into())
        .stack_size(32768)
        .spawn(move || -> Result<([u8; 32], String), String> {
            #[repr(align(16))]
            struct Aligned([u8; 32]);
            let aligned = Aligned(secret_copy);

            match heartwood_owned {
                Some(ctx) => {
                    // Derive a child key using nsec-tree.
                    let root = derive::create_tree_root(&aligned.0)
                        .map_err(|e| format!("create_tree_root: {e}"))?;
                    let identity = derive::derive(&root, &ctx.purpose, ctx.index)
                        .map_err(|e| format!("derive: {e}"))?;
                    let pubkey_hex = hex_encode(&identity.public_key);
                    let private_bytes = *identity.private_key;
                    Ok((private_bytes, pubkey_hex))
                }
                None => {
                    // Use master key directly.
                    use k256::schnorr::SigningKey;
                    let signing_key = SigningKey::from_bytes(&aligned.0)
                        .map_err(|_| "invalid master secret".to_string())?;
                    let pubkey_bytes: [u8; 32] =
                        signing_key.verifying_key().to_bytes().into();
                    let pubkey_hex = hex_encode(&pubkey_bytes);
                    Ok((aligned.0, pubkey_hex))
                }
            }
        })
        .map_err(|e| format!("thread spawn failed: {e}"))?
        .join()
        .map_err(|_| "derivation thread panicked".to_string())??;

    // Step 3: sign the event ID hash in another aligned thread.
    let sig_bytes: [u8; 64] = std::thread::Builder::new()
        .name("sign".into())
        .stack_size(32768)
        .spawn(move || -> Result<[u8; 64], String> {
            #[repr(align(16))]
            struct AlignedKey([u8; 32]);
            #[repr(align(16))]
            struct AlignedHash([u8; 32]);
            let aligned_key = AlignedKey(signing_secret);
            let aligned_hash = AlignedHash(event_id_bytes);
            crate::sign::sign_hash(&aligned_key.0, &aligned_hash.0)
                .map_err(|e| e.to_string())
        })
        .map_err(|e| format!("thread spawn failed: {e}"))?
        .join()
        .map_err(|_| "signing thread panicked".to_string())??;

    // Step 4: zeroize the signing secret.
    signing_secret.zeroize();

    // Step 5: assemble the signed event.
    let event_id_hex = hex_encode(&event_id_bytes);
    let sig_hex = hex_encode(&sig_bytes);

    Ok(SignedEvent {
        id: event_id_hex,
        pubkey: hex_pubkey,
        created_at: event.created_at,
        kind: event.kind,
        tags: event.tags.clone(),
        content: event.content.clone(),
        sig: sig_hex,
    })
}

// ---------------------------------------------------------------------------
// get_public_key
// ---------------------------------------------------------------------------

fn handle_get_public_key(
    usb: &mut UsbSerialDriver<'_>,
    master_secret: &[u8; 32],
    request: &nip46::Nip46Request,
) {
    let secret_copy = *master_secret;
    let heartwood_owned = request.heartwood.clone();

    let pubkey_result = std::thread::Builder::new()
        .name("pubkey".into())
        .stack_size(32768)
        .spawn(move || -> Result<String, String> {
            #[repr(align(16))]
            struct Aligned([u8; 32]);
            let aligned = Aligned(secret_copy);

            match heartwood_owned {
                Some(ctx) => {
                    let root = derive::create_tree_root(&aligned.0)
                        .map_err(|e| format!("create_tree_root: {e}"))?;
                    let identity = derive::derive(&root, &ctx.purpose, ctx.index)
                        .map_err(|e| format!("derive: {e}"))?;
                    Ok(hex_encode(&identity.public_key))
                }
                None => {
                    use k256::schnorr::SigningKey;
                    let signing_key = SigningKey::from_bytes(&aligned.0)
                        .map_err(|_| "invalid master secret".to_string())?;
                    let pubkey_bytes: [u8; 32] =
                        signing_key.verifying_key().to_bytes().into();
                    Ok(hex_encode(&pubkey_bytes))
                }
            }
        })
        .map_err(|e| format!("thread spawn failed: {e}"))
        .and_then(|h| h.join().map_err(|_| "pubkey thread panicked".to_string()))
        .and_then(|r| r);

    match pubkey_result {
        Ok(hex_pubkey) => match nip46::build_pubkey_response(&request.id, &hex_pubkey) {
            Ok(json) => {
                write_frame(usb, FRAME_TYPE_NIP46_RESPONSE, json.as_bytes());
                log::info!("get_public_key: sent pubkey {hex_pubkey}");
            }
            Err(e) => {
                log::error!("Failed to build pubkey response: {e}");
                send_error(usb, &request.id, -4, "failed to build response");
            }
        },
        Err(e) => {
            log::error!("get_public_key failed: {e}");
            send_error(usb, &request.id, -4, "signing/derivation failure");
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build and send a NIP-46 error response over USB serial.
///
/// If serialisation itself fails the error is logged and a NACK is sent
/// as a last-resort fallback.
fn send_error(usb: &mut UsbSerialDriver<'_>, request_id: &str, code: i32, message: &str) {
    match nip46::build_error_response(request_id, code, message) {
        Ok(json) => {
            write_frame(usb, FRAME_TYPE_NIP46_RESPONSE, json.as_bytes());
        }
        Err(e) => {
            log::error!("Failed to serialise error response: {e}");
            write_frame(usb, FRAME_TYPE_NACK, &[]);
        }
    }
}
