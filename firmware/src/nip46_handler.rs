// firmware/src/nip46_handler.rs
//
// NIP-46 request dispatcher for the Heartwood HSM.
//
// Handles two methods:
//   sign_event      — shows event on OLED, waits for button approval, signs
//   get_public_key  — returns the hex public key immediately (no approval needed)

use std::sync::Arc;
use std::time::Duration;

use esp_idf_hal::gpio::{Input, PinDriver};
use esp_idf_hal::usb_serial::UsbSerialDriver;

use heartwood_common::derive;
use heartwood_common::frame::Frame;
use heartwood_common::hex::hex_encode;
use heartwood_common::nip46::{
    self, HeartwoodContext, SignedEvent, UnsignedEvent,
};
use heartwood_common::types::{FRAME_TYPE_NACK, FRAME_TYPE_NIP46_RESPONSE};
use secp256k1::{Secp256k1, SignOnly};
use zeroize::Zeroize;

use crate::button::ButtonResult;
use crate::oled::Display;
use crate::protocol::write_frame;

/// Timeout in seconds shown on the OLED countdown bar.
const APPROVAL_TIMEOUT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn handle_request(
    usb: &mut UsbSerialDriver<'_>,
    frame: &Frame,
    master_secret: &[u8; 32],
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, Input>,
) {
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
        "sign_event" => handle_sign_event(usb, master_secret, secp, display, button_pin, &request),
        "get_public_key" => handle_get_public_key(usb, master_secret, secp, &request),
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
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'_>,
    button_pin: &PinDriver<'_, Input>,
    request: &nip46::Nip46Request,
) {
    let event = match nip46::parse_unsigned_event(&request.params) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("sign_event: bad event format: {e}");
            send_error(usb, &request.id, -3, "bad event format");
            return;
        }
    };

    let (kind, content_preview) = nip46::event_display_summary(&event, 50);

    let purpose = request
        .heartwood
        .as_ref()
        .map(|h| h.purpose.as_str())
        .unwrap_or("master");

    // Show the signing request on the OLED and wait for button approval.
    // The countdown bar updates every second; button press feedback is shown
    // as "Hold 2s..." while the button is held down.
    let start = std::time::Instant::now();
    let deadline = start + Duration::from_secs(APPROVAL_TIMEOUT_SECS);
    let mut last_remaining = APPROVAL_TIMEOUT_SECS as u32 + 1;
    let mut pressed = false;
    let mut press_start = std::time::Instant::now();

    let button_result = loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            break None;
        }

        let remaining = (deadline - now).as_secs() as u32;

        if remaining != last_remaining && !pressed {
            crate::oled::show_sign_request(display, purpose, kind, &content_preview, remaining);
            last_remaining = remaining;
        }

        let low = button_pin.is_low();
        if low && !pressed {
            pressed = true;
            press_start = now;
            crate::oled::show_error(display, "Hold 2s...");
        }
        if low && pressed {
            let held = now - press_start;
            if held >= Duration::from_millis(2000) {
                crate::oled::show_error(display, "Approved!");
                esp_idf_hal::delay::FreeRtos::delay_ms(300);
                break Some(ButtonResult::Approve);
            }
        }
        if !low && pressed {
            crate::oled::show_error(display, "Denied (short)");
            esp_idf_hal::delay::FreeRtos::delay_ms(500);
            break Some(ButtonResult::Deny);
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(20);
    };

    match button_result {
        Some(ButtonResult::Approve) => {
            log::info!("sign_event: approved");
            crate::oled::show_error(display, "Signing...");
            match do_sign(&event, master_secret, secp, request.heartwood.as_ref()) {
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
                Err(ref e) => {
                    log::error!("Signing failed: {e}");
                    crate::oled::show_error(display, &format!("ERR:{}", &e[..e.len().min(18)]));
                    esp_idf_hal::delay::FreeRtos::delay_ms(3000);
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
// do_sign — runs inline on the main thread
// ---------------------------------------------------------------------------

fn do_sign(
    event: &UnsignedEvent,
    master_secret: &[u8; 32],
    secp: &Arc<Secp256k1<SignOnly>>,
    heartwood: Option<&HeartwoodContext>,
) -> Result<SignedEvent, String> {
    let event_id_bytes = nip46::compute_event_id(event);

    let (mut signing_secret, hex_pubkey) = match heartwood {
        Some(ctx) => {
            let root = derive::create_tree_root(master_secret)
                .map_err(|e| format!("create_tree_root: {e}"))?;
            let identity = derive::derive(&root, &ctx.purpose, ctx.index)
                .map_err(|e| format!("derive: {e}"))?;
            let pubkey_hex = hex_encode(&identity.public_key);
            let private_bytes = *identity.private_key;
            (private_bytes, pubkey_hex)
        }
        None => {
            let keypair = secp256k1::Keypair::from_seckey_slice(secp, master_secret)
                .map_err(|_| "invalid master secret".to_string())?;
            let (xonly, _) = keypair.x_only_public_key();
            let pubkey_hex = hex_encode(&xonly.serialize());
            (*master_secret, pubkey_hex)
        }
    };

    let sig_bytes = crate::sign::sign_hash(secp, &signing_secret, &event_id_bytes)
        .map_err(|e| e.to_string())?;

    signing_secret.zeroize();

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
    secp: &Arc<Secp256k1<SignOnly>>,
    request: &nip46::Nip46Request,
) {
    let pubkey_result = match &request.heartwood {
        Some(ctx) => {
            derive::create_tree_root(master_secret)
                .map_err(|e| format!("create_tree_root: {e}"))
                .and_then(|root| {
                    derive::derive(&root, &ctx.purpose, ctx.index)
                        .map_err(|e| format!("derive: {e}"))
                })
                .map(|identity| hex_encode(&identity.public_key))
        }
        None => {
            secp256k1::Keypair::from_seckey_slice(secp, master_secret)
                .map(|keypair| {
                    let (xonly, _) = keypair.x_only_public_key();
                    hex_encode(&xonly.serialize())
                })
                .map_err(|_| "invalid master secret".to_string())
        }
    };

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
