//! Physically confirmed, offline bearer-note handover.
//!
//! This surface deliberately has no host, relay or serial output: an owner
//! enters from the private NOTES idle page with a two-second hold, chooses a
//! confirmed plain note, then confirms a second two-second hold before its QR
//! is drawn. A QR is bearer material, so it is displayed briefly, cleared on
//! any button press or timeout, and its buffers are zeroised before return.

use std::time::{Duration, Instant};

use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{PrimitiveStyle, Rectangle};
use qrcodegen_no_heap::{QrCode, QrCodeEcc, Version};
use zeroize::Zeroize;

use crate::approval::{self, ApprovalResult};
use crate::button::{self, Buttons, Gesture};
use crate::oled::Display;
use crate::palette::FG;

const PICK_TIMEOUT: Duration = Duration::from_secs(30);
const QR_TIMEOUT: Duration = Duration::from_secs(45);
const HOLD_MS: u128 = 2_000;
// A typical LUD-25 URL is v5 at ECC-L and renders at 3 px/module. The stored
// host permits 64 bytes and a u64 amount permits 20 digits; that valid edge
// needs v8 (49 modules), which still fits a colour panel at 2 px/module.
const QR_MAX_VERSION: Version = Version::new(8);
const QR_BUF: usize = QR_MAX_VERSION.buffer_len();

/// Consume a deliberate hold from the NOTES idle page and enter the physical
/// picker. A normal tap remains the existing carousel navigation action.
pub fn launch_if_requested(display: &mut Display<'_>, buttons: &Buttons<'_>) -> bool {
    if !buttons.a.is_low() {
        return false;
    }
    let started = Instant::now();
    while buttons.a.is_low() && started.elapsed().as_millis() < HOLD_MS {
        crate::wdt::feed();
        esp_idf_hal::delay::FreeRtos::delay_ms(20);
    }
    if started.elapsed().as_millis() < HOLD_MS {
        return false;
    }
    // The opening hold belongs to the QR flow, never to the idle carousel or
    // the confirmation that follows it.
    button::clear_press_edge();
    while buttons.a.is_low() {
        crate::wdt::feed();
        esp_idf_hal::delay::FreeRtos::delay_ms(20);
    }
    esp_idf_hal::delay::FreeRtos::delay_ms(30);
    button::clear_press_edge();
    run_picker(display, buttons);
    true
}

fn run_picker(display: &mut Display<'_>, buttons: &Buttons<'_>) {
    let count = crate::notes::offline_revealable_count();
    if count == 0 {
        crate::oled::show_result(display, "NO CONFIRMED\nPLAIN NOTES");
        wait_for_dismiss(buttons, Duration::from_secs(8));
        return;
    }

    let mut selected = 0usize;
    let deadline = Instant::now() + PICK_TIMEOUT;
    while Instant::now() < deadline {
        // The locker can change only through a separately confirmed operation,
        // but defend against an interrupted/removed entry without retaining a
        // secret from an earlier redraw.
        let Some(meta) = crate::notes::offline_revealable_meta_at(selected) else {
            selected = 0;
            continue;
        };
        crate::oled::show_offline_note_picker(
            display,
            selected + 1,
            count,
            meta.amount_msat,
            &meta.host,
        );

        if buttons.b_pressed() {
            buttons.drain_b();
            return;
        }
        match button::read_gesture(&buttons.a, Duration::from_millis(250)) {
            Some(Gesture::Single) => selected = (selected + 1) % count,
            Some(Gesture::Long) => return,
            Some(Gesture::Double) => {
                if confirm_and_render(display, buttons, selected) {
                    return;
                }
            }
            None => {}
        }
    }
}

fn confirm_and_render(display: &mut Display<'_>, buttons: &Buttons<'_>, selected: usize) -> bool {
    let Some(reveal) = crate::notes::offline_revealable_at(selected) else {
        return false;
    };
    let title = format!(
        "{} msat\n{}",
        reveal.amount_msat,
        shorten_host(&reveal.host)
    );
    let approved = matches!(
        approval::run_approval_loop(display, buttons, 30, |d, remaining| {
            crate::oled::show_titled_approval(d, "SHOW NOTE QR", &title, remaining, 30);
        }),
        ApprovalResult::Approved
    );
    if !approved {
        return false;
    }

    let result = render_reveal(display, &reveal);
    drop(reveal); // scrubs the copied secret before the dismissal wait.
    if result.is_err() {
        crate::oled::show_error(display, "NOTE QR\nTOO LARGE");
        wait_for_dismiss(buttons, Duration::from_secs(8));
        return true;
    }
    wait_for_dismiss(buttons, QR_TIMEOUT);
    // Never leave bearer material illuminated after a scanner leaves or a
    // visitor walks away. The caller restores an ordinary idle card.
    display.clear_buffer();
    display.flush().ok();
    true
}

#[cfg(any(feature = "tdisplay", feature = "c6"))]
fn render_reveal(
    display: &mut Display<'_>,
    reveal: &heartwood_common::note_store::OfflineReveal,
) -> Result<(), ()> {
    let mut url =
        heartwood_common::note_wrap::note_url(&reveal.host, reveal.secret(), reveal.amount_msat);
    let mut temp = [0u8; QR_BUF];
    let mut out = [0u8; QR_BUF];
    let result = QrCode::encode_text(
        &url,
        &mut temp,
        &mut out,
        QrCodeEcc::Low,
        Version::MIN,
        QR_MAX_VERSION,
        None,
        false,
    )
    .map_err(|_| ())
    .and_then(|qr| {
        draw_colour_qr(display, &qr)?;
        Ok(())
    });
    url.zeroize();
    temp.zeroize();
    out.zeroize();
    result
}

#[cfg(any(feature = "heltec-v3", feature = "heltec-v4"))]
fn render_reveal(
    display: &mut Display<'_>,
    reveal: &heartwood_common::note_store::OfflineReveal,
) -> Result<(), ()> {
    // The 128x64 OLED cannot carry the whole URL legibly. Its paired receiver
    // already knows this locker's host and amount from `heartwood_note_list`,
    // so a raw 32-byte `k1` is the useful offline form. Do not add a marker:
    // that would push v2 to v3 and destroy the OLED's essential quiet margin.
    let mut data_and_temp = [0u8; QR_BUF];
    data_and_temp[..32].copy_from_slice(reveal.secret());
    let mut out = [0u8; QR_BUF];
    let result = QrCode::encode_binary(
        &mut data_and_temp,
        32,
        &mut out,
        QrCodeEcc::Low,
        Version::new(2),
        Version::new(2),
        None,
        false,
    )
    .map_err(|_| ())
    .and_then(|qr| {
        // 25 modules at 2 px leaves a 7 px black margin on each side of the
        // 64 px OLED. It is the largest scanner-friendly square the panel can
        // present; the panel itself supplies the surrounding black quiet area.
        draw_qr(display, &qr, 2, 0);
        Ok(())
    });
    data_and_temp.zeroize();
    out.zeroize();
    result
}

fn draw_qr(display: &mut Display<'_>, qr: &QrCode<'_>, scale: i32, quiet: i32) {
    let size = qr.size();
    let pixels = size * scale + quiet * 2;
    let bounds = display.bounding_box().size;
    let x0 = ((bounds.width as i32 - pixels) / 2).max(0) + quiet;
    let y0 = ((bounds.height as i32 - pixels) / 2).max(0) + quiet;
    display.clear_buffer();
    for y in 0..size {
        for x in 0..size {
            if qr.get_module(x, y) {
                Rectangle::new(
                    Point::new(x0 + x * scale, y0 + y * scale),
                    Size::new(scale as u32, scale as u32),
                )
                .into_styled(PrimitiveStyle::with_fill(FG))
                .draw(display)
                .ok();
            }
        }
    }
    // The explicit clear guarantees a black quiet region even on colour
    // panels whose previous frame had bright pixels.
    display.flush().ok();
}

#[cfg(any(feature = "tdisplay", feature = "c6"))]
fn draw_colour_qr(display: &mut Display<'_>, qr: &QrCode<'_>) -> Result<(), ()> {
    // Preserve the reference-quality v5 presentation for ordinary URLs. Long
    // but valid mint paths use v6-v8; on a 135px-tall T-Display, 2px modules
    // and an 8px black margin remain comfortably scannable.
    let scale = if qr.size() <= 37 { 3 } else { 2 };
    let quiet = if scale == 3 { 12 } else { 8 };
    let panel = display.bounding_box().size;
    let needed = qr.size() * scale + quiet * 2;
    if needed > panel.width as i32 || needed > panel.height as i32 {
        return Err(());
    }
    draw_qr(display, qr, scale, quiet);
    Ok(())
}

fn wait_for_dismiss(buttons: &Buttons<'_>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        crate::wdt::feed();
        if buttons.b_pressed() {
            buttons.drain_b();
            return;
        }
        if buttons.a.is_low() {
            while buttons.a.is_low() {
                crate::wdt::feed();
                esp_idf_hal::delay::FreeRtos::delay_ms(20);
            }
            button::clear_press_edge();
            return;
        }
        esp_idf_hal::delay::FreeRtos::delay_ms(20);
    }
}

fn shorten_host(host: &str) -> String {
    if host.len() <= 22 {
        host.to_string()
    } else {
        format!("{}..{}", &host[..12], &host[host.len() - 8..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_secret_stays_in_a_v2_symbol() {
        let mut data = [0u8; QR_BUF];
        let mut out = [0u8; QR_BUF];
        let qr = QrCode::encode_binary(
            &mut data,
            32,
            &mut out,
            QrCodeEcc::Low,
            Version::new(2),
            Version::new(2),
            None,
            false,
        )
        .unwrap();
        assert_eq!(qr.size(), 25);
    }

    #[test]
    fn normal_note_url_fits_the_colour_panel_ceiling() {
        let url = heartwood_common::note_wrap::note_url("mint.example/w", &[0xab; 32], 21_000);
        let mut temp = [0u8; QR_BUF];
        let mut out = [0u8; QR_BUF];
        let qr = QrCode::encode_text(
            &url,
            &mut temp,
            &mut out,
            QrCodeEcc::Low,
            Version::MIN,
            QR_MAX_VERSION,
            None,
            false,
        )
        .unwrap();
        assert!(qr.size() <= 37);
    }

    #[test]
    fn maximum_stored_note_url_fits_the_colour_panel_ceiling() {
        let host = format!("{}/w", "m".repeat(62));
        let url = heartwood_common::note_wrap::note_url(&host, &[0xab; 32], u64::MAX);
        let mut temp = [0u8; QR_BUF];
        let mut out = [0u8; QR_BUF];
        let qr = QrCode::encode_text(
            &url,
            &mut temp,
            &mut out,
            QrCodeEcc::Low,
            Version::MIN,
            QR_MAX_VERSION,
            None,
            false,
        )
        .unwrap();
        assert!(qr.size() <= 49);
        assert!(qr.size() * 2 + 16 <= 135);
    }
}
