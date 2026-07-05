// firmware/src/wifi_scan.rs
//
//! WiFi access-point scan (frame 0x55 -> 0x56). A setup aid: over the USB cable
//! Sapwood asks the signer which 2.4 GHz networks it can actually see, so a user
//! picks an SSID the radio has proven it can reach — and at what signal
//! strength — instead of typing one blind. The most common WiFi-standalone
//! failure is a signer that cannot join because the network is 5 GHz-only, out
//! of range, or WPA3-only; a scan surfaces all three directly.
//!
//! Two entry points feed one routine:
//!  - `respond` — scan with an already-started driver (the relay loop reuses its
//!    own `wifi` while WiFi is up but idle).
//!  - `respond_on_demand` — bring the radio up transiently in USB-only mode,
//!    scan, then tear it straight back down.
//!
//! Radio-off tier: `respond_on_demand` is the only path that touches the radio
//! in USB-only mode, and it drops the driver before returning — which stops and
//! deinits WiFi, so the radio is off again the instant the scan completes. No
//! connection is ever attempted and no inbound listener is opened, so the
//! hardened tier's remote attack surface stays zero: the radio is live only
//! during an explicit, cabled scan the user asked for.

use esp_idf_hal::modem::Modem;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::sys::EspError;
use esp_idf_svc::wifi::{
    AccessPointInfo, AuthMethod, BlockingWifi, ClientConfiguration, Configuration as WifiConfig,
    EspWifi,
};

use heartwood_common::types::{FRAME_TYPE_NACK, FRAME_TYPE_WIFI_SCAN_RESPONSE};

use crate::protocol;
use crate::serial::SerialPort;

/// Cap the reported networks so the response frame stays small (each entry is a
/// few tens of bytes; 30 covers any real environment).
const MAX_APS: usize = 30;

/// Scan with an already-started WiFi driver and reply with a 0x56 frame.
///
/// A successful scan always answers 0x56 — even with an empty list, because "the
/// signer sees no networks here" is itself a useful diagnostic. A driver-level
/// failure answers NACK, so the host can tell "scanned, found none" apart from
/// "could not scan".
pub fn respond(usb: &mut SerialPort<'_>, wifi: &mut BlockingWifi<EspWifi<'_>>) {
    match wifi.scan() {
        Ok(aps) => {
            log::info!("[scan] {} access point(s) visible", aps.len());
            let json = build_scan_json(&aps);
            protocol::write_frame(usb, FRAME_TYPE_WIFI_SCAN_RESPONSE, json.as_bytes());
        }
        Err(e) => {
            log::error!("[scan] scan failed: {e:?}");
            protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        }
    }
}

/// Bring the radio up just long enough to scan, then drop the driver (stopping
/// and deiniting WiFi — the radio goes fully off again). Used from the USB-only
/// dispatch loop, where no persistent driver exists. `sysloop` is the shared
/// system event loop, taken once by the caller.
pub fn respond_on_demand(usb: &mut SerialPort<'_>, sysloop: &EspSystemEventLoop) {
    log::info!("[scan] bringing radio up for a one-shot scan (no connection)");

    // SAFETY: the USB-only dispatch loop is single-threaded and never otherwise
    // drives the modem — the relay path that owns it diverges (`-> !`) before
    // this loop is ever reached — so at most one modem-backed driver is live at
    // a time. The driver, and with it the radio, is torn down before this
    // function returns.
    let modem = unsafe { Modem::steal() };

    let esp_wifi = match EspWifi::new(modem, sysloop.clone(), None) {
        Ok(w) => w,
        Err(e) => return fail(usb, "wifi init", e),
    };
    let mut wifi = match BlockingWifi::wrap(esp_wifi, sysloop.clone()) {
        Ok(w) => w,
        Err(e) => return fail(usb, "blocking wrap", e),
    };
    // A default client config is enough to scan: no SSID or credentials are
    // needed and connect() is never called.
    if let Err(e) = wifi.set_configuration(&WifiConfig::Client(ClientConfiguration::default())) {
        return fail(usb, "configure", e);
    }
    if let Err(e) = wifi.start() {
        return fail(usb, "start", e);
    }

    respond(usb, &mut wifi);
    // `wifi` drops here -> esp_wifi_stop + esp_wifi_deinit: radio fully off.
    log::info!("[scan] radio powered down");
}

/// Log a stage failure and NACK the host.
fn fail(usb: &mut SerialPort<'_>, stage: &str, e: EspError) {
    log::error!("[scan] {stage} failed: {e:?}");
    protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
}

/// Build the `[{ssid,rssi,channel,auth,band24}]` JSON: strongest signal first,
/// one entry per SSID (mesh APs collapse to their best), hidden (empty) SSIDs
/// dropped. `AccessPointInfo` does not derive `Serialize` in this build, so each
/// object is assembled from its primitive fields (which do).
fn build_scan_json(aps: &[AccessPointInfo]) -> String {
    let mut best: Vec<&AccessPointInfo> = Vec::new();
    for ap in aps {
        if ap.ssid.as_str().is_empty() {
            continue; // hidden network — nothing for a user to pick
        }
        match best.iter_mut().find(|b| b.ssid == ap.ssid) {
            Some(slot) => {
                if ap.signal_strength > slot.signal_strength {
                    *slot = ap;
                }
            }
            None => best.push(ap),
        }
    }
    best.sort_by(|a, b| b.signal_strength.cmp(&a.signal_strength));
    best.truncate(MAX_APS);

    let arr: Vec<serde_json::Value> = best
        .iter()
        .map(|ap| {
            serde_json::json!({
                "ssid": ap.ssid.as_str(),
                "rssi": ap.signal_strength,
                "channel": ap.channel,
                "auth": auth_str(ap.auth_method),
                // These radios are 2.4 GHz-only, so every result is in-band. The
                // flag is explicit for the host and future-proof for dual-band.
                "band24": ap.channel <= 14,
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
}

/// Short, stable auth label for the host. Drives the lock icon and a hint when a
/// network is WPA3-only — a common reason an ESP32 cannot join.
fn auth_str(auth: Option<AuthMethod>) -> &'static str {
    match auth {
        Some(AuthMethod::None) => "open",
        Some(AuthMethod::WEP) => "wep",
        Some(AuthMethod::WPA) => "wpa",
        Some(AuthMethod::WPA2Personal) => "wpa2",
        Some(AuthMethod::WPAWPA2Personal) => "wpa/wpa2",
        Some(AuthMethod::WPA2Enterprise) => "wpa2-ent",
        Some(AuthMethod::WPA3Personal) => "wpa3",
        Some(AuthMethod::WPA2WPA3Personal) => "wpa2/wpa3",
        Some(AuthMethod::WAPIPersonal) => "wapi",
        _ => "unknown",
    }
}
