//! THROWAWAY feasibility spike — branch `spike/wifi-heap`, DO NOT MERGE.
//!
//! Purpose: measure two things the Plan 2 relay transport depends on, as far
//! as is possible without a board:
//!   1. Flash-size delta of linking WiFi + TLS into the existing firmware
//!      (answerable now, by building with `--features wifi-spike` and diffing
//!      the binary size against a plain build).
//!   2. Free-heap cost of WiFi + a TLS client live (only meaningful on real
//!      hardware — the `esp_get_free_heap_size()` logs below produce the number
//!      when this is flashed to a V3, or a V4 with PSRAM off).
//!
//! It brings up WiFi in STA mode (a dummy SSID — it will not associate without
//! a real AP, which is fine; the point is to link and exercise the code path)
//! and constructs a TLS-capable HTTP client (proxy for the wss:// TLS cost —
//! the websocket framing layer adds only a small increment on top).

use esp_idf_hal::modem::Modem;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::http::client::{Configuration as HttpConfig, EspHttpConnection};
use esp_idf_svc::wifi::{ClientConfiguration, Configuration as WifiConfig, EspWifi};

fn free_heap() -> u32 {
    unsafe { esp_idf_svc::sys::esp_get_free_heap_size() }
}

pub fn run_spike(modem: Modem) {
    log::info!("[spike] free heap at start:        {} bytes", free_heap());

    let sysloop = EspSystemEventLoop::take().expect("spike: sysloop");
    let mut wifi = EspWifi::new(modem, sysloop, None).expect("spike: wifi new");
    log::info!("[spike] free heap after EspWifi:   {} bytes", free_heap());

    wifi.set_configuration(&WifiConfig::Client(ClientConfiguration {
        ssid: "spike-ssid".try_into().expect("ssid"),
        password: "spike-pass".try_into().expect("pass"),
        ..Default::default()
    }))
    .expect("spike: wifi config");
    wifi.start().expect("spike: wifi start");
    log::info!("[spike] free heap after wifi.start:{} bytes", free_heap());

    // Will not associate without a real AP — links/exercises the connect path.
    let _ = wifi.connect();

    // Link esp_tls + mbedTLS via a TLS-capable HTTP client. This is the bulk of
    // the wss:// size/heap cost; the websocket framing layer is a small add-on.
    match EspHttpConnection::new(&HttpConfig {
        use_global_ca_store: true,
        crt_bundle_attach: Some(esp_idf_svc::sys::esp_crt_bundle_attach),
        ..Default::default()
    }) {
        Ok(_conn) => log::info!("[spike] TLS HTTP client constructed"),
        Err(e) => log::warn!("[spike] TLS HTTP client error: {e:?}"),
    }
    log::info!("[spike] free heap after TLS client:{} bytes", free_heap());
    log::info!("[spike] DONE — flash size from the build; heap from these logs on a board.");
}
