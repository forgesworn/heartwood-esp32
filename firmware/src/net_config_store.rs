// firmware/src/net_config_store.rs
//
//! NVS persistence for the WiFi-standalone network config (JSON blob).
//! Mirrors the bridge_secret pattern in session.rs.

use esp_idf_svc::nvs::{EspNvs, NvsDefault};

use heartwood_common::types::{FRAME_TYPE_ACK, FRAME_TYPE_NACK};

use crate::protocol;
use crate::serial::SerialPort;

const NVS_NET_CONFIG_KEY: &str = "net_config";
/// CRC32 of the config-partition blob last seeded into NVS. Lets `main`
/// re-seed on a genuine re-flash (CRC changed) while leaving USB
/// `SET_NET_CONFIG` changes (which don't touch the partition) untouched.
const NVS_SEEDED_CRC_KEY: &str = "ncfg_crc";

/// Maximum stored config size. The read buffer is fixed at this size, so the
/// write must reject anything larger — otherwise the blob writes but every
/// subsequent boot read returns None (ESP_ERR_NVS_INVALID_LENGTH swallowed).
const NET_CONFIG_MAX_LEN: usize = 512;

/// Write the network config blob to NVS.
pub fn write_net_config(nvs: &mut EspNvs<NvsDefault>, json: &[u8]) -> Result<(), &'static str> {
    if json.len() > NET_CONFIG_MAX_LEN {
        return Err("net config too large");
    }
    nvs.set_blob(NVS_NET_CONFIG_KEY, json)
        .map_err(|_| "nvs write failed")
}

/// Read the network config blob from NVS. Returns None if not provisioned.
pub fn read_net_config(nvs: &EspNvs<NvsDefault>) -> Option<Vec<u8>> {
    let mut buf = [0u8; NET_CONFIG_MAX_LEN];
    match nvs.get_blob(NVS_NET_CONFIG_KEY, &mut buf) {
        Ok(Some(b)) => Some(b.to_vec()),
        _ => None,
    }
}

/// CRC of the config-partition blob last seeded into NVS (`None` if never).
pub fn read_seeded_crc(nvs: &EspNvs<NvsDefault>) -> Option<u32> {
    nvs.get_u32(NVS_SEEDED_CRC_KEY).ok().flatten()
}

/// Record the CRC of the config-partition blob just seeded into NVS.
pub fn write_seeded_crc(nvs: &mut EspNvs<NvsDefault>, crc: u32) {
    if nvs.set_u32(NVS_SEEDED_CRC_KEY, crc).is_err() {
        log::warn!("Failed to persist seeded config CRC");
    }
}

/// Handle a SET_NET_CONFIG frame (0x54).
///
/// Parses and validates the JSON payload, requires a 30-second button-hold
/// confirmation on the OLED, then persists the config to NVS.
/// Mirrors handle_set_bridge_secret in session.rs exactly.
pub fn handle_set_net_config(
    usb: &mut SerialPort<'_>,
    payload: &[u8],
    nvs: &mut EspNvs<NvsDefault>,
    display: &mut crate::oled::Display<'_>,
    button_pin: &esp_idf_hal::gpio::PinDriver<'_, esp_idf_hal::gpio::Input>,
) {
    match heartwood_common::net_config::parse_net_config(payload) {
        Ok(cfg) if cfg.validate().is_ok() => {
            let result = crate::approval::run_approval_loop(
                display,
                button_pin,
                30,
                |d, remaining| {
                    let msg = format!("Set network\nconfig? {}s", remaining);
                    crate::oled::show_error(d, &msg);
                },
            );

            if !matches!(result, crate::approval::ApprovalResult::Approved) {
                log::info!("SET_NET_CONFIG denied by user");
                protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
                return;
            }

            match write_net_config(nvs, payload) {
                Ok(()) => {
                    log::info!("Network config written to NVS");
                    crate::oled::show_result(display, "Network config\nset");
                    esp_idf_hal::delay::FreeRtos::delay_ms(1500);
                    protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
                }
                Err(e) => {
                    log::error!("Failed to write network config: {e}");
                    protocol::write_frame(usb, FRAME_TYPE_NACK, b"nvs");
                }
            }
        }
        _ => {
            log::warn!("SET_NET_CONFIG rejected — invalid payload");
            protocol::write_frame(usb, FRAME_TYPE_NACK, b"invalid config");
        }
    }
}
