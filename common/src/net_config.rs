//! Network configuration for WiFi-standalone mode.
//! Pure, host-testable. Stored as a JSON blob in NVS by the firmware.

#[cfg(feature = "nip46")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMode {
    Usb,
    Wifi,
}

#[cfg(feature = "nip46")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetConfig {
    pub ssid: String,
    pub password: String,
    #[serde(default)]
    pub relays: Vec<String>,
    pub mode: String, // "usb" | "wifi"
}

#[cfg(feature = "nip46")]
impl NetConfig {
    pub fn device_mode(&self) -> DeviceMode {
        match self.mode.as_str() {
            "wifi" => DeviceMode::Wifi,
            _ => DeviceMode::Usb,
        }
    }

    /// WiFi mode requires an SSID and at least one relay; USB mode is always valid.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.device_mode() == DeviceMode::Wifi {
            if self.ssid.is_empty() {
                return Err("ssid required for wifi mode");
            }
            if self.relays.is_empty() {
                return Err("at least one relay required for wifi mode");
            }
        }
        Ok(())
    }
}

#[cfg(feature = "nip46")]
pub fn parse_net_config(bytes: &[u8]) -> Result<NetConfig, &'static str> {
    serde_json::from_slice(bytes).map_err(|_| "invalid net config json")
}

#[cfg(all(test, feature = "nip46"))]
mod tests {
    use super::*;

    #[test]
    fn parses_wifi_config() {
        let json = br#"{"ssid":"home","password":"secret","relays":["wss://relay.example"],"mode":"wifi"}"#;
        let cfg = parse_net_config(json).unwrap();
        assert_eq!(cfg.ssid, "home");
        assert_eq!(cfg.device_mode(), DeviceMode::Wifi);
        assert_eq!(cfg.relays, vec!["wss://relay.example".to_string()]);
        cfg.validate().unwrap();
    }

    #[test]
    fn wifi_without_relays_is_invalid() {
        let json = br#"{"ssid":"home","password":"x","relays":[],"mode":"wifi"}"#;
        let cfg = parse_net_config(json).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn usb_mode_defaults_ok() {
        let json = br#"{"ssid":"","password":"","relays":[],"mode":"usb"}"#;
        let cfg = parse_net_config(json).unwrap();
        assert_eq!(cfg.device_mode(), DeviceMode::Usb);
        cfg.validate().unwrap();
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_net_config(b"not json").is_err());
    }
}
