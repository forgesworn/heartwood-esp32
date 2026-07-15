// firmware/src/log_quiet.rs
//
//! Persisted "quiet logging" flag.
//!
//! On the T-Display the blue activity LED is wired to UART0 TX, which also
//! carries the ESP-IDF log stream — at the default INFO level the light
//! flashes with every request, publish and WiFi event, which owners read as
//! "something is wrong". Quiet mode drops runtime logging to warnings: the
//! LED goes dark in normal operation while real problems still print (and
//! stay visible in the USB log stream and the boot banner).

use esp_idf_svc::nvs::{EspNvs, NvsDefault};

const KEY: &str = "log_quiet";

/// Whether quiet logging is persisted on.
pub fn read(nvs: &EspNvs<NvsDefault>) -> bool {
    let mut buf = [0u8; 1];
    matches!(nvs.get_blob(KEY, &mut buf), Ok(Some(b)) if b.len() == 1 && b[0] == 1)
}

/// Persist the flag. The caller applies it separately so a failed write never
/// leaves the running level and the stored level disagreeing silently.
pub fn write(nvs: &mut EspNvs<NvsDefault>, quiet: bool) -> Result<(), String> {
    nvs.set_blob(KEY, &[u8::from(quiet)])
        .map_err(|e| format!("persist log_quiet: {e:?}"))
}

/// Apply the runtime log level for every tag.
pub fn apply(quiet: bool) {
    let level = if quiet {
        esp_idf_svc::sys::esp_log_level_t_ESP_LOG_WARN
    } else {
        esp_idf_svc::sys::esp_log_level_t_ESP_LOG_INFO
    };
    unsafe {
        esp_idf_svc::sys::esp_log_level_set(
            b"*\0".as_ptr() as *const core::ffi::c_char,
            level,
        )
    };
}
