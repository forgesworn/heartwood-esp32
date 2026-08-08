// firmware/src/wdt.rs
//
// Task watchdog: recover from a hung signer by rebooting, instead of freezing
// silently with keys loaded. The ESP-IDF task watchdog is configured in
// sdkconfig.defaults (60 s timeout — the Kconfig maximum — panic action, so
// the panic path records a crash crumb and the next boot can report
// "task-watchdog").
//
// Only the main task subscribes; every loop that can block long enough to
// matter (provision-wait, locked USB/relay phases, the frame dispatch loop,
// the relay poll loop, button-gesture waits, per-slot PBKDF2) calls `feed()`
// once per iteration. Bounded waits — signing approval (30 s), PIN entry
// (30 s steps), EC math, OTA frames — are all far under the timeout, so
// legitimate work never trips it.

use esp_idf_svc::sys;

/// Subscribe the calling task to the task watchdog. Call once from main after
/// logging is up. Fails are logged but non-fatal: a signer without the
/// watchdog is the status quo, not a new risk.
pub fn init() {
    unsafe {
        // NULL = current task.
        let rc = sys::esp_task_wdt_add(core::ptr::null_mut());
        if rc == 0 {
            log::info!("Task watchdog armed ({}s timeout)", timeout_secs());
        } else {
            log::warn!("Task watchdog subscribe failed (rc={rc}) — running without it");
        }
    }
}

/// Feed the watchdog for the calling task. Cheap; call once per iteration of
/// any loop that can otherwise block indefinitely.
pub fn feed() {
    unsafe {
        sys::esp_task_wdt_reset();
    }
}

/// The configured timeout, for logging. Mirrors sdkconfig.defaults (60 s is
/// the Kconfig maximum for ESP_TASK_WDT_TIMEOUT_S).
const fn timeout_secs() -> u32 {
    60
}
