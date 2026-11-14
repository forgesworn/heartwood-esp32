//! The tasks whose unused stack the device operator's full `get_status`
//! reports as `stack_free` (`firmware/src/relay.rs`, `stack_free`).
//!
//! Each value is the task's FreeRTOS high-water mark: the bytes of its stack
//! it has never touched since it started (`uxTaskGetStackHighWaterMark`; on
//! ESP-IDF `StackType_t` is a byte), or `null` when the task is not running.
//! It exists so a build that changes how Rust code is inlined (link-time
//! optimisation) can be benched, task by task, against one that does not.
//!
//! Every task that runs this firmware's Rust code is here: `main` (the relay
//! and USB loops, all signing and TLS), the button sampler, and `sys_evt`,
//! which runs the WiFi event subscriptions. `esp_timer` and lwIP's `tiT` run
//! only ESP-IDF's C and are reported as controls: a build that changes only
//! Rust code should leave them where they were.

use core::ffi::CStr;

/// The `get_status` key the marks are reported under.
pub const STACK_FREE_KEY: &str = "stack_free";

/// Wire key and FreeRTOS task name for each task looked up by name.
pub const TASKS_BY_NAME: &[(&str, &CStr)] = &[
    ("main", c"main"),
    ("sys_evt", c"sys_evt"),
    ("esp_timer", c"esp_timer"),
    ("tcpip", c"tiT"),
];

/// Wire key of the button sampler (`firmware/src/button.rs`). It is found by
/// the handle the thread records for itself, not by name: Rust's std cannot
/// name a thread on ESP-IDF, so every std thread is a task called "pthread".
pub const BTN_LATCH_KEY: &str = "btn_latch";

/// Longest name `xTaskGetHandle` can match: `CONFIG_FREERTOS_MAX_TASK_NAME_LEN`
/// is 16 with the terminating NUL, and a longer name is stored cut short.
pub const MAX_TASK_NAME_LEN: usize = 15;

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> impl Iterator<Item = &'static str> {
        TASKS_BY_NAME.iter().map(|(key, _)| *key).chain([BTN_LATCH_KEY])
    }

    #[test]
    fn every_task_name_fits_freertos() {
        for (_, name) in TASKS_BY_NAME {
            let len = name.to_bytes().len();
            assert!(len > 0 && len <= MAX_TASK_NAME_LEN, "{name:?} cannot be matched");
        }
    }

    #[test]
    fn wire_keys_are_unique_snake_case() {
        let all: alloc::vec::Vec<_> = keys().collect();
        for (i, key) in all.iter().enumerate() {
            assert!(
                !key.is_empty() && key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{key} is not a snake_case key"
            );
            assert!(!all[..i].contains(key), "{key} is reported twice");
        }
    }

    #[test]
    fn the_main_task_and_the_button_sampler_are_both_reported() {
        assert!(keys().any(|k| k == "main"));
        assert!(keys().any(|k| k == BTN_LATCH_KEY));
    }

    // Device-wide, like `min_free_heap`: a per-identity delegate's reply,
    // full or low-heap, never carries it.
    #[cfg(feature = "seed-encrypt")]
    #[test]
    fn neither_delegate_reply_carries_the_marks() {
        assert!(!crate::at_rest_status::DELEGATE_STATUS_KEYS.contains(&STACK_FREE_KEY));
        assert!(!crate::at_rest_status::DELEGATE_STATUS_FALLBACK_KEYS.contains(&STACK_FREE_KEY));
    }
}
