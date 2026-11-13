//! What kind of crash the last one was, beside the breadcrumb.
//!
//! The breadcrumb (`firmware/src/crash_crumb.rs`) names the operation in
//! flight when the signer reset. It cannot say whether that operation ran out
//! of heap or hit a bug, and every board builds with its console off, so the
//! panic message is printed nowhere. Two more RTC records answer that, each
//! stamped with the crumb window it happened in (a counter the firmware bumps
//! on every crumb `set` and `clear`):
//!
//! - a Rust panic hook records the panic's source location, `file:line`;
//! - ESP-IDF's failed-allocation callback records the size and caps of the
//!   last allocation that failed, and how many failed in that window.
//!
//! Only records from the final window are reported. C code on the board (TLS,
//! WiFi, lwIP) survives failed allocations, so a bare "last failed size" from
//! earlier in the boot would blame the wrong thing.
//!
//! A Rust allocation failure never reaches the panic hook: stable std prints
//! "memory allocation of N bytes failed" and aborts without running user
//! code, and the abort resets the chip as a panic. So a failed allocation
//! with no panic record, on a panic reset, is the out-of-memory signature.
//! After a watchdog or brownout the same record is only a fact about the
//! window, since C code survives failed allocations. Stack overflow, CPU
//! exceptions, C `abort()` and the watchdogs fire neither hook and read as
//! [`CrashCause::Unrecorded`].
//!
//! The panic message itself is deliberately not kept. FIRMWARE_INFO answers
//! any USB host, locked or not, and a formatted message (`unwrap` on an
//! `Err`, a bounds check, a `str` slice) can carry request data. The source
//! location is part of the published firmware and carries none.

#[allow(unused_imports)]
use alloc::{format, string::String};

/// Room for a panic location, `path:line`, in the RTC record.
pub const PANIC_SITE_CAP: usize = 40;

/// Write a panic location as `path:line` into `out`, returning its length.
///
/// No allocation: this runs inside the panic hook, possibly with the heap
/// already exhausted. The path keeps only what follows its last `src/`
/// (`relay.rs`, `client_grants/snapshot.rs`, `str/mod.rs` for std), so a
/// dependency's absolute build path never reaches the device's output and
/// the record stays short. When it is still too long the tail is kept,
/// since the file name and line are the parts that locate the panic. Bytes
/// outside printable ASCII, and `"`, become `?`; a `\\` becomes `/`. So the
/// result needs no escaping inside a JSON string.
pub fn format_panic_site(file: &str, line: u32, out: &mut [u8; PANIC_SITE_CAP]) -> usize {
    let path = short_path(file.as_bytes());

    let mut digits = [0u8; 10];
    let mut d = digits.len();
    let mut n = line;
    loop {
        d -= 1;
        digits[d] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let digits = &digits[d..];

    let path_room = PANIC_SITE_CAP - 1 - digits.len();
    let path = &path[path.len().saturating_sub(path_room)..];

    let mut len = 0;
    for &b in path {
        out[len] = match b {
            b'\\' => b'/',
            b'"' => b'?',
            0x21..=0x7e => b,
            _ => b'?',
        };
        len += 1;
    }
    out[len] = b':';
    len += 1;
    out[len..len + digits.len()].copy_from_slice(digits);
    len + digits.len()
}

fn short_path(file: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut i = 0;
    while i + 4 <= file.len() {
        let w = &file[i..i + 4];
        let at_boundary = i == 0 || matches!(file[i - 1], b'/' | b'\\');
        if at_boundary && (w == b"src/" || w == b"src\\") {
            start = i + 4;
        }
        i += 1;
    }
    let tail = &file[start..];
    if start == 0 {
        // No `src/`: fall back to the bare file name.
        match tail.iter().rposition(|&b| b == b'/' || b == b'\\') {
            Some(p) => &tail[p + 1..],
            None => tail,
        }
    } else {
        tail
    }
}

/// The last failed allocation in the final crumb window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocFailure {
    /// Requested size of the last allocation that failed, in bytes.
    pub bytes: u32,
    /// ESP-IDF `MALLOC_CAP_*` bits it asked for. Rust's `malloc` arrives as
    /// `MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL` on boards without PSRAM; a
    /// driver's DMA buffer carries `MALLOC_CAP_DMA`.
    pub caps: u32,
    /// How many allocations failed in that window, this one included.
    pub failures: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashCause {
    /// The panic hook ran in the final window: a Rust panic. Its location is
    /// in [`CrashDetail::panic_site`].
    RustPanic,
    /// No panic, but an allocation failed in the final window and the chip
    /// reset as a panic: the shape of a Rust out-of-memory abort.
    AllocFailed,
    /// Neither of those: a watchdog, stack overflow, CPU exception or C
    /// abort. The breadcrumb, `last_reset` and any failed-allocation record
    /// are all there is.
    Unrecorded,
}

impl CrashCause {
    pub fn wire(self) -> &'static str {
        match self {
            CrashCause::RustPanic => "rust-panic",
            CrashCause::AllocFailed => "alloc-failed",
            CrashCause::Unrecorded => "unrecorded",
        }
    }
}

/// Everything the board knows about its last crash beyond the breadcrumb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashDetail {
    pub cause: CrashCause,
    pub panic_site: Option<String>,
    pub alloc: Option<AllocFailure>,
}

impl CrashDetail {
    /// Classify the final window's records. `panic_reset` is whether the
    /// chip reset as a panic (`ESP_RST_PANIC`), which is how a Rust
    /// out-of-memory abort resets. A panic record wins over a failed
    /// allocation: the allocation may be one the code survived (a fallible
    /// reserve), while the panic is what took the board down. A failed
    /// allocation alone is called out-of-memory only on a panic reset.
    pub fn from_records(
        panic_site: Option<String>,
        alloc: Option<AllocFailure>,
        panic_reset: bool,
    ) -> Self {
        let cause = match (&panic_site, &alloc) {
            (Some(_), _) => CrashCause::RustPanic,
            (None, Some(_)) if panic_reset => CrashCause::AllocFailed,
            _ => CrashCause::Unrecorded,
        };
        CrashDetail { cause, panic_site, alloc }
    }
}

impl CrashDetail {
    /// `{"cause", "panic_site", "alloc_failed_bytes", "alloc_failed_caps",
    /// "alloc_failures"}`, with `null` for what was not recorded and
    /// `alloc_failures` 0 when nothing failed. FIRMWARE_INFO and the device
    /// operator's `get_status` (full and low-heap) both carry it as
    /// `crash_detail`, next to `crashed_during`. Written by hand rather than
    /// through serde: the Heltec app slot has little room, and every value
    /// here is a number, a fixed word or a [`format_panic_site`] string,
    /// which never needs escaping.
    pub fn to_json(&self) -> String {
        fn num(v: Option<u32>) -> String {
            v.map_or_else(|| String::from("null"), |n| format!("{n}"))
        }
        let site = match &self.panic_site {
            Some(s) => format!("\"{s}\""),
            None => String::from("null"),
        };
        format!(
            "{{\"cause\":\"{}\",\"panic_site\":{},\"alloc_failed_bytes\":{},\
             \"alloc_failed_caps\":{},\"alloc_failures\":{}}}",
            self.cause.wire(),
            site,
            num(self.alloc.map(|a| a.bytes)),
            num(self.alloc.map(|a| a.caps)),
            self.alloc.map_or(0, |a| a.failures),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(file: &str, line: u32) -> String {
        let mut out = [0u8; PANIC_SITE_CAP];
        let n = format_panic_site(file, line, &mut out);
        String::from_utf8(out[..n].to_vec()).unwrap()
    }

    #[test]
    fn keeps_the_path_after_the_last_src() {
        assert_eq!(site("src/relay.rs", 9180), "relay.rs:9180");
        assert_eq!(
            site("/home/builder/heartwood/common/src/client_grants/snapshot.rs", 12),
            "client_grants/snapshot.rs:12"
        );
        assert_eq!(site("/rustc/abc123/library/core/src/str/mod.rs", 0), "str/mod.rs:0");
        assert_eq!(site("C:\\b\\common\\src\\mgmt.rs", 7), "mgmt.rs:7");
    }

    #[test]
    fn never_reports_a_builders_home_path() {
        let s = site("/Users/someone/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_json-1.0.149/src/ser.rs", 2177);
        assert_eq!(s, "ser.rs:2177");
    }

    #[test]
    fn a_src_inside_a_name_is_not_a_boundary() {
        // "mysrc/" is not "src/": only a whole path component counts.
        assert_eq!(site("/x/mysrc/main.rs", 3), "main.rs:3");
    }

    #[test]
    fn falls_back_to_the_file_name() {
        assert_eq!(site("/x/y/build.rs", 40), "build.rs:40");
        assert_eq!(site("lib.rs", 1), "lib.rs:1");
    }

    #[test]
    fn long_paths_keep_the_tail_and_the_whole_line() {
        let s = site("src/a_very_long_module_name/with/many/nested/levels/file.rs", u32::MAX);
        assert_eq!(s.len(), PANIC_SITE_CAP);
        assert!(s.ends_with("/file.rs:4294967295"), "{s}");
    }

    #[test]
    fn non_printable_bytes_are_replaced() {
        assert_eq!(site("src/re lay\u{e9}.rs", 5), "re?lay??.rs:5");
    }

    #[test]
    fn nothing_in_a_site_needs_json_escaping() {
        assert_eq!(site("C:\\b\\common\\src\\client_grants\\snapshot.rs", 3), "client_grants/snapshot.rs:3");
        assert_eq!(site("src/a\"b.rs", 1), "a?b.rs:1");
    }

    #[test]
    fn a_panic_outranks_a_failed_allocation() {
        let alloc = AllocFailure { bytes: 9984, caps: 0x1804, failures: 2 };
        let d = CrashDetail::from_records(Some("relay.rs:1".into()), Some(alloc), true);
        assert_eq!(d.cause, CrashCause::RustPanic);
        assert_eq!(d.alloc, Some(alloc));
        assert_eq!(CrashDetail::from_records(None, Some(alloc), true).cause, CrashCause::AllocFailed);
        assert_eq!(CrashDetail::from_records(None, None, true).cause, CrashCause::Unrecorded);
    }

    #[test]
    fn a_failed_allocation_before_a_watchdog_is_not_called_out_of_memory() {
        // TLS or WiFi survived it, then a watchdog fired: the record stays,
        // as a fact, but the cause is not claimed.
        let alloc = AllocFailure { bytes: 16_384, caps: 0x1804, failures: 1 };
        let d = CrashDetail::from_records(None, Some(alloc), false);
        assert_eq!(d.cause, CrashCause::Unrecorded);
        assert_eq!(d.alloc, Some(alloc));
        // A panic record still names a panic whatever the reset said.
        let p = CrashDetail::from_records(Some("relay.rs:1".into()), None, false);
        assert_eq!(p.cause, CrashCause::RustPanic);
    }

    fn parsed(d: &CrashDetail) -> serde_json::Value {
        serde_json::from_str(&d.to_json()).expect("valid JSON")
    }

    #[test]
    fn renders_every_state_as_json_with_stable_keys() {
        assert_eq!(
            parsed(&CrashDetail::from_records(None, None, true)),
            serde_json::json!({
                "cause": "unrecorded",
                "panic_site": null,
                "alloc_failed_bytes": null,
                "alloc_failed_caps": null,
                "alloc_failures": 0,
            })
        );
        let oom = CrashDetail::from_records(
            None,
            Some(AllocFailure { bytes: 9984, caps: 6148, failures: 1 }),
            true,
        );
        assert_eq!(
            parsed(&oom),
            serde_json::json!({
                "cause": "alloc-failed",
                "panic_site": null,
                "alloc_failed_bytes": 9984,
                "alloc_failed_caps": 6148,
                "alloc_failures": 1,
            })
        );
        let worst = CrashDetail::from_records(
            Some(site("C:\\x\\src\\we\"ird\\\u{7f}.rs", u32::MAX)),
            Some(AllocFailure { bytes: u32::MAX, caps: u32::MAX, failures: u32::MAX }),
            true,
        );
        assert_eq!(parsed(&worst)["panic_site"], "we?ird/?.rs:4294967295");
        assert_eq!(parsed(&worst)["alloc_failed_bytes"], u64::from(u32::MAX));
    }
}
