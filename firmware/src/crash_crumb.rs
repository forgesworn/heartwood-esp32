// firmware/src/crash_crumb.rs
//
//! Crash breadcrumb: what the signer was doing when it last crashed.
//!
//! A panic/watchdog reset makes the device reboot silently, which owners
//! experience as "it restarts itself". `reset_reason_str()` already tells a
//! crash from a planned restart; this adds the missing half — WHAT was in
//! flight — so "reboots itself, no pattern" becomes "crashes on sign_event
//! kind 1059 from client ab12…".
//!
//! The breadcrumb lives in RTC-slow "noinit" memory: NOLOAD, so it is NOT
//! zeroed by the C runtime on a CPU/panic/watchdog reset and survives into the
//! next boot. It IS lost on power-off (that resets as "power-on", which is not
//! a crash, so nothing to attribute). `set` before a risky step, `clear` after
//! it returns; on boot, if the reset was a crash and a valid crumb survived,
//! report it, then clear so it is attributed exactly once.
//!
//! Two more records say what KIND of crash it was
//! (`heartwood_common::crash_record` has the rules): the panic hook keeps the
//! panic's `file:line`, and ESP-IDF's failed-allocation callback keeps the
//! last failed allocation's size and caps. Both are stamped with the crumb
//! window, a counter every `set` and `clear` bumps, and only records from the
//! final window are reported. Installed by [`install_recorders`].

use core::sync::atomic::{compiler_fence, Ordering};

use heartwood_common::crash_record::{format_panic_site, AllocFailure, PANIC_SITE_CAP};

const MAGIC: u32 = 0x4857_4342; // "HWCB"
const CAP: usize = 48;
const PANIC_MAGIC: u32 = 0x4857_5053; // "HWPS"
const ALLOC_MAGIC: u32 = 0x4857_4146; // "HWAF"

#[repr(C)]
struct Crumb {
    magic: u32,
    len: u32,
    bytes: [u8; CAP],
}

// RTC-slow noinit: preserved across panic/watchdog/software resets, lost on
// power-off. Never read/written except through the accessors below.
#[link_section = ".rtc_noinit"]
static mut CRUMB: Crumb = Crumb {
    magic: 0,
    len: 0,
    bytes: [0; CAP],
};

/// The crumb window: bumped by every `set` and `clear`, so a panic or failed
/// allocation record can say which crumb it happened under.
#[link_section = ".rtc_noinit"]
static mut WINDOW: u32 = 0;

#[repr(C)]
struct PanicRecord {
    magic: u32,
    window: u32,
    len: u32,
    bytes: [u8; PANIC_SITE_CAP],
}

#[link_section = ".rtc_noinit"]
static mut PANIC: PanicRecord = PanicRecord {
    magic: 0,
    window: 0,
    len: 0,
    bytes: [0; PANIC_SITE_CAP],
};

#[repr(C)]
struct AllocRecord {
    magic: u32,
    window: u32,
    bytes: u32,
    caps: u32,
    failures: u32,
}

#[link_section = ".rtc_noinit"]
static mut ALLOC: AllocRecord = AllocRecord {
    magic: 0,
    window: 0,
    bytes: 0,
    caps: 0,
    failures: 0,
};

fn next_window() {
    unsafe {
        let w = core::ptr::read_volatile(core::ptr::addr_of!(WINDOW));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(WINDOW), w.wrapping_add(1));
    }
}

/// Record the operation about to run. Keep `label` short and non-secret — it
/// survives a crash and is shown to the owner (e.g. "sign_event kind 1059").
pub fn set(label: &str) {
    next_window();
    let src = label.as_bytes();
    let n = src.len().min(CAP);
    unsafe {
        // Write payload before the magic so a reset mid-write never presents a
        // valid-magic crumb with stale bytes.
        core::ptr::copy_nonoverlapping(src.as_ptr(), core::ptr::addr_of_mut!(CRUMB.bytes) as *mut u8, n);
        compiler_fence(Ordering::SeqCst);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(CRUMB.len), n as u32);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(CRUMB.magic), MAGIC);
        compiler_fence(Ordering::SeqCst);
    }
}

/// Mark the risky operation as completed cleanly — no crash to attribute.
pub fn clear() {
    next_window();
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(CRUMB.magic), 0);
        compiler_fence(Ordering::SeqCst);
    }
}

/// Take a surviving crumb (valid magic) exactly once, clearing it. Returns the
/// recorded label, or None if there was none (clean boot or already taken).
pub fn take() -> Option<String> {
    unsafe {
        let magic = core::ptr::read_volatile(core::ptr::addr_of!(CRUMB.magic));
        if magic != MAGIC {
            return None;
        }
        let len = core::ptr::read_volatile(core::ptr::addr_of!(CRUMB.len)) as usize;
        core::ptr::write_volatile(core::ptr::addr_of_mut!(CRUMB.magic), 0);
        let n = len.min(CAP);
        let mut out = [0u8; CAP];
        core::ptr::copy_nonoverlapping(core::ptr::addr_of!(CRUMB.bytes) as *const u8, out.as_mut_ptr(), n);
        Some(String::from_utf8_lossy(&out[..n]).into_owned())
    }
}

/// Install the panic hook and the failed-allocation callback that fill the
/// crash-detail records. Call once at boot, after [`take_detail`] or
/// [`discard_detail`] has dealt with the previous boot's records.
pub fn install_recorders() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(loc) = info.location() {
            record_panic(loc.file(), loc.line());
        }
        previous(info);
    }));
    let err = unsafe {
        esp_idf_svc::sys::heap_caps_register_failed_alloc_callback(Some(on_alloc_failed))
    };
    if err != esp_idf_svc::sys::ESP_OK {
        log::warn!("failed-allocation recorder not installed: {err}");
    }
}

/// Panic hook body. No allocation: the heap may be what failed.
fn record_panic(file: &str, line: u32) {
    let mut site = [0u8; PANIC_SITE_CAP];
    let n = format_panic_site(file, line, &mut site);
    unsafe {
        let rec = core::ptr::addr_of_mut!(PANIC);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*rec).magic), 0);
        compiler_fence(Ordering::SeqCst);
        core::ptr::copy_nonoverlapping(site.as_ptr(), core::ptr::addr_of_mut!((*rec).bytes) as *mut u8, n);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*rec).len), n as u32);
        let window = core::ptr::read_volatile(core::ptr::addr_of!(WINDOW));
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*rec).window), window);
        compiler_fence(Ordering::SeqCst);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*rec).magic), PANIC_MAGIC);
    }
}

/// ESP-IDF calls this after any heap allocation fails, before returning NULL.
/// It runs with no heap lock held, possibly from an ISR or with the flash
/// cache off (the heap's own code is in IRAM for that reason), so it lives in
/// IRAM too and only reads and writes RTC memory: no allocation, logging or
/// locks.
#[link_section = ".iram1.hw_alloc_failed"]
unsafe extern "C" fn on_alloc_failed(size: usize, caps: u32, _function: *const core::ffi::c_char) {
    let rec = core::ptr::addr_of_mut!(ALLOC);
    let window = core::ptr::read_volatile(core::ptr::addr_of!(WINDOW));
    let same_window = core::ptr::read_volatile(core::ptr::addr_of!((*rec).magic)) == ALLOC_MAGIC
        && core::ptr::read_volatile(core::ptr::addr_of!((*rec).window)) == window;
    let failures = if same_window {
        core::ptr::read_volatile(core::ptr::addr_of!((*rec).failures)).saturating_add(1)
    } else {
        1
    };
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*rec).magic), 0);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*rec).window), window);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*rec).bytes), size as u32);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*rec).caps), caps);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*rec).failures), failures);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*rec).magic), ALLOC_MAGIC);
}

/// Take the previous boot's panic and failed-allocation records, keeping only
/// those from the final crumb window, and clear both. Call before anything
/// this boot sets or clears the crumb (each bumps the window).
pub fn take_detail() -> (Option<String>, Option<AllocFailure>) {
    unsafe {
        let window = core::ptr::read_volatile(core::ptr::addr_of!(WINDOW));

        let p = core::ptr::addr_of_mut!(PANIC);
        let panic_site = if core::ptr::read_volatile(core::ptr::addr_of!((*p).magic)) == PANIC_MAGIC
            && core::ptr::read_volatile(core::ptr::addr_of!((*p).window)) == window
        {
            let n = (core::ptr::read_volatile(core::ptr::addr_of!((*p).len)) as usize).min(PANIC_SITE_CAP);
            let mut out = [0u8; PANIC_SITE_CAP];
            core::ptr::copy_nonoverlapping(core::ptr::addr_of!((*p).bytes) as *const u8, out.as_mut_ptr(), n);
            Some(String::from_utf8_lossy(&out[..n]).into_owned())
        } else {
            None
        };

        let a = core::ptr::addr_of_mut!(ALLOC);
        let alloc = if core::ptr::read_volatile(core::ptr::addr_of!((*a).magic)) == ALLOC_MAGIC
            && core::ptr::read_volatile(core::ptr::addr_of!((*a).window)) == window
        {
            Some(AllocFailure {
                bytes: core::ptr::read_volatile(core::ptr::addr_of!((*a).bytes)),
                caps: core::ptr::read_volatile(core::ptr::addr_of!((*a).caps)),
                failures: core::ptr::read_volatile(core::ptr::addr_of!((*a).failures)),
            })
        } else {
            None
        };

        discard_detail();
        (panic_site, alloc)
    }
}

/// Forget any panic or failed-allocation record: after a reset that was not
/// a crash, or once a crash's records have been taken.
pub fn discard_detail() {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(PANIC.magic), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(ALLOC.magic), 0);
        compiler_fence(Ordering::SeqCst);
    }
}
