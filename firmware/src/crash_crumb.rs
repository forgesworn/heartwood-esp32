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

use core::sync::atomic::{compiler_fence, Ordering};

const MAGIC: u32 = 0x4857_4342; // "HWCB"
const CAP: usize = 48;

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

/// Record the operation about to run. Keep `label` short and non-secret — it
/// survives a crash and is shown to the owner (e.g. "sign_event kind 1059").
pub fn set(label: &str) {
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
