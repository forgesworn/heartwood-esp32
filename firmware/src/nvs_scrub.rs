// firmware/src/nvs_scrub.rs
//
// Zero, in place, every NVS entry ESP-IDF has deleted but not yet erased, so
// a flash dump no longer holds a revoked phone's record, a plaintext seed
// written before sealing, or a replaced wrapper. The decisions (which pages
// parse, which entries are safe to touch, the recheck before each write) are
// `heartwood_common::nvs_scrub`, host-tested; this is only the flash glue.
//
// Runs at boot, straight after a phone revoke, a pairing revoke or an
// identity removal, and after every at-rest encryption change (PIN or vault
// key set, changed or cleared, a seed migration, the note locker's sealing).
//
// Concurrency: the scrub bypasses NVS's own lock, so nothing may write NVS
// while it runs. Every firmware NVS write happens on the main task (the relay
// loop runs there, and the only other thread, the button sampler, never
// touches NVS), and so does every call here. WiFi is created with no NVS
// partition (`EspWifi::new(.., None)`), so its driver keeps nothing there.
// The one ESP-IDF writer left is PHY calibration, which stores to the `phy`
// namespace inside the first `esp_phy_enable` of a boot (esp_phy
// phy_init.c:252-254, :865-880), reached from the WiFi driver while WiFi
// starts. Boot runs the scrub before any WiFi exists; every later call comes
// from the main task after `BlockingWifi::start` has returned, and the
// common module still re-reads the page header and bitmap before each write
// and stops on a page that changed.

use core::ffi::{c_char, c_void};
use std::sync::Mutex;

use esp_idf_svc::sys;
use heartwood_common::nvs_scrub::{self, Flash, ScrubReport, PAGE_SIZE};

/// The last pass this boot, for FIRMWARE_INFO.
static LAST: Mutex<Option<ScrubReport>> = Mutex::new(None);

/// The default NVS partition, as `nvs_flash_init` finds it.
struct NvsPartition(*const sys::esp_partition_t);

impl Flash for NvsPartition {
    type Error = sys::esp_err_t;

    fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), sys::esp_err_t> {
        let rc = unsafe {
            sys::esp_partition_read(self.0, offset, buf.as_mut_ptr() as *mut c_void, buf.len())
        };
        if rc == sys::ESP_OK { Ok(()) } else { Err(rc) }
    }

    // `esp_partition_write` on an unencrypted partition is `esp_flash_write`
    // (esp_partition/partition_target.c:77-78): a page program with no erase,
    // so it can only clear bits. A 32-byte write at a 32-byte-aligned offset
    // is one program of exactly those bytes (spi_flash_chip_generic.c:279-300,
    // memspi_host_driver.c:209-231).
    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), sys::esp_err_t> {
        let rc = unsafe {
            sys::esp_partition_write(self.0, offset, data.as_ptr() as *const c_void, data.len())
        };
        if rc == sys::ESP_OK { Ok(()) } else { Err(rc) }
    }
}

/// One pass over the NVS partition. Call from the main task only (see the
/// module notes). Never fails: what it could not do is in the report.
pub fn run(reason: &str) -> ScrubReport {
    let report = pass();
    if report.complete() {
        log::info!(
            "[nvs-scrub] {reason}: {} zeroed, {} already clean",
            report.zeroed,
            report.already_clean
        );
    } else {
        log::warn!(
            "[nvs-scrub] {reason}: {} zeroed, {} already clean, {} left, {} page(s) skipped, {} failed",
            report.zeroed,
            report.already_clean,
            report.left,
            report.pages_skipped,
            report.failed
        );
    }
    *LAST.lock().unwrap_or_else(|e| e.into_inner()) = Some(report);
    report
}

/// The last pass this boot. Boot always runs one.
pub fn last() -> Option<ScrubReport> {
    *LAST.lock().unwrap_or_else(|e| e.into_inner())
}

fn pass() -> ScrubReport {
    let label = b"nvs\0";
    let partition = unsafe {
        sys::esp_partition_find_first(
            sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
            sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_DATA_NVS,
            label.as_ptr() as *const c_char,
        )
    };
    if partition.is_null() {
        return ScrubReport::not_run(1);
    }
    let size = unsafe { (*partition).size as usize };
    // One sector's buffer on the heap, not the stack; a failed allocation is
    // reported, never an abort.
    let mut page: Vec<u8> = Vec::new();
    if page.try_reserve_exact(PAGE_SIZE).is_err() {
        return ScrubReport::not_run((size / PAGE_SIZE) as u32);
    }
    page.resize(PAGE_SIZE, 0);
    crate::wdt::feed();
    nvs_scrub::scrub(&mut NvsPartition(partition), size, &mut page)
}
