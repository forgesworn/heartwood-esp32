// firmware/src/nvs_stats.rs
//
// NVS entry-table statistics for the storage gauge and the persona add gate.
// ESP-IDF charges one 32-byte entry per key plus one per 32 bytes of blob
// data; `nvs_get_stats` reports the default partition's totals across all
// namespaces, which is exactly what the gauge should show — personas, policy,
// network config and the rest all share the same pool.

use esp_idf_svc::sys;

/// Snapshot of the default NVS partition's entry table.
#[derive(Clone, Copy, Debug)]
pub struct NvsStats {
    pub used_entries: usize,
    /// Includes the page NVS keeps back for garbage collection.
    pub free_entries: usize,
    /// Free entries a write can actually use: `free_entries` less that page.
    pub available_entries: usize,
    pub total_entries: usize,
    pub namespace_count: usize,
}

/// Read the default partition's stats. `None` on API failure.
pub fn read() -> Option<NvsStats> {
    let mut stats = sys::nvs_stats_t::default();
    let err = unsafe { sys::nvs_get_stats(b"nvs\0".as_ptr().cast(), &mut stats) };
    if err != sys::ESP_OK {
        log::warn!("nvs_get_stats failed: {err}");
        return None;
    }
    Some(NvsStats {
        used_entries: stats.used_entries as usize,
        free_entries: stats.free_entries as usize,
        available_entries: stats.available_entries as usize,
        total_entries: stats.total_entries as usize,
        namespace_count: stats.namespace_count as usize,
    })
}

/// Stats as a JSON object for FIRMWARE_INFO and the relay `get_status` reply.
/// `null` when the API fails, so consumers can distinguish "unknown" from a
/// healthy zero.
pub fn as_json() -> serde_json::Value {
    match read() {
        Some(stats) => serde_json::json!({
            "used_entries": stats.used_entries,
            "free_entries": stats.free_entries,
            "total_entries": stats.total_entries,
            "namespace_count": stats.namespace_count,
        }),
        None => serde_json::Value::Null,
    }
}
