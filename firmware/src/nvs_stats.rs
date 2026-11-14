// firmware/src/nvs_stats.rs
//
// NVS entry-table statistics for the storage gauge and the persona add gate.
// ESP-IDF charges one 32-byte entry per key plus one per 32 bytes of blob
// data; `nvs_get_stats` reports the default partition's totals across all
// namespaces, which is exactly what the gauge should show — personas, policy,
// network config and the rest all share the same pool.

use core::ptr;

use esp_idf_svc::sys;
use heartwood_common::nvs_diag::{entry_hash, DupCounter};

/// Snapshot of the default NVS partition's entry table.
#[derive(Clone, Copy, Debug)]
pub struct NvsStats {
    pub used_entries: usize,
    pub free_entries: usize,
    pub total_entries: usize,
    pub namespace_count: usize,
}

/// Entries held back so policy writes (an app pairing mid-connect writes a
/// connslot plus a policy blob, each with a copy-on-write shadow) never hit
/// the wall: persona creation refuses first. 128 entries is 4 KB of table.
pub const RESERVED_POLICY_ENTRIES: usize = 128;

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
        total_entries: stats.total_entries as usize,
        namespace_count: stats.namespace_count as usize,
    })
}

/// Whether a persona write still leaves the reserved policy headroom. Fails
/// open on a stats API error: the write itself will still error cleanly if
/// the partition is genuinely full, and a transient stats failure must not
/// brick persona creation.
pub fn persona_write_allowed() -> bool {
    match read() {
        Some(stats) => stats.free_entries > RESERVED_POLICY_ENTRIES,
        None => true,
    }
}

/// Namespaces whose used entries are reported one by one: the firmware's own
/// three (`nvs.rs` and `main.rs` "heartwood", `notes.rs` NAMESPACE and
/// IDENTITY_NAMESPACE) plus the two ESP-IDF writers that share the default
/// partition (PHY calibration, `phy`; the Wi-Fi driver's, `nvs.net80211`,
/// which this firmware leaves unused). The allocation journal's namespace is
/// derived per root and must not be named on the wire, so it is not here.
pub const DIAG_NAMESPACES: [&str; 5] = ["heartwood", "hw_notes", "hw_device", "phy", "nvs.net80211"];

/// Read-only diagnostics that say which namespace a used-entry swing belongs
/// to. Counts only: no key names, namespace contents or values.
#[derive(Clone, Copy, Debug)]
pub struct NvsDiag {
    /// Used entries per [`DIAG_NAMESPACES`] name, in order. A namespace that
    /// does not exist is 0 (opening read-only never creates one); `None` is
    /// an API failure.
    pub ns_used: [Option<usize>; DIAG_NAMESPACES.len()],
    /// (namespace, key) pairs the entry iterator returned more than once
    /// across the whole partition, `None` when the walk could not finish.
    pub dup_blob_keys: Option<usize>,
}

impl NvsDiag {
    /// `ns_used` as a JSON object keyed by namespace name.
    pub fn ns_used_value(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for (name, used) in DIAG_NAMESPACES.iter().zip(self.ns_used) {
            map.insert((*name).into(), used.into());
        }
        serde_json::Value::Object(map)
    }
}

/// Closes a read-only namespace handle on every path.
struct ReadOnlyHandle(sys::nvs_handle_t);
impl Drop for ReadOnlyHandle {
    fn drop(&mut self) {
        unsafe { sys::nvs_close(self.0) };
    }
}

/// Releases the iterator pointer `nvs_entry_next` mutates (it frees and nulls
/// it at the end of the walk; `nvs_release_iterator(NULL)` is allowed).
struct EntryIter(sys::nvs_iterator_t);
impl Drop for EntryIter {
    fn drop(&mut self) {
        unsafe { sys::nvs_release_iterator(self.0) };
    }
}

fn ns_used_entries(name: &str) -> Option<usize> {
    let bytes = name.as_bytes();
    let mut buf = [0u8; 16];
    if bytes.len() >= buf.len() {
        return None;
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    let mut raw: sys::nvs_handle_t = 0;
    // READONLY never creates a namespace: a missing one is NOT_FOUND.
    let err = unsafe {
        sys::nvs_open(buf.as_ptr().cast(), sys::nvs_open_mode_t_NVS_READONLY, &mut raw)
    };
    if err == sys::ESP_ERR_NVS_NOT_FOUND {
        return Some(0);
    }
    if err != sys::ESP_OK {
        return None;
    }
    let handle = ReadOnlyHandle(raw);
    let mut used = 0usize;
    let err = unsafe { sys::nvs_get_used_entry_count(handle.0, &mut used) };
    (err == sys::ESP_OK).then_some(used)
}

/// Copy a NUL-terminated entry-info name into a fixed buffer, returning it
/// and its length.
fn name_bytes(raw: &[core::ffi::c_char; 16]) -> ([u8; 16], usize) {
    let mut out = [0u8; 16];
    let mut len = 0;
    for (dst, &c) in out.iter_mut().zip(raw) {
        if c == 0 {
            break;
        }
        *dst = c as u8;
        len += 1;
    }
    (out, len)
}

/// One walk of the default partition, counting (namespace, key) pairs the
/// iterator returns more than once. The iterator skips blob index entries and
/// later chunks, so a blob is returned once per first chunk; a repeat means
/// two first chunks for one key (see `heartwood_common::nvs_diag`). Bounded by
/// `total_entries` visits and one fixed hash buffer; `None` past either.
fn dup_blob_keys(total_entries: usize) -> Option<usize> {
    let mut counter = DupCounter::new()?;
    let mut it = EntryIter(ptr::null_mut());
    let err = unsafe {
        sys::nvs_entry_find(
            b"nvs\0".as_ptr().cast(),
            ptr::null(),
            sys::nvs_type_t_NVS_TYPE_ANY,
            &mut it.0,
        )
    };
    if err == sys::ESP_ERR_NVS_NOT_FOUND {
        return Some(0);
    }
    if err != sys::ESP_OK || it.0.is_null() {
        return None;
    }
    let mut visited = 0usize;
    loop {
        visited += 1;
        if visited > total_entries {
            return None;
        }
        let mut info = sys::nvs_entry_info_t::default();
        if unsafe { sys::nvs_entry_info(it.0, &mut info) } != sys::ESP_OK {
            return None;
        }
        if info.type_ == sys::nvs_type_t_NVS_TYPE_BLOB {
            let (ns, ns_len) = name_bytes(&info.namespace_name);
            let (key, key_len) = name_bytes(&info.key);
            counter.push(entry_hash(&ns[..ns_len], &key[..key_len]));
        }
        info.key = [0; 16];
        let next = unsafe { sys::nvs_entry_next(&mut it.0) };
        if next == sys::ESP_ERR_NVS_NOT_FOUND {
            break;
        }
        if next != sys::ESP_OK {
            return None;
        }
    }
    counter.finish()
}

/// Read the diagnostics. Each field degrades to `None` on its own failure.
pub fn read_diag(total_entries: usize) -> NvsDiag {
    let mut ns_used = [None; DIAG_NAMESPACES.len()];
    for (slot, name) in ns_used.iter_mut().zip(DIAG_NAMESPACES) {
        *slot = ns_used_entries(name);
    }
    NvsDiag { ns_used, dup_blob_keys: dup_blob_keys(total_entries) }
}

/// Stats as a JSON object for FIRMWARE_INFO and the relay `get_status` reply.
/// `null` when the API fails, so consumers can distinguish "unknown" from a
/// healthy zero. `ns_used` and `dup_blob_keys` (see [`NvsDiag`]) are added
/// after the literal, as `get_status` does for its other late additions.
pub fn as_json() -> serde_json::Value {
    match read() {
        Some(stats) => {
            let mut v = serde_json::json!({
                "used_entries": stats.used_entries,
                "free_entries": stats.free_entries,
                "total_entries": stats.total_entries,
                "namespace_count": stats.namespace_count,
            });
            let diag = read_diag(stats.total_entries);
            v["ns_used"] = diag.ns_used_value();
            v["dup_blob_keys"] = diag.dup_blob_keys.into();
            v
        }
        None => serde_json::Value::Null,
    }
}
