//! Raw partition boundary mock for the real firmware persistent wipe adapter.
#![allow(non_camel_case_types, non_upper_case_globals)]
use std::{
    cell::RefCell,
    ffi::{c_char, c_void, CStr},
};

pub(crate) type esp_err_t = i32;
pub(crate) const ESP_OK: esp_err_t = 0;
pub(crate) const esp_partition_type_t_ESP_PARTITION_TYPE_DATA: u32 = 1;
pub(crate) const esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY: u32 = 255;
pub(crate) const esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_DATA_NVS: u32 = 2;

pub(crate) struct esp_partition_t {
    pub size: u32,
    kind: u32,
    subtype: u32,
    label: &'static str,
    id: usize,
}
struct Partition {
    // Stable address: the adapter retains this pointer between SDK calls.
    header: Box<esp_partition_t>,
    bytes: Vec<u8>,
}
#[derive(Clone, Copy)]
enum Fault {
    Erase(usize),
    Read(usize),
    NotBlank(usize),
}
#[derive(Default)]
struct State {
    partitions: Vec<Partition>,
    calls: Vec<(String, usize, usize)>,
    erases: usize,
    reads: usize,
    fault: Option<Fault>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }

pub(crate) unsafe fn esp_partition_find_first(
    kind: u32,
    subtype: u32,
    label: *const c_char,
) -> *const esp_partition_t {
    let label = if label.is_null() {
        None
    } else {
        Some(CStr::from_ptr(label).to_str().expect("valid adapter label"))
    };
    STATE.with(|state| {
        let state = state.borrow();
        state
            .partitions
            .iter()
            .find(|p| {
                p.header.kind == kind
                    && (subtype == esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY
                        || p.header.subtype == subtype)
                    && label.is_none_or(|name| p.header.label == name)
            })
            .map(|p| p.header.as_ref() as *const esp_partition_t)
            .unwrap_or(std::ptr::null())
    })
}

pub(crate) unsafe fn esp_partition_erase_range(
    partition: *const esp_partition_t,
    offset: usize,
    size: usize,
) -> esp_err_t {
    let id = (*partition).id;
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.erases += 1;
        let nth = state.erases;
        let label = state.partitions[id].header.label;
        state.calls.push((format!("erase:{label}"), offset, size));
        let fault = state.fault;
        let bytes = &mut state.partitions[id].bytes;
        assert!(offset <= bytes.len() && size <= bytes.len() - offset);
        if matches!(fault, Some(Fault::Erase(n)) if n == nth) {
            // A failed physical erase need not leave the target unchanged.
            bytes[offset..offset + size / 2].fill(0xff);
            return -7;
        }
        bytes[offset..offset + size].fill(0xff);
        if matches!(fault, Some(Fault::NotBlank(n)) if n == nth) && size > 0 {
            bytes[offset + size - 1] = 0;
        }
        ESP_OK
    })
}

pub(crate) unsafe fn esp_partition_read_raw(
    partition: *const esp_partition_t,
    offset: usize,
    out: *mut c_void,
    size: usize,
) -> esp_err_t {
    let id = (*partition).id;
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.reads += 1;
        let nth = state.reads;
        let label = state.partitions[id].header.label;
        state.calls.push((format!("read:{label}"), offset, size));
        if matches!(state.fault, Some(Fault::Read(n)) if n == nth) {
            return -8;
        }
        let bytes = &state.partitions[id].bytes;
        assert!(offset <= bytes.len() && size <= bytes.len() - offset);
        assert!(!out.is_null());
        std::ptr::copy_nonoverlapping(bytes.as_ptr().add(offset), out.cast(), size);
        ESP_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{firmware_persistent_wipe as wipe, persistent_state::PersistentRegion};

    fn setup(entries: &[(&'static str, u32, u32, usize)], fault: Option<Fault>) {
        STATE.with(|state| {
            *state.borrow_mut() = State {
                partitions: entries
                    .iter()
                    .enumerate()
                    .map(|(id, &(label, kind, subtype, size))| Partition {
                        header: Box::new(esp_partition_t {
                            size: size.try_into().unwrap(),
                            kind,
                            subtype,
                            label,
                            id,
                        }),
                        bytes: vec![0xa5; size],
                    })
                    .collect(),
                fault,
                ..State::default()
            };
        });
    }
    fn standard(fault: Option<Fault>) {
        // The second NVS comes first in the table; default NVS is deliberately
        // not selected by subtype order. Lengths span full and partial chunks.
        setup(
            &[
                ("hwalloc", 1, 2, 768),
                ("nvs", 1, 2, 600),
                ("config", 1, 0x40, 515),
            ],
            fault,
        );
    }
    fn erased() -> Vec<String> {
        STATE.with(|state| {
            state
                .borrow()
                .calls
                .iter()
                .filter(|(name, _, _)| name.starts_with("erase:"))
                .map(|(name, _, _)| name.clone())
                .collect()
        })
    }
    fn assert_other_partition_intact() {
        STATE.with(|state| {
            let state = state.borrow();
            assert!(state.partitions[0].bytes.iter().all(|&b| b == 0xa5));
            assert!(!state.calls.iter().any(|(n, _, _)| n.ends_with("hwalloc")));
        });
    }

    #[test]
    fn real_adapter_erases_named_default_after_config_despite_secondary_nvs_first() {
        standard(None);
        assert_eq!(wipe::erase_all(), Ok(()));
        assert_eq!(erased(), ["erase:config", "erase:nvs"]);
        assert_other_partition_intact();
        STATE.with(|state| {
            let state = state.borrow();
            assert!(state.partitions[1..]
                .iter()
                .all(|p| p.bytes.iter().all(|&b| b == 0xff)));
            let reads: Vec<_> = state
                .calls
                .iter()
                .filter(|(name, _, _)| name.starts_with("read:"))
                .map(|(n, off, len)| (n.as_str(), *off, *len))
                .collect();
            assert_eq!(
                reads,
                [
                    ("read:config", 0, 256),
                    ("read:config", 256, 256),
                    ("read:config", 512, 3),
                    ("read:nvs", 0, 256),
                    ("read:nvs", 256, 256),
                    ("read:nvs", 512, 88),
                ]
            );
        });
    }

    #[test]
    fn missing_default_never_substitutes_another_nvs_partition() {
        setup(&[("hwalloc", 1, 2, 768), ("config", 1, 0x40, 515)], None);
        assert_eq!(
            wipe::erase_all(),
            Err(wipe::WipeError::PartitionMissing(PersistentRegion::Nvs))
        );
        assert_eq!(erased(), ["erase:config"]);
        assert_other_partition_intact();
    }

    #[test]
    fn wrong_type_or_subtype_under_default_label_is_missing() {
        for (kind, subtype) in [(0, 2), (1, 0x40)] {
            setup(&[("hwalloc", 1, 2, 768), ("nvs", kind, subtype, 600)], None);
            assert_eq!(
                wipe::erase_all(),
                Err(wipe::WipeError::PartitionMissing(PersistentRegion::Nvs))
            );
            assert!(erased().is_empty());
            assert_other_partition_intact();
        }
    }

    #[test]
    fn legacy_no_config_erases_only_named_default() {
        setup(&[("hwalloc", 1, 2, 768), ("nvs", 1, 2, 600)], None);
        assert_eq!(wipe::erase_all(), Ok(()));
        assert_eq!(erased(), ["erase:nvs"]);
        assert_other_partition_intact();
    }

    #[test]
    fn partial_erase_failures_never_report_success_or_erase_later_regions() {
        for (nth, region) in [
            (1, PersistentRegion::FlashConfig),
            (2, PersistentRegion::Nvs),
        ] {
            standard(Some(Fault::Erase(nth)));
            assert_eq!(
                wipe::erase_all(),
                Err(wipe::WipeError::Erase { region, code: -7 })
            );
            assert_eq!(erased().len(), nth);
            assert_other_partition_intact();
        }
    }

    #[test]
    fn every_verify_read_failure_holds_before_any_later_region() {
        for nth in 1..=6 {
            standard(Some(Fault::Read(nth)));
            let region = if nth <= 3 {
                PersistentRegion::FlashConfig
            } else {
                PersistentRegion::Nvs
            };
            assert_eq!(
                wipe::erase_all(),
                Err(wipe::WipeError::VerifyRead { region, code: -8 })
            );
            assert_eq!(erased().len(), if nth <= 3 { 1 } else { 2 });
            assert_other_partition_intact();
        }
    }

    #[test]
    fn final_byte_of_each_region_is_verified_and_nonblank_holds() {
        for (nth, region) in [
            (1, PersistentRegion::FlashConfig),
            (2, PersistentRegion::Nvs),
        ] {
            standard(Some(Fault::NotBlank(nth)));
            assert_eq!(
                wipe::erase_all(),
                Err(wipe::WipeError::VerifyNotBlank(region))
            );
            assert_eq!(erased().len(), nth);
            assert_other_partition_intact();
        }
    }

    #[test]
    fn retry_repeats_complete_order_and_never_touches_secondary_nvs() {
        standard(Some(Fault::Erase(2)));
        assert!(wipe::erase_all().is_err());
        STATE.with(|state| state.borrow_mut().fault = None);
        assert_eq!(wipe::erase_all(), Ok(()));
        assert_eq!(
            erased(),
            ["erase:config", "erase:nvs", "erase:config", "erase:nvs"]
        );
        assert_other_partition_intact();
    }
}
