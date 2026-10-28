//! Only SDK boundaries are mocked; tests run the real dormant owner/collector.
#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]
pub(crate) use crate::allocation_nvs_host_sys::{
    nvs_close, nvs_handle_t, nvs_open_mode_t_NVS_READONLY, ESP_ERR_NVS_NOT_FOUND, ESP_OK,
};
use std::{
    cell::RefCell,
    ffi::{c_char, c_void, CStr},
    ptr,
};
pub(crate) const esp_partition_type_t_ESP_PARTITION_TYPE_ANY: u32 = 255;
pub(crate) const esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY: u32 = 255;
pub(crate) const esp_partition_type_t_ESP_PARTITION_TYPE_DATA: u32 = 1;
pub(crate) const esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_DATA_NVS: u32 = 2;
pub(crate) struct esp_flash_t;
pub(crate) const esp_flash_default_chip: *mut esp_flash_t = ptr::dangling_mut();
#[derive(Clone)]
pub(crate) struct esp_partition_t {
    pub flash_chip: *mut esp_flash_t,
    pub type_: u32,
    pub subtype: u32,
    pub address: u32,
    pub size: u32,
    pub erase_size: u32,
    pub label: [c_char; 17],
    pub encrypted: bool,
    pub readonly: bool,
}
pub(crate) type esp_partition_iterator_t = *mut PartIter;
pub(crate) struct PartIter {
    index: usize,
}
#[derive(Clone, Copy)]
pub(crate) enum Mutation {
    Table,
    Physical,
    Addressable,
    Descriptor,
    None,
}
pub(crate) struct Hook {
    pub op: &'static str,
    pub nth: usize,
    pub mutation: Mutation,
}
pub(crate) struct Fault {
    pub op: &'static str,
    pub nth: usize,
    pub error: i32,
}
pub(crate) struct State {
    pub table: Vec<u8>,
    pub physical: u32,
    pub addressable: u32,
    pub descriptors: Vec<Box<esp_partition_t>>,
    pub calls: Vec<&'static str>,
    pub live_iterators: usize,
    pub fault: Option<Fault>,
    pub hook: Option<Hook>,
    pub close_checks: usize,
    pub open_error_handle: Option<i32>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State {
    table:vec![],physical:0,addressable:0,descriptors:vec![],calls:vec![],
    live_iterators:0,fault:None,hook:None,close_checks:0,open_error_handle:None
}); }
pub(crate) fn reset(table: Vec<u8>, physical: u32, addressable: u32, offset: u32) {
    let mut label = [0; 17];
    for (x, b) in label.iter_mut().zip(b"hwalloc") {
        *x = *b as c_char;
    }
    STATE.with(|state| {
        assert_eq!(state.borrow().live_iterators, 0);
        *state.borrow_mut() = State {
            table,
            physical,
            addressable,
            descriptors: vec![Box::new(esp_partition_t {
                flash_chip: esp_flash_default_chip,
                type_: 1,
                subtype: 2,
                address: offset,
                size: 0x40000,
                erase_size: 4096,
                label,
                encrypted: false,
                readonly: false,
            })],
            calls: vec![],
            live_iterators: 0,
            fault: None,
            hook: None,
            close_checks: 0,
            open_error_handle: None,
        };
    });
}
pub(crate) fn change(f: impl FnOnce(&mut State)) {
    STATE.with(|s| f(&mut s.borrow_mut()));
}
pub(crate) fn checked<T>(f: impl FnOnce(&State) -> T) -> T {
    STATE.with(|s| f(&s.borrow()))
}
fn call(s: &mut State, op: &'static str) -> i32 {
    s.calls.push(op);
    let counts = |target: &str| {
        if let Some(nvs) = target.strip_prefix("nvs:") {
            crate::allocation_nvs_host_sys::checked(|s| {
                s.calls.iter().filter(|&&x| x == nvs).count()
            })
        } else {
            s.calls.iter().filter(|&&x| x == target).count()
        }
    };
    let should = s.hook.as_ref().is_some_and(|h| counts(h.op) >= h.nth);
    if should {
        match s.hook.take().unwrap().mutation {
            Mutation::Table => s.table[4095] ^= 1,
            Mutation::Physical => s.physical /= 2,
            Mutation::Addressable => s.addressable /= 2,
            Mutation::Descriptor => s.descriptors[0].address ^= 4096,
            Mutation::None => {}
        }
    }
    if op == "physical"
        && crate::allocation_nvs_host_sys::checked(|n| n.calls.last() == Some(&"close"))
    {
        crate::allocation_nvs_host_sys::checked(|n| {
            assert_eq!(n.live_handles, 0);
            assert_eq!(n.live_iterators, 0);
        });
        assert_eq!(s.live_iterators, 0);
        s.close_checks += 1;
    }
    s.fault
        .as_ref()
        .filter(|f| f.op == op && s.calls.iter().filter(|&&x| x == op).count() == f.nth)
        .map_or(ESP_OK, |f| f.error)
}
pub(crate) unsafe fn esp_flash_get_physical_size(chip: *mut esp_flash_t, out: *mut u32) -> i32 {
    assert_eq!(chip, esp_flash_default_chip);
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let err = call(&mut s, "physical");
        *out = s.physical;
        err
    })
}
pub(crate) unsafe fn esp_flash_get_size(chip: *mut esp_flash_t, out: *mut u32) -> i32 {
    assert_eq!(chip, esp_flash_default_chip);
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let err = call(&mut s, "addressable");
        *out = s.addressable;
        err
    })
}
pub(crate) unsafe fn esp_flash_read(
    chip: *mut esp_flash_t,
    out: *mut c_void,
    address: u32,
    length: u32,
) -> i32 {
    assert_eq!(chip, esp_flash_default_chip);
    assert_eq!(length, 256);
    assert!(address >= 0x8000 && address + length <= 0x9000);
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let err = call(&mut s, "flash-read");
        if err == ESP_OK {
            ptr::copy_nonoverlapping(
                s.table.as_ptr().add((address - 0x8000) as usize),
                out.cast(),
                length as usize,
            );
        }
        err
    })
}
pub(crate) unsafe fn esp_partition_find(
    ty: u32,
    sub: u32,
    label: *const c_char,
) -> esp_partition_iterator_t {
    assert_eq!((ty, sub), (255, 255));
    assert_eq!(CStr::from_ptr(label).to_bytes(), b"hwalloc");
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        call(&mut s, "part-find");
        if s.descriptors.is_empty() {
            ptr::null_mut()
        } else {
            s.live_iterators += 1;
            Box::into_raw(Box::new(PartIter { index: 0 }))
        }
    })
}
pub(crate) unsafe fn esp_partition_get(it: esp_partition_iterator_t) -> *const esp_partition_t {
    assert!(!it.is_null());
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        if call(&mut s, "part-get") != ESP_OK {
            return ptr::null();
        }
        &*s.descriptors[(*it).index]
    })
}
pub(crate) unsafe fn esp_partition_next(it: esp_partition_iterator_t) -> esp_partition_iterator_t {
    assert!(!it.is_null());
    let next = (*it).index + 1;
    drop(Box::from_raw(it));
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        call(&mut s, "part-next");
        if next == s.descriptors.len() {
            s.live_iterators -= 1;
            ptr::null_mut()
        } else {
            Box::into_raw(Box::new(PartIter { index: next }))
        }
    })
}
pub(crate) unsafe fn esp_partition_iterator_release(it: esp_partition_iterator_t) {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        call(&mut s, "part-release");
        if !it.is_null() {
            drop(Box::from_raw(it));
            s.live_iterators -= 1;
        }
    });
}
pub(crate) unsafe fn nvs_flash_init_partition_ptr(p: *const esp_partition_t) -> i32 {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        assert_eq!(p, &*s.descriptors[0] as *const _);
        call(&mut s, "init")
    })
}
pub(crate) unsafe fn nvs_open_from_partition(
    part: *const c_char,
    name: *const c_char,
    mode: u32,
    out: *mut nvs_handle_t,
) -> i32 {
    assert_eq!(CStr::from_ptr(part).to_bytes(), b"hwalloc");
    assert_eq!(mode, nvs_open_mode_t_NVS_READONLY);
    let override_err = STATE.with(|s| {
        let mut s = s.borrow_mut();
        let err = call(&mut s, "custom-open");
        if err != ESP_OK {
            Some((err, false))
        } else {
            s.open_error_handle.map(|e| (e, true))
        }
    });
    if let Some((err, nonzero)) = override_err {
        if nonzero {
            assert_eq!(
                crate::allocation_nvs_host_sys::nvs_open(name, mode, out),
                ESP_OK
            );
        }
        return err;
    }
    crate::allocation_nvs_host_sys::nvs_open(name, mode, out)
}
