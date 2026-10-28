//! Raw NVS boundary mock. Tests compile and execute the real firmware adapter.
#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]
use std::{
    cell::RefCell,
    ffi::{c_char, c_void, CStr},
};
pub(crate) const ESP_OK: i32 = 0;
pub(crate) const ESP_ERR_NVS_NOT_FOUND: i32 = 0x1102;
pub(crate) const ESP_ERR_INVALID_ARG: i32 = 0x102;
pub(crate) const nvs_open_mode_t_NVS_READONLY: u32 = 0;
pub(crate) const nvs_open_mode_t_NVS_READWRITE: u32 = 1;
#[derive(Clone, Copy)]
pub(crate) enum WriteEffect {
    Old,
    New,
    Missing,
    Corrupt,
}
pub(crate) const nvs_type_t_NVS_TYPE_ANY: u32 = 255;
pub(crate) const nvs_type_t_NVS_TYPE_BLOB: u32 = 0x42;
pub(crate) type nvs_handle_t = u32;
pub(crate) type nvs_iterator_t = *mut Iter;
pub(crate) struct Iter {
    index: usize,
    pass: usize,
}
#[derive(Default, Clone)]
pub(crate) struct nvs_entry_info_t {
    pub namespace_name: [c_char; 16],
    pub key: [c_char; 16],
    pub type_: u32,
}
#[derive(Clone)]
pub(crate) struct Entry {
    pub info: nvs_entry_info_t,
    pub bytes: Vec<u8>,
}
pub(crate) fn entry(namespace: &str, key: &str, bytes: Vec<u8>) -> Entry {
    let mut info = nvs_entry_info_t {
        type_: nvs_type_t_NVS_TYPE_BLOB,
        ..Default::default()
    };
    for (a, &b) in info.namespace_name.iter_mut().zip(namespace.as_bytes()) {
        *a = b as c_char;
    }
    for (a, &b) in info.key.iter_mut().zip(key.as_bytes()) {
        *a = b as c_char;
    }
    Entry { info, bytes }
}
#[derive(Clone)]
pub(crate) struct Fault {
    pub op: &'static str,
    pub nth: usize,
    pub err: i32,
    pub null: bool,
    pub length: Option<usize>,
}
pub(crate) struct State {
    pub namespace: String,
    pub writable: bool,
    pub mode: Option<u32>,
    pub write_effect: WriteEffect,
    pub mutations: Vec<String>,
    pub passes: Vec<Vec<Entry>>,
    pub fault: Option<Fault>,
    pub calls: Vec<&'static str>,
    pub finds: usize,
    pub active_pass: usize,
    pub live_handles: usize,
    pub live_iterators: usize,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State {namespace:String::new(),writable:false,mode:None,write_effect:WriteEffect::Old,mutations:vec![],passes:vec![],fault:None,calls:vec![],finds:0,active_pass:0,live_handles:0,live_iterators:0});}
pub(crate) fn reset(namespace: String, passes: Vec<Vec<Entry>>, fault: Option<Fault>) {
    STATE.with(|s| {
        assert_eq!(s.borrow().live_handles, 0);
        assert_eq!(s.borrow().live_iterators, 0);
        *s.borrow_mut() = State {
            namespace,
            writable: false,
            mode: None,
            write_effect: WriteEffect::Old,
            mutations: vec![],
            passes,
            fault,
            calls: vec![],
            finds: 0,
            active_pass: 0,
            live_handles: 0,
            live_iterators: 0,
        };
    });
}
pub(crate) fn checked<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|s| f(&s.borrow()))
}
fn call(s: &mut State, op: &'static str) -> Option<Fault> {
    s.calls.push(op);
    s.fault
        .as_ref()
        .filter(|f| f.op == op && s.calls.iter().filter(|&&x| x == op).count() == f.nth)
        .cloned()
}
pub(crate) unsafe fn nvs_open(name: *const c_char, mode: u32, out: *mut u32) -> i32 {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        assert!(
            mode == nvs_open_mode_t_NVS_READONLY
                || (s.writable && mode == nvs_open_mode_t_NVS_READWRITE)
        );
        assert_eq!(s.live_handles, 0);
        assert_eq!(CStr::from_ptr(name).to_str().unwrap(), s.namespace);
        if let Some(f) = call(&mut s, "open") {
            if f.err == ESP_OK && !f.null {
                *out = 1;
                s.live_handles += 1;
                s.mode = Some(mode);
            }
            return f.err;
        }
        *out = 1;
        s.live_handles += 1;
        s.mode = Some(mode);
        ESP_OK
    })
}
pub(crate) unsafe fn nvs_close(h: u32) {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        assert_eq!(h, 1);
        s.live_handles -= 1;
        s.mode = None;
        s.calls.push("close");
    });
}
pub(crate) unsafe fn nvs_entry_find_in_handle(h: u32, ty: u32, out: *mut nvs_iterator_t) -> i32 {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        assert_eq!(h, 1);
        assert_eq!(ty, nvs_type_t_NVS_TYPE_ANY);
        assert!((*out).is_null());
        let f = call(&mut s, "find");
        let pass = s.finds.min(s.passes.len() - 1);
        s.finds += 1;
        s.active_pass = pass;
        if let Some(f) = f {
            if !f.null {
                *out = Box::into_raw(Box::new(Iter { index: 0, pass }));
                s.live_iterators += 1;
            }
            return f.err;
        }
        if s.passes[pass].is_empty() {
            return ESP_ERR_NVS_NOT_FOUND;
        }
        *out = Box::into_raw(Box::new(Iter { index: 0, pass }));
        s.live_iterators += 1;
        ESP_OK
    })
}
pub(crate) unsafe fn nvs_entry_info(it: nvs_iterator_t, out: *mut nvs_entry_info_t) -> i32 {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        assert!(!it.is_null());
        if let Some(f) = call(&mut s, "info") {
            return f.err;
        }
        *out = s.passes[(*it).pass][(*it).index].info.clone();
        ESP_OK
    })
}
pub(crate) unsafe fn nvs_entry_next(it: *mut nvs_iterator_t) -> i32 {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        assert!(!(*it).is_null());
        if let Some(f) = call(&mut s, "next") {
            if f.null {
                drop(Box::from_raw(*it));
                *it = std::ptr::null_mut();
                s.live_iterators -= 1;
            }
            return f.err;
        }
        (*(*it)).index += 1;
        if (*(*it)).index == s.passes[(*(*it)).pass].len() {
            drop(Box::from_raw(*it));
            *it = std::ptr::null_mut();
            s.live_iterators -= 1;
            return ESP_ERR_NVS_NOT_FOUND;
        }
        ESP_OK
    })
}
pub(crate) unsafe fn nvs_release_iterator(it: nvs_iterator_t) {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.calls.push("release");
        if !it.is_null() {
            drop(Box::from_raw(it));
            s.live_iterators -= 1;
        }
    });
}
pub(crate) unsafe fn nvs_get_blob(
    h: u32,
    name: *const c_char,
    out: *mut c_void,
    len: *mut usize,
) -> i32 {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        assert_eq!(h, 1);
        let op = if out.is_null() { "length" } else { "read" };
        if let Some(f) = call(&mut s, op) {
            if let Some(n) = f.length {
                *len = n;
            }
            return f.err;
        }
        let k = CStr::from_ptr(name).to_bytes();
        let data = s.passes[s.active_pass]
            .iter()
            .find(|e| CStr::from_ptr(e.info.key.as_ptr()).to_bytes() == k);
        let Some(data) = data else {
            return ESP_ERR_NVS_NOT_FOUND;
        };
        if !out.is_null() {
            assert!(*len >= data.bytes.len());
            std::ptr::copy_nonoverlapping(data.bytes.as_ptr(), out.cast(), data.bytes.len());
        }
        *len = data.bytes.len();
        ESP_OK
    })
}

// ESP-IDF set_blob writes immediately. commit is not a transaction boundary.
pub(crate) fn enable_writes(effect: WriteEffect) {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        s.writable = true;
        s.write_effect = effect;
    });
}
pub(crate) unsafe fn nvs_set_blob(
    h: u32,
    name: *const c_char,
    data: *const c_void,
    len: usize,
) -> i32 {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        assert_eq!(h, 1);
        assert_eq!(s.mode, Some(nvs_open_mode_t_NVS_READWRITE));
        let fault = call(&mut s, "set");
        let effect = if fault.is_some() {
            s.write_effect
        } else {
            WriteEffect::New
        };
        let key = CStr::from_ptr(name).to_str().unwrap();
        let bytes = std::slice::from_raw_parts(data.cast::<u8>(), len).to_vec();
        s.mutations.push(key.into());
        let ns = s.namespace.clone();
        for pass in &mut s.passes {
            let pos = pass
                .iter()
                .position(|e| CStr::from_ptr(e.info.key.as_ptr()).to_bytes() == key.as_bytes());
            match effect {
                WriteEffect::Old => {}
                WriteEffect::Missing => {
                    if let Some(i) = pos {
                        pass.remove(i);
                    }
                }
                WriteEffect::New | WriteEffect::Corrupt => {
                    let mut next = entry(&ns, key, bytes.clone());
                    if matches!(effect, WriteEffect::Corrupt) {
                        next.bytes[0] ^= 1;
                    }
                    if let Some(i) = pos {
                        pass[i] = next;
                    } else {
                        pass.push(next);
                    }
                }
            }
        }
        fault.map_or(ESP_OK, |f| f.err)
    })
}
pub(crate) unsafe fn nvs_commit(h: u32) -> i32 {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        assert_eq!(h, 1);
        assert_eq!(s.mode, Some(nvs_open_mode_t_NVS_READWRITE));
        call(&mut s, "commit").map_or(ESP_OK, |f| f.err)
    })
}

pub(crate) fn inject_fault(fault: Option<Fault>, effect: WriteEffect) {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        assert_eq!(s.live_handles, 0);
        s.calls.clear();
        s.fault = fault;
        s.write_effect = effect;
    });
}
pub(crate) fn alter(key: &str, bytes: Option<Vec<u8>>) {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        assert_eq!(s.live_handles, 0);
        let ns = s.namespace.clone();
        for pass in &mut s.passes {
            pass.retain(|e| unsafe {
                CStr::from_ptr(e.info.key.as_ptr()).to_bytes() != key.as_bytes()
            });
            if let Some(b) = &bytes {
                pass.push(entry(&ns, key, b.clone()));
            }
        }
    });
}
