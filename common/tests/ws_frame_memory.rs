//! Heap cost of putting a sealed reply on the WebSocket.
//!
//! A T-Display (classic ESP32, no PSRAM) panicked under the breadcrumb
//! "relay envelope kind 24134" asking for 14,526 B: the firmware's whole-frame
//! copy (14-byte header room, the content, 768 bytes of slack) of a
//! `list_clients` reply whose 13,744 B NIP-44 ciphertext was already held.
//! The transport guard had passed it, because it allows for one allocation
//! that size and the send made a second.
//!
//! This measures that whole-frame build beside `ws_frame::write_event_frame`,
//! which must allocate nothing the size of the content, and checks the two
//! put the same bytes on the wire. Its own test binary, with one test, so the
//! counting allocator sees nothing but the code under measurement.
#![cfg(all(feature = "nip46", feature = "std"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use heartwood_common::nip46::SignedEvent;
use heartwood_common::ws_frame::{event_payload_len, write_event_frame, CHUNK_LEN};

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static LARGEST: AtomicUsize = AtomicUsize::new(0);

fn note_growth(bytes: usize, single: usize) {
    let now = CURRENT.fetch_add(bytes, Ordering::SeqCst) + bytes;
    PEAK.fetch_max(now, Ordering::SeqCst);
    LARGEST.fetch_max(single, Ordering::SeqCst);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            note_growth(layout.size(), layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            // A move briefly holds both blocks.
            note_growth(new_size, new_size);
            CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
        }
        p
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Heap used by `f` above the level it started at.
#[derive(Debug)]
struct Cost {
    peak: usize,
    largest: usize,
}

fn measure<T>(f: impl FnOnce() -> T) -> (T, Cost) {
    let start = CURRENT.load(Ordering::SeqCst);
    PEAK.store(start, Ordering::SeqCst);
    LARGEST.store(0, Ordering::SeqCst);
    let out = f();
    let cost = Cost {
        peak: PEAK.load(Ordering::SeqCst) - start,
        largest: LARGEST.load(Ordering::SeqCst),
    };
    (out, cost)
}

/// The firmware's whole-frame build (`ws_send_framed` before this change),
/// without the socket.
fn whole_frame(command: &str, event: &SignedEvent, mask: [u8; 4]) -> Vec<u8> {
    const MAX_HEADER_LEN: usize = 14;
    let mut frame = Vec::with_capacity(MAX_HEADER_LEN + event.content.len() + 768);
    frame.resize(MAX_HEADER_LEN, 0);
    serde_json::to_writer(&mut frame, &(command, event)).unwrap();
    let payload_len = frame.len() - MAX_HEADER_LEN;
    let header_len = if payload_len < 126 {
        6
    } else if payload_len < 65_536 {
        8
    } else {
        14
    };
    frame.copy_within(MAX_HEADER_LEN.., header_len);
    frame.truncate(header_len + payload_len);
    frame[0] = 0x81;
    if payload_len < 126 {
        frame[1] = 0x80 | payload_len as u8;
    } else if payload_len < 65_536 {
        frame[1] = 0x80 | 126;
        frame[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        frame[1] = 0x80 | 127;
        frame[2..10].copy_from_slice(&(payload_len as u64).to_be_bytes());
    }
    let mask_offset = header_len - 4;
    frame[mask_offset..header_len].copy_from_slice(&mask);
    for (index, byte) in frame[header_len..].iter_mut().enumerate() {
        *byte ^= mask[index & 3];
    }
    frame
}

#[test]
fn a_sealed_reply_goes_out_without_a_second_content_sized_allocation() {
    // The panicking reply's shape: a NIP-44 payload of 13,744 base64 bytes
    // (plaintext 8,193 to 10,240 B), one p tag.
    const CONTENT_LEN: usize = 13_744;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let event = SignedEvent {
        id: "a1".repeat(32),
        pubkey: "da".repeat(32),
        created_at: 1_794_000_000,
        kind: 24134,
        tags: vec![vec!["p".to_string(), "37".repeat(32)]],
        content: (0..CONTENT_LEN)
            .map(|i| alphabet[(i * 7) % 64] as char)
            .collect(),
        sig: "5c".repeat(64),
    };
    let mask = [0x6b, 0x01, 0xd2, 0x9e];

    let (reference, whole) = measure(|| whole_frame("EVENT", &event, mask));

    // What the firmware now does, with a socket that keeps a running sum
    // instead of storing anything.
    let ((len, sent, sum), streamed) = measure(|| {
        let len = event_payload_len("EVENT", &event).unwrap();
        let mut buf = [0u8; CHUNK_LEN];
        let (mut sent, mut sum) = (0usize, 0u64);
        write_event_frame("EVENT", &event, len, mask, &mut buf, |piece: &[u8]| {
            sent += piece.len();
            sum = piece
                .iter()
                .fold(sum, |s, &b| s.wrapping_mul(31).wrapping_add(u64::from(b)));
            Ok::<(), ()>(())
        })
        .unwrap();
        (len, sent, sum)
    });
    println!("whole frame {whole:?}; streamed {streamed:?}");

    assert!(
        whole.largest >= CONTENT_LEN + 768,
        "the reference must show the old frame's allocation: {whole:?}"
    );
    assert!(
        streamed.largest < 1_024 && streamed.peak < 1_024,
        "sending must not allocate anything near the content's size: {streamed:?}"
    );

    // Same bytes on the wire.
    let mut wire = Vec::new();
    let mut buf = [0u8; CHUNK_LEN];
    write_event_frame("EVENT", &event, len, mask, &mut buf, |piece: &[u8]| {
        wire.extend_from_slice(piece);
        Ok::<(), ()>(())
    })
    .unwrap();
    assert_eq!(wire, reference);
    assert_eq!(sent, reference.len());
    assert_eq!(
        sum,
        reference
            .iter()
            .fold(0u64, |s, &b| s.wrapping_mul(31).wrapping_add(u64::from(b)))
    );
}
