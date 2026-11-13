//! Heap cost of the relay `list_clients` reply.
//!
//! A T-Display (classic ESP32, no PSRAM) rebooted with the crash breadcrumb
//! "relay mgmt list_clients", which is set before the reply is built and only
//! overwritten once the reply reaches encryption. This measures what building
//! that reply allocates: the peak heap above the starting point and the
//! largest single allocation, for a typical board and for the largest slots
//! the policy caps allow.
//!
//! The trees it used to build are measured beside the one-buffer encoder
//! that replaced them (`mgmt::encode_list_clients_reply`), which must cost
//! one buffer sized for encryption (or, while counting, a scratch buffer for
//! the largest slot) plus a few short-lived strings, and the two are
//! compared again through NIP-44 encryption.
//!
//! Its own test binary, with one test, so the counting allocator sees nothing
//! but the code under measurement. Host figures are 64-bit; the ESP32 is
//! 32-bit, so its `serde_json::Value` nodes and pointers are smaller, but the
//! shape (a tree several times the reply's size, alive while the reply string
//! grows beside it) is the same. Needs the `std` feature, which the encoder
//! uses for serde_json's writer, and `nip44`.
#![cfg(all(feature = "nip46", feature = "nip44", feature = "std"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use heartwood_common::client_grants::GrantSnapshot;
use heartwood_common::hex::hex_encode;
use heartwood_common::nip44;
use heartwood_common::mgmt::{
    client_summary, encode_list_clients_reply, ListClientsEncodeError, NIP44_MAX_PLAINTEXT,
};
use heartwood_common::policy::{identity_tag, ConnectSlot};

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
            // A realloc that moves briefly holds both blocks. Count the move
            // as the new block arriving before the old one leaves, which is
            // what a heap without room to grow in place has to find.
            note_growth(new_size, new_size);
            CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
        }
        p
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Heap used by `f` above the level it started at.
struct Cost {
    peak: usize,
    largest: usize,
}

fn measure<T>(f: impl FnOnce() -> T) -> (T, Cost) {
    let base = CURRENT.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    LARGEST.store(0, Ordering::SeqCst);
    let out = f();
    let cost = Cost {
        peak: PEAK.load(Ordering::SeqCst) - base,
        largest: LARGEST.load(Ordering::SeqCst),
    };
    (out, cost)
}

fn key(seed: u8, salt: u8) -> [u8; 32] {
    let mut k = [seed; 32];
    k[0] = salt;
    k[31] = seed.wrapping_mul(31).wrapping_add(salt);
    k
}

fn tags(identities: &[[u8; 32]]) -> String {
    identities
        .iter()
        .map(|id| String::from_utf8(identity_tag(id).to_vec()).unwrap())
        .collect()
}

const METHODS: &[&str] = &[
    "connect", "ping", "get_public_key", "sign_event", "nip04_encrypt", "nip04_decrypt",
    "nip44_encrypt", "nip44_decrypt", "get_relays", "switch_relays", "heartwood_derive",
    "heartwood_list_identities", "heartwood_switch", "heartwood_create_proof",
    "heartwood_verify_proof", "heartwood_recover", "heartwood_remove_persona",
    "heartwood_rename_persona", "heartwood_note_put", "heartwood_note_get",
    "heartwood_note_list", "heartwood_note_delete", "heartwood_note_rename",
    "heartwood_note_send", "heartwood_note_receive", "heartwood_cash_balance",
    "heartwood_cash_send", "heartwood_cash_receive", "heartwood_cash_history",
    "heartwood_cash_mint", "heartwood_cash_melt", "heartwood_cash_swap",
];

/// A slot as a board in daily use tends to hold one: one paired client, a
/// handful of kinds and methods, the binding plus one more identity approved.
fn typical_slot(index: u8) -> ConnectSlot {
    let client = key(index, 0xc1);
    let bound = key(index, 0xb0);
    let extra = key(index, 0xe1);
    let mut slot = ConnectSlot {
        slot_index: index,
        label: format!("App number {index}"),
        secret: hex_encode(&key(index, 0x5e)),
        current_pubkey: Some(hex_encode(&client)),
        allowed_methods: METHODS[..8].iter().map(|m| m.to_string()).collect(),
        allowed_kinds: vec![0, 1, 3, 4, 5, 6, 7, 1059, 1111, 9734, 10002, 30023],
        auto_approve: true,
        signing_approved: true,
        strict_permissions: true,
        authorized_pubkeys: vec![hex_encode(&client)],
        escalate: false,
        petition_on_deny: false,
        audit_child_wrap: false,
        guardian_notice_wrap: false,
        bound_identity: Some(hex_encode(&bound)),
        approved_identities: tags(&[extra]),
        was_bound: true,
        client_grants: None,
    };
    let mut grants = GrantSnapshot::from_legacy(&slot).expect("typical legacy grants");
    grants.approve(&client, &extra).expect("typical approval");
    slot.client_grants = Some(grants);
    slot
}

/// The largest slot the caps allow: 8 paired clients, 32 methods, 64 kinds,
/// 16 approved identities captured as legacy tags, 16 explicit approvals.
fn max_slot(index: u8) -> ConnectSlot {
    let clients: Vec<[u8; 32]> = (0..8).map(|i| key(index, 0xc0 + i)).collect();
    let identities: Vec<[u8; 32]> = (0..16).map(|i| key(index, 0xa0 + i)).collect();
    let mut slot = ConnectSlot {
        slot_index: index,
        label: format!("{:-<64}", format!("App number {index} with a long label ")),
        secret: hex_encode(&key(index, 0x5e)),
        current_pubkey: Some(hex_encode(&clients[0])),
        allowed_methods: METHODS.iter().map(|m| m.to_string()).collect(),
        allowed_kinds: (0..64).map(|i| 30_000 + i).collect(),
        auto_approve: true,
        signing_approved: true,
        strict_permissions: true,
        authorized_pubkeys: clients.iter().map(|k| hex_encode(k)).collect(),
        escalate: true,
        petition_on_deny: true,
        audit_child_wrap: true,
        guardian_notice_wrap: true,
        bound_identity: Some(hex_encode(&identities[0])),
        approved_identities: tags(&identities),
        was_bound: true,
        client_grants: None,
    };
    let mut grants = GrantSnapshot::from_legacy(&slot).expect("max legacy grants");
    for n in 0..16 {
        grants
            .approve(&clients[n % clients.len()], &identities[n])
            .expect("max approval");
    }
    slot.client_grants = Some(grants);
    slot
}

/// The old `dispatch_mgmt` arm: one `client_summary` tree per slot, copied
/// into `{"clients": ...}` (`json!` serialises an interpolated value afresh,
/// so this is a second tree). The per-slot list drops when the arm returns.
fn old_dispatch_arm(slots: &[ConnectSlot]) -> serde_json::Value {
    let clients: Vec<serde_json::Value> = slots.iter().map(client_summary).collect();
    serde_json::json!({ "clients": clients })
}

/// The old call site: the arm's result, copied again into `{"id", "result"}`
/// and serialised while both trees are alive. As `relay.rs` did it before
/// this change, scope for scope.
fn old_reply(id: &str, slots: &[ConnectSlot]) -> String {
    let result = old_dispatch_arm(slots);
    serde_json::json!({ "id": id, "result": result }).to_string()
}

/// What `sign_and_publish` does next with the reply: NIP-44, consuming it.
fn encrypt(reply: String) -> String {
    nip44::encrypt_owned(&[7; 32], reply, &[9; 32]).expect("encrypts")
}

fn report(name: &str, reply_len: usize, cost: &Cost) {
    println!(
        "{name:<34} reply {reply_len:>7} B  peak {:>7} B ({:.1}x)  largest alloc {:>7} B",
        cost.peak,
        cost.peak as f64 / reply_len as f64,
        cost.largest,
    );
}

/// Short-lived strings the encoder makes on the way (a slot's fingerprint and
/// its decoded secret, the approved-identity tag list, a client key in hex,
/// a grant list), never more than a few at once.
const TRANSIENT_ALLOWANCE: usize = 1024;

#[test]
fn list_clients_reply_heap_cost() {
    let id = "4f1c9e0b2a7d4e8f9a6b3c5d7e0f1a2b";
    let cases: Vec<(&str, Vec<ConnectSlot>)> = vec![
        ("5 typical apps", (0..5).map(typical_slot).collect()),
        ("1 max app", vec![max_slot(0)]),
        ("16 max apps", (0..16).map(max_slot).collect()),
    ];
    for (name, slots) in &cases {
        let (tree, tree_cost) = measure(|| old_reply(id, slots));
        report(&format!("{name}, old build"), tree.len(), &tree_cost);
        assert!(tree_cost.peak > 4 * tree.len(), "the trees were the cost");

        // Counting runs each slot through one scratch buffer, which grows by
        // doubling to the largest slot's JSON: under 3x that while it moves.
        let largest_slot = slots
            .iter()
            .map(|slot| serde_json::to_string(&client_summary(slot)).unwrap().len())
            .max()
            .unwrap_or(0);
        let scratch_bound = 3 * largest_slot;

        let (encoded, cost) = measure(|| encode_list_clients_reply(id, slots));
        if tree.len() > NIP44_MAX_PLAINTEXT {
            // Refused after the counting pass, before the reply exists.
            assert_eq!(encoded, Err(ListClientsEncodeError::TooLarge(tree.len())));
            println!("{name:<34} refused, peak {} B", cost.peak);
            assert!(cost.peak <= scratch_bound + TRANSIENT_ALLOWANCE, "peak {}", cost.peak);
            continue;
        }
        let encoded = encoded.expect("encodes");
        report(&format!("{name}, one buffer"), encoded.len(), &cost);
        assert_eq!(encoded, tree, "same reply, byte for byte");
        let capacity = nip44::owned_capacity(encoded.len()).unwrap();
        assert!(cost.largest <= capacity.max(2 * largest_slot), "largest {}", cost.largest);
        assert!(
            cost.peak <= capacity.max(scratch_bound) + TRANSIENT_ALLOWANCE,
            "peak {} for a {} B buffer (scratch bound {scratch_bound})",
            cost.peak,
            capacity
        );

        // Through encryption as well, which the breadcrumb says the crash
        // never reached: the one buffer is padded in place, so the new
        // pipeline never needs more than the old one did.
        let (_, old_pipeline) = measure(|| encrypt(old_reply(id, slots)));
        let (_, new_pipeline) = measure(|| encrypt(encode_list_clients_reply(id, slots).unwrap()));
        report(&format!("{name}, old build + encrypt"), tree.len(), &old_pipeline);
        report(&format!("{name}, one buffer + encrypt"), encoded.len(), &new_pipeline);
        assert!(new_pipeline.peak < old_pipeline.peak);
    }
}
