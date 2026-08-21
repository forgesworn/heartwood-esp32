// firmware/src/relay.rs
//
//! WiFi-standalone relay transport (Plan 2). A hand-rolled minimal Nostr
//! WebSocket client over `EspTls`: the device connects **out** to its
//! configured relay (`wss://`), subscribes for the NIP-46 requests addressed to
//! its master pubkey(s), signs responses on-device, and publishes them back.
//! No inbound listener (no Tor, no open port).
//! See heartwood/docs/2026-06-19-relay-mediated-management.md
//!
//! The signing pipeline mirrors `transport::handle_encrypted_request` (the
//! USB-bridged path) exactly — NIP-44 decrypt → `nip46_handler::handle_request`
//! → re-encrypt → build + sign a kind:24133 envelope — but here the device also
//! does the parts the Pi bridge used to do: it subscribes, parses the inbound
//! EVENT, and publishes the response itself.
//!
//! Per-identity routing (parity with the USB path): the NIP-46 subscription is
//! `#p`-tagged to every served identity — each master AND every derived persona —
//! and an inbound request is routed by its `p` tag to the addressed identity. A
//! persona re-derives its signing key from the owning master and uses that key
//! for BOTH the NIP-44 transport and the envelope signature, so one connection ==
//! one identity, exactly as the software sidecar's `#p` routing does. Management
//! (kind 24134) stays master-only — the master pubkey is the v1 management
//! address; personas are signing-only.
//!
//! Increments 1–3 (done): wifi up → TLS → RFC-6455 handshake → subscribe by
//! served identity (master + personas) → on EVENT, decrypt/sign/publish → answer pings.
//!
//! Connection hardening: the read loop must never block forever on a silently
//! dead socket (else published requests are lost while we sit in `read`). Three
//! layers guard against that: (1) **TCP keepalive** tears down a dead peer/NAT
//! mapping (~25s) so a blocking read errors → reconnect; its ACKs are automatic
//! so it also survives the up-to-30s button wait. (2) A **recv timeout**
//! (`SO_RCVTIMEO`) makes the read loop wake periodically without busy-spinning.
//! (3) A **WS ping** every ~20s plus a silence deadline detects relay-level
//! death (TCP fine but no events flowing) and forces a reconnect.

use std::sync::Arc;
use std::time::{Duration, Instant};

use esp_idf_hal::delay::FreeRtos;
use esp_idf_hal::modem::Modem;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use esp_idf_svc::tls::{Config as TlsConfig, EspTls, InternalSocket, KeepAliveConfig};
use esp_idf_svc::wifi::{
    AuthMethod, BlockingWifi, ClientConfiguration, Configuration as WifiConfig, EspWifi,
    PmfConfiguration,
};
use secp256k1::{Keypair, Secp256k1, SignOnly};
use zeroize::Zeroize;

use heartwood_common::deadline::{
    deadline_io_action, retryable_tls_io_code, DeadlineIoAction, NonblockingIoEvent,
};
use heartwood_common::hex::{hex_decode, hex_encode};
use heartwood_common::mgmt;
use heartwood_common::net_config::{
    apply_remote_net_config_patch, network_activation_source_allowed,
    network_commit_source_allowed, NetConfig, NetworkConfigTransactionParams, NetworkRuntimeError,
    NetworkRuntimeStage, NetworkRuntimeStatus, NetworkTrialPhase, StageNetworkConfigParams,
};
use heartwood_common::nip44;
use heartwood_common::nip46::{self, SignedEvent, UnsignedEvent};
use heartwood_common::policy::{validate_exact_slot_policy, ExactSlotPolicy};
use heartwood_common::types::{
    FRAME_TYPE_ACK, FRAME_TYPE_BACKUP_EXPORT_REQUEST, FRAME_TYPE_BACKUP_IMPORT_REQUEST,
    FRAME_TYPE_CONNSLOT_CREATE, FRAME_TYPE_CONNSLOT_LIST, FRAME_TYPE_CONNSLOT_REVOKE,
    FRAME_TYPE_CONNSLOT_UPDATE, FRAME_TYPE_CONNSLOT_URI, FRAME_TYPE_ENCRYPTED_REQUEST,
    FRAME_TYPE_FACTORY_RESET, FRAME_TYPE_FIRMWARE_INFO, FRAME_TYPE_FIRMWARE_INFO_RESPONSE,
    FRAME_TYPE_NOTE_CMD,
    FRAME_TYPE_GENERATE_IDENTITY, FRAME_TYPE_GET_NET_CONFIG, FRAME_TYPE_NACK,
    FRAME_TYPE_NIP46_REQUEST, FRAME_TYPE_NIP46_RESPONSE, FRAME_TYPE_OTA_BEGIN,
    FRAME_TYPE_OTA_CHUNK, FRAME_TYPE_OTA_FINISH, FRAME_TYPE_PATCH_NET_CONFIG, FRAME_TYPE_PROVISION,
    FRAME_TYPE_DERIVE_IDENTITY,
    FRAME_TYPE_PROVISION_LIST, FRAME_TYPE_PROVISION_REMOVE, FRAME_TYPE_RESTORE_IDENTITY,
    FRAME_TYPE_SESSION_AUTH, FRAME_TYPE_SESSION_ACK, FRAME_TYPE_SET_BRIDGE_SECRET, FRAME_TYPE_SET_IDENTITY_META,
    FRAME_TYPE_SET_NET_CONFIG, FRAME_TYPE_SET_OPERATOR, FRAME_TYPE_SET_PIN,
    FRAME_TYPE_PIN_UNLOCK, FRAME_TYPE_VAULT_SET, FRAME_TYPE_VAULT_UNLOCK,
    FRAME_TYPE_SIGN_ENVELOPE, FRAME_TYPE_WIFI_SCAN_REQUEST,
};

use crate::identity_cache::IdentityCache;
use crate::masters::{self, LoadedMaster};
use crate::oled::{Display, NetworkDisplayState};
use crate::policy::PolicyEngine;
use crate::serial::SerialPort;
use crate::sign;

type Tls = EspTls<InternalSocket>;

const TLS_PORT: u16 = 443;
/// One wall-clock budget for the complete HTTP Upgrade request and response.
/// `TlsConfig::timeout_ms` covers `connect`; this separate deadline prevents a
/// peer from extending the upgrade forever with partial writes or trickled reads.
const WS_UPGRADE_TIMEOUT: Duration = Duration::from_secs(10);
/// NIP-46 request/response event kind (also the inline envelope kind).
const NIP46_KIND: u64 = 24133;
const GIFT_WRAP_KIND: u64 = heartwood_common::nip59::GIFT_WRAP_KIND;
/// Relay-management event kind (distinct permission boundary from NIP-46).
/// Requests are authenticated to the baked operator key (`op_mgmt`).
const MGMT_KIND: u64 = 24134;
/// Bound on the RAM-only management duplicate-delivery set.
const SEEN_MAX: usize = 64;
/// NVS-persisted device challenge consumed by every relay-management mutation.
/// Rotation is persisted before dispatch, so an old captured ciphertext can
/// never become current again after request-id eviction or reboot.
/// Initial capacity of the inbound byte-accumulation buffer.
const READ_BUF: usize = 8192;
/// Largest single inbound WS frame we'll accept; bigger ⇒ drop + reconnect.
/// Sized for the biggest legitimate message: a `set_identity_meta` mgmt event
/// carrying a 64x64 Rgb565 avatar (8KB raw → ~11KB base64 inside the NIP-44
/// ciphertext → ~17KB event JSON), with headroom.
const MAX_WS_FRAME: usize = 32768;
/// `SO_RCVTIMEO` for the read loop — how long a `read` blocks before returning
/// "no data yet" so the loop can ping / check the silence deadline.
const RECV_TIMEOUT_MS: i64 = 1000;
/// `SO_SNDTIMEO` for session sockets. A peer that stops ACKing (stalled relay,
/// dead NAT path) leaves data queued unACKed, so TCP keepalive never fires and
/// `write_all` blocks inside lwIP's retransmission backoff — for MINUTES — the
/// moment anything publishes. That froze the whole single-threaded loop: every
/// client saw timeouts, the log showed nothing (the loop was inside `send`),
/// and replies flushed in a late burst when the peer recovered. With a send
/// timeout the write errors instead, the one session is dropped mid-record
/// (mandatory after a partial TLS write) and the primary re-dials ~3s later,
/// so a stalled relay costs ~11s on one socket instead of a global freeze.
const SEND_TIMEOUT_MS: i64 = 8_000;
/// Send a WebSocket ping after this much inactivity (relay-level keepalive).
const PING_INTERVAL: Duration = Duration::from_secs(20);
/// Reconnect if nothing at all (data or pong) arrives for this long.
const SILENCE_LIMIT: Duration = Duration::from_secs(50);
/// A RECEIVE card that lapsed is offered again this much later, and keeps
/// being offered until the owner holds or declines: a note that landed while
/// nobody was watching must not need a power cycle to come back, and must
/// not take the screen every 30 s either.
const LAPSED_WRAP_RETRY: Duration = Duration::from_secs(10 * 60);
/// Lapsed wraps tracked for that retry. Past this, the oldest is released
/// to the next catch-up early rather than forgotten.
const LAPSED_WRAP_MAX: usize = 8;

/// A catch-up that comes back with a full page may be hiding older wraps
/// behind it (#89): the relay hands back the newest CATCH_UP_LIMIT, and a
/// flood, or simply a long life, pushes an undecided wrap past them. Page
/// down with `until` this many times before giving up for this pass.
const CATCH_UP_MAX_PAGES: u8 = 4;
/// The side subscription the pages arrive on, closed after each page.
const CATCH_UP_PAGE_SUB: &str = "wrappage";

/// A catch-up in progress: what the current page has delivered so far.
struct CatchUp {
    delivered: u32,
    /// Oldest `created_at` seen across every page of this pass; the next
    /// page asks for strictly older.
    oldest: u64,
    pages: u8,
}

/// Re-send the `REQ` this often so a silently-dropped subscription self-heals.
/// Some relays close a subscription (or stop delivering to it) while keeping the
/// WS connection alive, so the connection never looks dead — periodic re-REQ
/// (same sub id, idempotent overwrite) re-establishes delivery either way.
const RESUB_INTERVAL: Duration = Duration::from_secs(40);
/// Blank the OLED after this much inactivity to prevent burn-in on a 24/7 shelf
/// device. The wifi-standalone relay loop otherwise leaves a static npub on the
/// panel forever. Mirrors the USB frame loop's DISPLAY_TIMEOUT. A request or a
/// PRG press wakes it again.
const DISPLAY_TIMEOUT: Duration = Duration::from_secs(30);
/// Recent NIP-46 activity exposed to Sapwood over authenticated management.
/// Entries are summaries only: no secrets, no encrypted payloads or plaintexts.
const SIGN_AUDIT_MAX: usize = 32;
/// How many of the stored audit entries the polled get_status response carries.
/// The full ring is kept in RAM; but a status response that serialised all 32 —
/// each re-encrypted, padded and base64'd for transport — is the largest, most
/// allocation-heavy relay response on a no-PSRAM heap, and get_status is polled
/// every few seconds. Reporting only the most recent window keeps the routine
/// poll small enough to clear the transport heap guard, so the request log stays
/// visible under the fragmentation that would otherwise force it dropped whole.
const SIGN_AUDIT_REPORT_MAX: usize = 16;
/// Ceiling on simultaneous relay sessions: the primary (rotating over the
/// configured set) plus pinned relays joined at nostrconnect pairing. Each
/// mbedTLS session costs ~40-50KB of heap; PSRAM is off and one build profile
/// must hold on the weakest board, so two is the safe ceiling.
const MAX_SESSIONS: usize = 2;
/// Backoff between reconnect attempts for the primary session (as before).
const PRIMARY_BACKOFF: Duration = Duration::from_secs(3);
/// Base backoff for pinned relays — slower than the primary, and doubling per
/// consecutive failure up to PINNED_BACKOFF_MAX: each failed dial blocks the
/// loop for up to the 10s TLS timeout, so a dead client relay must decay to a
/// rare probe rather than a 40% duty-cycle drain.
const PINNED_BACKOFF: Duration = Duration::from_secs(15);
/// Ceiling for the pinned-relay exponential backoff (10 minutes).
const PINNED_BACKOFF_MAX: Duration = Duration::from_secs(600);
/// Minimum free heap before dialling a second relay session. A fresh mbedTLS
/// session costs ~40-50KB and an allocation failure deep inside the TLS or
/// WiFi stack can abort the chip rather than error — observed as a reset on
/// the no-PSRAM T-Display when pairing dialled mid-session (2026-07-08).
const DIAL_MIN_FREE_HEAP: u32 = 70_000;
/// Minimum largest contiguous free block before dialling: mbedTLS wants a
/// 16KB record buffer in one piece, so total-free alone is not enough on a
/// fragmented heap.
const DIAL_MIN_LARGEST_BLOCK: usize = 24_000;
/// Relay-health watchdog: restart the signer when WiFi is up and relays are
/// configured, yet no session has been simultaneously live and publishable
/// for this long. A fragmented no-PSRAM heap can reach a state where every
/// TLS dial or response publish is refused — the guards here deliberately
/// degrade instead of crashing, so nothing panics, nothing self-resets, and
/// the owner sees a signer that answers nothing until power-cycled. A
/// controlled restart with attribution beats an indefinitely deaf signer.
/// Longer than any outage the loop rides out itself (relay failover ~13s per
/// candidate; WiFi-down and no-relay-config states reset the timer so USB
/// recovery is never interrupted), and equal to NETWORK_TRIAL_TIMEOUT — but
/// trials are excluded outright: their own deadline owns recovery until the
/// candidate config commits or rolls back.
const RELAY_HEALTH_RESTART_AFTER: Duration = Duration::from_secs(5 * 60);
/// A live session only counts as healthy while the largest contiguous free
/// block clears response_transportable's floor — below it every reply
/// degrades to an error, which is deafness with extra steps.
const RELAY_HEALTH_MIN_BLOCK: usize = 16_384;
/// Cadence of the heap telemetry line. The decay curve of the largest free
/// block against sign/mgmt traffic is exactly the evidence needed to pin
/// field fragmentation reports, and one line a minute costs nothing.
const RELAY_HEAP_LOG_INTERVAL: Duration = Duration::from_secs(60);
/// Whether the free heap can safely transport a response of `len` bytes.
///
/// The owned encryption and direct WebSocket writers now reuse the plaintext
/// allocation and keep at most one output-sized allocation beside it. Require
/// one contiguous block large enough for the exact NIP-44 output plus envelope
/// overhead, and enough total free heap for that allocation plus runtime
/// working room. A genuinely starved or fragmented heap still degrades to a
/// clean error instead of aborting the allocator.
pub(crate) fn response_transportable(len: usize) -> bool {
    const ENVELOPE_OVERHEAD: usize = 1_024;
    const WORKING_MARGIN: usize = 16_384;

    let Some(encoded_len) = nip44::encoded_len(len) else {
        return false;
    };
    let largest_need = encoded_len
        .saturating_add(ENVELOPE_OVERHEAD)
        .max(16_384);
    let total_need = encoded_len.saturating_add(WORKING_MARGIN);
    let free = unsafe { esp_idf_svc::sys::esp_get_free_heap_size() } as usize;
    let largest = unsafe {
        esp_idf_svc::sys::heap_caps_get_largest_free_block(esp_idf_svc::sys::MALLOC_CAP_8BIT)
    };
    free >= total_need && largest >= largest_need
}

/// NVS key the pinned-relay list is persisted under (JSON array).
const PINNED_NVS_KEY: &str = "pinned_rly";
/// A candidate that reconnects but is never committed rolls back automatically.
const NETWORK_TRIAL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Management responses are published synchronously; retain a little extra
/// flush time before an activated/aborted trial restarts the device.
const NETWORK_RESTART_DELAY: Duration = Duration::from_secs(2);

struct SignAuditEntry {
    seq: u64,
    method: String,
    label: String,
    client: String,
    kind: Option<u64>,
    preview: String,
    outcome: String,
}

struct SignAuditDraft {
    method: String,
    label: String,
    client: String,
    kind: Option<u64>,
    preview: String,
    success_outcome: String,
}

/// Signing context borrowed from `main` for the lifetime of the relay loop.
/// `masters`/`secp`/`buttons` are shared refs; the rest are exclusive.
/// `'d` (display) and `'b` (button) stay independent — like the USB path —
/// so the `main` call site needn't prove the two peripherals share a lifetime.
struct SignCtx<'a, 'd, 'b> {
    masters: &'a [LoadedMaster],
    secp: &'a Arc<Secp256k1<SignOnly>>,
    display: &'a mut Display<'d>,
    buttons: &'a crate::button::Buttons<'b>,
    policy_engine: &'a mut PolicyEngine,
    identity_caches: &'a mut Vec<IdentityCache>,
    nvs: &'a mut EspNvs<NvsDefault>,
    /// Persona registry, needed by the encrypted (bridge) USB signing path so
    /// the cable stays fully usable in wifi mode. Not touched by the relay
    /// signing path, so it does not affect the `masters` borrow discipline.
    personas: &'a mut Vec<crate::personas::LoadedPersona>,
    /// In-flight OTA transfer, when a firmware update is being streamed over USB
    /// while in wifi mode. `None` when idle.
    ota_session: Option<crate::ota::OtaSession>,
    /// Operator pubkey authorised for kind-24134 management (`None` disables it).
    op_mgmt: Option<[u8; 32]>,
    /// The relay currently being served (one of `relays`).
    relay_url: String,
    /// All configured relays — advertised in bunker URIs so clients publish to
    /// every relay, and cycled through on reconnect for failover.
    relays: Vec<String>,
    /// RAM-only bounded set suppressing duplicate delivery across live relays.
    /// Durable mutation replay safety comes from `MGMT_CHALLENGE_KEY`, not this.
    seen: Vec<String>,
    /// OLED power state — false once blanked for burn-in protection.
    display_on: bool,
    /// Last time a real request touched the screen (drives the blank timeout).
    last_activity: Instant,
    /// Cached display name from the primary master's own kind-0 profile, shown on
    /// the idle identity screen once fetched. `None` until a profile arrives (the
    /// screen falls back to the short npub). `identity_name_ts` is the source
    /// event's `created_at`, so only a newer replaceable event overwrites it.
    identity_name: Option<String>,
    identity_name_ts: u64,
    sign_audit: Vec<SignAuditEntry>,
    sign_audit_seq: u64,
    /// Recently-processed NIP-46 event ids. With more than one live relay
    /// session, a client that publishes one request event to several relays
    /// would otherwise be dispatched once per session — a double button
    /// prompt, or a double execution of a non-idempotent method. Bounded ring;
    /// management (24134) has its own persisted inner-id replay guard.
    nip46_seen: Vec<String>,
    /// Same ring for bearer-note gift wraps (kind 1059), kept apart so busy
    /// NIP-46 traffic cannot evict a wrap id inside the re-REQ interval.
    /// Holds what is on a card or was junk; a wrap dropped for want of room
    /// is deliberately NOT here, so the next catch-up can offer it again.
    wrap_seen: Vec<String>,
    /// Wraps the owner has decided on, across reboots, and the lower bound
    /// of the catch-up REQ (`wrap_ledger`).
    wrap_ledger: heartwood_common::wrap_ledger::WrapLedger,
    /// A wrap was dropped because the letterbox was full: re-run the
    /// catch-up once there is room, rather than waiting for a reconnect.
    wrap_retry_when_room: bool,
    /// RECEIVE cards that lapsed, oldest first, with when: each is released
    /// from `wrap_seen` after [`LAPSED_WRAP_RETRY`] so the catch-up can
    /// offer it again.
    wrap_lapsed: Vec<(String, Instant)>,
    /// The button was down when the card on screen resolved: the rest of
    /// that hold, and its release, belong to the card and must not page the
    /// idle carousel. Cleared the first time the button is seen up.
    button_settle: bool,
    /// The catch-up pass in flight, if any (see [`CatchUp`]).
    catch_up: Option<CatchUp>,
    /// Last failed nostrconnect dial (url, when): throttles operator-driven
    /// re-dials of a dead relay, which the pinned backoff cannot cover (no
    /// PinnedRelay exists until a dial succeeds).
    dial_cooldown: Option<(String, Instant)>,
    /// Present only while this boot is serving a TRYING network candidate.
    network_trial_id: Option<String>,
    network_trial_deadline: Option<Instant>,
    /// Set by a management method, acted on only after its encrypted response
    /// has returned through `sign_and_publish` and control reaches the loop.
    network_restart_at: Option<Instant>,
    /// Identifier-free runtime connectivity state exposed only on local USB.
    network_runtime: NetworkRuntimeStatus,
    /// A short-lived network status card restores to the idle identity screen
    /// at this deadline. Progress/failure cards leave this unset and remain
    /// visible until the next transition or normal burn-in blanking.
    network_display_restore_at: Option<Instant>,
    /// Idle info carousel position: 0 identity, 1 network, 2 device. Short
    /// presses while the panel is awake advance it; sleep resets it.
    idle_page: u8,
    /// Set when the served persona set changed (a derive over any path, or a
    /// registry removal): the live "hw" subscriptions re-REQ with fresh
    /// filters on the next loop pass instead of waiting for a reconnect, so
    /// a freshly derived persona is addressable promptly (D4). A rename never
    /// sets it — pubkeys are unchanged.
    resubscribe_needed: bool,
    /// C4 parked interactive requests awaiting a guardian verdict (RAM only,
    /// capped at `PARK_MAX`, expired by `service_parks`).
    parks: Vec<ParkedRequest>,
    /// Expired parks' (client, key) so a late approve verdict can still
    /// install the transient allow (schema §1.4's expired column). RAM only.
    park_tombstones: Vec<ParkTombstone>,
    /// C4 petition counters per (client, method-or-kind): asks since the
    /// last verdict, so repeated nagging coalesces into one notice row.
    petitions: Vec<PetitionCounter>,
    /// Session-monotonic floor for C4/C5 rumor timestamps (schema §0.1).
    audit_last_stamped: u64,
    /// Uniqueness counter inside the C5 `d` tag's pseudo-millisecond suffix.
    audit_emit_seq: u64,
    /// Freshest wall-clock reading seen from the relays. The chip has no
    /// clock of its own, so this is what lets a reply held behind an approval
    /// window be stamped for when it is sent rather than when it arrived (#64).
    reply_clock: heartwood_common::reply_clock::ReplyClock,
    /// Interactive asks waiting on the device button. Index 0 is the card on
    /// screen; the rest wait their turn. RAM only, capped by the counts in
    /// `approval_queue` and by `CARD_BYTE_BUDGET`.
    button_cards: Vec<ButtonCard>,
}

/// Timestamp for a reply to a request that arrived `held` ago.
///
/// A park can sit on the shelf for the whole ten-minute TTL and an approval
/// card for its whole window, so echoing the trigger's own `created_at` — as
/// every reply used to — backdates the answer by the entire wait (#64). See
/// [`heartwood_common::reply_clock`] for how the two estimates combine.
fn reply_stamp(ctx: &SignCtx, request_created_at: u64, held: Duration) -> u64 {
    let now = crate::uptime_s();
    ctx.reply_clock
        .stamp(request_created_at, now.saturating_sub(held.as_secs()), now)
}

/// Wake the panel on a press; while awake, further presses page the idle
/// info carousel. Drains the press (bounded) so one physical press moves
/// exactly one page. Called from the top of the relay loop AND from inside
/// the USB-serving wait windows, so a wake press keeps working while WiFi is
/// reconnecting instead of playing dead for the length of the retry.
fn service_button(ctx: &mut SignCtx<'_, '_, '_>) {
    // The finger that approved (or declined) the last card is still coming
    // off the button. A 2 s hold does not end the instant the bar fills, and
    // the release that follows was reported from the bench as "approving
    // takes you onto the next screen". Swallow the level until it is up,
    // and the edge with it.
    if ctx.button_settle {
        crate::button::clear_press_edge();
        if ctx.buttons.a.is_low() {
            return;
        }
        ctx.button_settle = false;
        return;
    }
    // A latched edge counts even when the finger is already off: this loop's
    // pass is ~1 s (socket recv timeouts dominate), longer than a human tap,
    // so sampling the live level alone missed most dismiss-taps (#61).
    let latched = crate::button::take_press_edge();
    if !latched && !ctx.buttons.a.is_low() {
        return;
    }
    if latched && !ctx.buttons.a.is_low() {
        // The level sample would have missed this tap entirely — the latch
        // is what caught it. Logged so the fix is verifiable over serial.
        log::info!("[relay] press consumed from latch (tap ended before sample)");
    }
    if !ctx.display_on {
        crate::oled::wake_display(ctx.display);
        ctx.display_on = true;
        ctx.idle_page = 0;
        // Redraw the idle card rather than re-lighting whatever frame was in
        // panel RAM — waking into a stale approval countdown reads as a live
        // prompt that ignores the buttons.
        show_idle_identity(ctx);
    } else if crate::confirm::dismiss() {
        // A press while a signing confirmation is held dismisses the run
        // early, back to the idle identity card.
        ctx.idle_page = 0;
        show_idle_identity(ctx);
    } else {
        // Awake: a short press pages the idle info carousel.
        ctx.idle_page = (ctx.idle_page + 1) % 3;
        draw_relay_idle_page(ctx);
    }
    ctx.last_activity = Instant::now();
    let drain_start = Instant::now();
    while ctx.buttons.a.is_low() && drain_start.elapsed() < Duration::from_millis(1900) {
        crate::wdt::feed();
        FreeRtos::delay_ms(20);
    }
    // The drain consumed the physical press; swallow release bounce and drop
    // any edge the sampler latched from this same press so it cannot replay
    // as a phantom carousel page.
    FreeRtos::delay_ms(30);
    crate::button::clear_press_edge();
}

/// One page of the idle info carousel. Page 1 shows the stored SSID with the
/// live runtime stage; page 2 the firmware version, board, and uptime.
fn draw_relay_idle_page(ctx: &mut SignCtx<'_, '_, '_>) {
    match ctx.idle_page {
        1 => {
            let ssid = crate::net_config_store::read_net_config(ctx.nvs)
                .and_then(|raw| heartwood_common::net_config::parse_net_config(&raw).ok())
                .filter(|cfg| !cfg.ssid.is_empty())
                .map(|cfg| cfg.ssid);
            let status = match ctx.network_runtime.stage {
                NetworkRuntimeStage::Online => "online",
                NetworkRuntimeStage::SubscriptionSent => "relay connecting",
                NetworkRuntimeStage::RelayConnecting => "relay connecting",
                NetworkRuntimeStage::WifiReady => "wifi up",
                NetworkRuntimeStage::WifiConnecting => "joining wifi",
                NetworkRuntimeStage::Starting => "starting",
                NetworkRuntimeStage::ConfigError => "config error",
                NetworkRuntimeStage::RadioOff => "radio off",
            };
            crate::oled::show_info_network(
                ctx.display,
                "WiFi standalone",
                ssid.as_deref(),
                status,
            );
        }
        2 => crate::oled::show_info_device(
            ctx.display,
            env!("CARGO_PKG_VERSION"),
            crate::board::BOARD,
            crate::uptime_s(),
        ),
        _ => show_idle_identity(ctx),
    }
}

fn show_idle_identity(ctx: &mut SignCtx<'_, '_, '_>) {
    if !ctx.display_on {
        return;
    }
    if ctx.masters.len() == 1 {
        let slot = ctx.masters[0].slot;
        let npub = heartwood_common::encoding::encode_npub(&ctx.masters[0].pubkey);
        let meta = crate::identity_meta::load(ctx.nvs, slot);
        let fallback = ctx.identity_name.clone();
        let (name, avatar) = match &meta {
            Some(m) => (Some(m.name.as_str()), Some((m.w, m.h, m.avatar.as_slice()))),
            None => (fallback.as_deref(), None),
        };
        crate::oled::show_npub(ctx.display, name, &npub, avatar);
    } else {
        crate::oled::show_boot(ctx.display, ctx.masters.len() as u8);
    }
}

fn show_network_feedback(
    ctx: &mut SignCtx<'_, '_, '_>,
    state: NetworkDisplayState,
    wake: bool,
    restore_after: Option<Duration>,
) {
    // An approval card owns the screen until the operator answers it - the
    // same rule the idle carousel and the confirm-restore already follow.
    // Connectivity churn is frequent and unprompted, so without this a relay
    // reconnect or a wifi rejoin repaints straight over a live card: the
    // operator is asked to hold a button for something they can no longer
    // see, and the hold they do make lands on whatever replaced it. Found
    // running checklist section 14, where a RECEIVE card was clobbered by
    // the wifi-standalone screen mid-decision.
    if approval_card_open(ctx) {
        return;
    }
    if wake && !ctx.display_on {
        crate::oled::wake_display(ctx.display);
        ctx.display_on = true;
    }
    if !ctx.display_on {
        return;
    }
    crate::oled::show_network_status(ctx.display, state);
    ctx.last_activity = Instant::now();
    ctx.network_display_restore_at = restore_after.map(|delay| Instant::now() + delay);
}

fn set_network_runtime(
    ctx: &mut SignCtx<'_, '_, '_>,
    stage: NetworkRuntimeStage,
    wifi_connected: bool,
    relay_connected: bool,
    last_error_class: NetworkRuntimeError,
) {
    let next = NetworkRuntimeStatus {
        stage,
        wifi_connected,
        relay_connected,
        last_error_class,
    };
    if ctx.network_runtime == next {
        return;
    }
    ctx.network_runtime = next;

    let feedback = match stage {
        NetworkRuntimeStage::RadioOff => None,
        NetworkRuntimeStage::Starting | NetworkRuntimeStage::WifiConnecting => Some(
            if last_error_class == NetworkRuntimeError::WifiUnavailable {
                NetworkDisplayState::WifiFailed
            } else {
                NetworkDisplayState::JoiningWifi
            },
        ),
        NetworkRuntimeStage::WifiReady
        | NetworkRuntimeStage::RelayConnecting
        | NetworkRuntimeStage::SubscriptionSent => {
            Some(if last_error_class == NetworkRuntimeError::None {
                NetworkDisplayState::OpeningRelay
            } else {
                NetworkDisplayState::RelayFailed
            })
        }
        NetworkRuntimeStage::Online => Some(NetworkDisplayState::Online),
        NetworkRuntimeStage::ConfigError => Some(NetworkDisplayState::InvalidConfig),
    };
    if let Some(feedback) = feedback {
        let restore = (stage == NetworkRuntimeStage::Online).then_some(Duration::from_secs(2));
        // Automatic connectivity churn does not wake a panel already blanked
        // for burn-in protection. Explicit management transitions do.
        show_network_feedback(ctx, feedback, false, restore);
    }
}

/// Collapse detailed internal transport errors into the closed diagnostic
/// vocabulary exposed over USB. Raw messages stay in local logs only.
fn runtime_error_class(error: &str) -> NetworkRuntimeError {
    if error.contains("silent") {
        NetworkRuntimeError::RelaySilent
    } else if error.starts_with("ws handshake")
        || error.starts_with("ws upgrade")
        || error.starts_with("ws req")
        || error.starts_with("ws resp")
    {
        NetworkRuntimeError::WebsocketUpgrade
    } else if error.contains("closed") || error.contains("eof") {
        NetworkRuntimeError::RelayClosed
    } else if error.contains("frame") || error.contains("protocol") {
        NetworkRuntimeError::RelayProtocol
    } else {
        NetworkRuntimeError::RelayTransport
    }
}

/// Host out of a `wss://`/`ws://` relay URL (scheme, port and path stripped).
fn relay_host(url: &str) -> &str {
    let h = url.trim_start_matches("wss://").trim_start_matches("ws://");
    let h = h.split('/').next().unwrap_or(h);
    h.split(':').next().unwrap_or(h)
}

/// Two relay URLs naming the same endpoint, ignoring scheme case and a
/// trailing slash. Used to decide whether a client's relay is already served.
fn same_relay(a: &str, b: &str) -> bool {
    let norm = |u: &str| u.trim().trim_end_matches('/').to_ascii_lowercase();
    norm(a) == norm(b)
}

/// One live relay connection: TLS + WS + subscription plus its keepalive
/// bookkeeping. The primary session rotates over the configured relay set on
/// failure; a pinned session is bound to one URL joined at nostrconnect
/// pairing and reconnects only to that URL.
struct RelaySession {
    tls: Tls,
    url: String,
    rx: Vec<u8>,
    last_rx: Instant,
    last_ping: Instant,
    last_resub: Instant,
    recv_timeout_on: bool,
    /// The subscription REQ sent at connect, re-sent periodically to self-heal.
    sub_req: String,
    pinned: bool,
    /// Bytes still owed from an oversize frame being discarded. See `try_parse`:
    /// an over-cap frame is skipped rather than killing the session, and it may
    /// span several reads, so the remainder is carried here between pump passes.
    skip: usize,
}

/// A relay joined at nostrconnect pairing because the client dictated it.
/// Persisted to NVS so the pairing survives reboot; pruned when the slot that
/// created it is revoked.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PinnedRelay {
    url: String,
    /// Master slot and client slot the pairing created, for revoke-time pruning.
    ms: u8,
    si: u8,
    /// Not persisted: next reconnect attempt.
    #[serde(skip, default = "Instant::now")]
    next_attempt: Instant,
    /// Not persisted: consecutive dial failures, drives the exponential backoff.
    #[serde(skip)]
    fails: u32,
}

/// The relay sessions OTHER than the one currently being pumped, plus the
/// pinned-relay bookkeeping. The main loop split-borrows: it takes the active
/// session out of the vec, so a management command (nostrconnect dial-out)
/// can add or address sessions without aliasing the one it arrived on.
struct RelayPool<'p> {
    others: &'p mut Vec<RelaySession>,
    pinned: &'p mut Vec<PinnedRelay>,
}

/// Load the persisted pinned-relay list. Absent/corrupt ⇒ empty.
fn load_pinned(nvs: &mut EspNvs<NvsDefault>) -> Vec<PinnedRelay> {
    let mut buf = [0u8; 512];
    match nvs.get_blob(PINNED_NVS_KEY, &mut buf) {
        Ok(Some(data)) => serde_json::from_slice(data).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Persist the pinned-relay list (bounded by MAX_SESSIONS - 1 in practice) and
/// verify the exact bytes before a pairing reports durable reachability.
fn save_pinned(nvs: &mut EspNvs<NvsDefault>, pinned: &[PinnedRelay]) -> bool {
    match serde_json::to_vec(pinned) {
        Ok(json) => {
            if let Err(e) = nvs.set_blob(PINNED_NVS_KEY, &json) {
                log::error!("[relay] persist pinned relays: {e:?}");
            }
            match nvs.blob_len(PINNED_NVS_KEY) {
                Ok(Some(len)) if len == json.len() => {
                    let mut verify = vec![0u8; len];
                    matches!(
                        nvs.get_blob(PINNED_NVS_KEY, &mut verify),
                        Ok(Some(stored)) if stored == json.as_slice()
                    )
                }
                Ok(Some(len)) => {
                    log::error!(
                        "[relay] pinned relay read-back length mismatch: {len} != {}",
                        json.len()
                    );
                    false
                }
                Ok(None) => {
                    log::error!("[relay] pinned relay read-back missing");
                    false
                }
                Err(e) => {
                    log::error!("[relay] pinned relay read-back failed: {e:?}");
                    false
                }
            }
        }
        Err(e) => {
            log::error!("[relay] serialise pinned relays: {e}");
            false
        }
    }
}

/// Drop pinned relays whose creating slot no longer exists (revoked), and any
/// duplicates of a configured relay (nothing to pin if the primary set covers
/// it). Returns true when the list changed.
fn prune_pinned(
    pinned: &mut Vec<PinnedRelay>,
    policy_engine: &PolicyEngine,
    cfg_relays: &[String],
) -> bool {
    let before = pinned.len();
    pinned.retain(|p| {
        let slot_alive = policy_engine
            .list_slots(p.ms)
            .iter()
            .any(|s| s.slot_index == p.si);
        let already_configured = cfg_relays.iter().any(|r| same_relay(r, &p.url));
        slot_alive && !already_configured
    });
    pinned.len() != before
}

/// Bring up wifi and serve the relay forever. Never returns.
#[allow(clippy::too_many_arguments)]
pub fn run_wifi_standalone<'d, 'b>(
    modem: Modem,
    cfg: &NetConfig,
    masters: &mut [LoadedMaster],
    personas: &mut Vec<crate::personas::LoadedPersona>,
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'d>,
    buttons: &crate::button::Buttons<'b>,
    policy_engine: &mut PolicyEngine,
    identity_caches: &mut Vec<IdentityCache>,
    nvs: &mut EspNvs<NvsDefault>,
    op_mgmt: Option<[u8; 32]>,
    network_trial_id: Option<String>,
    usb: &mut SerialPort<'_>,
) -> ! {
    log::info!(
        "[relay] WiFi-standalone: SSID={:?} (+{} fallback(s)), {} relay(s), {} master(s), mgmt={}",
        cfg.ssid,
        cfg.networks.len(),
        cfg.relays.len(),
        masters.len(),
        if op_mgmt.is_some() { "on" } else { "off" }
    );
    if let Some(op) = &op_mgmt {
        log::info!("[relay] operator (op_mgmt): {}", hex_encode(op));
    }

    let sysloop = EspSystemEventLoop::take().expect("relay: sysloop");
    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(modem, sysloop.clone(), None).expect("relay: wifi new"),
        sysloop,
    )
    .expect("relay: blocking wrap");

    // Ordered join candidates: the primary pair first, then the stored
    // fallback list. Owned copies so the list is free of `cfg` borrows for
    // the lifetime of the loop below. Any credential that does not fit the
    // fixed-capacity ESP-IDF fields is dropped, loudly (FW-M4): a config
    // written by older/looser firmware must degrade to a USB-servable
    // config error, never a boot-time panic.
    let wifi_candidates: Vec<(String, String)> = cfg
        .network_candidates()
        .into_iter()
        .map(|(ssid, password)| (ssid.to_string(), password.to_string()))
        .filter(|(ssid, password)| {
            let usable = wifi_client_config(ssid, password).is_some();
            if !usable {
                log::error!(
                    "[relay] stored credential for {ssid:?} exceeds ESP-IDF field bounds — unusable"
                );
            }
            usable
        })
        .collect();
    let wifi_config_ok = !wifi_candidates.is_empty();
    let mut wifi_candidate_idx = 0usize;
    if wifi_config_ok {
        select_wifi_candidate(&mut wifi, &wifi_candidates, wifi_candidate_idx);
    }
    wifi.start().expect("relay: wifi start");
    // RF entropy source is live from here on — plain esp_fill_random (via
    // crate::fill_random) is a true RNG again.
    crate::set_radio_active();

    // All configured relays. The signer listens on one at a time and fails over
    // to the next on any disconnect, so a single dead or quiet relay never takes
    // it offline. Bunker URIs advertise every relay, so clients publish to all of
    // them and still meet the device on whichever one it is currently serving.
    let relays: Vec<String> = cfg
        .relays
        .iter()
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();
    let mut relay_idx = 0usize;

    // Locked at rest (PIN/vault encryption)? The full signer cannot run — its
    // subscription and every decrypt need the seeds. Serve only the vault
    // delivery channel (plus USB PIN/vault unlock) until they are decrypted,
    // then fall through to the normal boot below with the radio already up.
    if crate::pin::is_locked(masters) {
        if let Some(op) = &op_mgmt {
            if !relays.is_empty() {
                log::info!("[relay] seeds locked — entering vault-unlock phase");
                locked_relay_phase(
                    &mut wifi,
                    &wifi_candidates,
                    &relays,
                    op,
                    secp,
                    masters,
                    personas,
                    nvs,
                    usb,
                    display,
                    buttons,
                );
            }
        }
    }

    let network_trial_deadline = network_trial_id
        .as_ref()
        .map(|_| Instant::now() + NETWORK_TRIAL_TIMEOUT);
    let mut ctx = SignCtx {
        masters,
        secp,
        display,
        buttons,
        policy_engine,
        identity_caches,
        nvs,
        personas,
        ota_session: None,
        op_mgmt,
        relay_url: relays.first().cloned().unwrap_or_default(),
        relays: relays.clone(),
        // Do not persist read request ids: Sapwood polls every four seconds and
        // would otherwise cause tens of thousands of needless NVS writes/day.
        // The old `mgmt_seen` blob from earlier firmware is intentionally ignored.
        seen: Vec::new(),
        display_on: true,
        last_activity: Instant::now(),
        identity_name: None,
        identity_name_ts: 0,
        sign_audit: Vec::new(),
        sign_audit_seq: 0,
        nip46_seen: Vec::new(),
        wrap_seen: Vec::new(),
        wrap_ledger: crate::notes::load_wrap_ledger()
            .and_then(|blob| heartwood_common::wrap_ledger::WrapLedger::decode(&blob))
            .unwrap_or_default(),
        wrap_retry_when_room: false,
        wrap_lapsed: Vec::new(),
        button_settle: false,
        catch_up: None,
        dial_cooldown: None,
        network_trial_id,
        network_trial_deadline,
        network_restart_at: None,
        network_runtime: NetworkRuntimeStatus::starting(),
        network_display_restore_at: None,
        idle_page: 0,
        resubscribe_needed: false,
        parks: Vec::new(),
        park_tombstones: Vec::new(),
        petitions: Vec::new(),
        audit_last_stamped: 0,
        audit_emit_seq: 0,
        reply_clock: heartwood_common::reply_clock::ReplyClock::new(),
        button_cards: Vec::new(),
    };

    // Pinned relays joined at nostrconnect pairing, restored from NVS. Prune
    // entries whose creating slot has since been revoked over USB.
    let mut pinned = load_pinned(ctx.nvs);
    if prune_pinned(&mut pinned, ctx.policy_engine, &relays) {
        let _ = save_pinned(ctx.nvs, &pinned);
    }
    if !pinned.is_empty() {
        log::info!("[relay] restored {} pinned relay(s) from NVS", pinned.len());
    }

    // Live sessions: at most MAX_SESSIONS — one primary rotating over the
    // configured set, the rest pinned. The vec is split-borrowed each pump so
    // management commands can dial new sessions (see RelayPool).
    let mut sessions: Vec<RelaySession> = Vec::new();
    let mut primary_next = Instant::now();

    // Relay-health watchdog + heap telemetry (see RELAY_HEALTH_RESTART_AFTER).
    let mut last_relay_healthy = Instant::now();
    let mut next_heap_log = Instant::now();

    // Opening a USB-UART adapter commonly resets the classic ESP32. Sapwood
    // sends its first read-only probe as soon as the port opens, so service the
    // bytes already waiting in UART before the first blocking WiFi/TLS dial.
    // Without this grace window a healthy T-Display can look absent for tens of
    // seconds while networking starts, precisely when USB is needed for local
    // recovery. This does not hold the radio off: WiFi is already started and
    // the normal relay loop begins immediately afterwards.
    let usb_startup_grace = Instant::now() + Duration::from_secs(2);
    while Instant::now() < usb_startup_grace {
        poll_usb(usb, &mut ctx, Some(&mut wifi));
        FreeRtos::delay_ms(20);
    }

    loop {
        crate::wdt::feed();
        network_state_tick(&mut ctx);
        // Expire overdue C4 parks into tombstones so late verdicts still land.
        service_parks(&mut ctx);
        // Advance held signing confirmations; restore the idle identity card
        // once the last hold expires. An approval card outranks them: it owns
        // the screen until the operator answers it.
        if ctx.display_on && !approval_card_open(&ctx) && crate::confirm::service(ctx.display) {
            ctx.idle_page = 0;
            show_idle_identity(&mut ctx);
        }
        if ctx.network_restart_at.is_some() {
            // A management response already scheduled a restart. Do not enter
            // any socket read (including another session's degraded blocking
            // read) before the deadline is serviced at the top of the loop.
            FreeRtos::delay_ms(20);
            continue;
        }
        if !wifi_config_ok {
            // No stored credential is usable (FW-M4) — a config error,
            // fixable only over USB. Exactly like the no-relay case below:
            // not the watchdog's case, and the cable stays fully served.
            last_relay_healthy = Instant::now();
            log::error!("[relay] no usable wifi credential in stored config");
            set_network_runtime(
                &mut ctx,
                NetworkRuntimeStage::ConfigError,
                true,
                false,
                NetworkRuntimeError::InvalidConfig,
            );
            let until = Instant::now() + Duration::from_secs(10);
            while Instant::now() < until {
                poll_usb(usb, &mut ctx, Some(&mut wifi));
                service_button(&mut ctx);
                FreeRtos::delay_ms(20);
            }
            continue;
        }
        // Every relay session depends on the station link; restore it before
        // attempting any relay dial.
        if !wifi.is_up().unwrap_or(false) {
            // Offline is not rot: a restart cannot fix the AP, and USB
            // service (fixing credentials over the cable) must never be
            // interrupted. The health watchdog only times unhealthy periods
            // while the station link is up.
            last_relay_healthy = Instant::now();
            let previous_error = ctx.network_runtime.last_error_class;
            set_network_runtime(
                &mut ctx,
                NetworkRuntimeStage::WifiConnecting,
                false,
                false,
                previous_error,
            );
            if !sessions.is_empty() {
                log::warn!(
                    "[relay] wifi down; dropping {} live session(s)",
                    sessions.len()
                );
                sessions.clear();
            }
            if let Err(e) = wifi.connect().and_then(|_| wifi.wait_netif_up()) {
                // Keep serving USB while wifi is unreachable, so a bad SSID or
                // password can always be fixed over the cable.
                log::error!("[relay] wifi connect failed: {e:?}; serving USB, retry in 3s");
                // Rotate to the next stored network for the next attempt. With
                // a single configured network this re-selects the same one.
                wifi_candidate_idx = wifi_candidate_idx.wrapping_add(1);
                select_wifi_candidate(&mut wifi, &wifi_candidates, wifi_candidate_idx);
                set_network_runtime(
                    &mut ctx,
                    NetworkRuntimeStage::WifiConnecting,
                    false,
                    false,
                    NetworkRuntimeError::WifiUnavailable,
                );
                let until = Instant::now() + Duration::from_secs(3);
                while Instant::now() < until {
                    poll_usb(usb, &mut ctx, Some(&mut wifi));
                    service_button(&mut ctx);
                    FreeRtos::delay_ms(20);
                }
                continue;
            }
            log::info!("[relay] wifi up");
            set_network_runtime(
                &mut ctx,
                NetworkRuntimeStage::WifiReady,
                true,
                false,
                NetworkRuntimeError::None,
            );
        }

        if relays.is_empty() {
            // Config error, fixable only over USB — not the watchdog's case.
            last_relay_healthy = Instant::now();
            log::error!("[relay] no relay configured");
            set_network_runtime(
                &mut ctx,
                NetworkRuntimeStage::ConfigError,
                true,
                false,
                NetworkRuntimeError::InvalidConfig,
            );
            // Keep the cable fully served while stuck — this state is only
            // fixable over USB.
            let until = Instant::now() + Duration::from_secs(10);
            while Instant::now() < until {
                poll_usb(usb, &mut ctx, Some(&mut wifi));
                service_button(&mut ctx);
                FreeRtos::delay_ms(20);
            }
            continue;
        }

        // Wake the panel promptly on a BOOT-button press, and serve USB, once
        // per pass regardless of how many sessions are live or connecting.
        // While an approval card is up the button belongs to that decision,
        // so the idle carousel does not get to consume the press.
        if !approval_card_open(&ctx) {
            service_button(&mut ctx);
        }
        // The WiFi driver is lent to USB only while no relay session is live —
        // a scan mid-connection would knock the link off its channel, so a
        // 0x55 during live service is declined (matches the old per-session
        // loop, which lent the driver only in the between-sessions gaps).
        if sessions.is_empty() {
            poll_usb(usb, &mut ctx, Some(&mut wifi));
        } else {
            poll_usb(usb, &mut ctx, None);
        }

        // Advance any approval card. This is the whole point of holding the
        // ask rather than blocking inside the dispatch: the cable was served
        // immediately above, and the sessions are pumped immediately below,
        // both of them while the card is still on screen (#64).
        service_button_cards(&mut ctx, &mut sessions);

        // Ensure the primary session (rotates over the configured set).
        if !sessions.iter().any(|s| !s.pinned) && Instant::now() >= primary_next {
            // Same heap guard as the pinned dial below: a fresh mbedTLS
            // session costs ~40-50KB and an allocation failure deep inside
            // the TLS or WiFi stack can abort the chip rather than error.
            // Skipping the dial keeps USB served; the relay-health watchdog
            // bounds how long a heap this tight may keep the signer offline.
            let free = unsafe { esp_idf_svc::sys::esp_get_free_heap_size() };
            let largest = unsafe {
                esp_idf_svc::sys::heap_caps_get_largest_free_block(
                    esp_idf_svc::sys::MALLOC_CAP_8BIT,
                )
            };
            if free < DIAL_MIN_FREE_HEAP || largest < DIAL_MIN_LARGEST_BLOCK {
                log::warn!(
                    "[relay] heap too tight to dial (free {free} B, largest {largest} B); retry in 3s"
                );
                primary_next = Instant::now() + PRIMARY_BACKOFF;
            } else {
                let previous_error = ctx.network_runtime.last_error_class;
                set_network_runtime(
                    &mut ctx,
                    NetworkRuntimeStage::RelayConnecting,
                    true,
                    false,
                    previous_error,
                );
                let url = relays[relay_idx % relays.len()].clone();
                let host = relay_host(&url).to_string();
                if relays.len() > 1 {
                    log::info!(
                        "[relay] serving via {host} (relay {} of {})",
                        relay_idx % relays.len() + 1,
                        relays.len()
                    );
                }
                match connect_relay(&url, false, &mut ctx) {
                    Ok(s) => {
                        ctx.relay_url = url;
                        sessions.push(s);
                        retune_recv_timeouts(&mut sessions);
                        set_network_runtime(
                            &mut ctx,
                            NetworkRuntimeStage::SubscriptionSent,
                            true,
                            true,
                            NetworkRuntimeError::None,
                        );
                    }
                    Err(e) => {
                        log::error!("[relay] {e}; failing over in 3s");
                        let error_class = runtime_error_class(&e);
                        set_network_runtime(
                            &mut ctx,
                            NetworkRuntimeStage::RelayConnecting,
                            true,
                            false,
                            error_class,
                        );
                        relay_idx = relay_idx.wrapping_add(1);
                        primary_next = Instant::now() + PRIMARY_BACKOFF;
                    }
                }
            }
        }

        // Ensure pinned sessions, capacity and backoff permitting. A pinned
        // dial failing never advances the primary rotation, and no pinned dial
        // happens while any live session runs degraded (a blocking-read
        // session already stalls the loop; more sockets multiply the stall).
        let any_degraded = sessions.iter().any(|se| !se.recv_timeout_on);
        for p in pinned.iter_mut() {
            if sessions.len() >= MAX_SESSIONS || any_degraded {
                break;
            }
            if sessions.iter().any(|s| same_relay(&s.url, &p.url))
                || Instant::now() < p.next_attempt
            {
                continue;
            }
            // Same heap guard as the pairing-time dial: never let an automatic
            // reconnect abort the chip on a tight heap. Counts as a failure so
            // the backoff still decays a persistently tight board to rare probes.
            let free = unsafe { esp_idf_svc::sys::esp_get_free_heap_size() };
            let largest = unsafe {
                esp_idf_svc::sys::heap_caps_get_largest_free_block(
                    esp_idf_svc::sys::MALLOC_CAP_8BIT,
                )
            };
            if free < DIAL_MIN_FREE_HEAP || largest < DIAL_MIN_LARGEST_BLOCK {
                p.fails = p.fails.saturating_add(1);
                let delay = (PINNED_BACKOFF * (1u32 << p.fails.min(6))).min(PINNED_BACKOFF_MAX);
                log::warn!(
                    "[relay] pinned {}: heap too tight for a second session (free {free} B, largest {largest} B); retry in {}s",
                    p.url,
                    delay.as_secs()
                );
                p.next_attempt = Instant::now() + delay;
                continue;
            }
            match connect_relay(&p.url, true, &mut ctx) {
                Ok(s) => {
                    log::info!("[relay] pinned relay joined: {}", p.url);
                    p.fails = 0;
                    sessions.push(s);
                    retune_recv_timeouts(&mut sessions);
                }
                Err(e) => {
                    p.fails = p.fails.saturating_add(1);
                    let delay = (PINNED_BACKOFF * (1u32 << p.fails.min(6))).min(PINNED_BACKOFF_MAX);
                    log::warn!(
                        "[relay] pinned {}: {e}; retry in {}s",
                        p.url,
                        delay.as_secs()
                    );
                    p.next_attempt = Instant::now() + delay;
                }
            }
        }

        // Relay-health watchdog: a session that is live while the heap can
        // still place a response proves the signer useful. Anything else —
        // every dial refused or failing, or a heap too fragmented to publish
        // — sustained for RELAY_HEALTH_RESTART_AFTER is rot a reboot alone
        // clears, so take a controlled one and attribute it: the crumb
        // survives a software reset and the next boot reports it.
        let health_now = Instant::now();
        let heap_log_due = health_now >= next_heap_log;
        if !sessions.is_empty() || heap_log_due {
            let free = unsafe { esp_idf_svc::sys::esp_get_free_heap_size() };
            let largest = unsafe {
                esp_idf_svc::sys::heap_caps_get_largest_free_block(
                    esp_idf_svc::sys::MALLOC_CAP_8BIT,
                )
            };
            if !sessions.is_empty() && largest >= RELAY_HEALTH_MIN_BLOCK {
                last_relay_healthy = health_now;
            }
            if heap_log_due {
                log::info!(
                    "[relay] heap: free {free} B, largest {largest} B, {} session(s)",
                    sessions.len()
                );
                next_heap_log = health_now + RELAY_HEAP_LOG_INTERVAL;
            }
        }
        if ctx.network_trial_id.is_none()
            && ctx.ota_session.is_none()
            && health_now.duration_since(last_relay_healthy) >= RELAY_HEALTH_RESTART_AFTER
        {
            let largest = unsafe {
                esp_idf_svc::sys::heap_caps_get_largest_free_block(
                    esp_idf_svc::sys::MALLOC_CAP_8BIT,
                )
            };
            log::error!(
                "[relay] no usable relay session for {}s (largest free block {largest} B); restarting to clear the heap",
                RELAY_HEALTH_RESTART_AFTER.as_secs()
            );
            crate::crash_crumb::set(&format!(
                "relay watchdog: deaf {}s largest {}k",
                RELAY_HEALTH_RESTART_AFTER.as_secs(),
                largest / 1024
            ));
            FreeRtos::delay_ms(200);
            unsafe { esp_idf_svc::sys::esp_restart() };
        }

        if sessions.is_empty() {
            // Nothing live and nothing dialled this pass — don't busy-spin.
            FreeRtos::delay_ms(20);
            continue;
        }

        // Pump each session: split-borrow the active one out so management
        // commands arriving on it can dial/address the others.
        let mut i = 0;
        while i < sessions.len() {
            let mut s = sessions.swap_remove(i);
            let step = {
                let mut pool = RelayPool {
                    others: &mut sessions,
                    pinned: &mut pinned,
                };
                session_step(&mut s, &mut ctx, &mut pool)
            };
            match step {
                Ok(()) => {
                    sessions.insert(i.min(sessions.len()), s);
                    i += 1;
                }
                Err(e) => {
                    if s.pinned {
                        log::warn!("[relay] pinned {} dropped: {e}", s.url);
                        if let Some(p) = pinned.iter_mut().find(|p| same_relay(&p.url, &s.url)) {
                            // A connect succeeded (fails reset then), so this
                            // counts one failure: flaky relays settle at ~30s.
                            p.fails = p.fails.saturating_add(1);
                            let delay =
                                (PINNED_BACKOFF * (1u32 << p.fails.min(6))).min(PINNED_BACKOFF_MAX);
                            p.next_attempt = Instant::now() + delay;
                        }
                    } else {
                        log::error!("[relay] {e}; failing over in 3s");
                        let error_class = runtime_error_class(&e);
                        set_network_runtime(
                            &mut ctx,
                            NetworkRuntimeStage::RelayConnecting,
                            true,
                            false,
                            error_class,
                        );
                        relay_idx = relay_idx.wrapping_add(1);
                        primary_next = Instant::now() + PRIMARY_BACKOFF;
                    }
                    retune_recv_timeouts(&mut sessions);
                    // `s` dropped here; do not advance `i` — swap_remove moved
                    // a new candidate into this position.
                }
            }
        }

        // The persona set changed this pass (derive or removal, over any
        // transport): rebuild the "hw" subscription and re-REQ it on every
        // live session NOW — the same-id REQ replaces the filters server-side
        // — instead of waiting for a reconnect or the keepalive re-REQ (which
        // would resend the stale stored filters). The stored copy is updated
        // so the keepalive stays truthful. A failed send is left to the
        // session's own silence/reconnect machinery.
        // A RECEIVE card settling, or the letterbox regaining room, raises
        // the same flag: the catch-up filter goes out once, and the stored
        // keepalive copy stays live-only.
        // Re-run once ANY room appears (a trusted sender's room is the
        // wider of the two); a stranger's wrap that still does not fit is
        // cheaply deferred again.
        if ctx.wrap_retry_when_room
            && crate::notes::with_locker(|n| n.store.has_room_for_received(true))
        {
            ctx.wrap_retry_when_room = false;
            ctx.resubscribe_needed = true;
        }
        if ctx
            .wrap_lapsed
            .first()
            .is_some_and(|(_, at)| at.elapsed() >= LAPSED_WRAP_RETRY)
        {
            let (id, _) = ctx.wrap_lapsed.remove(0);
            ctx.wrap_seen.retain(|seen| *seen != id);
            ctx.resubscribe_needed = true;
        }
        if ctx.resubscribe_needed {
            ctx.resubscribe_needed = false;
            if !sessions.is_empty() {
                let sub_req = build_sub_req(&ctx, true);
                let keepalive_req = build_sub_req(&ctx, false);
                ctx.catch_up = Some(CatchUp { delivered: 0, oldest: u64::MAX, pages: 0 });
                for s in sessions.iter_mut() {
                    s.sub_req = keepalive_req.clone();
                    s.last_resub = Instant::now();
                    if let Err(e) = ws_send(&mut s.tls, OP_TEXT, sub_req.as_bytes()) {
                        log::warn!(
                            "[relay] persona resubscribe on {} failed: {e}; session will heal on reconnect",
                            s.url
                        );
                    }
                }
                log::info!("[relay] re-subscribed with the fresh persona set");
            }
        }

        // A revoke (relay or USB) may have orphaned a pinned relay: prune the
        // list when its creating slot is gone, and close any session whose pin
        // was dropped. Cheap (slots × pinned, pinned ≤ 1) so it runs each pass.
        if prune_pinned(&mut pinned, ctx.policy_engine, &relays) {
            let _ = save_pinned(ctx.nvs, &pinned);
        }
        let before = sessions.len();
        sessions.retain(|se| !se.pinned || pinned.iter().any(|p| same_relay(&p.url, &se.url)));
        if sessions.len() != before {
            log::info!("[relay] closed pinned session(s) after revoke");
            retune_recv_timeouts(&mut sessions);
        }

        // Burn-in protection is global, not per-session: blank the OLED after
        // inactivity; a PRG press (top of loop) or a request wakes it.
        let now = Instant::now();
        if ctx.display_on && now.duration_since(ctx.last_activity) >= DISPLAY_TIMEOUT {
            crate::oled::sleep_display(ctx.display);
            ctx.display_on = false;
            ctx.idle_page = 0;
            // Observable on the serial tap: lets a bench run measure how long
            // an outcome card actually stayed lit before burn-in blanking.
            log::info!("[relay] display blanked after inactivity");
        }
    }
}

/// Apply delayed network restarts only from the outer relay loop, after the
/// management handler has returned and its encrypted response has been sent.
/// A live candidate that is never committed is aborted and rebooted back to A.
fn network_state_tick(ctx: &mut SignCtx) {
    let now = Instant::now();
    // Deferred while a card is up, not cancelled: the deadline stays pending
    // so the identity screen still returns once the operator has answered.
    // Firing it under a live card is what put "N masters loaded" over a
    // RECEIVE card in the section 14 bench run.
    if ctx
        .network_display_restore_at
        .map(|deadline| now >= deadline)
        .unwrap_or(false)
        && !approval_card_open(ctx)
    {
        ctx.network_display_restore_at = None;
        show_idle_identity(ctx);
    }

    if ctx
        .network_restart_at
        .map(|deadline| now >= deadline)
        .unwrap_or(false)
    {
        log::info!("[relay] applying scheduled network restart");
        FreeRtos::delay_ms(100);
        unsafe { esp_idf_svc::sys::esp_restart() };
    }

    if ctx
        .network_trial_deadline
        .map(|deadline| now >= deadline)
        .unwrap_or(false)
    {
        let transaction_id = ctx.network_trial_id.clone().unwrap_or_default();
        log::warn!(
            "[relay] network trial {} timed out before commit — rolling back",
            transaction_id
        );
        match crate::net_config_store::rollback_trial(ctx.nvs, &transaction_id) {
            Ok(true) => {
                // Commit crossed the authoritative active=B write before its
                // ACK/cleanup failed. Finalisation won; never reboot/rollback B.
                log::info!("[relay] timed trial reconciled as already committed");
                ctx.network_trial_id = None;
                ctx.network_trial_deadline = None;
                return;
            }
            Ok(false) => {}
            Err(_) => {
                if crate::net_config_store::read_trial(ctx.nvs).is_some() {
                    // NVS may be transiently unable to write the terminal
                    // marker. Preserve the last valid trial proof and retry;
                    // never erase/reboot a possibly committed transaction.
                    log::error!(
                        "[relay] network trial finalisation failed; retaining proof for retry"
                    );
                    ctx.network_trial_deadline = Some(Instant::now() + Duration::from_secs(10));
                    return;
                }
                // Only genuinely unreadable/corrupt trial state is safe to
                // clear before returning to untouched active A.
                let _ = crate::net_config_store::clear_trial(ctx.nvs);
            }
        }
        show_network_feedback(ctx, NetworkDisplayState::UpdateFailed, true, None);
        FreeRtos::delay_ms(800);
        show_network_feedback(ctx, NetworkDisplayState::RollingBack, true, None);
        FreeRtos::delay_ms(800);
        unsafe { esp_idf_svc::sys::esp_restart() };
    }
}

/// Split `RECV_TIMEOUT_MS` across live sessions so one pass of the pump loop
/// still wakes about once a second for USB and keepalive work, no matter how
/// many sockets are quiet.
fn retune_recv_timeouts(sessions: &mut [RelaySession]) {
    let n = sessions.len().max(1) as i64;
    for s in sessions.iter_mut() {
        if s.recv_timeout_on {
            if let Err(e) = set_recv_timeout(&mut s.tls, RECV_TIMEOUT_MS / n) {
                log::warn!("[relay] recv-timeout retune failed on {}: {e}", s.url);
            }
        }
    }
}

/// The subscription REQ for one session. NIP-46 (24133) is addressable to any
/// served identity — each master AND every derived persona — so a persona's
/// bunker URI reaches the device exactly as it does on the USB path.
/// Management (24134), when an operator is configured, stays master-only: the
/// master pubkey is the v1 management address; personas are signing-only. Two
/// filters keep that boundary explicit. limit:0 → no stored replay, live
/// stream only. A third filter fetches our own masters' kind-0 profiles (by
/// author, limit:1 → the stored replaceable event) for the idle screen name.
/// `catch_up` widens the gift-wrap filter to stored events; see there.
fn build_sub_req(ctx: &SignCtx, catch_up: bool) -> String {
    let quoted = |pk: &[u8; 32]| format!("\"{}\"", hex_encode(pk));
    let master_p = ctx
        .masters
        .iter()
        .map(|m| quoted(&m.pubkey))
        .collect::<Vec<_>>();
    let master_p_list = master_p.join(",");
    let mut nip46_p = master_p.clone();
    nip46_p.extend(ctx.personas.iter().map(|p| quoted(&p.pubkey)));
    let nip46_p_list = nip46_p.join(",");
    let profile_filter = format!(r##"{{"kinds":[0],"authors":[{master_p_list}],"limit":1}}"##);
    // Bearer notes gift-wrapped to a master npub. A wrap is a stored event
    // and nobody but this device can open one sealed to its key, so the
    // connect-time REQ (and the one after a settled card) asks for what
    // arrived while the device was off: newest first, bounded, and no older
    // than the last decision less the NIP-59 backdate. The keepalive re-REQ
    // goes back to live-only so the relay is not replaying every 40 s.
    let wrap_filter = if catch_up {
        wrap_catch_up_filter(ctx, None)
    } else {
        format!(r##"{{"kinds":[{GIFT_WRAP_KIND}],"#p":[{master_p_list}],"limit":0}}"##)
    };
    if ctx.op_mgmt.is_some() {
        format!(
            r##"["REQ","hw",{{"kinds":[{NIP46_KIND}],"#p":[{nip46_p_list}],"limit":0}},{{"kinds":[{MGMT_KIND}],"#p":[{master_p_list}],"limit":0}},{profile_filter},{wrap_filter}]"##
        )
    } else {
        format!(
            r##"["REQ","hw",{{"kinds":[{NIP46_KIND}],"#p":[{nip46_p_list}],"limit":0}},{profile_filter},{wrap_filter}]"##
        )
    }
}

/// At the end of a catch-up page: if the relay filled it, there may be
/// older wraps behind it, so ask for the next page below the oldest seen,
/// on a side subscription that is closed again once it has answered.
fn continue_catch_up(s: &mut RelaySession, ctx: &mut SignCtx) {
    let Some(c) = ctx.catch_up.as_mut() else {
        return;
    };
    let full_page = c.delivered >= heartwood_common::wrap_ledger::CATCH_UP_LIMIT;
    if full_page && c.pages < CATCH_UP_MAX_PAGES && c.oldest > 0 {
        c.pages += 1;
        c.delivered = 0;
        let until = c.oldest - 1;
        let page = c.pages;
        let req = format!(r##"["REQ","{CATCH_UP_PAGE_SUB}",{}]"##, wrap_catch_up_filter(ctx, Some(until)));
        match ws_send(&mut s.tls, OP_TEXT, req.as_bytes()) {
            Ok(()) => log::info!("[relay] catch-up page {page}: wraps older than {until}"),
            Err(e) => {
                log::warn!("[relay] catch-up page failed to send: {e}");
                ctx.catch_up = None;
            }
        }
        return;
    }
    if c.pages > 0 {
        if full_page {
            log::warn!("[relay] catch-up stopped after {} pages with more behind", c.pages);
        }
        let close = format!(r##"["CLOSE","{CATCH_UP_PAGE_SUB}"]"##);
        let _ = ws_send(&mut s.tls, OP_TEXT, close.as_bytes());
    }
    ctx.catch_up = None;
}

/// The stored-wrap filter: newest CATCH_UP_LIMIT, no older than the ledger
/// allows, and when paging, strictly older than `until`.
fn wrap_catch_up_filter(ctx: &SignCtx, until: Option<u64>) -> String {
    let master_p_list = ctx
        .masters
        .iter()
        .map(|m| format!("\"{}\"", hex_encode(&m.pubkey)))
        .collect::<Vec<_>>()
        .join(",");
    let since = ctx
        .wrap_ledger
        .since(wall_clock_estimate())
        .map(|s| format!(r##","since":{s}"##))
        .unwrap_or_default();
    let until = until.map(|u| format!(r##","until":{u}"##)).unwrap_or_default();
    format!(
        r##"{{"kinds":[{GIFT_WRAP_KIND}],"#p":[{master_p_list}]{since}{until},"limit":{}}}"##,
        heartwood_common::wrap_ledger::CATCH_UP_LIMIT
    )
}

/// Open one relay session: TLS → WS handshake → recv timeout → subscribe.
fn connect_relay(url: &str, pinned: bool, ctx: &mut SignCtx) -> Result<RelaySession, String> {
    let sub_req = build_sub_req(ctx, true);
    let keepalive_req = build_sub_req(ctx, false);
    ctx.catch_up = Some(CatchUp { delivered: 0, oldest: u64::MAX, pages: 0 });
    // A session without the recv timeout would starve its peers, so a pinned
    // dial (or a network trial, whose rollback deadline must stay live)
    // refuses to run degraded.
    let require_recv_timeout = pinned || ctx.network_trial_id.is_some();
    connect_relay_raw(url, sub_req, pinned, require_recv_timeout)
        .map(|mut s| {
            s.sub_req = keepalive_req;
            s
        })
        .map_err(|e| {
        if e == RECV_TIMEOUT_REQUIRED && require_recv_timeout {
            if pinned {
                "pinned relay needs a recv timeout (would starve the primary)".into()
            } else {
                "network trial needs a recv timeout (rollback deadline must remain live)".into()
            }
        } else {
            e
        }
    })
}

/// Sentinel error: the relay socket could not be given a recv timeout and the
/// caller required one (see [`connect_relay_raw`]).
const RECV_TIMEOUT_REQUIRED: &str = "recv-timeout required";

/// Open one relay session against a caller-supplied subscription. Split from
/// [`connect_relay`] so the locked-boot vault phase can subscribe for vault
/// deliveries without a full SignCtx. When `require_recv_timeout` is set and
/// the socket refuses one, fails with [`RECV_TIMEOUT_REQUIRED`].
fn connect_relay_raw(
    url: &str,
    sub_req: String,
    pinned: bool,
    require_recv_timeout: bool,
) -> Result<RelaySession, String> {
    let host = relay_host(url).to_string();
    // Rolling activity marker over the TLS handshake — the other place a
    // panic could strike (cert/allocation) with no request in flight.
    crate::crash_crumb::set(&format!("relay connecting {host}"));
    let mut tls = EspTls::new().map_err(|e| format!("tls init: {e:?}"))?;
    let mut tls_cfg = TlsConfig::new();
    tls_cfg.common_name = Some(&host);
    tls_cfg.timeout_ms = 10_000;
    // TCP keepalive: probe an idle link so a dead peer/NAT mapping tears the
    // socket down (~25s) instead of blocking `read` forever. Probe ACKs are
    // handled by the peer's TCP stack, so this also keeps the link alive during
    // the up-to-30s sign-approval button wait.
    tls_cfg.keep_alive_cfg = Some(KeepAliveConfig {
        enable: true,
        idle: Duration::from_secs(10),
        interval: Duration::from_secs(5),
        count: 3,
    });
    // Config::new() defaults use_crt_bundle_attach = true → Mozilla CA bundle.
    tls.connect(&host, TLS_PORT, &tls_cfg)
        .map_err(|e| format!("tls connect {host}: {e:?}"))?;
    log::info!("[relay] TLS connected to {host}:{TLS_PORT}");

    // The TLS timeout above ends with `connect`. The HTTP Upgrade temporarily
    // makes the underlying socket nonblocking and drives EspTls itself against
    // one absolute deadline, so a partial TLS record cannot restart a blocking
    // socket timeout. The original fd flags are restored before this returns.
    let upgrade_started = Instant::now();
    ws_handshake(&mut tls, &host, upgrade_started)?;
    log::info!("[relay] websocket open ({url})");

    // From here on, reads are paced by a shorter recv timeout so the pump wakes
    // periodically to ping / check silence. If this fails we degrade to
    // blocking reads (still functional for single
    // round-trips, just without the WS-ping/silence layer) rather than tearing
    // the session down — TCP keepalive still guards against a dead socket.
    // Note: a session without the timeout would starve its peers, so a pinned
    // dial refuses to run degraded (checked at the dial site).
    let recv_timeout_on = match set_recv_timeout(&mut tls, RECV_TIMEOUT_MS) {
        Ok(()) => true,
        Err(e) => {
            log::warn!(
                "[relay] recv-timeout unavailable ({e}); blocking reads, TCP-keepalive only"
            );
            false
        }
    };
    if !recv_timeout_on && require_recv_timeout {
        return Err(RECV_TIMEOUT_REQUIRED.into());
    }

    // A send timeout bounds how long a publish to a stalled peer can hold the
    // loop (see SEND_TIMEOUT_MS). Failure degrades to blocking sends — same
    // posture as the recv timeout above — but on lwIP both use one setsockopt
    // path, so if the recv timeout landed this one will too.
    if let Err(e) = set_send_timeout(&mut tls, SEND_TIMEOUT_MS) {
        log::warn!("[relay] send-timeout unavailable ({e}); blocking sends");
    }

    ws_send(&mut tls, OP_TEXT, sub_req.as_bytes())?;
    log::info!("[relay] subscribed on {url}");

    let now = Instant::now();
    Ok(RelaySession {
        tls,
        url: url.to_string(),
        rx: Vec::with_capacity(READ_BUF),
        last_rx: now,
        last_ping: now,
        last_resub: now,
        recv_timeout_on,
        sub_req,
        pinned,
        skip: 0,
    })
}

// ---------------------------------------------------------------------------
// Locked-boot vault phase (WiFi-standalone)
// ---------------------------------------------------------------------------

/// Ephemeral kind: locked-signer boot announcement, device → operator. Signed
/// by the one-time unlock keypair; content is unauthenticated metadata only.
pub const LOCKED_ANNOUNCE_KIND: u64 = 24135;
/// Ephemeral kind: vault-key delivery, operator → one-time unlock pubkey.
/// Content is NIP-44(operator → unlock_pk) of the 64-char hex vault key.
pub const VAULT_DELIVERY_KIND: u64 = 24136;
/// How often a locked signer re-announces. Ephemeral events are not stored,
/// so an operator who opens Sapwood after the boot must still hear it.
const LOCKED_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(60);

/// Publish the locked-boot announcement: a one-time unlock pubkey the
/// operator's Sapwood can encrypt the vault key to. See the security notes on
/// [`locked_relay_phase`].
fn publish_locked_announce(
    tls: &mut Tls,
    secp: &Arc<Secp256k1<SignOnly>>,
    unlock_sk: &[u8; 32],
    unlock_pk_hex: &str,
    op_mgmt: &[u8; 32],
) -> Result<(), String> {
    let unsigned = UnsignedEvent {
        pubkey: unlock_pk_hex.to_string(),
        // No wall clock on the signer; ephemeral events are never stored, so
        // relays do not age-filter them. Seconds-since-boot is fine here.
        created_at: (unsafe { esp_idf_svc::sys::esp_timer_get_time() } / 1_000_000) as u64,
        kind: LOCKED_ANNOUNCE_KIND,
        tags: vec![vec!["p".to_string(), hex_encode(op_mgmt)]],
        content: "{\"status\":\"locked\"}".to_string(),
    };
    let event_id = nip46::compute_event_id(&unsigned);
    let sig = sign::sign_hash(secp, unlock_sk, &event_id).map_err(|e| format!("sign: {e}"))?;
    let signed = SignedEvent {
        id: hex_encode(&event_id),
        pubkey: unsigned.pubkey,
        created_at: unsigned.created_at,
        kind: unsigned.kind,
        tags: unsigned.tags,
        content: unsigned.content,
        sig: hex_encode(&sig),
    };
    ws_send_event(tls, &signed)?;
    log::info!("[relay] locked: announced unlock pubkey {}…", &unlock_pk_hex[..16]);
    Ok(())
}

/// Serve the relays while the seeds are locked: announce the one-time unlock
/// pubkey, wait for the operator's vault-key delivery, and keep the USB cable
/// live for PIN/vault unlock. Returns once the seeds are decrypted in RAM.
///
/// Security notes (docs/specs/2026-08-08-encrypted-at-rest-unlock-design.md):
/// - The unlock keypair is generated fresh each locked boot and lives only in
///   RAM — a flash dump yields no unlock capability.
/// - Delivery is a live push to an ephemeral kind addressed to the one-time
///   pubkey; relays never store it, so there is no standing ciphertext to
///   scrape.
/// - The announcement is NOT authenticated (it cannot be — every attesting
///   key is locked). A fake announcement could phish a vault key out of an
///   inattentive operator, but exploiting it still requires the physical
///   flash. Sapwood therefore never auto-sends: the operator taps, and the UI
///   tells them to unlock only a signer they know rebooted.
#[allow(clippy::too_many_arguments)]
/// Client configuration for one stored network. The auth/PMF pairing keeps
/// the original single-network behaviour: ESP-IDF treats auth_method as a
/// minimum-strength scan threshold, so WPA2 admits WPA2 and stronger WPA3
/// APs, while PMF-capable supplies the WPA3 requirement without excluding a
/// WPA2 AP that does not advertise PMF. Open networks advertise no PMF.
///
/// Returns `None` when a stored credential does not fit the fixed-capacity
/// ESP-IDF fields — never a panic (FW-M4): a malformed stored config must
/// degrade to a USB-servable config error, not a boot loop.
fn wifi_client_config(ssid: &str, password: &str) -> Option<WifiConfig> {
    let (auth, pmf_cfg) = if password.is_empty() {
        (AuthMethod::None, PmfConfiguration::NotCapable)
    } else {
        (
            AuthMethod::WPA2Personal,
            PmfConfiguration::Capable { required: false },
        )
    };
    Some(WifiConfig::Client(ClientConfiguration {
        ssid: ssid.try_into().ok()?,
        password: password.try_into().ok()?,
        auth_method: auth,
        pmf_cfg,
        ..Default::default()
    }))
}

/// Point the station at candidate `idx` (mod len) of the configured network
/// list. Config failures are logged, not fatal: the next connect attempt
/// fails cleanly and the rotation moves on.
fn select_wifi_candidate(
    wifi: &mut BlockingWifi<EspWifi<'_>>,
    candidates: &[(String, String)],
    idx: usize,
) {
    if candidates.is_empty() {
        return;
    }
    let (ssid, password) = &candidates[idx % candidates.len()];
    if candidates.len() > 1 {
        log::info!(
            "[relay] wifi network {}/{}: {:?}",
            idx % candidates.len() + 1,
            candidates.len(),
            ssid
        );
    }
    let Some(config) = wifi_client_config(ssid, password) else {
        log::error!("[relay] stored credential for {ssid:?} exceeds ESP-IDF field bounds — skipped");
        return;
    };
    if let Err(e) = wifi.set_configuration(&config) {
        log::error!("[relay] wifi config for {ssid:?} failed: {e:?}");
    }
}

fn locked_relay_phase(
    wifi: &mut BlockingWifi<EspWifi<'_>>,
    wifi_candidates: &[(String, String)],
    relays: &[String],
    op_mgmt: &[u8; 32],
    secp: &Arc<Secp256k1<SignOnly>>,
    masters: &mut [LoadedMaster],
    personas: &[crate::personas::LoadedPersona],
    nvs: &mut EspNvs<NvsDefault>,
    usb: &mut SerialPort<'_>,
    display: &mut Display<'_>,
    buttons: &crate::button::Buttons<'_>,
) {
    // One-time unlock keypair, RAM only. Loop in the (astronomically
    // unlikely) case the draw is not a valid scalar.
    let mut unlock_sk = [0u8; 32];
    let unlock_pk = loop {
        crate::fill_random(&mut unlock_sk);
        if let Ok(kp) = Keypair::from_seckey_slice(secp, &unlock_sk) {
            break kp.x_only_public_key().0.serialize();
        }
    };
    let unlock_pk_hex = hex_encode(&unlock_pk);
    crate::oled::show_error(display, "Locked\nAwait unlock...");

    let sub_req = format!(
        r##"["REQ","locked",{{"kinds":[{VAULT_DELIVERY_KIND}],"#p":["{unlock_pk_hex}"],"limit":0}}]"##
    );

    // PIN state for the USB path mirrors the main locked loop exactly.
    let mut failed_attempts: u8 = match crate::pin::read_failed_attempts(nvs) {
        Ok(count) => count,
        Err(e) => {
            log::error!("PIN-attempt state invalid ({e}) — wiping fail-closed");
            crate::pin::wipe_and_reboot(usb, display);
        }
    };
    if failed_attempts >= crate::pin::MAX_FAILED_ATTEMPTS {
        log::error!("PIN wipe threshold persisted across reboot — completing wipe");
        crate::pin::wipe_and_reboot(usb, display);
    }
    let mut vault_authed = false;

    let mut relay_idx = 0usize;
    let mut session: Option<RelaySession> = None;
    let mut next_announce = Instant::now();
    let mut wifi_idx = 0usize;
    let mut next_wifi_attempt = Instant::now();

    loop {
        crate::wdt::feed();
        // This phase runs before the main loop ever connects the station, so
        // it owns its own join attempts — without this, the unlock announce
        // could never reach a relay. Rotates through the stored network list,
        // paced so USB unlock stays served between blocking attempts.
        if !wifi.is_up().unwrap_or(false) {
            if session.is_some() {
                session = None;
            }
            if Instant::now() >= next_wifi_attempt {
                if let Err(e) = wifi.connect().and_then(|_| wifi.wait_netif_up()) {
                    log::warn!("[relay] locked: wifi connect failed: {e:?}; retry in 3s");
                    wifi_idx = wifi_idx.wrapping_add(1);
                    select_wifi_candidate(wifi, wifi_candidates, wifi_idx);
                    next_wifi_attempt = Instant::now() + Duration::from_secs(3);
                } else {
                    log::info!("[relay] locked: wifi up");
                }
            }
        }
        // (Re)connect round-robin until a relay holds.
        if session.is_none() && wifi.is_up().unwrap_or(false) {
            match connect_relay_raw(&relays[relay_idx], sub_req.clone(), false, true) {
                Ok(s) => {
                    log::info!("[relay] locked: connected {}", relays[relay_idx]);
                    session = Some(s);
                    // Announce immediately on every (re)connect.
                    next_announce = Instant::now();
                }
                Err(e) => {
                    log::warn!("[relay] locked: connect {} failed: {e}", relays[relay_idx]);
                    relay_idx = (relay_idx + 1) % relays.len();
                    FreeRtos::delay_ms(1000);
                }
            }
        }

        if let Some(s) = session.as_mut() {
            // Periodic boot announcement.
            if Instant::now() >= next_announce {
                if let Err(e) =
                    publish_locked_announce(&mut s.tls, secp, &unlock_sk, &unlock_pk_hex, op_mgmt)
                {
                    log::warn!("[relay] locked: announce failed: {e}");
                    session = None;
                    continue;
                }
                next_announce = Instant::now() + LOCKED_ANNOUNCE_INTERVAL;
            }

            // Drain one buffered frame, else one read (recv-timeout paced).
            match try_parse(&mut s.rx, &mut s.skip) {
                Ok(Some(WsMsg::Text(raw))) => {
                    s.last_rx = Instant::now();
                    if nip46::relay_message_tag(&raw) == Some("EVENT") {
                        if let Ok(msg) =
                            serde_json::from_slice::<nip46::RelayEventMessage>(&raw)
                        {
                            let ev = &msg.2;
                            if ev.kind == VAULT_DELIVERY_KIND
                                && handle_vault_delivery(ev, &unlock_sk, op_mgmt, nvs, masters)
                            {
                                unlock_sk.iter_mut().for_each(|b| *b = 0);
                                crate::oled::show_error(display, "Unlocked!");
                                FreeRtos::delay_ms(500);
                                return;
                            }
                        }
                    }
                }
                Ok(Some(WsMsg::Ping(p))) => {
                    if ws_send(&mut s.tls, OP_PONG, &p).is_err() {
                        session = None;
                        continue;
                    }
                }
                Ok(Some(WsMsg::Close)) => {
                    session = None;
                    continue;
                }
                Ok(Some(WsMsg::Pong)) | Ok(Some(WsMsg::Other)) => {}
                Ok(None) => match pump(&mut s.tls, &mut s.rx) {
                    Ok(n) if n > 0 => s.last_rx = Instant::now(),
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("[relay] locked: read failed: {e}");
                        session = None;
                        continue;
                    }
                },
                Err(e) => {
                    log::warn!("[relay] locked: frame parse failed: {e}");
                    session = None;
                    continue;
                }
            }
        }

        // USB stays live while locked over relay: PIN or vault unlock locally.
        // `mut`: secret-bearing payloads are scrubbed after use (FW-L3).
        if let Some(mut frame) = crate::protocol::try_read_frame(usb, 0) {
            match frame.frame_type {
                FRAME_TYPE_PIN_UNLOCK => {
                    if crate::pin::handle_pin_unlock(
                        usb,
                        &frame.payload,
                        nvs,
                        masters,
                        &mut failed_attempts,
                        display,
                    ) {
                        // Same proven secret unwraps the note key (and
                        // self-heals torn sealed state) — relay-created
                        // notes must not sit plaintext under sealed seeds.
                        crate::notes::sync_sealed(&frame.payload);
                        frame.scrub_payload();
                        unlock_sk.iter_mut().for_each(|b| *b = 0);
                        return;
                    }
                    frame.scrub_payload();
                }
                FRAME_TYPE_SESSION_AUTH => {
                    match crate::session::verify_bridge_secret(&frame.payload, nvs) {
                        Some(true) => {
                            vault_authed = true;
                            crate::protocol::write_frame(usb, FRAME_TYPE_SESSION_ACK, &[0x00]);
                        }
                        Some(false) => {
                            // A wrong secret must not deauthenticate an
                            // already-authenticated vault session (FW-M1).
                            crate::protocol::write_frame(usb, FRAME_TYPE_SESSION_ACK, &[0x01]);
                        }
                        None => {
                            crate::protocol::write_frame(usb, FRAME_TYPE_SESSION_ACK, &[0x02]);
                        }
                    }
                    frame.scrub_payload();
                }
                FRAME_TYPE_VAULT_UNLOCK => {
                    if !vault_authed {
                        crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"bridge auth required");
                        frame.scrub_payload();
                    } else if crate::pin::handle_vault_unlock(
                        usb,
                        &frame.payload,
                        nvs,
                        masters,
                        display,
                    ) {
                        // See PIN_UNLOCK above: the note key rides the same
                        // secret.
                        crate::notes::sync_sealed(&frame.payload);
                        frame.scrub_payload();
                        unlock_sk.iter_mut().for_each(|b| *b = 0);
                        return;
                    } else {
                        frame.scrub_payload();
                    }
                }
                FRAME_TYPE_FIRMWARE_INFO => crate::protocol::write_frame(
                    usb,
                    FRAME_TYPE_FIRMWARE_INFO_RESPONSE,
                    crate::firmware_info_json().as_bytes(),
                ),
                FRAME_TYPE_PROVISION_LIST => {
                    // Safe while locked (npubs only, no secrets) and REQUIRED
                    // for Sapwood to recognise the signer and show its locked
                    // banner — without it a locked signer looks brand new.
                    crate::provision::handle_list(usb, masters, personas, None);
                }
                FRAME_TYPE_FACTORY_RESET => {
                    // A locked device MUST stay resettable: with the unlock
                    // secret lost, the button-gated wipe is the only way back
                    // to a restorable state. Always physically confirmed.
                    crate::provision::handle_factory_reset(usb, nvs, display, buttons);
                }
                _ => crate::protocol::write_frame(usb, FRAME_TYPE_NACK, &[]),
            }
        }

        FreeRtos::delay_ms(10);
    }
}

/// Handle one vault-delivery event. The event must be authored by the
/// operator and p-tagged to our one-time unlock pubkey (the subscription
/// already filters the tag; re-check both regardless — relays are not
/// trusted). Content decrypts with the operator⇄unlock conversation key to
/// the 64-char hex vault key. Returns true when the seeds unlocked.
fn handle_vault_delivery(
    ev: &SignedEvent,
    unlock_sk: &[u8; 32],
    op_mgmt: &[u8; 32],
    nvs: &mut EspNvs<NvsDefault>,
    masters: &mut [LoadedMaster],
) -> bool {
    if hex_decode(&ev.pubkey).ok().and_then(|v| v.try_into().ok())
        != Some(*op_mgmt)
    {
        log::warn!("[relay] vault delivery from non-operator {}; ignoring", &ev.pubkey[..16.min(ev.pubkey.len())]);
        return false;
    }
    let conversation_key = match nip44::get_conversation_key(unlock_sk, op_mgmt) {
        Ok(ck) => ck,
        Err(e) => {
            log::warn!("[relay] vault delivery conversation key failed: {e}");
            return false;
        }
    };
    let plaintext = match nip44::decrypt(&conversation_key, &ev.content) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("[relay] vault delivery decrypt failed: {e}");
            return false;
        }
    };
    let mut vault_key: [u8; 32] = match hex_decode(&plaintext).ok().and_then(|v| v.try_into().ok()) {
        Some(k) => k,
        None => {
            log::warn!("[relay] vault delivery payload not 64-char hex");
            return false;
        }
    };
    let ok = crate::pin::try_unlock(nvs, masters, &vault_key);
    if ok {
        log::info!("[relay] vault key accepted — device unlocked");
        crate::pin::clear_failed_attempts(nvs);
        // The note key rides the same secret (see the locked-phase USB
        // unlock arms) — sync before the key is scrubbed.
        crate::notes::sync_sealed(&vault_key);
    } else {
        log::warn!("[relay] vault key rejected (AEAD check failed)");
    }
    vault_key.iter_mut().for_each(|b| *b = 0);
    ok
}

/// One pump pass over a session: drain buffered frames, one read, idle tick.
/// An `Err` means the session is dead and should be dropped; per-request
/// errors are handled (and swallowed) further down the dispatch chain.
fn session_step(
    s: &mut RelaySession,
    ctx: &mut SignCtx,
    pool: &mut RelayPool,
) -> Result<(), String> {
    // Process at most ONE buffered frame per step, so the outer loop serves
    // USB between frames — same cadence the single-session loop kept (a burst
    // of frames must never starve the cable).
    if let Some(msg) = try_parse(&mut s.rx, &mut s.skip)? {
        match msg {
            WsMsg::Text(p) => handle_relay_msg(s, &p, ctx, pool)?,
            WsMsg::Ping(p) => ws_send(&mut s.tls, OP_PONG, &p)?,
            WsMsg::Close => return Err("relay sent close".into()),
            WsMsg::Pong | WsMsg::Other => {}
        }
        // A large frame (avatar event ~17KB) grows rx and Vec never gives
        // capacity back on its own — reclaim it so one big message doesn't
        // permanently shrink the heap for the rest of the session.
        if s.rx.capacity() > READ_BUF * 2 {
            s.rx.shrink_to(READ_BUF);
        }
        // Handling a sign_event can block ~30s on the button; treat that as
        // activity so the silence deadline doesn't trip right after.
        s.last_rx = Instant::now();
        return Ok(());
    }

    // No full frame — one read. With the recv timeout this returns 0 after the
    // tuned quiet period; without it (degraded, primary only) it blocks.
    if pump(&mut s.tls, &mut s.rx)? > 0 {
        s.last_rx = Instant::now();
        return Ok(());
    }

    // Idle tick (only meaningful when the recv timeout is active): keep the
    // relay link warm, refresh the subscription, and bail if it's gone quiet.
    if s.recv_timeout_on {
        let now = Instant::now();
        if now.duration_since(s.last_ping) >= PING_INTERVAL {
            ws_send(&mut s.tls, OP_PING, b"hw")?;
            s.last_ping = now;
        }
        // Periodic re-REQ: self-heals a subscription the relay dropped
        // silently (connection still alive, so silence never trips).
        if now.duration_since(s.last_resub) >= RESUB_INTERVAL {
            ws_send(&mut s.tls, OP_TEXT, s.sub_req.as_bytes())?;
            s.last_resub = now;
            log::debug!("[relay] re-subscribed on {} (keepalive)", s.url);
        }
        if now.duration_since(s.last_rx) >= SILENCE_LIMIT {
            return Err(format!(
                "relay {} silent (no data/pong); reconnecting",
                s.url
            ));
        }
    }
    Ok(())
}

/// Reboot after a command changed persisted state the live relay subscription
/// depends on (the master set). The subscription is built from the masters at
/// boot, so re-deriving from fresh NVS on the next boot is the simplest correct
/// way to pick up an add/remove — cheaper to reason about than live re-subscribe.
fn reboot_after_state_change(reason: &str) {
    log::info!("[relay] {reason} — rebooting to re-derive signer state");
    // Let the ACK flush to the host before the USB CDC drops on restart.
    FreeRtos::delay_ms(400);
    unsafe { esp_idf_svc::sys::esp_restart() };
}

/// Serve one USB frame while the relay loop runs — the FULL command set, so the
/// cable stays completely usable in wifi mode (signing + management + OTA), not
/// a restricted subset. Non-blocking: a quiet poll returns at once. Commands
/// that change the master set reboot afterwards so the relay subscription
/// re-derives from fresh NVS. Mirrors the USB-only dispatch loop in `main`.
/// `wifi` is the live driver when the caller can lend it (WiFi up but idle in the
/// connect loop), letting a 0x55 scan reuse the already-started radio; it is
/// `None` while a relay connection is being served, where scanning would knock
/// the link off its channel — that case declines rather than disrupt signing.
fn poll_usb(
    usb: &mut SerialPort<'_>,
    ctx: &mut SignCtx,
    wifi: Option<&mut BlockingWifi<EspWifi<'_>>>,
) {
    let mut frame = match crate::protocol::try_read_frame(usb, 0) {
        Some(f) => f,
        None => return,
    };

    // USB activity wakes the panel, same as a relay request.
    if !ctx.display_on {
        crate::oled::wake_display(ctx.display);
        ctx.display_on = true;
    }
    ctx.last_activity = Instant::now();

    match frame.frame_type {
        FRAME_TYPE_FIRMWARE_INFO => crate::protocol::write_frame(
            usb,
            FRAME_TYPE_FIRMWARE_INFO_RESPONSE,
            crate::firmware_info_json().as_bytes(),
        ),

        // 0x5B — Sapwood-provisioned display metadata (name + avatar), stored in
        // NVS. The signer never fetches/decodes images itself. Bridge-auth gated
        // (FW-L1) exactly as in the USB-only loop: the OLED identity card is
        // what the owner approves against, so it is not freely rewritable. Same
        // open-tier carve-out as FW-M2: no bridge secret provisioned → the
        // cable is the trust anchor (first-run avatar sync precedes pairing).
        FRAME_TYPE_SET_IDENTITY_META => {
            if !ctx.policy_engine.bridge_authenticated
                && crate::session::read_bridge_secret(ctx.nvs).is_some()
            {
                log::warn!("[relay] SET_IDENTITY_META rejected — bridge not authenticated");
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"bridge auth required");
            } else {
            let ok = crate::identity_meta::handle_frame(&frame.payload, ctx.masters, ctx.nvs);
            crate::protocol::write_frame(
                usb,
                if ok { FRAME_TYPE_ACK } else { FRAME_TYPE_NACK },
                &[],
            );
            if ok && ctx.masters.len() == 1 && ctx.display_on {
                let slot = ctx.masters[0].slot;
                let npub = heartwood_common::encoding::encode_npub(&ctx.masters[0].pubkey);
                let meta = crate::identity_meta::load(ctx.nvs, slot);
                let (name, avatar) = match &meta {
                    Some(m) => (Some(m.name.as_str()), Some((m.w, m.h, m.avatar.as_slice()))),
                    None => (None, None),
                };
                crate::oled::show_npub(ctx.display, name, &npub, avatar);
            }
            }
        }

        FRAME_TYPE_PROVISION_LIST => crate::provision::handle_list(usb, ctx.masters, ctx.personas, Some(ctx.policy_engine)),

        // Plaintext NIP-46 — only when the bridge is not authenticated (mirrors
        // the USB-only loop). Uses the first master, like the tethered path.
        FRAME_TYPE_NIP46_REQUEST => {
            if approval_card_open(ctx) {
                // The USB paths still put their own card up and block on it,
                // which would paint over the relay card already on screen and
                // silently let it expire. One screen, one decision: say so.
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"approval on screen");
            } else if ctx.policy_engine.bridge_authenticated || ctx.masters.is_empty() {
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            } else {
                let master_secret = ctx.masters[0].secret;
                let master_label = ctx.masters[0].label.clone();
                let master_mode = ctx.masters[0].mode;
                let master_slot = ctx.masters[0].slot;
                let response_json = crate::nip46_handler::handle_request(
                    frame,
                    &master_secret,
                    &master_label,
                    master_mode,
                    master_slot,
                    ctx.secp,
                    ctx.display,
                    ctx.buttons,
                    ctx.policy_engine,
                    ctx.identity_caches,
                    None,
                    ctx.nvs,
                    ctx.personas,
                );
                crate::protocol::write_nip46_response(
                    usb,
                    FRAME_TYPE_NIP46_RESPONSE,
                    response_json,
                );
                ctx.policy_engine.persist_slots(ctx.nvs, master_slot);
                // Persist identities derived during this request, exactly as
                // the encrypted and relay paths do — the plaintext cable path
                // historically cached them RAM-only, silently losing them at
                // reboot. Registry changes join the live `#p` filters below.
                let personas_before = ctx.personas.len();
                crate::transport::persist_fresh_identities(
                    ctx.nvs,
                    ctx.identity_caches,
                    ctx.personas,
                    master_slot,
                );
                if ctx.personas.len() != personas_before {
                    ctx.resubscribe_needed = true;
                }
            }
        }

        // Encrypted NIP-46 (bridge transport) — requires an authenticated bridge.
        FRAME_TYPE_ENCRYPTED_REQUEST => {
            if approval_card_open(ctx) {
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"approval on screen");
            } else if !ctx.policy_engine.bridge_authenticated {
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            } else {
                let personas_before = ctx.personas.len();
                crate::transport::handle_encrypted_request(
                    usb,
                    &frame,
                    ctx.masters,
                    ctx.personas,
                    ctx.secp,
                    ctx.display,
                    ctx.buttons,
                    ctx.policy_engine,
                    ctx.identity_caches,
                    ctx.nvs,
                );
                if ctx.personas.len() != personas_before {
                    ctx.resubscribe_needed = true;
                }
            }
        }

        // Deprecated inline-envelope signing — explicit reject like the USB loop.
        FRAME_TYPE_SIGN_ENVELOPE => crate::protocol::write_frame(usb, FRAME_TYPE_NACK, &[]),

        FRAME_TYPE_SESSION_AUTH => {
            crate::session::handle_auth(usb, &frame.payload, ctx.nvs, ctx.policy_engine);
            // The payload is the presented bridge secret (FW-L3).
            frame.scrub_payload();
        }
        FRAME_TYPE_SET_BRIDGE_SECRET => {
            crate::session::handle_set_bridge_secret(
                usb,
                &frame.payload,
                ctx.nvs,
                ctx.policy_engine,
                ctx.display,
                ctx.buttons,
            );
            frame.scrub_payload();
        }

        // Network reconfig — the handler reboots into the new mode itself on a
        // wifi save (and simply persists a radio-off save).
        FRAME_TYPE_SET_NET_CONFIG => {
            crate::net_config_store::handle_set_net_config(
                usb,
                &frame.payload,
                ctx.nvs,
                ctx.display,
                ctx.buttons,
                true,
            );
            // The config JSON carries the WiFi password (FW-L3).
            frame.scrub_payload();
        }

        FRAME_TYPE_GET_NET_CONFIG => {
            crate::net_config_store::handle_get_net_config(usb, ctx.nvs, ctx.network_runtime)
        }

        FRAME_TYPE_PATCH_NET_CONFIG => {
            crate::net_config_store::handle_patch_net_config(
                usb,
                &frame.payload,
                ctx.nvs,
                ctx.display,
                ctx.buttons,
            );
            // A `set` password action carries the WiFi password (FW-L3).
            frame.scrub_payload();
        }

        FRAME_TYPE_SET_OPERATOR => crate::net_config_store::handle_set_operator(
            usb,
            &frame.payload,
            ctx.nvs,
            ctx.display,
            ctx.buttons,
            true,
        ),

        // At-rest changes are refused while notes are held: the at-rest
        // enable/disable note-sync only runs on the USB-mode path, and
        // changing the secret under sealed notes here would strand them.
        // The flag stays fresh — every note command (USB frame or relay
        // method) re-stores it.
        FRAME_TYPE_SET_PIN => {
            if crate::notes::any_notes_held() {
                crate::protocol::write_frame(
                    usb,
                    FRAME_TYPE_NACK,
                    b"at-rest changes need USB mode while notes are held",
                );
            } else {
                let _ = crate::pin::handle_set_pin(
                    usb,
                    &frame.payload,
                    ctx.nvs,
                    ctx.masters,
                    ctx.display,
                    ctx.buttons,
                );
            }
            // The payload is the PIN digits (FW-L3).
            frame.scrub_payload();
        }

        // Vault management over the cable in wifi mode (mirrors the USB-only
        // loop). VAULT_UNLOCK is a no-op here — a device serving poll_usb is
        // already unlocked; the locked wifi path handles it in
        // locked_relay_phase.
        FRAME_TYPE_VAULT_SET => {
            if crate::notes::any_notes_held() {
                crate::protocol::write_frame(
                    usb,
                    FRAME_TYPE_NACK,
                    b"at-rest changes need USB mode while notes are held",
                );
            } else {
                let _ = crate::pin::handle_vault_set(
                    usb,
                    &frame.payload,
                    ctx.nvs,
                    ctx.masters,
                    ctx.policy_engine.bridge_authenticated,
                    ctx.display,
                    ctx.buttons,
                );
            }
            // The payload is the vault key (FW-L3).
            frame.scrub_payload();
        }
        FRAME_TYPE_VAULT_UNLOCK => {
            crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"already unlocked");
        }

        FRAME_TYPE_CONNSLOT_CREATE => {
            crate::connslot::handle_create(usb, &frame, ctx.policy_engine, ctx.masters, ctx.nvs)
        }
        FRAME_TYPE_CONNSLOT_LIST => crate::connslot::handle_list(usb, &frame, ctx.policy_engine),
        FRAME_TYPE_CONNSLOT_UPDATE => crate::connslot::handle_update(
            usb,
            &frame,
            ctx.policy_engine,
            ctx.nvs,
            ctx.display,
            ctx.buttons,
        ),
        FRAME_TYPE_CONNSLOT_REVOKE => {
            crate::connslot::handle_revoke(usb, &frame, ctx.policy_engine, ctx.nvs)
        }
        FRAME_TYPE_CONNSLOT_URI => {
            crate::connslot::handle_uri(usb, &frame, ctx.policy_engine, ctx.masters)
        }

        FRAME_TYPE_BACKUP_EXPORT_REQUEST => {
            if !ctx.policy_engine.bridge_authenticated {
                log::warn!("[relay] Backup export rejected -- bridge not authenticated");
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            } else {
                crate::backup::handle_export(
                    usb,
                    ctx.masters,
                    ctx.policy_engine,
                    ctx.nvs,
                    ctx.display,
                    ctx.buttons,
                );
            }
        }
        FRAME_TYPE_BACKUP_IMPORT_REQUEST => {
            // Same bridge-auth gate as export (FW-H2).
            if !ctx.policy_engine.bridge_authenticated {
                log::warn!("[relay] Backup import rejected -- bridge not authenticated");
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"bridge auth required");
            } else if approval_card_open(ctx) {
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"approval on screen");
            } else {
                crate::backup::handle_import(
                    usb,
                    &frame.payload,
                    ctx.masters,
                    ctx.policy_engine,
                    ctx.nvs,
                    ctx.display,
                    ctx.buttons,
                );
            }
            // The payload carries slot secrets and the bridge secret — scrub
            // on every outcome (FW-L3).
            frame.scrub_payload();
        }

        // OTA — the finish handler verifies the image and reboots into it.
        FRAME_TYPE_OTA_BEGIN => crate::ota::handle_ota_begin(
            usb,
            &frame.payload,
            ctx.display,
            ctx.buttons,
            &mut ctx.ota_session,
        ),
        FRAME_TYPE_OTA_CHUNK => {
            crate::ota::handle_ota_chunk(usb, &frame.payload, ctx.display, &mut ctx.ota_session)
        }
        FRAME_TYPE_OTA_FINISH => {
            crate::ota::handle_ota_finish(usb, ctx.display, &mut ctx.ota_session)
        }

        // Master-set changes: perform, then reboot so the relay re-subscribes
        // from the fresh master set. `masters` here is a shared slice, so the
        // add handlers persist to NVS and we reboot rather than mutate in place.
        FRAME_TYPE_PROVISION | FRAME_TYPE_GENERATE_IDENTITY | FRAME_TYPE_RESTORE_IDENTITY => {
            if approval_card_open(ctx) {
                // One screen, one decision: these handlers now run their own
                // button prompt (FW-M3) and must not paint over a relay card.
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"approval on screen");
            } else {
            let provisioned = match frame.frame_type {
                FRAME_TYPE_GENERATE_IDENTITY => crate::provision::handle_generate(
                    usb,
                    &frame,
                    ctx.nvs,
                    ctx.secp,
                    ctx.display,
                    ctx.buttons,
                ),
                FRAME_TYPE_RESTORE_IDENTITY => crate::provision::handle_restore(
                    // `Buttons` carries the second button where the board has
                    // one, so a restore over USB in Wi-Fi relay mode now gets
                    // the same two-button picker as the main.rs paths.
                    usb,
                    &frame,
                    ctx.nvs,
                    ctx.secp,
                    ctx.display,
                    ctx.buttons,
                ),
                _ => crate::provision::handle_add(usb, &frame, ctx.nvs, ctx.secp, ctx.display, ctx.buttons),
            };
            // 0x01's payload carries the host-pushed seed (FW-L3).
            frame.scrub_payload();
            if provisioned.is_some() {
                reboot_after_state_change("master added");
            }
            }
        }

        // Derive a named child on-device and store it as a new master. A
        // master-set change like PROVISION, so reboot to re-subscribe; an
        // idempotent re-derive (existing slot) returns None and needs none.
        FRAME_TYPE_DERIVE_IDENTITY => {
            if approval_card_open(ctx) {
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"approval on screen");
            } else if crate::provision::handle_derive(usb, &frame, ctx.nvs, ctx.secp, ctx.display, ctx.buttons, ctx.masters)
                .is_some()
            {
                reboot_after_state_change("identity derived");
            }
        }
        // 0x04 — remove a master. Routes through the same handler as the
        // USB-only loop (FW-H1): the OLED shows slot + npub and the owner must
        // complete the 2 s hold — a bare frame from the USB host must never
        // destroy an identity on a wifi-standalone signer. On success the
        // relay subscription re-derives from the fresh master set by reboot.
        FRAME_TYPE_PROVISION_REMOVE => {
            if approval_card_open(ctx) {
                // One screen, one decision: a relay approval card already owns
                // the display and the button.
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"approval on screen");
            } else if crate::provision::handle_remove(
                usb,
                &frame,
                ctx.nvs,
                ctx.masters,
                ctx.display,
                ctx.buttons,
            ) {
                reboot_after_state_change("master removed");
            }
        }
        // Factory reset wipes NVS and reboots inside the handler.
        FRAME_TYPE_FACTORY_RESET => {
            crate::provision::handle_factory_reset(usb, ctx.nvs, ctx.display, ctx.buttons)
        }

        // 0x55 — scan nearby WiFi APs. Reuses the relay's own started driver when
        // it is lent (WiFi up but idle); mid-connection the caller passes `None`
        // and we decline, so a diagnostic scan never bumps a live signing link.
        FRAME_TYPE_WIFI_SCAN_REQUEST => match wifi {
            Some(w) => crate::wifi_scan::respond(usb, w),
            None => crate::protocol::write_frame(usb, FRAME_TYPE_NACK, &[]),
        },

        // 0x70 — the USB note-frame surface is USB-mode only: its gated
        // commands run a blocking 30 s approval, which must not stall this
        // loop (the exact problem #64's Deferred machinery solved). In this
        // mode the locker is served as `heartwood_note_*` NIP-46 extensions
        // instead, whose gated methods ride that machinery. NACK with a
        // reason so the wallet reports "wrong surface", not "broken".
        FRAME_TYPE_NOTE_CMD => {
            crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"use heartwood_note_* over the relay");
        }

        other => {
            log::warn!("[relay] USB frame 0x{other:02x} not recognised");
            crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"unknown frame");
        }
    }

    // Approval-gated arms (plaintext and encrypted NIP-46, slot updates,
    // restores) can block on the button for tens of seconds, so the arrival
    // refresh above is already spent by the time their outcome card draws —
    // which then blanked within moments (#62). The interaction that just
    // finished is user activity: restart the blank clock so the outcome
    // card gets its full window.
    ctx.last_activity = Instant::now();
}

/// Parse one inbound relay message (`["EVENT",sub,ev]` / `EOSE` / `OK` / …).
fn handle_relay_msg(
    s: &mut RelaySession,
    raw: &[u8],
    ctx: &mut SignCtx,
    pool: &mut RelayPool,
) -> Result<(), String> {
    // Route on the tag WITHOUT building a Value tree.
    //
    // Every inbound message used to be parsed into a serde_json::Value first,
    // just to read its first element. For an EVENT that tree is a complete
    // second copy of the message — including the event's whole content string —
    // held at the same time as the raw bytes, and `from_value` then copied the
    // content a THIRD time into the SignedEvent. At the top of the signing
    // range the message is ~28 KB, so the peak was ~84 KB of transient
    // allocation for a 28 KB message.
    //
    // That was fatal in the field: the same 27824-byte message was handled
    // successfully on one occasion and panicked the device on another, leaving
    // "relay inbound event". The size guard in nip46_handler cannot help — it
    // runs after decryption, long past this point. Deserialising the event
    // directly removes one full copy and the tree.
    let tag = match heartwood_common::nip46::relay_message_tag(raw) {
        Some(t) => t,
        None => {
            log::warn!("[relay] non-JSON or untagged frame ({} bytes)", raw.len());
            return Ok(());
        }
    };
    match tag {
        "EVENT" => {
            set_network_runtime(
                ctx,
                NetworkRuntimeStage::Online,
                true,
                true,
                NetworkRuntimeError::None,
            );
            // Coarse breadcrumb over the WHOLE inbound-event window: the parse,
            // signature verification, and kind routing all run before any
            // per-handler breadcrumb, so a crash there (not a NIP-46 request)
            // previously left nothing. Handlers refine this with specifics.
            let free = unsafe { esp_idf_svc::sys::esp_get_free_heap_size() };
            crate::crash_crumb::set(&format!("relay inbound event (heap {}k)", free / 1024));
            match serde_json::from_slice::<heartwood_common::nip46::RelayEventMessage>(raw) {
                // No clear here: the breadcrumb is a rolling "last activity"
                // marker. The pump's next read overwrites it with "relay
                // reading" once the loop goes idle, so a stale request is
                // never misattributed, and the reset-reason gate ignores it
                // entirely on a clean (non-crash) restart.
                Ok(msg) => process_event(s, msg.2, ctx, pool)?,
                Err(e) => log::warn!("[relay] bad EVENT json: {e}"),
            }
        }
        "EOSE" => {
            set_network_runtime(
                ctx,
                NetworkRuntimeStage::Online,
                true,
                true,
                NetworkRuntimeError::None,
            );
            log::info!("[relay] EOSE — live, waiting for requests");
            continue_catch_up(s, ctx);
        }
        "OK" => {
            set_network_runtime(
                ctx,
                NetworkRuntimeStage::Online,
                true,
                true,
                NetworkRuntimeError::None,
            );
            log::info!("[relay] OK: {}", snippet(raw, 120));
        }
        "NOTICE" => log::warn!("[relay] NOTICE: {}", snippet(raw, 160)),
        // The relay closed our subscription (limit, error, policy). The WS stays
        // open so silence-detection won't fire — propagate so we reconnect and
        // re-subscribe cleanly rather than sit with a dead subscription.
        "CLOSED" => {
            log::warn!("[relay] CLOSED: {}; reconnecting", snippet(raw, 160));
            return Err("relay closed our subscription".into());
        }
        _ => {}
    }
    Ok(())
}

/// Cache the primary master's own kind-0 profile name and refresh the idle
/// identity screen with it. Ignores profiles not authored by one of our masters,
/// keeps only the newest replaceable event, and redraws only a live (non-blanked)
/// single-master screen — a multi-master device shows a count, not one identity.
fn handle_profile_event(ev: &SignedEvent, ctx: &mut SignCtx) {
    let author: [u8; 32] = match hex_decode(&ev.pubkey).ok().and_then(|v| v.try_into().ok()) {
        Some(a) => a,
        None => return,
    };
    if !ctx.masters.iter().any(|m| m.pubkey == author) {
        return; // not ours — ignore
    }
    if ev.created_at < ctx.identity_name_ts {
        return; // older than what we already have
    }
    let name = match profile_name(&ev.content) {
        Some(n) => n,
        None => return, // profile with no usable name
    };
    ctx.identity_name_ts = ev.created_at;
    let changed = ctx.identity_name.as_deref() != Some(name.as_str());
    ctx.identity_name = Some(name);
    log::info!(
        "[relay] profile name: {}",
        ctx.identity_name.as_deref().unwrap_or("")
    );

    if changed && ctx.display_on && ctx.masters.len() == 1 {
        let slot = ctx.masters[0].slot;
        let npub = heartwood_common::encoding::encode_npub(&ctx.masters[0].pubkey);
        // Sapwood-provisioned metadata (name + avatar) wins; the kind-0 name is
        // only the fallback when nothing has been provisioned.
        let meta = crate::identity_meta::load(ctx.nvs, slot);
        let fallback = ctx.identity_name.clone();
        let (name, avatar) = match &meta {
            Some(m) => (Some(m.name.as_str()), Some((m.w, m.h, m.avatar.as_slice()))),
            None => (fallback.as_deref(), None),
        };
        // Refine the inbound-event breadcrumb to the render: a kind-0 event
        // echoes back when the signer's own profile is edited, and drawing the
        // name/avatar is a non-request path. handle_relay_msg owns the clear.
        crate::crash_crumb::set("relay profile render");
        crate::oled::show_npub(ctx.display, name, &npub, avatar);
    }
}

/// Extract a display name from a kind-0 profile's JSON content: prefer
/// `display_name`, then `name`, then `nip05`. `None` if none are usable.
fn profile_name(content: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(content).ok()?;
    for key in ["display_name", "name", "nip05"] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            let s = s.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Route an inbound EVENT by kind. Errors specific to one request are logged
/// and swallowed (return `Ok`) so a single bad request never drops the session;
/// only transport errors propagate to trigger a reconnect.
fn process_event(
    s: &mut RelaySession,
    ev: SignedEvent,
    ctx: &mut SignCtx,
    pool: &mut RelayPool,
) -> Result<(), String> {
    if let Err(e) = nip46::verify_signed_event(&ev) {
        log::warn!("[relay] invalid Nostr EVENT ({e}); ignoring");
        return Ok(());
    }

    // Every authentic event carries someone's idea of the wall clock, which is
    // the only such reading this chip ever gets. Feed it to the reply clock
    // before any routing decision, so even traffic we go on to ignore keeps
    // our sense of "now" fresh. Backdated events (a NIP-59 seal jitters into
    // the past) cannot drag it backwards.
    ctx.reply_clock.observe(ev.created_at, crate::uptime_s());
    note_wall_clock(ctx);

    // Our own kind-0 profile: cache the name and refresh the idle identity
    // screen. This is not a user request, so it must never wake a blanked panel.
    if ev.kind == 0 {
        handle_profile_event(&ev, ctx);
        return Ok(());
    }
    if ev.kind == GIFT_WRAP_KIND {
        handle_note_wrap(ev, ctx);
        return Ok(());
    }
    if ev.kind != NIP46_KIND && ev.kind != MGMT_KIND {
        return Ok(());
    }
    // A real request is about to draw to the OLED — wake it and mark activity so
    // the burn-in blank timer restarts. (Relay control traffic does NOT count,
    // or the periodic re-REQ would keep the static screen lit forever.)
    if !ctx.display_on {
        crate::oled::wake_display(ctx.display);
        ctx.display_on = true;
    }
    ctx.last_activity = Instant::now();

    // The identity this request addresses — its `p` tag. NIP-46 (24133) can
    // target any served identity (a master or one of its personas); management
    // (24134) is master-only. There is exactly one `p` tag on a NIP-46 request,
    // so the first valid one is the target.
    let target_pk: [u8; 32] = match ev
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == "p")
        .find_map(|t| hex_decode(&t[1]).ok().and_then(|v| v.try_into().ok()))
    {
        Some(pk) => pk,
        None => {
            log::warn!("[relay] EVENT has no valid p tag; ignoring");
            return Ok(());
        }
    };

    let result = if ev.kind == MGMT_KIND {
        match masters::find_by_pubkey(ctx.masters, &target_pk) {
            Some(master_idx) => {
                // The mgmt dispatch can also grow the persona registry — a
                // park completion's persist hook retries cache entries whose
                // first write failed (bench-observed: the NP auto-derived for
                // a notice under NVS pressure). Mirror the 24133 path's
                // growth check or the fresh persona never joins the live
                // `#p` filters until reboot.
                let personas_before = ctx.personas.len();
                let outcome = handle_mgmt_event(s, &ev, ctx, master_idx, pool);
                if ctx.personas.len() != personas_before {
                    ctx.resubscribe_needed = true;
                }
                outcome
            }
            None => {
                log::warn!("[relay] mgmt EVENT not addressed to a known master; ignoring");
                Ok(())
            }
        }
    } else {
        // Dedupe across sessions: one request published to several relays must
        // dispatch once, not once per session (see SignCtx::nip46_seen).
        if ctx.nip46_seen.iter().any(|id| id == &ev.id) {
            log::debug!(
                "[relay] duplicate NIP-46 event {}…; ignoring",
                &ev.id[..ev.id.len().min(12)]
            );
            return Ok(());
        }
        if ctx.nip46_seen.len() >= SEEN_MAX {
            ctx.nip46_seen.remove(0);
        }
        ctx.nip46_seen.push(ev.id.clone());
        // Registry mutations inside the dispatch (a fresh persona persisted by
        // the post-request hook, or heartwood_remove_persona) must reach the
        // live `#p` filters without waiting for a reconnect.
        let personas_before = ctx.personas.len();
        let outcome = handle_nip46_event(&mut s.tls, ev, ctx, &target_pk);
        if ctx.personas.len() != personas_before {
            ctx.resubscribe_needed = true;
        }
        outcome
    };
    // A button-gated approval can spend its whole 30 s window inside the
    // dispatch above, leaving the arrival refresh already expired when the
    // outcome card draws (#62's USB variant, latent here for slow
    // approvals). The finished interaction is activity — restart the clock.
    ctx.last_activity = Instant::now();
    result
}

fn client_label(ctx: &SignCtx, master_slot: u8, client_hex: &str) -> String {
    ctx.policy_engine
        .find_slot_by_pubkey(master_slot, client_hex)
        .map(|s| s.label.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("client {}", &client_hex[..client_hex.len().min(8)]))
}

// ---------------------------------------------------------------------------
// C4 escalation + C5 audit rail (family bunker, schema doc 2026-08-14).
// Pure semantics live in heartwood_common::{escalate, nip59}; this section is
// the relay-loop state and the gift-wrap emission glue. Every emission is
// best-effort: a failed publish logs and never fails the signing path.
// ---------------------------------------------------------------------------

/// Parked interactive requests held in RAM (schema §1.1 `park-ttl`).
const PARK_MAX: usize = 4;
/// Expired-park records kept so late verdicts still land (RAM ring).
const PARK_TOMBSTONE_MAX: usize = 8;
/// Petition counters kept per (client, key) (RAM ring).
const PETITION_MAX: usize = 8;
/// Best-effort child wraps per audit emission (schema §2.1 cap discipline).
const CHILD_WRAP_MAX: usize = 4;

/// One interactive request parked for a guardian verdict. Holds the parsed
/// request (its params carry the event to sign) but never a secret — the
/// signing key is re-derived at completion, exactly as live dispatch does.
struct ParkedRequest {
    /// The triggering request event's id hex — the notice's `park` handle.
    park_id: String,
    request: nip46::Nip46Request,
    target_pk: [u8; 32],
    client_pubkey: [u8; 32],
    client_hex: String,
    /// The trigger event's created_at: completion responses echo it, and the
    /// notice stamps from it (§0.1).
    created_at: u64,
    master_slot: u8,
    method: String,
    event_kind: Option<u64>,
    parked_at: Instant,
}

/// What survives a park's expiry: enough to honour a late approve verdict
/// by installing the transient allow (schema §1.4's expired column).
#[derive(Clone)]
struct ParkTombstone {
    park_id: String,
    client_hex: String,
    key: String,
    master_slot: u8,
}

/// Asks since the last verdict for one (client, method-or-kind).
struct PetitionCounter {
    client_hex: String,
    key: String,
    count: u64,
}

/// The C5 facts extracted from a request before dispatch consumes its params.
struct RailDraft {
    event_kind: Option<u64>,
    method_tag: Option<String>,
    counterparty: Option<String>,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Build the C5 draft for the methods the rail covers: sign_event (compact
/// included) carries the kind and, for small events, the first `p` tag;
/// the four transport methods carry the method name and their peer.
fn audit_rail_draft(req: &nip46::Nip46Request) -> Option<RailDraft> {
    match req.method.as_str() {
        "sign_event" | "sign_event_compact" => {
            let kind = nip46::unsigned_event_kind(&req.params)?;
            let encoded_bytes = req
                .params
                .first()
                .and_then(|value| value.as_str())
                .map(str::len)
                .unwrap_or(0);
            // Mirror sign_audit_draft's bound: never re-parse a large event
            // just for a metadata tag.
            let counterparty = if encoded_bytes <= 2_048 {
                nip46::parse_unsigned_event(&req.params).ok().and_then(|event| {
                    event
                        .tags
                        .iter()
                        .find(|t| t.len() >= 2 && t[0] == "p" && is_hex64(&t[1]))
                        .map(|t| t[1].to_ascii_lowercase())
                })
            } else {
                None
            };
            Some(RailDraft { event_kind: Some(kind), method_tag: None, counterparty })
        }
        "nip04_encrypt" | "nip04_decrypt" | "nip44_encrypt" | "nip44_decrypt" => {
            let peer = req
                .params
                .first()
                .and_then(|v| v.as_str())
                .filter(|s| is_hex64(s))
                .map(|s| s.to_ascii_lowercase());
            Some(RailDraft {
                event_kind: None,
                method_tag: Some(req.method.clone()),
                counterparty: peer,
            })
        }
        _ => None,
    }
}

/// The same C5 draft, built from an event dispatch has already parsed out of
/// `params`.
///
/// A deferred ask (#64) carries the parsed event and an emptied `params`, so
/// the builder above would see nothing there and silently drop the record for
/// every button-approved sign on a dependant persona.
fn audit_rail_draft_from_event(event: &UnsignedEvent) -> RailDraft {
    // Same bound as above: never walk a large event just for a metadata tag.
    let counterparty = if event.content.len() <= 2_048 {
        event
            .tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == "p" && is_hex64(&t[1]))
            .map(|t| t[1].to_ascii_lowercase())
    } else {
        None
    };
    RailDraft {
        event_kind: Some(event.kind),
        method_tag: None,
        counterparty,
    }
}

/// The NIP-46 error string of a response, if it carried one.
fn response_error_of(response_json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(response_json)
        .ok()?
        .get("error")?
        .as_str()
        .map(str::to_string)
}

/// Derive the guardian NP identity (secret + x-only pubkey) of the owning
/// tree — the author and addressee of every C4/C5 rumor (schema §0.2/§0.3).
/// `natural-person` is a fixed protocol name, so it derives blind whether or
/// not the persona is in the registry.
fn guardian_np(
    masters: &[LoadedMaster],
    master_slot: u8,
) -> Result<(zeroize::Zeroizing<[u8; 32]>, [u8; 32]), String> {
    let master = masters
        .iter()
        .find(|m| m.slot == master_slot)
        .ok_or("owning master not loaded")?;
    crate::nip46_handler::derive_identity(
        &master.secret,
        master.mode,
        "nostr:persona:natural-person",
        0,
    )
    .map_err(|e| format!("guardian NP derivation: {e}"))
}

/// Gift-wrap a rumor to `recipient_pk` (sealed by `author_secret`, wrapped by
/// a fresh ephemeral key) and publish it on the given session. Heap-guarded:
/// on a fragmented heap the emission is skipped, never crashed.
fn emit_gift_wrap(
    tls: &mut Tls,
    secp: &Arc<Secp256k1<SignOnly>>,
    rumor: &heartwood_common::nip46::UnsignedEvent,
    author_secret: &[u8; 32],
    recipient_pk: &[u8; 32],
    expiration: Option<u64>,
) -> Result<(), String> {
    let wrap = build_gift_wrap(secp, rumor, author_secret, recipient_pk, expiration)?;
    ws_send_event(tls, &wrap).map(|_| ())
}

fn build_gift_wrap(
    secp: &Arc<Secp256k1<SignOnly>>,
    rumor: &heartwood_common::nip46::UnsignedEvent,
    author_secret: &[u8; 32],
    recipient_pk: &[u8; 32],
    expiration: Option<u64>,
) -> Result<SignedEvent, String> {
    // Rumors here are small (~600 B of tags); the outermost plaintext is the
    // serialised seal, roughly 1.5x the rumor after one NIP-44+base64 round.
    // Budget conservatively at 2x + envelope overhead and skip when tight.
    //
    // black_box stops LLVM folding the two constants into `2*len + 2048`:
    // 2048 is one past xtensa's signed 12-bit `movi` range and hits an
    // instruction-selection hole in the esp 1.94/1.95 toolchains — the
    // release build dies with `rustc-LLVM ERROR: Cannot select: i32 =
    // Constant<2048>` (#63). Semantics are identical.
    let rumor_estimate = rumor.content.len()
        + rumor.tags.iter().flatten().map(String::len).sum::<usize>()
        + 512;
    if !response_transportable(rumor_estimate * 2 + core::hint::black_box(1_024)) {
        return Err("low heap; emission skipped".into());
    }

    let mut eph_sk = [0u8; 32];
    let eph_pk = loop {
        crate::fill_random(&mut eph_sk);
        if let Ok(kp) = Keypair::from_seckey_slice(secp, &eph_sk) {
            break kp.x_only_public_key().0.serialize();
        }
    };
    let mut jitter = [0u8; 8];
    crate::fill_random(&mut jitter);
    let seal_jitter = u64::from_be_bytes(jitter);
    crate::fill_random(&mut jitter);
    let wrap_jitter = u64::from_be_bytes(jitter);
    let seal_nonce = random_nonce_32();
    let wrap_nonce = random_nonce_32();

    let secp_ref = Arc::clone(secp);
    let sign = move |secret: &[u8; 32], hash: &[u8; 32]| {
        crate::sign::sign_hash(&secp_ref, secret, hash)
    };
    let wrap = heartwood_common::nip59::gift_wrap(
        rumor,
        author_secret,
        recipient_pk,
        &eph_sk,
        &eph_pk,
        heartwood_common::nip59::WrapTimes {
            seal_created_at: heartwood_common::nip59::jitter_past(rumor.created_at, seal_jitter),
            wrap_created_at: heartwood_common::nip59::jitter_past(rumor.created_at, wrap_jitter),
        },
        expiration,
        &seal_nonce,
        &wrap_nonce,
        &sign,
    );
    eph_sk.iter_mut().for_each(|b| *b = 0);
    wrap.map_err(|e| format!("gift wrap: {e}"))
}

/// Publish the §1.1 approval-needed notice for a park, addressed to the
/// guardian NP of the owning tree.
fn emit_approval_notice(
    tls: &mut Tls,
    ctx: &mut SignCtx,
    park: &ParkedRequest,
) -> Result<(), String> {
    let (np_secret, np_pk) = guardian_np(ctx.masters, park.master_slot)?;
    let stamped =
        heartwood_common::nip59::stamp_monotonic(park.created_at, &mut ctx.audit_last_stamped);
    let rumor = heartwood_common::nip59::build_approval_notice(
        &heartwood_common::nip59::ApprovalNotice {
            guardian_np_hex: &hex_encode(&np_pk),
            client_hex: &park.client_hex,
            park_id_hex: &park.park_id,
            identity_hex: &hex_encode(&park.target_pk),
            method: &park.method,
            event_kind: park.event_kind,
            park_ttl_secs: heartwood_common::escalate::PARK_TTL_SECS,
            created_at: stamped,
        },
    );
    emit_gift_wrap(
        tls,
        ctx.secp,
        &rumor,
        &np_secret,
        &np_pk,
        Some(stamped + heartwood_common::nip59::APPROVAL_EXPIRY_SECS),
    )
}

/// Count a petition ask and publish the §1.2 notice (low priority, 7-day
/// expiry). The deny already happened; this is purely a message.
fn petition_and_notify(
    tls: &mut Tls,
    ctx: &mut SignCtx,
    master_slot: u8,
    client_hex: &str,
    target_pk: &[u8; 32],
    method: &str,
    event_kind: Option<u64>,
    trigger_created_at: u64,
) {
    let key = heartwood_common::nip59::method_or_kind_key(method, event_kind);
    let count = {
        if let Some(entry) = ctx
            .petitions
            .iter_mut()
            .find(|p| p.client_hex == client_hex && p.key == key)
        {
            entry.count = entry.count.saturating_add(1);
            entry.count
        } else {
            if ctx.petitions.len() >= PETITION_MAX {
                ctx.petitions.remove(0);
            }
            ctx.petitions.push(PetitionCounter {
                client_hex: client_hex.to_string(),
                key: key.clone(),
                count: 1,
            });
            1
        }
    };
    let result = (|| -> Result<(), String> {
        let (np_secret, np_pk) = guardian_np(ctx.masters, master_slot)?;
        let stamped = heartwood_common::nip59::stamp_monotonic(
            trigger_created_at,
            &mut ctx.audit_last_stamped,
        );
        let rumor = heartwood_common::nip59::build_petition_notice(
            &hex_encode(&np_pk),
            client_hex,
            &hex_encode(target_pk),
            method,
            event_kind,
            count,
            stamped,
        );
        emit_gift_wrap(
            tls,
            ctx.secp,
            &rumor,
            &np_secret,
            &np_pk,
            Some(stamped + heartwood_common::nip59::PETITION_EXPIRY_SECS),
        )
    })();
    if let Err(e) = result {
        log::warn!("[relay] petition notice: {e}");
    }
}

/// Publish the C5 audit rumor for a policy-decided request on a dependant
/// persona: guardian wrap always (no expiration — the permanent record),
/// then best-effort child wraps to every flagged slot bound to the identity.
#[allow(clippy::too_many_arguments)]
fn emit_audit_rail(
    tls: &mut Tls,
    ctx: &mut SignCtx,
    master_slot: u8,
    target_hex: &str,
    draft: &RailDraft,
    outcome: &'static str,
    trigger_created_at: u64,
) -> Result<(), String> {
    let (np_secret, np_pk) = guardian_np(ctx.masters, master_slot)?;
    let stamped =
        heartwood_common::nip59::stamp_monotonic(trigger_created_at, &mut ctx.audit_last_stamped);
    ctx.audit_emit_seq = ctx.audit_emit_seq.wrapping_add(1);
    let rumor = heartwood_common::nip59::build_audit_rumor(&heartwood_common::nip59::AuditRumor {
        guardian_np_hex: &hex_encode(&np_pk),
        dependant_hex: target_hex,
        created_at: stamped,
        emit_counter: ctx.audit_emit_seq,
        event_kind: draft.event_kind,
        method: draft.method_tag.as_deref(),
        outcome,
        counterparty_hex: draft.counterparty.as_deref(),
    });
    emit_gift_wrap(tls, ctx.secp, &rumor, &np_secret, &np_pk, None)?;

    // §2.1 dual-address: same rumor, sealed by the same NP, wrapped to each
    // audit-visible child slot bound to this identity. Best effort each.
    let child_targets: Vec<[u8; 32]> = ctx
        .policy_engine
        .list_slots(master_slot)
        .iter()
        .filter(|slot| slot.audit_child_wrap && slot.bound_identity.as_deref() == Some(target_hex))
        .filter_map(|slot| {
            slot.current_pubkey
                .as_deref()
                .and_then(|hex| hex_decode(hex).ok())
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        })
        .take(CHILD_WRAP_MAX)
        .collect();
    for child_pk in child_targets {
        if let Err(e) = emit_gift_wrap(tls, ctx.secp, &rumor, &np_secret, &child_pk, None) {
            log::warn!("[relay] audit child wrap: {e}");
        }
    }
    Ok(())
}

/// Record a park's (client, key) so a late verdict still lands after expiry.
fn tombstone_park(ctx: &mut SignCtx, park: &ParkedRequest) {
    if ctx.park_tombstones.len() >= PARK_TOMBSTONE_MAX {
        ctx.park_tombstones.remove(0);
    }
    ctx.park_tombstones.push(ParkTombstone {
        park_id: park.park_id.clone(),
        client_hex: park.client_hex.clone(),
        key: heartwood_common::nip59::method_or_kind_key(&park.method, park.event_kind),
        master_slot: park.master_slot,
    });
}

/// Park an interactive request and notify the guardian. No response is
/// published — the child's client waits (fast verdicts complete the original
/// request; slow ones land as a transient allow for the retry, §7.1's
/// timing-honesty rule).
fn park_and_notify(tls: &mut Tls, ctx: &mut SignCtx, park: ParkedRequest) {
    if ctx.parks.len() >= PARK_MAX {
        let dropped = ctx.parks.remove(0);
        log::warn!("[relay] park queue full; oldest park expired early");
        tombstone_park(ctx, &dropped);
    }
    log::info!(
        "[relay] parked interactive {} from {}… awaiting guardian verdict",
        park.method,
        &park.client_hex[..park.client_hex.len().min(8)]
    );
    if let Err(e) = emit_approval_notice(tls, ctx, &park) {
        log::warn!("[relay] approval notice: {e}");
    }
    ctx.parks.push(park);
}

/// Expire overdue parks into tombstones. Called once per relay-loop pass.
fn service_parks(ctx: &mut SignCtx) {
    let ttl = Duration::from_secs(heartwood_common::escalate::PARK_TTL_SECS);
    let now = Instant::now();
    let mut index = 0;
    while index < ctx.parks.len() {
        if now.duration_since(ctx.parks[index].parked_at) >= ttl {
            let expired = ctx.parks.remove(index);
            log::info!("[relay] park for {} expired unresolved", expired.method);
            tombstone_park(ctx, &expired);
        } else {
            index += 1;
        }
    }
}

/// Complete a guardian-approved park: install the transient allow (which is
/// what makes both this dispatch and the child's own retry silent), re-derive
/// the signing identity, dispatch through the normal handler, publish the
/// response with the original request's timestamp, and emit the C5 `approved`
/// record. Returns true when the response was published.
fn complete_parked(
    tls: &mut Tls,
    ctx: &mut SignCtx,
    park: ParkedRequest,
    window_secs: u64,
) -> bool {
    let key = heartwood_common::nip59::method_or_kind_key(&park.method, park.event_kind);
    ctx.policy_engine.install_transient_allow(
        park.master_slot,
        park.client_hex.clone(),
        key,
        window_secs,
    );

    // Re-resolve the identity — the served set may have changed while parked.
    let Some((signing_secret, label, mode, slot, persona_purpose)) =
        resolve_served_identity(ctx, &park.target_pk)
    else {
        log::warn!("[relay] parked identity no longer served; park dropped");
        return false;
    };
    let Ok(conversation_key) = nip44::get_conversation_key(&signing_secret, &park.client_pubkey)
    else {
        log::warn!("[relay] park completion: conversation key failed");
        return false;
    };

    let rail = persona_purpose
        .as_deref()
        .filter(|purpose| heartwood_common::escalate::is_dependant_purpose(purpose))
        .and_then(|_| audit_rail_draft(&park.request));
    let request_id = park.request.id.clone();
    let target_hex = hex_encode(&park.target_pk);
    let created_at = park.created_at;
    let held = park.parked_at.elapsed();
    let client_hex = park.client_hex;
    let client_pubkey = park.client_pubkey;

    let mut response_json = crate::nip46_handler::handle_parsed_request(
        park.request,
        &signing_secret,
        &label,
        mode,
        slot,
        ctx.secp,
        ctx.display,
        ctx.buttons,
        ctx.policy_engine,
        ctx.identity_caches,
        Some(&client_pubkey),
        ctx.nvs,
        ctx.personas,
    );
    if !ctx.policy_engine.persist_slots(ctx.nvs, slot) {
        log::error!("[relay] slot persist failed after park completion");
    }
    crate::transport::persist_fresh_identities(ctx.nvs, ctx.identity_caches, ctx.personas, slot);

    if let Some(draft) = rail {
        let error = response_error_of(&response_json);
        if let Some(outcome) = heartwood_common::escalate::audit_outcome(
            heartwood_common::policy::ApprovalTier::AutoApprove,
            error.as_deref(),
            true,
        ) {
            if let Err(e) =
                emit_audit_rail(tls, ctx, slot, &target_hex, &draft, outcome, created_at)
            {
                log::warn!("[relay] audit rail: {e}");
            }
        }
    }

    if !response_transportable(response_json.len()) {
        response_json = nip46::build_error_response(
            &request_id,
            -4,
            "response too large for this signer's memory; the request was not completed",
        )
        .unwrap_or_default();
    }
    match sign_and_publish(
        tls,
        ctx.secp,
        &signing_secret,
        &conversation_key,
        &client_hex,
        NIP46_KIND,
        reply_stamp(ctx, created_at, held),
        response_json,
    ) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("[relay] park completion publish: {e}");
            false
        }
    }
}

/// NACK a guardian-denied park to its client and emit the C5 `denied` record.
fn deny_parked(tls: &mut Tls, ctx: &mut SignCtx, park: ParkedRequest) {
    let resolved = if let Some(midx) = masters::find_by_pubkey(ctx.masters, &park.target_pk) {
        let m = &ctx.masters[midx];
        Some((zeroize::Zeroizing::new(m.secret), None))
    } else if let Some(pidx) = crate::personas::find_by_pubkey(ctx.personas, &park.target_pk) {
        let p = &ctx.personas[pidx];
        ctx.masters
            .iter()
            .find(|m| m.slot == p.master_slot)
            .and_then(|owning| {
                crate::nip46_handler::derive_identity(&owning.secret, owning.mode, &p.purpose, p.index)
                    .ok()
                    .map(|(secret, _pk)| (secret, Some(p.purpose.clone())))
            })
    } else {
        None
    };
    let Some((signing_secret, persona_purpose)) = resolved else {
        return;
    };
    if let Some(draft) = persona_purpose
        .as_deref()
        .filter(|purpose| heartwood_common::escalate::is_dependant_purpose(purpose))
        .and_then(|_| audit_rail_draft(&park.request))
    {
        let target_hex = hex_encode(&park.target_pk);
        if let Err(e) = emit_audit_rail(
            tls,
            ctx,
            park.master_slot,
            &target_hex,
            &draft,
            "denied",
            park.created_at,
        ) {
            log::warn!("[relay] audit rail: {e}");
        }
    }
    let Ok(conversation_key) = nip44::get_conversation_key(&signing_secret, &park.client_pubkey)
    else {
        return;
    };
    let response = nip46::build_error_response(&park.request.id, -1, "user denied")
        .unwrap_or_default();
    if let Err(e) = sign_and_publish(
        tls,
        ctx.secp,
        &signing_secret,
        &conversation_key,
        &park.client_hex,
        NIP46_KIND,
        reply_stamp(ctx, park.created_at, park.parked_at.elapsed()),
        response,
    ) {
        log::warn!("[relay] park deny publish: {e}");
    }
}

// ---------------------------------------------------------------------------
// Interactive approvals that do not stop the loop (#64)
// ---------------------------------------------------------------------------
//
// The button approval used to run inside the dispatch call: one main task owns
// the display, the buttons, the websocket and the USB cable, so a card on
// screen stopped all four for the length of its window. A status probe over
// the cable went unanswered, and a burst of unapproved sign_events ran their
// windows one after another — minutes of a wedged signer for what the operator
// sees as one decision.
//
// So a card is held here instead, the way a C4 park is held: the ask is
// remembered, the dispatch returns immediately, and the loop carries on
// serving everything else while the card is up. The hold itself is measured by
// the sampler thread that already watches the pin (#61), which is what lets a
// loop running at roughly one pass a second judge a two-second hold — or one
// that started and finished entirely between two passes.
//
// What has NOT changed: the request is still dispatched only after a physical
// 2-second hold on the same GPIO, by the same signing path, and a denial or an
// expiry still answers with an error. The identity is re-resolved at answer
// time exactly as a park's is, so a registry change while the card was up
// cannot sign with a stale key.

/// How long a card stays up before it expires unanswered. Matches the blocking
/// loop's window, so what the operator sees is unchanged.
const CARD_WINDOW: Duration = Duration::from_secs(30);

/// Hold that approves, matching `approval::run_approval_loop`.
const CARD_HOLD_MS: u32 = 2000;

/// How long the tick may sample closely while the button is actually down,
/// and how often. The loop's own cadence is roughly a second — far too coarse
/// to fill a two-second bar, which would jump in two or three steps and then
/// leave the operator holding a finished hold. Polling tightly for half a
/// second while their finger is on the button is not the stall this change
/// exists to remove: it happens only during a hold, and only for as long as
/// the hold lasts.
const CARD_HOLD_BURST: Duration = Duration::from_millis(600);
/// Characters that fit one title line on the narrowest panel we ship
/// (128 px at FONT_5X8). Titles are built to this so the renderer never has
/// to clip one.
const TITLE_LINE_CHARS: usize = 25;
const CARD_HOLD_POLL_MS: u32 = 40;

/// Total bytes all waiting asks may hold. Cards keep whole parsed requests
/// alive, and a signing request can be tens of kilobytes on a board with no
/// PSRAM, so the count caps in `approval_queue` are not enough on their own.
const CARD_BYTE_BUDGET: usize = 8 * 1024;

/// How long an ask may wait for a screen it has not yet reached. With one
/// operator and one button the queue is inherently serial, so an ask behind
/// several full windows outlives its client's patience — answer it rather
/// than hold a request whose caller stopped listening.
const CARD_QUEUE_TTL_SECS: u64 = 90;

/// One request inside a card's batch.
struct ButtonAsk {
    ask: crate::nip46_handler::DeferredAsk,
    created_at: u64,
    received_uptime: u64,
    /// Roughly what this ask is holding, for [`CARD_BYTE_BUDGET`].
    weight: usize,
    /// Drawn before dispatch, while the request still had its params, and
    /// pushed to the activity ring once the card is answered — otherwise a
    /// button-approved sign would go missing from the ring the moment the
    /// approval stopped happening inside the dispatch call.
    audit: Option<SignAuditDraft>,
}

/// An interactive ask waiting on the device button.
struct ButtonCard {
    key: heartwood_common::approval_queue::AskKey,
    target_pk: [u8; 32],
    client_pubkey: [u8; 32],
    /// Asks this one decision answers. More than one only when the same client
    /// asked again for the same identity while the card was already up.
    asks: Vec<ButtonAsk>,
    /// Set when the card reaches the screen. The window runs from then, not
    /// from when the ask arrived, so a queued ask still gets a full window.
    opened_at: Option<Instant>,
    /// A press already under way when the card appeared must not answer it,
    /// and neither must that press's release: the card arms only once the
    /// button has been seen up.
    armed: bool,
    last_remaining: u32,
    last_pct: u32,
}

/// What one card tick concluded.
enum CardTick {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// Re-resolve a served identity to its signing key and owning master.
///
/// Both deferred paths answer long after the ask arrived, by which time the
/// served set may have changed — so the key is derived again at answer time
/// rather than held in RAM for the wait.
fn resolve_served_identity(
    ctx: &SignCtx,
    target_pk: &[u8; 32],
) -> Option<(
    zeroize::Zeroizing<[u8; 32]>,
    String,
    heartwood_common::types::MasterMode,
    u8,
    Option<String>,
)> {
    if let Some(midx) = masters::find_by_pubkey(ctx.masters, target_pk) {
        let m = &ctx.masters[midx];
        return Some((
            zeroize::Zeroizing::new(m.secret),
            m.label.clone(),
            m.mode,
            m.slot,
            None,
        ));
    }
    let pidx = crate::personas::find_by_pubkey(ctx.personas, target_pk)?;
    let p = &ctx.personas[pidx];
    let owning = ctx.masters.iter().find(|m| m.slot == p.master_slot)?;
    crate::nip46_handler::derive_identity(&owning.secret, owning.mode, &p.purpose, p.index)
        .ok()
        .map(|(secret, _pk)| {
            (
                secret,
                owning.label.clone(),
                owning.mode,
                owning.slot,
                Some(p.purpose.clone()),
            )
        })
}

/// Take an interactive ask off the dispatch path and put it on the button.
///
/// Publishes nothing when the ask is accepted — the client waits, exactly as
/// it does for a C4 park — and answers busy rather than growing without bound.
#[allow(clippy::too_many_arguments)]
fn queue_button_ask(
    tls: &mut Tls,
    ctx: &mut SignCtx,
    ask: crate::nip46_handler::DeferredAsk,
    slot: u8,
    target_pk: &[u8; 32],
    client_pubkey: &[u8; 32],
    client_hex: &str,
    conversation_key: &[u8; 32],
    signing_secret: &[u8; 32],
    created_at: u64,
    received_uptime: u64,
    audit: Option<SignAuditDraft>,
) -> Result<(), String> {
    use heartwood_common::approval_queue::{admit, Admission, AskKey};

    let mut kind_key = heartwood_common::nip59::method_or_kind_key(
        &ask.request.method,
        ask.event.as_ref().map(|event| event.kind),
    );
    // Sends to two recipients are two decisions: the batch card names one
    // recipient, so only sends to that recipient may share it.
    if ask.request.method == "heartwood_note_send" {
        let to = note_param(&ask.request, "to").unwrap_or_default();
        kind_key = format!("{kind_key}:{to}");
    }
    let key = AskKey::new(slot, client_hex.to_string(), hex_encode(target_pk), kind_key);
    let weight = ask
        .event
        .as_ref()
        .map(|event| event.content.len() + 256)
        .unwrap_or(256);
    let held_bytes: usize = ctx
        .button_cards
        .iter()
        .flat_map(|card| card.asks.iter())
        .map(|ask| ask.weight)
        .sum();

    let open = ctx.button_cards.first();
    let admission = if held_bytes.saturating_add(weight) > CARD_BYTE_BUDGET {
        Admission::Busy
    } else {
        admit(
            open.map(|card| &card.key),
            open.map(|card| card.asks.len()).unwrap_or(0),
            ctx.button_cards.len().saturating_sub(1),
            &key,
        )
    };

    let request_id = ask.request.id.clone();
    match admission {
        Admission::Busy => {
            log::warn!("[relay] approval queue full; answering busy for {request_id}");
            let response = nip46::build_error_response(
                &request_id,
                -1,
                "signer is busy with another approval; retry shortly",
            )
            .unwrap_or_default();
            sign_and_publish(
                tls,
                ctx.secp,
                signing_secret,
                conversation_key,
                client_hex,
                NIP46_KIND,
                reply_stamp(
                    ctx,
                    created_at,
                    Duration::from_secs(crate::uptime_s().saturating_sub(received_uptime)),
                ),
                response,
            )
        }
        Admission::Collapse => {
            if let Some(card) = ctx.button_cards.first_mut() {
                card.asks.push(ButtonAsk {
                    ask,
                    created_at,
                    received_uptime,
                    weight,
                    audit,
                });
                // Redraw: the card now speaks for more than it did. And
                // disarm: a press already under way was aimed at the card
                // as it read a moment ago, so it is discarded along with
                // its release, and the operator must press again on the
                // card that names the whole batch (tick_button_card).
                card.last_remaining = u32::MAX;
                card.armed = false;
                log::info!(
                    "[relay] {request_id} joins the open approval card ({} asks)",
                    card.asks.len()
                );
            }
            Ok(())
        }
        Admission::Open | Admission::Wait => {
            log::info!("[relay] {request_id} waiting on the button");
            ctx.button_cards.push(ButtonCard {
                key,
                target_pk: *target_pk,
                client_pubkey: *client_pubkey,
                asks: vec![ButtonAsk {
                    ask,
                    created_at,
                    received_uptime,
                    weight,
                    audit,
                }],
                opened_at: None,
                armed: false,
                last_remaining: u32::MAX,
                last_pct: u32::MAX,
            });
            Ok(())
        }
    }
}

/// Draw the front card, when what it shows has changed.
fn draw_button_card(ctx: &mut SignCtx, remaining: u32, hold_ms: u32) {
    if !ctx.display_on {
        crate::oled::wake_display(ctx.display);
        ctx.display_on = true;
    }
    // A live card is activity: the panel must not blank mid-decision.
    ctx.last_activity = Instant::now();

    if hold_ms > 0 {
        let pct = (hold_ms * 100 / CARD_HOLD_MS).min(100);
        if pct / 5 != ctx.button_cards[0].last_pct / 5 {
            ctx.button_cards[0].last_pct = pct;
            crate::oled::show_hold_progress(ctx.display, pct);
        }
        return;
    }

    if remaining == ctx.button_cards[0].last_remaining {
        return;
    }
    ctx.button_cards[0].last_remaining = remaining;
    ctx.button_cards[0].last_pct = u32::MAX;

    let batch = ctx.button_cards[0].asks.len();
    enum Draw {
        Sign(String, u64),
        Extension(String, String, String),
        Titled(&'static str, String),
        Batch(String, String),
    }
    let card = match &ctx.button_cards[0].asks[0].ask.card {
        crate::nip46_handler::AskCard::Sign { requester, kind } => {
            // The count belongs on screen: one hold answers all of them, and
            // the operator must never be shown "sign this" for a batch.
            let label = if batch > 1 {
                format!("{requester} x{batch}")
            } else {
                requester.clone()
            };
            Draw::Sign(label, *kind)
        }
        crate::nip46_handler::AskCard::Extension {
            master_label,
            method,
            preview,
        } => match note_card_header(method) {
            // A batched note card must say what the one hold releases: the
            // count, the total and the mint, never just the first note.
            Some(header) if batch > 1 => {
                let (head, title) = note_batch_card(header, &ctx.button_cards[0].asks);
                Draw::Batch(head, title)
            }
            Some(header) => Draw::Titled(header, preview.clone()),
            None => Draw::Extension(master_label.clone(), method.clone(), preview.clone()),
        },
        crate::nip46_handler::AskCard::Receive { title } => {
            Draw::Titled("RECEIVE NOTE", title.clone())
        }
    };
    match card {
        Draw::Sign(label, kind) => {
            crate::oled::show_sign_request(ctx.display, &label, kind, "", remaining)
        }
        Draw::Extension(master_label, method, preview) => crate::oled::show_master_sign_request(
            ctx.display,
            &master_label,
            &method,
            None,
            &preview,
            remaining,
        ),
        Draw::Titled(header, title) => crate::oled::show_titled_approval(
            ctx.display,
            header,
            &title,
            remaining,
            CARD_WINDOW.as_secs() as u32,
        ),
        Draw::Batch(header, title) => crate::oled::show_titled_approval(
            ctx.display,
            &header,
            &title,
            remaining,
            CARD_WINDOW.as_secs() as u32,
        ),
    }
}

/// A string parameter of a `heartwood_note_*` request (`params[0].<name>`).
fn note_param(request: &nip46::Nip46Request, name: &str) -> Option<String> {
    request
        .params
        .first()
        .and_then(|p| p.get(name))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Header and title for a note card answering several asks with one hold:
/// each ask's note looked up in the locker now, so the total is what the
/// locker would release, and the count is every ask whatever the locker
/// says (`heartwood_common::note_cmd::batch_card`).
fn note_batch_card(header: &str, asks: &[ButtonAsk]) -> (String, String) {
    use heartwood_common::note_cmd::{batch_card, BatchNote};
    let metas: Vec<Option<heartwood_common::note_store::NoteMeta>> = asks
        .iter()
        .map(|a| {
            let id = note_param(&a.ask.request, "id")?;
            crate::notes::with_locker(|notes| notes.store.get_meta(&id))
        })
        .collect();
    let notes: Vec<BatchNote<'_>> = metas
        .iter()
        .map(|m| match m {
            Some(m) => BatchNote { amount_msat: m.amount_msat, host: m.host.as_str() },
            None => BatchNote { amount_msat: 0, host: "" },
        })
        .collect();
    let to = if header == "SEND NOTE" {
        asks.first().and_then(|a| note_param(&a.ask.request, "to"))
    } else {
        None
    };
    batch_card(header, &notes, to.as_deref())
}

/// Note methods get the amount card rather than the method-name card, with
/// the same header the cable path uses for the same command.
fn note_card_header(method: &str) -> Option<&'static str> {
    Some(match method {
        "heartwood_note_export" => "RELEASE NOTE",
        "heartwood_note_spent" => "SPEND NOTE",
        "heartwood_note_discard" => "DISCARD NOTE",
        "heartwood_note_send" => "SEND NOTE",
        "heartwood_note_trust" => "TRUST SENDER",
        "heartwood_pair_wallet" => "PAIR NEW WALLET",
        _ => return None,
    })
}

/// Advance the front card by one loop pass.
fn tick_button_card(ctx: &mut SignCtx) -> CardTick {
    if ctx.button_cards.is_empty() {
        return CardTick::Pending;
    }
    let now = Instant::now();
    if ctx.button_cards[0].opened_at.is_none() {
        // Anything the sampler latched before the card went up belongs to
        // whatever the operator was doing then, not to this decision.
        crate::button::clear_press_edge();
        ctx.button_cards[0].opened_at = Some(now);
        log::info!(
            "[relay] card took the screen: queue={} asks={}",
            ctx.button_cards.len(),
            ctx.button_cards[0].asks.len()
        );
    }

    let opened_at = ctx.button_cards[0].opened_at.unwrap_or(now);
    let elapsed = now.duration_since(opened_at);
    if elapsed >= CARD_WINDOW {
        return CardTick::Expired;
    }
    let remaining = (CARD_WINDOW - elapsed).as_secs() as u32;

    let hold_ms = crate::button::hold_ms();
    let released = crate::button::take_release();

    if !ctx.button_cards[0].armed {
        if hold_ms == 0 {
            ctx.button_cards[0].armed = true;
        }
        // Both the in-progress hold and its release are discarded until the
        // card is armed, so a press aimed at the idle carousel cannot answer
        // a card that appeared underneath it.
        draw_button_card(ctx, remaining, 0);
        return CardTick::Pending;
    }

    // B, where the board has one, is an explicit cancel and never an approve.
    if ctx.buttons.b_pressed() {
        ctx.buttons.drain_b();
        return CardTick::Denied;
    }

    if hold_ms >= CARD_HOLD_MS {
        return CardTick::Approved;
    }
    if let Some(ms) = released {
        // A hold that began and ended between two passes still counts: the
        // sampler measured it even though the loop never saw it in progress.
        return if ms >= CARD_HOLD_MS {
            CardTick::Approved
        } else {
            CardTick::Denied
        };
    }

    if hold_ms > 0 {
        // The button is down: follow it to the end rather than for a fixed
        // burst. A 600 ms window did not cover a 2 s hold, so the bar froze
        // partway - reported from the bench as "only got to 75% before it
        // said 12 sats" - while the relay pass that followed took long
        // enough for the hold to complete unseen. An operator with a finger
        // on the button is a foreground interaction: the socket can wait the
        // second or so it takes, and the watchdog is fed every poll.
        let burst_until = Instant::now()
            + CARD_HOLD_BURST.max(Duration::from_millis(u64::from(CARD_HOLD_MS - hold_ms) + 200));
        loop {
            crate::wdt::feed();
            let held = crate::button::hold_ms();
            if held >= CARD_HOLD_MS {
                return CardTick::Approved;
            }
            if held == 0 {
                // Released mid-burst: the sampler has the length.
                return match crate::button::take_release() {
                    Some(ms) if ms >= CARD_HOLD_MS => CardTick::Approved,
                    Some(_) => CardTick::Denied,
                    // No release recorded: treat it as nothing having
                    // happened and let the next pass decide.
                    None => CardTick::Pending,
                };
            }
            draw_button_card(ctx, remaining, held);
            if Instant::now() >= burst_until {
                return CardTick::Pending;
            }
            FreeRtos::delay_ms(CARD_HOLD_POLL_MS);
        }
    }

    draw_button_card(ctx, remaining, hold_ms);
    CardTick::Pending
}

/// Answer every ask on one card with a single decision, and publish.
///
/// `index` is 0 for the card on screen; a later index is a card that timed
/// out in the queue without ever reaching it, which draws nothing.
fn resolve_button_card(
    ctx: &mut SignCtx,
    sessions: &mut [RelaySession],
    index: usize,
    outcome: &CardTick,
) {
    if index >= ctx.button_cards.len() {
        return;
    }
    let card = ctx.button_cards.remove(index);
    if index == 0 {
        // Whatever the button did to decide this card is spent: the edge
        // that started the hold, and the hold itself if it is still going.
        crate::button::clear_press_edge();
        ctx.button_settle = ctx.buttons.a.is_low();
    }
    if card
        .asks
        .first()
        .is_some_and(|a| matches!(a.ask.card, crate::nip46_handler::AskCard::Receive { .. }))
    {
        // Nobody is owed a NIP-46 response: the wrap's sender hears nothing
        // either way, and the outcome is the locker's state.
        resolve_receive_card(ctx, card, outcome, index == 0);
        return;
    }
    if index == 0 {
        match outcome {
            CardTick::Approved => crate::oled::show_approved(ctx.display),
            CardTick::Denied => crate::oled::show_denied(ctx.display),
            _ => crate::oled::show_request_expired(ctx.display),
        }
    }

    let Some(session) = sessions.first_mut() else {
        log::warn!(
            "[relay] approval decided with no live relay session; {} ask(s) unanswered",
            card.asks.len()
        );
        return;
    };

    let Some((signing_secret, label, mode, slot, persona_purpose)) =
        resolve_served_identity(ctx, &card.target_pk)
    else {
        log::warn!("[relay] approved identity no longer served; card dropped");
        return;
    };
    let Ok(conversation_key) = nip44::get_conversation_key(&signing_secret, &card.client_pubkey)
    else {
        log::warn!("[relay] approval completion: conversation key failed");
        return;
    };
    let target_hex = hex_encode(&card.target_pk);
    let dependant = persona_purpose
        .as_deref()
        .is_some_and(heartwood_common::escalate::is_dependant_purpose);

    for ask in card.asks {
        let request_id = ask.ask.request.id.clone();
        let rail = if !dependant {
            None
        } else if let Some(event) = ask.ask.event.as_ref() {
            Some(audit_rail_draft_from_event(event))
        } else {
            audit_rail_draft(&ask.ask.request)
        };

        let mut response_json = match outcome {
            CardTick::Approved => {
                match crate::nip46_handler::dispatch(
                    ask.ask.request,
                    ask.ask.event,
                    &signing_secret,
                    &label,
                    mode,
                    slot,
                    ctx.secp,
                    ctx.display,
                    ctx.buttons,
                    ctx.policy_engine,
                    ctx.identity_caches,
                    Some(&card.client_pubkey),
                    ctx.nvs,
                    ctx.personas,
                    crate::nip46_handler::ApprovalDecision::ButtonApproved,
                ) {
                    crate::nip46_handler::Dispatch::Answered(json) => json,
                    // Unreachable: the hold is in hand, so nothing defers.
                    crate::nip46_handler::Dispatch::NeedsApproval(pending) => {
                        log::error!("[relay] approved dispatch asked to defer again; refusing");
                        nip46::build_error_response(
                            &pending.request.id,
                            -4,
                            "internal approval error",
                        )
                        .unwrap_or_default()
                    }
                }
            }
            CardTick::Denied => nip46::build_error_response(&request_id, -1, "user denied")
                .unwrap_or_default(),
            _ => nip46::build_error_response(&request_id, -1, "timeout").unwrap_or_default(),
        };

        if matches!(outcome, CardTick::Approved) {
            if !ctx.policy_engine.persist_slots(ctx.nvs, slot) {
                log::error!("[relay] slot persist failed after an approved card");
            }
            crate::transport::persist_fresh_identities(
                ctx.nvs,
                ctx.identity_caches,
                ctx.personas,
                slot,
            );
        }
        if let Some(draft) = ask.audit {
            push_sign_audit(ctx, draft, &response_json);
        }

        if let Some(draft) = rail {
            let error = response_error_of(&response_json);
            if let Some(rail_outcome) = heartwood_common::escalate::audit_outcome(
                heartwood_common::policy::ApprovalTier::ButtonRequired,
                error.as_deref(),
                false,
            ) {
                if let Err(e) = emit_audit_rail(
                    &mut session.tls,
                    ctx,
                    slot,
                    &target_hex,
                    &draft,
                    rail_outcome,
                    ask.created_at,
                ) {
                    log::warn!("[relay] audit rail: {e}");
                }
            }
        }

        if !response_transportable(response_json.len()) {
            log::warn!("[relay] approved response for {request_id} too large for free heap");
            response_json = nip46::build_error_response(
                &request_id,
                -4,
                "response too large for this signer's memory; the request was not completed",
            )
            .unwrap_or_default();
        }

        let held = Duration::from_secs(crate::uptime_s().saturating_sub(ask.received_uptime));
        if let Err(e) = sign_and_publish(
            &mut session.tls,
            ctx.secp,
            &signing_secret,
            &conversation_key,
            &card.key.client_hex,
            NIP46_KIND,
            reply_stamp(ctx, ask.created_at, held),
            response_json,
        ) {
            log::warn!("[relay] approval publish for {request_id}: {e}");
        }
    }
}

/// A kind-1059 addressed to one of our masters: open it, read the note, and
/// put a RECEIVE card up. Every failure is silent, as vault delivery is --
/// an unsolicited event from anyone on the internet gets no diagnostics.
fn handle_note_wrap(ev: SignedEvent, ctx: &mut SignCtx) {
    if let Some(c) = ctx.catch_up.as_mut() {
        c.delivered += 1;
        c.oldest = c.oldest.min(ev.created_at);
    }
    // Decided across reboots, or already on a card / already junk this
    // boot. The catch-up REQ replays stored wraps on every connect and
    // settle, so this is the common path, and it runs before any decrypt.
    if ctx.wrap_ledger.decided(&ev.id) || ctx.wrap_seen.iter().any(|id| *id == ev.id) {
        return;
    }

    let Some(target_pk) = ev
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "p")
        .and_then(|t| hex_decode(&t[1]).ok())
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
    else {
        return;
    };
    let Some(midx) = masters::find_by_pubkey(ctx.masters, &target_pk) else {
        return;
    };
    let slot = ctx.masters[midx].slot;
    let secret = zeroize::Zeroizing::new(ctx.masters[midx].secret);
    let opened = match heartwood_common::nip59::unwrap(&ev, &secret) {
        Ok(o) => o,
        Err(e) => {
            log::info!("[relay] gift wrap {} not for us: {e}", &ev.id[..8.min(ev.id.len())]);
            remember_wrap(ctx, &ev.id);
            return;
        }
    };
    let note = match heartwood_common::note_wrap::parse_note_rumor(&opened.rumor) {
        Ok(n) => n,
        Err(e) => {
            log::info!("[relay] gift wrap {} is not a note: {e}", &ev.id[..8.min(ev.id.len())]);
            remember_wrap(ctx, &ev.id);
            return;
        }
    };
    // The locker refuses past its cap (the letterbox cap for a stranger,
    // the locker's own for a trusted sender); say so once, before the
    // owner is shown a card for money the device cannot keep. Not
    // remembered: the wrap is still on the relay, and the catch-up re-runs
    // when the wallet collects and makes room.
    if !crate::notes::has_room_for_wrap_from(&opened.sender) {
        log::warn!("[relay] note received with the letterbox full; dropped until there is room");
        ctx.wrap_retry_when_room = true;
        return;
    }

    let sender_hex = hex_encode(&opened.sender);
    let sats = note.amount_msat / 1000;

    // A trusted sender (a public mint the owner holds the button for once,
    // see common/src/trust.rs) is stored on arrival: a zap paid out as a
    // note should not need a human. The hold protected a slot, and the
    // letterbox cap above still does. Decided for the ledger as a hold
    // would be; a refusal by the locker is left undecided so the wrap
    // comes back once there is room.
    if crate::notes::is_trusted_sender(&opened.sender) {
        match crate::notes::receive_note(&note.secret, &note.host, note.amount_msat, &opened.sender) {
            Ok((id, created)) => {
                log::info!(
                    "[relay] note {id} received from trusted sender {} (new: {created})",
                    &sender_hex[..8]
                );
                remember_wrap(ctx, &ev.id);
                if ctx.wrap_ledger.decide(&ev.id, ev.created_at) {
                    crate::notes::store_wrap_ledger(&ctx.wrap_ledger.encode());
                }
                if created && !approval_card_open(ctx) {
                    if !ctx.display_on {
                        crate::oled::wake_display(ctx.display);
                        ctx.display_on = true;
                    }
                    let bare_host = note.host.split('/').next().unwrap_or(note.host.as_str());
                    crate::oled::show_change_done(
                        ctx.display,
                        &format!("{sats} sats received"),
                        &format!("from {bare_host}"),
                    );
                    ctx.last_activity = Instant::now();
                    ctx.network_display_restore_at = Some(Instant::now() + Duration::from_secs(3));
                }
            }
            Err(e) => log::warn!("[relay] trusted note refused by the locker: {}", e.code()),
        }
        return;
    }

    // The host is the field that decides whether this note is worth
    // anything, and it is the field an attacker wants cut short: clipped at
    // the panel's edge, mint.forgesworn.dev and mint.forgesworn.evil.com
    // read the same. So drop the withdraw path, which carries no identity,
    // and give the host a line of its own when it cannot share one.
    let bare_host = note.host.split('/').next().unwrap_or(note.host.as_str());
    // Elide from the LEFT: a host is decided by its tail, so dropping the
    // front keeps the registrable domain and TLD on screen. Cutting the end
    // instead is what makes a lookalike indistinguishable.
    let host = if bare_host.chars().count() > TITLE_LINE_CHARS {
        let tail: String = bare_host
            .chars()
            .skip(bare_host.chars().count() - (TITLE_LINE_CHARS - 2))
            .collect();
        format!("..{tail}")
    } else {
        bare_host.to_string()
    };
    let sender_short = format!("{}..{}", &sender_hex[..8], &sender_hex[56..]);
    let inline = format!("{sats} sats @ {host}");
    let title = if inline.chars().count() <= TITLE_LINE_CHARS {
        format!("{inline}\nfrom {sender_short}")
    } else {
        format!("{host}\n{sats} sats from {}", &sender_hex[..8])
    };
    queue_receive_card(
        ctx,
        slot,
        &target_pk,
        &opened.sender,
        &ev.id,
        title,
        // The rumor rides the ask the way a sign_event's event does: the
        // secret is re-read from it at resolution and zeroised there.
        opened.rumor.clone(),
        ev.created_at,
    );
}

/// Queue a RECEIVE card outside `queue_button_ask`: there is no client to
/// answer busy to, and a full queue simply drops the wrap (the wallet can
/// still collect it from the inbox relays).
#[allow(clippy::too_many_arguments)]
fn queue_receive_card(
    ctx: &mut SignCtx,
    slot: u8,
    target_pk: &[u8; 32],
    sender: &[u8; 32],
    wrap_id: &str,
    title: String,
    rumor: UnsignedEvent,
    created_at: u64,
) {
    use heartwood_common::approval_queue::{admit, Admission, AskKey};
    // One RECEIVE card at a time. Anyone on the internet can address a wrap
    // to a public npub, and the approval queue is shared with the owner's
    // own sign requests; a stranger must not be able to fill it.
    if ctx.button_cards.iter().any(|card| {
        card.asks
            .first()
            .is_some_and(|a| matches!(a.ask.card, crate::nip46_handler::AskCard::Receive { .. }))
    }) {
        // Not remembered: the catch-up after that card settles brings this
        // one back for its own card.
        log::info!("[relay] a note is already waiting on the button; wrap deferred");
        return;
    }
    // Keyed on the wrap id so two notes never collapse into one hold.
    let key = AskKey::new(
        slot,
        hex_encode(sender),
        hex_encode(target_pk),
        format!("receive:{}", &wrap_id[..16.min(wrap_id.len())]),
    );
    let weight = rumor.content.len() + 256;
    let held_bytes: usize = ctx
        .button_cards
        .iter()
        .flat_map(|card| card.asks.iter())
        .map(|ask| ask.weight)
        .sum();
    let open = ctx.button_cards.first();
    let admission = if held_bytes.saturating_add(weight) > CARD_BYTE_BUDGET {
        Admission::Busy
    } else {
        admit(
            open.map(|card| &card.key),
            open.map(|card| card.asks.len()).unwrap_or(0),
            ctx.button_cards.len().saturating_sub(1),
            &key,
        )
    };
    match admission {
        Admission::Busy | Admission::Collapse => {
            log::warn!("[relay] approval queue full; note wrap deferred");
        }
        Admission::Open | Admission::Wait => {
            log::info!("[relay] note received; waiting on the button");
            remember_wrap(ctx, wrap_id);
            ctx.button_cards.push(ButtonCard {
                key,
                target_pk: *target_pk,
                client_pubkey: *sender,
                asks: vec![ButtonAsk {
                    ask: crate::nip46_handler::DeferredAsk {
                        card: crate::nip46_handler::AskCard::Receive { title },
                        request: nip46::Nip46Request {
                            id: wrap_id.to_string(),
                            method: "heartwood_note_receive".to_string(),
                            params: Vec::new(),
                            heartwood: None,
                            legacy_client_pubkey: None,
                        },
                        event: Some(rumor),
                    },
                    created_at,
                    received_uptime: crate::uptime_s(),
                    weight,
                    audit: None,
                }],
                opened_at: None,
                armed: false,
                last_remaining: u32::MAX,
                last_pct: u32::MAX,
            });
        }
    }
}

/// This boot has dealt with the wrap: on a card, or junk. RAM only.
fn remember_wrap(ctx: &mut SignCtx, wrap_id: &str) {
    if ctx.wrap_seen.iter().any(|id| id == wrap_id) {
        return;
    }
    if ctx.wrap_seen.len() >= SEEN_MAX {
        ctx.wrap_seen.remove(0);
    }
    ctx.wrap_seen.push(wrap_id.to_string());
}

/// Settle a RECEIVE card: store the note on a hold, forget it otherwise.
///
/// A hold or a decline is the owner's decision and goes to the ledger, so
/// no catch-up offers that wrap again. A lapse is nobody's decision: the
/// wrap is offered again after [`LAPSED_WRAP_RETRY`], so money that landed
/// while nobody was watching is not lost, and not a 30 s loop either.
/// Either way the catch-up re-runs now, for any wrap deferred behind this
/// card.
fn resolve_receive_card(ctx: &mut SignCtx, card: ButtonCard, outcome: &CardTick, on_screen: bool) {
    let sender = card.client_pubkey;
    let mut ledger_changed = false;
    for mut ask in card.asks {
        let wrap_id = ask.ask.request.id.clone();
        match outcome {
            // A hold is recorded below, once the locker has the note: a
            // hold the locker refused must come back, not be written off.
            CardTick::Approved => {}
            CardTick::Denied => {
                ledger_changed |= ctx.wrap_ledger.decide(&wrap_id, ask.created_at);
            }
            _ => {
                if ctx.wrap_lapsed.len() >= LAPSED_WRAP_MAX {
                    let (old, _) = ctx.wrap_lapsed.remove(0);
                    ctx.wrap_seen.retain(|id| *id != old);
                }
                ctx.wrap_lapsed.push((wrap_id.clone(), Instant::now()));
            }
        }
        let Some(mut rumor) = ask.ask.event.take() else { continue };
        if matches!(outcome, CardTick::Approved) {
            match heartwood_common::note_wrap::parse_note_rumor(&rumor) {
                Ok(note) => {
                    match crate::notes::receive_note(
                        &note.secret,
                        &note.host,
                        note.amount_msat,
                        &sender,
                    ) {
                        Ok((id, created)) => {
                            log::info!("[relay] note {id} received (new: {created})");
                            ledger_changed |= ctx.wrap_ledger.decide(&wrap_id, ask.created_at);
                            if on_screen {
                                let sats = note.amount_msat / 1000;
                                crate::oled::show_change_done(
                                    ctx.display,
                                    &format!("{sats} sats received"),
                                    "wallet collects it",
                                );
                            }
                        }
                        Err(e) => {
                            log::warn!("[relay] note receive refused: {}", e.code());
                            if on_screen {
                                crate::oled::show_error(ctx.display, "Note not kept");
                            }
                        }
                    }
                }
                Err(e) => log::warn!("[relay] note rumor unreadable at accept: {e}"),
            }
        } else if on_screen {
            match outcome {
                CardTick::Denied => crate::oled::show_denied(ctx.display),
                _ => crate::oled::show_request_expired(ctx.display),
            }
        }
        rumor.content.zeroize();
    }
    if ledger_changed {
        crate::notes::store_wrap_ledger(&ctx.wrap_ledger.encode());
    }
    ctx.resubscribe_needed = true;
    if on_screen {
        ctx.network_display_restore_at = Some(Instant::now() + Duration::from_secs(3));
    }
}

/// Build the kind-1059 for a `send`: the note as a rumor authored by the
/// served identity, sealed to `to`. Called from the note dispatch arm with
/// the secret the locker handed over for exactly this; the wrap is what the
/// client relays.
pub fn seal_note_wrap(
    secp: &Arc<Secp256k1<SignOnly>>,
    author_secret: &[u8; 32],
    secret: &[u8; 32],
    meta: &heartwood_common::note_store::NoteMeta,
    to: &[u8; 32],
) -> Result<serde_json::Value, &'static str> {
    let author_pk = Keypair::from_seckey_slice(secp, author_secret)
        .map_err(|_| "bad signing key")?
        .x_only_public_key()
        .0
        .serialize();
    let rumor = heartwood_common::note_wrap::build_note_rumor(
        &hex_encode(&author_pk),
        to,
        secret,
        &meta.host,
        meta.amount_msat,
        wall_clock_estimate(),
    );
    // No NIP-40 expiry: the recipient may not have a wallet yet, and the
    // wrap waiting on their inbox relay until they do is the point.
    let wrap = build_gift_wrap(secp, &rumor, author_secret, to, None)
        .map_err(|_| "gift wrap failed")?;
    serde_json::to_value(wrap).map_err(|_| "wrap serialisation failed")
}

/// Wall-clock reading for code that has no `SignCtx` in hand (the note
/// dispatch arm). Refreshed from the reply clock on every inbound event.
/// u32 because the Xtensa core has no 64-bit atomics; good until 2106.
static WALL_HINT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static WALL_HINT_UPTIME: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn note_wall_clock(ctx: &SignCtx) {
    let up = crate::uptime_s();
    let projected = ctx.reply_clock.projected(up);
    if projected > 0 {
        WALL_HINT.store(projected.min(u32::MAX as u64) as u32, std::sync::atomic::Ordering::Relaxed);
        WALL_HINT_UPTIME.store(up.min(u32::MAX as u64) as u32, std::sync::atomic::Ordering::Relaxed);
    }
}

fn wall_clock_estimate() -> u64 {
    let hint = WALL_HINT.load(std::sync::atomic::Ordering::Relaxed) as u64;
    if hint == 0 {
        return 0;
    }
    let then = WALL_HINT_UPTIME.load(std::sync::atomic::Ordering::Relaxed) as u64;
    hint.saturating_add(crate::uptime_s().saturating_sub(then))
}

/// Service the interactive approval cards: one tick of the front card, and the
/// whole batch answered when it resolves. Called once per relay loop pass, so
/// the websocket, the USB cable and the other clients keep running underneath.
fn service_button_cards(ctx: &mut SignCtx, sessions: &mut [RelaySession]) {
    if ctx.button_cards.is_empty() {
        return;
    }

    // Anything that has waited past the queue TTL without reaching the screen
    // is answered where it stands, one per pass.
    let now = crate::uptime_s();
    let stale = ctx
        .button_cards
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, card)| {
            card.asks
                .first()
                .is_some_and(|ask| now.saturating_sub(ask.received_uptime) >= CARD_QUEUE_TTL_SECS)
        })
        .map(|(index, _)| index);
    if let Some(index) = stale {
        log::info!("[relay] approval ask timed out waiting for the screen");
        resolve_button_card(ctx, sessions, index, &CardTick::Expired);
        return;
    }

    let outcome = tick_button_card(ctx);
    if matches!(outcome, CardTick::Pending) {
        return;
    }
    resolve_button_card(ctx, sessions, 0, &outcome);
}

/// True while an approval card owns the screen and the button.
fn approval_card_open(ctx: &SignCtx) -> bool {
    !ctx.button_cards.is_empty()
}

fn sign_audit_draft(
    req: &nip46::Nip46Request,
    label: String,
    client_hex: &str,
) -> Option<SignAuditDraft> {
    let method = req.method.clone();
    match method.as_str() {
        "sign_event" => {
            let kind = nip46::unsigned_event_kind(&req.params)?;
            let encoded_bytes = req
                .params
                .first()
                .and_then(|value| value.as_str())
                .map(str::len)
                .unwrap_or(0);
            // Preserve descriptive previews for normal notes, but never parse
            // and allocate a second copy of a large document just for audit UI.
            let preview = if encoded_bytes <= 2_048 {
                nip46::parse_unsigned_event(&req.params)
                    .ok()
                    .map(|event| nip46::event_display_summary(&event, 80).1)
                    .unwrap_or_else(|| format!("event content ({encoded_bytes} bytes)"))
            } else {
                format!("large event ({encoded_bytes} bytes)")
            };
            Some(SignAuditDraft {
                method,
                label,
                client: client_hex.to_string(),
                kind: Some(kind),
                preview,
                success_outcome: "signed".to_string(),
            })
        }
        "nip04_encrypt" | "nip04_decrypt" | "nip44_encrypt" | "nip44_decrypt" => {
            let peer = req
                .params
                .first()
                .and_then(|v| v.as_str())
                .filter(|s| s.len() >= 8)
                .map(|s| &s[..8])
                .unwrap_or("unknown");
            Some(SignAuditDraft {
                method,
                label,
                client: client_hex.to_string(),
                kind: None,
                preview: format!("peer {peer} - content redacted"),
                success_outcome: "ok".to_string(),
            })
        }
        _ => None,
    }
}

fn push_sign_audit(ctx: &mut SignCtx, draft: SignAuditDraft, response_json: &str) {
    let outcome = serde_json::from_str::<serde_json::Value>(response_json)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.as_str())
                .map(|e| format!("error: {e}"))
        })
        .unwrap_or_else(|| draft.success_outcome.clone());
    ctx.sign_audit_seq = ctx.sign_audit_seq.wrapping_add(1);
    if ctx.sign_audit.len() >= SIGN_AUDIT_MAX {
        ctx.sign_audit.remove(0);
    }
    ctx.sign_audit.push(SignAuditEntry {
        seq: ctx.sign_audit_seq,
        method: draft.method,
        label: draft.label,
        client: draft.client,
        kind: draft.kind,
        preview: draft.preview,
        outcome,
    });
}

fn sign_audit_json(ctx: &SignCtx) -> Vec<serde_json::Value> {
    // Report only the most recent window (chronological order preserved). The
    // full ring stays in RAM; capping what each poll transports is what keeps
    // the response under the heap guard on a fragmented no-PSRAM board.
    let skip = ctx.sign_audit.len().saturating_sub(SIGN_AUDIT_REPORT_MAX);
    ctx.sign_audit
        .iter()
        .skip(skip)
        .map(|a| {
            serde_json::json!({
                "seq": a.seq,
                "method": a.method,
                "label": a.label,
                "client": a.client,
                "kind": a.kind,
                "preview": a.preview,
                "outcome": a.outcome,
            })
        })
        .collect()
}

/// A get_status response stripped to the essentials: identity counts, uptime,
/// reset attribution, the crash breadcrumb and live heap health. It omits the
/// audit ring and relay lists — the large arrays whose re-encrypted, padded and
/// base64'd transport buffers are what abort the allocator on a fragmented
/// no-PSRAM heap. get_status is polled every few seconds, so the poll that
/// reports a starved heap must never itself be the allocation that reboots the
/// signer. `truncated` tells the manager the request log was omitted this poll.
fn minimal_status_json(id: &str, ctx: &SignCtx, master_idx: usize) -> String {
    let master_hex = hex_encode(&ctx.masters[master_idx].pubkey);
    serde_json::json!({
        "id": id,
        "result": {
            "master_count": ctx.masters.len(),
            "master_npub_hex": master_hex,
            "mode": "wifi-standalone",
            "relay": ctx.relay_url,
            "uptime_s": crate::uptime_s(),
            "last_reset": crate::reset_reason_str(),
            "crashed_during": crate::crash_context(),
            "free_heap": unsafe { esp_idf_svc::sys::esp_get_free_heap_size() },
            "largest_free_block": unsafe {
                esp_idf_svc::sys::heap_caps_get_largest_free_block(esp_idf_svc::sys::MALLOC_CAP_8BIT)
            } as u32,
            "log_quiet": crate::log_quiet::read(ctx.nvs),
            "version": env!("CARGO_PKG_VERSION"),
            "board": crate::board::BOARD,
            "truncated": true,
        }
    })
    .to_string()
}

/// NIP-46 signing path (kind 24133): resolve the addressed identity → decrypt →
/// `handle_request` → re-encrypt → sign + publish. Mirrors the USB
/// `transport::handle_encrypted_request`, including per-persona routing.
fn handle_nip46_event(
    tls: &mut Tls,
    mut ev: SignedEvent,
    ctx: &mut SignCtx,
    target_pk: &[u8; 32],
) -> Result<(), String> {
    // When this request reached us, on the only monotonic counter the chip
    // has. Everything published below is stamped from it rather than from the
    // request's own `created_at`, so a reply held behind an approval window is
    // not backdated to the moment the ask arrived (#64).
    let received_uptime = crate::uptime_s();
    // Resolve the addressed identity to its signing key. A master signs with its
    // own secret; a persona re-derives its key from the owning master and uses
    // that key for BOTH the NIP-44 transport and the envelope signature — so one
    // connection == one identity, exactly as the USB path does. `label`/`mode`/
    // `slot` are the owning master's (personas share the master's policy slot).
    // All resolved values are owned, so no `ctx` borrow is held past this block.
    let (signing_secret, label, mode, slot, is_persona, persona_purpose) =
        if let Some(midx) = masters::find_by_pubkey(ctx.masters, target_pk) {
            let m = &ctx.masters[midx];
            (
                zeroize::Zeroizing::new(m.secret),
                m.label.clone(),
                m.mode,
                m.slot,
                false,
                None,
            )
        } else if let Some(pidx) = crate::personas::find_by_pubkey(ctx.personas, target_pk) {
            let p = &ctx.personas[pidx];
            let owning = match ctx.masters.iter().find(|m| m.slot == p.master_slot) {
                Some(m) => m,
                None => {
                    log::warn!(
                        "[relay] persona's owning master slot {} not loaded; ignoring",
                        p.master_slot
                    );
                    return Ok(());
                }
            };
            match crate::nip46_handler::derive_identity(
                &owning.secret,
                owning.mode,
                &p.purpose,
                p.index,
            ) {
                Ok((secret, _pk)) => (
                    secret,
                    owning.label.clone(),
                    owning.mode,
                    owning.slot,
                    true,
                    Some(p.purpose.clone()),
                ),
                Err(e) => {
                    log::error!("[relay] persona key derivation failed: {e}");
                    return Ok(());
                }
            }
        } else {
            log::warn!("[relay] EVENT not addressed to a known identity; ignoring");
            return Ok(());
        };

    // The event author is the remote client.
    let client_pubkey: [u8; 32] = match hex_decode(&ev.pubkey).ok().and_then(|v| v.try_into().ok())
    {
        Some(pk) => pk,
        None => {
            log::warn!("[relay] EVENT has invalid author pubkey; ignoring");
            return Ok(());
        }
    };

    // A persona connection must act AS the persona for every inner method, so
    // clear any session active-identity (set by a legacy heartwood_switch) that
    // would otherwise double-derive on top of the persona secret. Mirrors
    // transport::handle_encrypted_request.
    if is_persona {
        if let Some(session) = ctx.policy_engine.get_or_create_session(client_pubkey, slot) {
            session.active_identity = None;
        }
    }

    let conversation_key = match nip44::get_conversation_key(&signing_secret, &client_pubkey) {
        Ok(ck) => ck,
        Err(e) => {
            log::error!("[relay] conversation key: {e}");
            return Ok(());
        }
    };

    let plaintext = match nip44::decrypt(&conversation_key, &ev.content) {
        Ok(pt) => pt,
        Err(e) => {
            log::warn!("[relay] NIP-44 decrypt failed: {e}");
            return Ok(());
        }
    };
    // Signature verification and decryption are complete; release the large
    // base64 request envelope before parsing the inner request or signing it.
    drop(std::mem::take(&mut ev.content));
    log::info!(
        "[relay] decrypted request ({} bytes) from {}… for {}{}",
        plaintext.len(),
        &ev.pubkey[..ev.pubkey.len().min(8)],
        label,
        if is_persona { " (persona)" } else { "" }
    );
    // Refuse an over-budget request BEFORE serde_json sees it.
    //
    // The size guard in `handle_parsed_request` is too late to protect this:
    // parsing is what dies. NIP-46 carries the event as a JSON *string inside*
    // params, so every quote in it is escaped, and `serde_json::read::parse_escape`
    // unescapes into a Vec that grows by DOUBLING. A 16503-byte request asked for
    // 32878 bytes in one block, the allocation failed, and Rust's alloc-error
    // path aborts the chip — a reboot, not a refusal:
    //
    //     [relay] decrypted request (16503 bytes) ...
    //     memory allocation of 32878 bytes failed
    //     abort() was called
    //
    // It needs roughly 2x the plaintext contiguous, which is why this bites far
    // below any wire limit and why free heap looked ample (156 KB) at the time.
    // Observed from two different paired clients, so any app sending a largish
    // event could reboot the signer.
    //
    // Only kind-24133 reaches here; MGMT_KIND branched off earlier, so the ~17 KB
    // set_identity_meta path is unaffected by this bound.
    // Which budget applies depends on the encoding, so decide that first and
    // without parsing. The string form pays an unescape pass that grows a Vec by
    // doubling; the object form does not, and can therefore be allowed a much
    // larger event on the same board.
    // The larger ceiling needs BOTH halves, because there are two allocations of
    // about twice the content and each is fatal on its own:
    //
    //   - the request's unescape pass, avoided only by the object form;
    //   - the reply, which echoes the whole signed event back unless the client
    //     asked for the compact one. An 18432-byte event cleared the parse and
    //     then died on a 37270-byte response allocation.
    //
    // So a client gets the headroom only if it sends an object AND accepts the
    // compact reply. Either alone leaves one of the two costs in place.
    let ceiling = nip46::request_ceiling(
        &plaintext,
        crate::board::MAX_SIGN_BYTES,
        crate::board::MAX_SIGN_BYTES_OBJECT,
    );
    let request_budget = ceiling + heartwood_common::types::SIGN_RESPONSE_OVERHEAD;
    if plaintext.len() > request_budget {
        log::warn!(
            "[relay] request of {} bytes exceeds the {} byte {} parse budget; refusing",
            plaintext.len(),
            request_budget,
            if ceiling > crate::board::MAX_SIGN_BYTES { "object+compact" } else { "standard" }
        );
        // Scan the id out rather than parsing for it: parsing is the thing that
        // aborts. Without it the refusal reaches the client as silence, and an
        // app shows a timeout instead of "too large".
        let response = nip46::build_error_response(
            nip46::scan_rpc_id(&plaintext).unwrap_or("unknown"),
            -3,
            "request is too large for this signer",
        )
        .unwrap_or_default();
        drop(plaintext);
        return sign_and_publish(
            tls,
            ctx.secp,
            &signing_secret,
            &conversation_key,
            &ev.pubkey,
            NIP46_KIND,
            ctx.reply_clock
                .stamp(ev.created_at, received_uptime, crate::uptime_s()),
            response,
        );
    }
    let request = match nip46::parse_request(plaintext.as_bytes()) {
        Ok(request) => request,
        Err(e) => {
            log::warn!("[relay] failed to parse NIP-46 request: {e}");
            drop(plaintext);
            let response = nip46::build_error_response(
                "unknown",
                -3,
                "invalid JSON-RPC request",
            )
            .unwrap_or_default();
            return sign_and_publish(
                tls,
                ctx.secp,
                &signing_secret,
                &conversation_key,
                &ev.pubkey,
                NIP46_KIND,
                ctx.reply_clock
                    .stamp(ev.created_at, received_uptime, crate::uptime_s()),
                response,
            );
        }
    };
    drop(plaintext);
    let audit = sign_audit_draft(
        &request,
        client_label(ctx, slot, &ev.pubkey),
        &ev.pubkey,
    );

    // Only connect binding and first-sign TOFU can change durable slot
    // authority. Snapshot those uncommon requests before dispatch so an NVS
    // failure can roll RAM back without cloning the slot table on every
    // unattended auto-sign. The tier is also what the C4 escalation gate and
    // the C5 outcome mapping key off, so compute it once here.
    let request_id = request.id.clone();
    let method_enum = nip46::Nip46Method::from_str(&request.method);
    let event_kind = if matches!(method_enum, nip46::Nip46Method::SignEvent) {
        nip46::unsigned_event_kind(&request.params)
    } else {
        None
    };
    let tier = ctx
        .policy_engine
        .check(slot, &ev.pubkey, &method_enum, event_kind);
    let slot_snapshot = crate::nip46_handler::request_may_mutate_slot_state(&request, tier)
        .then(|| ctx.policy_engine.snapshot_slot_state(slot));

    // C4 escalation (schema §1.1): an interactive ask on an escalate-flagged
    // slot parks and notifies the guardian's phone instead of blocking the
    // relay loop on the physical button — the loop must stay live so a fast
    // verdict can complete the request within the client's wait. Non-flagged
    // slots keep today's button behaviour exactly.
    if matches!(tier, heartwood_common::policy::ApprovalTier::ButtonRequired)
        && ctx
            .policy_engine
            .find_slot_by_pubkey(slot, &ev.pubkey)
            .is_some_and(|s| s.escalate)
    {
        let park = ParkedRequest {
            park_id: ev.id.clone(),
            target_pk: *target_pk,
            client_pubkey,
            client_hex: ev.pubkey.clone(),
            created_at: ev.created_at,
            master_slot: slot,
            method: request.method.clone(),
            event_kind,
            parked_at: Instant::now(),
            request,
        };
        park_and_notify(tls, ctx, park);
        return Ok(());
    }

    // C4 petitions (schema §1.2): a strict deny on a petition-flagged slot
    // records the ask and notifies, low priority. The deny below stays
    // enforced — dispatch still answers "unauthorised" as it always did.
    if matches!(tier, heartwood_common::policy::ApprovalTier::Denied)
        && ctx
            .policy_engine
            .find_slot_by_pubkey(slot, &ev.pubkey)
            .is_some_and(|s| s.petition_on_deny)
    {
        petition_and_notify(
            tls,
            ctx,
            slot,
            &ev.pubkey,
            target_pk,
            &request.method,
            event_kind,
            ev.created_at,
        );
    }

    // C5 rail draft: extracted before dispatch consumes the params, emitted
    // after dispatch when the target is a dependant-tagged persona.
    let rail_draft = persona_purpose
        .as_deref()
        .filter(|purpose| heartwood_common::escalate::is_dependant_purpose(purpose))
        .and_then(|_| audit_rail_draft(&request));

    // Breadcrumb the in-flight request so a crash while handling it is
    // attributable on the next boot. Cleared right after the handler returns;
    // it only survives if the chip resets before that (panic/watchdog).
    {
        let mut crumb = format!("relay {}", request.method);
        if matches!(
            nip46::Nip46Method::from_str(&request.method),
            nip46::Nip46Method::SignEvent
        ) {
            if let Some(kind) = nip46::unsigned_event_kind(&request.params) {
                crumb.push_str(&format!(" kind {kind}"));
            }
        }
        // Free heap at request time distinguishes a big-response OOM from a
        // fragmentation crash on a small request — the field diagnostic.
        let free = unsafe { esp_idf_svc::sys::esp_get_free_heap_size() };
        crumb.push_str(&format!(" from {} (heap {}k)", &ev.pubkey[..ev.pubkey.len().min(8)], free / 1024));
        crate::crash_crumb::set(&crumb);
    }

    // Dispatch — same handler as the USB path. sign_event is ButtonRequired
    // until the slot is physically button-upgraded; auto-approve covers the
    // safe methods and post-upgrade signing.
    //
    // Deferred, unlike the USB paths: an ask that needs the button comes back
    // here undispatched instead of holding this call — and the whole loop —
    // for the length of a window (#64). The card goes up, the loop carries on,
    // and the request is dispatched by `resolve_button_card` once the hold is
    // in hand.
    let mut response_json = match crate::nip46_handler::dispatch(
        request,
        None,
        &signing_secret,
        &label,
        mode,
        slot,
        ctx.secp,
        ctx.display,
        ctx.buttons,
        ctx.policy_engine,
        ctx.identity_caches,
        Some(&client_pubkey),
        ctx.nvs,
        ctx.personas,
        crate::nip46_handler::ApprovalDecision::Deferred,
    ) {
        crate::nip46_handler::Dispatch::Answered(json) => json,
        crate::nip46_handler::Dispatch::NeedsApproval(ask) => {
            return queue_button_ask(
                tls,
                ctx,
                *ask,
                slot,
                target_pk,
                &client_pubkey,
                &ev.pubkey,
                &conversation_key,
                &signing_secret,
                ev.created_at,
                received_uptime,
                audit,
            );
        }
    };
    if !ctx.policy_engine.persist_slots(ctx.nvs, slot) {
        if let Some(snapshot) = slot_snapshot {
            let rollback_durable = ctx
                .policy_engine
                .restore_slot_state_durably(ctx.nvs, snapshot);
            let error = if rollback_durable {
                log::error!(
                    "[relay] slot authority for NIP-46 request {request_id} was not durable; prior authority restored durably"
                );
                "client policy could not be saved; request was not applied"
            } else {
                log::error!(
                    "[relay] FATAL: slot authority for NIP-46 request {request_id} was not durable and prior authority could not be restored durably"
                );
                "fatal storage error: prior client policy could not be restored; take the device offline for USB recovery"
            };
            response_json = nip46::build_error_response(
                &request_id,
                -4,
                error,
            )
            .unwrap_or_default();
        }
    }
    if let Some(audit) = audit {
        push_sign_audit(ctx, audit, &response_json);
    }

    // C5 device audit rail: policy-decided outcomes on dependant-tagged
    // personas emit the gift-wrapped kind-31000 record the app's Activity
    // page already reads. Best effort — never fails the signing path.
    if let Some(draft) = rail_draft {
        let error = response_error_of(&response_json);
        if let Some(outcome) =
            heartwood_common::escalate::audit_outcome(tier, error.as_deref(), false)
        {
            let target_hex = hex_encode(target_pk);
            if let Err(e) =
                emit_audit_rail(tls, ctx, slot, &target_hex, &draft, outcome, ev.created_at)
            {
                log::warn!("[relay] audit rail: {e}");
            }
        }
    }

    // Persist any identities derived during this request (e.g. via
    // heartwood_derive_persona) to the registry, so they survive reboot and
    // become addressable by their own bunker URI. The dispatch site notices
    // the registry growing and refreshes the live `#p` subscriptions, so the
    // fresh persona is reachable without a reconnect.
    crate::transport::persist_fresh_identities(ctx.nvs, ctx.identity_caches, ctx.personas, slot);

    // Heap guard before the response re-encryption. Publishing re-encrypts the
    // response (NIP-44 pads to the next power of two), base64-encodes it, and
    // builds + signs the envelope — several transient buffers a few times the
    // response size. On a no-PSRAM board with a fragmented heap a large
    // response (e.g. a big nip44_decrypt plaintext, which nostr.com sends after
    // login) would abort the allocator, rebooting the signer. Rather than
    // crash, substitute a small error so the app sees a clean failure and the
    // signer stays up. Verified in the field by the crash breadcrumb naming
    // "relay nip44_decrypt".
    if !response_transportable(response_json.len()) {
        log::warn!(
            "[relay] response for {request_id} ({} B) too large for free heap; returning error instead of risking a crash",
            response_json.len()
        );
        response_json = nip46::build_error_response(
            &request_id,
            -4,
            "response too large for this signer's memory; the request was not completed",
        )
        .unwrap_or_default();
    }

    // The publish (re-encrypt + inline envelope sign) is the other crash-prone
    // step on a fragmented no-PSRAM heap, so keep the breadcrumb set across it.
    // handle_relay_msg clears the breadcrumb once the whole event is processed.
    sign_and_publish(
        tls,
        ctx.secp,
        &signing_secret,
        &conversation_key,
        &ev.pubkey,
        NIP46_KIND,
        ctx.reply_clock
            .stamp(ev.created_at, received_uptime, crate::uptime_s()),
        response_json,
    )
}

/// Relay-management path (kind 24134): authenticate the author against the
/// baked operator key, decrypt, replay-guard, dispatch, then sign + publish.
fn handle_mgmt_event(
    s: &mut RelaySession,
    ev: &SignedEvent,
    ctx: &mut SignCtx,
    master_idx: usize,
    pool: &mut RelayPool,
) -> Result<(), String> {
    // Receipt time on the monotonic counter, so an ack for a command that
    // stopped for the button (or completed a park) is not backdated (#64).
    let received_uptime = crate::uptime_s();
    // SECURITY CRUX: the command runs only if it comes from an operator
    // authorised for THIS identity — either the device-wide operator or the
    // per-identity operator this master was delegated to. NIP-44 (below) already
    // makes forgery impossible (a third party can't encrypt under the
    // master⇄operator conversation key without the operator secret); this author
    // gate is the explicit authority check on top. The rule itself,
    // `mgmt::is_authorised_operator`, is unit-tested on the host.
    let author: [u8; 32] = match hex_decode(&ev.pubkey).ok().and_then(|v| v.try_into().ok()) {
        Some(a) => a,
        None => return Ok(()),
    };
    let device_op = ctx.op_mgmt;
    let identity_op = ctx.masters[master_idx].operator;
    if !mgmt::is_authorised_operator(&author, identity_op.as_ref(), device_op.as_ref()) {
        log::warn!(
            "[relay] mgmt from unauthorised {}…; rejecting",
            &ev.pubkey[..ev.pubkey.len().min(16)]
        );
        return Ok(());
    }
    // Device-level actions (adding identities, delegating operators) stay with
    // the device operator; a delegated per-identity operator is confined to
    // managing the one identity it was granted.
    let is_device_op = device_op == Some(author);

    // Conversation key is master ⇄ the authenticated operator (device or the
    // per-identity delegate), so the response seals back to whoever sent the
    // command. Scope the borrow so `ctx` is free for the mutable dispatch below.
    let conversation_key = {
        let master = &ctx.masters[master_idx];
        match nip44::get_conversation_key(&master.secret, &author) {
            Ok(ck) => ck,
            Err(e) => {
                log::error!("[relay] mgmt conversation key: {e}");
                return Ok(());
            }
        }
    };

    let plaintext = match nip44::decrypt(&conversation_key, &ev.content) {
        Ok(pt) => pt,
        Err(e) => {
            log::warn!("[relay] mgmt NIP-44 decrypt failed: {e}");
            return Ok(());
        }
    };
    let req: serde_json::Value = match serde_json::from_str(&plaintext) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("[relay] mgmt request not JSON: {e}");
            return Ok(());
        }
    };
    // An avatar-carrying request is ~11KB of plaintext; free it before dispatch
    // rather than hold it through the NVS write on an already-tight heap.
    drop(plaintext);
    let id = req
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let method = req
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // The same encrypted management event may be delivered by both the
    // configured primary and an unrelated client-pinned relay. A pinned copy
    // must not enter the replay seen-set first and poison the later valid
    // primary delivery. Silently pre-gate it (and any non-candidate source)
    // before remembering the inner request id.
    if method == "commit_network_config" {
        if s.pinned {
            log::warn!(
                "[relay] ignoring network commit delivered by pinned relay {}",
                s.url
            );
            return Ok(());
        }
        if let Some(trial) = crate::net_config_store::read_trial(ctx.nvs) {
            if trial.phase == NetworkTrialPhase::Staged
                || (trial.phase == NetworkTrialPhase::Trying && trial.attempts == 0)
            {
                log::warn!("[relay] ignoring network commit before candidate boot");
                return Ok(());
            }
            if !network_commit_source_allowed(false, &s.url, &trial.candidate.relays) {
                log::warn!(
                    "[relay] ignoring network commit from non-candidate relay {}",
                    s.url
                );
                return Ok(());
            }
        }
    }

    // Duplicate-delivery guard. The id checked here is the *inner* request id —
    // it lives inside the NIP-44 ciphertext, so it cannot be forged or altered
    // without the operator secret. The persisted set is deliberately bounded;
    // the one-time mutation challenge below is the durable replay boundary once
    // an old id has been evicted. No wall-clock is needed.
    match mgmt::classify_replay(&id, &ctx.seen) {
        mgmt::Replay::Fresh => {}
        mgmt::Replay::Empty => {
            log::warn!("[relay] mgmt request with empty id; ignoring");
            return Ok(());
        }
        mgmt::Replay::Seen => {
            log::warn!("[relay] mgmt replay (id {id}); ignoring");
            return Ok(());
        }
    }
    mgmt::remember(&id, &mut ctx.seen, SEEN_MAX);
    log::info!("[relay] mgmt request: method={method} id={id} (operator authenticated)");

    // Breadcrumb the management op so a crash while handling it (e.g. an
    // identity-card render) is attributable on the next boot, not just the
    // NIP-46 signing path. Cleared after dispatch returns.
    crate::crash_crumb::set(&format!("relay mgmt {method}"));

    let dispatch_result = (|| {
        if mgmt::requires_mutation_challenge(&method) {
            let current = crate::management_challenge::current(
                ctx.nvs,
                crate::management_challenge::EntropySource::RadioActive,
            )
            .map_err(|e| {
                log::error!("[relay] {e}");
                "management challenge unavailable; mutation was not applied".to_string()
            })?;
            let current_hex = hex_encode(&current);
            let supplied = req.get("mutation_challenge").and_then(|value| value.as_str());
            match mgmt::classify_mutation_challenge(&method, supplied, &current_hex) {
                mgmt::MutationChallenge::Current => {
                    crate::management_challenge::rotate(
                        ctx.nvs,
                        &current,
                        crate::management_challenge::EntropySource::RadioActive,
                    )
                    .map_err(|e| {
                        log::error!("[relay] {e}");
                        "management challenge could not be rotated; mutation was not applied"
                            .to_string()
                    })?;
                }
                mgmt::MutationChallenge::Missing => {
                    return Err("replay_safe_mutation_required: request get_management_challenge before changing the device".into());
                }
                mgmt::MutationChallenge::Malformed => {
                    return Err("invalid_management_challenge: expected 64 hex characters".into());
                }
                mgmt::MutationChallenge::Stale => {
                    return Err("stale_management_challenge: another manager changed the device; refresh state and retry".into());
                }
                mgmt::MutationChallenge::NotRequired => unreachable!(),
            }
        }
        dispatch_mgmt(&method, &req, s, ctx, master_idx, pool, is_device_op)
    })();
    // The breadcrumb stays set across the response publish below too;
    // handle_relay_msg clears it once the whole event is processed.

    let response_json = match dispatch_result {
        Ok(result) => serde_json::json!({ "id": id, "result": result }).to_string(),
        Err(e) => serde_json::json!({ "id": id, "error": e }).to_string(),
    };

    // Heap guard on the management publish, mirroring the NIP-46 sign path
    // above. Publishing re-encrypts, pads, base64-encodes and signs the response
    // — several transient buffers a few times its size — and on a fragmented
    // no-PSRAM heap a large one aborts the allocator and reboots the signer.
    // get_status is the offender: polled every few seconds, it carries the whole
    // audit ring plus relay lists (field-observed crash breadcrumb: "relay mgmt
    // get_status"). Rather than crash, degrade. For get_status, resend the vital
    // status without the heavy arrays, so the crash telemetry itself still
    // reaches the manager; for any other method, a clean retryable error.
    let response_json = if response_transportable(response_json.len()) {
        response_json
    } else if method == "get_status" {
        log::warn!(
            "[relay] get_status response ({} B) too large for free heap; sending minimal status",
            response_json.len()
        );
        minimal_status_json(&id, ctx, master_idx)
    } else {
        log::warn!(
            "[relay] mgmt {method} response ({} B) too large for free heap; returning error instead of risking a crash",
            response_json.len()
        );
        serde_json::json!({
            "id": id,
            "error": "device low on memory; state unchanged, retry shortly"
        })
        .to_string()
    };

    let stamped = ctx
        .reply_clock
        .stamp(ev.created_at, received_uptime, crate::uptime_s());
    let master = &ctx.masters[master_idx];
    sign_and_publish(
        &mut s.tls,
        ctx.secp,
        &master.secret,
        &conversation_key,
        &ev.pubkey,
        MGMT_KIND,
        stamped,
        response_json,
    )
}

/// The identity a pairing mint is addressed to (D2 persona-addressed
/// pairing). Resolved from an optional `params.identity`; absent means the
/// master, exactly the pre-D2 behaviour.
enum AddressedIdentity {
    Master,
    Persona {
        hex: String,
        purpose: String,
        index: u32,
    },
}

/// Resolve an optional `params.identity` (x-only hex) against the identities
/// THIS master serves — itself or one of its registry personas. An operator
/// can therefore never mint a URI pointing at a key the signer will not
/// answer for, and a persona of a *different* master is rejected rather than
/// silently cross-wired.
fn identity_param(
    req: &serde_json::Value,
    masters: &[crate::masters::LoadedMaster],
    personas: &[crate::personas::LoadedPersona],
    master_idx: usize,
) -> Result<AddressedIdentity, String> {
    let raw = match req.pointer("/params/identity").and_then(|v| v.as_str()) {
        None => return Ok(AddressedIdentity::Master),
        Some(s) => s,
    };
    let bytes: [u8; 32] = hex_decode(raw)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("identity must be 32-byte hex")?;
    let master = &masters[master_idx];
    if bytes == master.pubkey {
        return Ok(AddressedIdentity::Master);
    }
    match crate::personas::find_by_pubkey(personas, &bytes) {
        Some(pidx) if personas[pidx].master_slot == master.slot => {
            let p = &personas[pidx];
            Ok(AddressedIdentity::Persona {
                hex: hex_encode(&bytes),
                purpose: p.purpose.clone(),
                index: p.index,
            })
        }
        _ => Err("identity not served by this master".into()),
    }
}

/// Parse the v2 exact-policy envelope strictly. The versioned method name is
/// intentional: old firmware rejects it before mutation instead of silently
/// ignoring fields it does not understand and creating a broad signing slot.
fn exact_policy_from_request(req: &serde_json::Value) -> Result<ExactSlotPolicy, String> {
    let raw_methods = req
        .pointer("/params/policy/allowed_methods")
        .and_then(|value| value.as_array())
        .ok_or("v2 policy requires params.policy.allowed_methods")?;
    let mut methods = Vec::with_capacity(raw_methods.len());
    for value in raw_methods {
        methods.push(
            value
                .as_str()
                .ok_or("v2 policy allowed_methods must contain only strings")?
                .to_string(),
        );
    }

    let raw_kinds = req
        .pointer("/params/policy/allowed_kinds")
        .and_then(|value| value.as_array())
        .ok_or("v2 policy requires params.policy.allowed_kinds")?;
    let mut kinds = Vec::with_capacity(raw_kinds.len());
    for value in raw_kinds {
        kinds.push(
            value
                .as_u64()
                .ok_or("v2 policy allowed_kinds must contain only unsigned integers")?,
        );
    }

    let auto_approve = req
        .pointer("/params/policy/auto_approve")
        .and_then(|value| value.as_bool())
        .ok_or("v2 policy requires params.policy.auto_approve")?;

    let mut policy =
        validate_exact_slot_policy(methods, kinds, auto_approve).map_err(str::to_string)?;

    // Family-bunker C3 additive flags (escalation schema §1.5/§2.1):
    // optional, default false/absent — older operators that never send them
    // are byte-for-byte unaffected.
    policy.escalate = req
        .pointer("/params/policy/escalate")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    policy.petition_on_deny = req
        .pointer("/params/policy/petition_on_deny")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    policy.audit_child_wrap = req
        .pointer("/params/policy/audit_child_wrap")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    policy.bound_identity = req
        .pointer("/params/policy/bound_identity")
        .and_then(|value| value.as_str())
        .filter(|s| is_hex64(s))
        .map(|s| s.to_ascii_lowercase());
    Ok(policy)
}

/// Make a slot-authority mutation durable before its management response may
/// report success. The complete per-master snapshot closes partial rollback
/// gaps (including client keys moved out of another slot by uniqueness rules).
fn persist_slot_mutation_or_rollback(
    ctx: &mut SignCtx,
    master_slot: u8,
    snapshot: crate::policy::SlotStateSnapshot,
    action: &str,
) -> Result<(), String> {
    if ctx.policy_engine.persist_slots(ctx.nvs, master_slot) {
        return Ok(());
    }
    if ctx
        .policy_engine
        .restore_slot_state_durably(ctx.nvs, snapshot)
    {
        log::error!("[relay] {action} was not durable; prior slot authority restored durably");
        Err(format!(
            "could not persist {action}; request was not applied"
        ))
    } else {
        log::error!(
            "[relay] FATAL: {action} failed and prior slot authority could not be restored durably"
        );
        Err(format!(
            "fatal storage error: could not restore prior client policy after {action}; take the device offline for USB recovery"
        ))
    }
}

/// Bind a numeric-slot management action to the credential the operator last
/// observed. Slot indices are reused after revocation, so the index alone is
/// not a stable identity: a delayed/stale UI action could otherwise target a
/// newly-created client that inherited the same index.
fn require_expected_slot_fingerprint(
    req: &serde_json::Value,
    slot: &heartwood_common::policy::ConnectSlot,
) -> Result<String, String> {
    let actual = mgmt::credential_fingerprint(&slot.secret);
    match mgmt::classify_credential_fingerprint(
        req.pointer("/params/expected_secret_fingerprint")
            .and_then(|value| value.as_str()),
        &actual,
    ) {
        mgmt::CredentialFingerprintMatch::Match => Ok(actual),
        mgmt::CredentialFingerprintMatch::Missing => {
            Err("expected_secret_fingerprint is required".into())
        }
        mgmt::CredentialFingerprintMatch::Malformed => Err(
            "invalid expected_secret_fingerprint: expected 64 lowercase hex characters".into(),
        ),
        mgmt::CredentialFingerprintMatch::Mismatch => {
            Err("stale_client_slot: slot credential changed; refresh clients and try again".into())
        }
    }
}

/// Execute one authenticated management method. Maps onto the same
/// connslot/policy operations as the USB path. `create_client` mirrors
/// `CONNSLOT_CREATE`; `list_identities` enumerates the served identities
/// (master + personas) with their bunker URIs for discovery; trust-root/seed
/// changes are deliberately NOT exposed.
fn dispatch_mgmt(
    method: &str,
    req: &serde_json::Value,
    // The session the command arrived on — `nostrconnect` publishes the connect
    // ACK on it when the client's relay is already served.
    s: &mut RelaySession,
    ctx: &mut SignCtx,
    master_idx: usize,
    // The other live sessions + pinned bookkeeping, for nostrconnect dial-out.
    pool: &mut RelayPool,
    // True when the authenticated author is the device-wide operator (not a
    // per-identity delegate). Gates identity-adding and delegation methods.
    is_device_op: bool,
) -> Result<serde_json::Value, String> {
    // Extract owned master facts before borrowing policy_engine mutably.
    let master_slot = ctx.masters[master_idx].slot;
    let master_hex = hex_encode(&ctx.masters[master_idx].pubkey);

    match method {
        "get_management_challenge" => {
            let challenge = crate::management_challenge::current(
                ctx.nvs,
                crate::management_challenge::EntropySource::RadioActive,
            )
            .map_err(|e| {
                log::error!("[relay] {e}");
                "management challenge unavailable".to_string()
            })?;
            Ok(serde_json::json!({
                "version": 1,
                "challenge": hex_encode(&challenge),
            }))
        }

        "get_network_config" => {
            if !is_device_op {
                return Err("reading the device network configuration is a device-level operation and requires the device operator".into());
            }
            // Capture the atomic marker before best-effort cleanup. Once this
            // exists, B and a committed outcome are authoritative even when
            // active/terminal NVS writes are temporarily unavailable.
            let committed_marker = crate::net_config_store::read_trial(ctx.nvs)
                .filter(|trial| trial.phase == NetworkTrialPhase::Committed);
            let _ = crate::net_config_store::reconcile_terminal_state(ctx.nvs);
            let persisted_terminal = crate::net_config_store::read_terminal(ctx.nvs);
            let terminal = match committed_marker.as_ref() {
                Some(marker) => persisted_terminal
                    .filter(|last| {
                        last.transaction_id == marker.transaction_id
                            && last.revision == marker.accepted_revision
                            && last.outcome
                                == heartwood_common::net_config::NetworkTerminalOutcome::Committed
                    })
                    .or_else(|| {
                        Some(heartwood_common::net_config::NetworkTerminalRecord {
                            version: 1,
                            transaction_id: marker.transaction_id.clone(),
                            revision: marker.accepted_revision,
                            outcome:
                                heartwood_common::net_config::NetworkTerminalOutcome::Committed,
                        })
                    }),
                None => persisted_terminal,
            };
            if terminal.as_ref().map(|last| {
                last.outcome == heartwood_common::net_config::NetworkTerminalOutcome::Committed
                    && ctx.network_trial_id.as_deref() == Some(last.transaction_id.as_str())
            }) == Some(true)
            {
                ctx.network_trial_id = None;
                ctx.network_trial_deadline = None;
            }
            let active = committed_marker
                .as_ref()
                .map(|trial| trial.candidate.clone())
                .or_else(|| {
                    crate::net_config_store::read_net_config(ctx.nvs).and_then(|raw| {
                        heartwood_common::net_config::parse_net_config(&raw).ok()
                    })
                })
                .ok_or("active network config unavailable")?;
            let active_json = serde_json::json!({
                "mode": active.mode,
                "ssid": active.ssid,
                "relays": active.relays,
                "password_set": !active.password.is_empty(),
                "networks": crate::net_config_store::redacted_networks(&active),
            });
            let terminal_transaction = terminal
                .as_ref()
                .map(|last| (last.transaction_id.as_str(), last.revision));
            let trial_json = crate::net_config_store::read_trial(ctx.nvs)
                .filter(|trial| {
                    trial.phase != NetworkTrialPhase::Committed
                        && terminal_transaction
                            != Some((trial.transaction_id.as_str(), trial.accepted_revision))
                })
                .map(|trial| {
                    serde_json::json!({
                        "transaction_id": trial.transaction_id,
                        "revision": trial.accepted_revision,
                        "phase": trial.phase,
                        "mode": trial.candidate.mode,
                        "ssid": trial.candidate.ssid,
                        "relays": trial.candidate.relays,
                        "password_set": !trial.candidate.password.is_empty(),
                        "networks": crate::net_config_store::redacted_networks(&trial.candidate),
                        "attempted": trial.attempts > 0,
                    })
                });
            let last_result = terminal.map(|last| {
                serde_json::json!({
                    "transaction_id": last.transaction_id,
                    "revision": last.revision,
                    "outcome": last.outcome,
                })
            });
            let revision = crate::net_config_store::reconcile_network_revision(ctx.nvs);
            Ok(serde_json::json!({
                "revision": revision,
                "active": active_json,
                "trial": trial_json,
                "last_result": last_result,
            }))
        }

        "stage_network_config" => {
            if !is_device_op {
                return Err("network configuration is a device-level operation and requires the device operator".into());
            }
            let params: StageNetworkConfigParams = serde_json::from_value(
                req.get("params")
                    .cloned()
                    .ok_or("stage_network_config requires params")?,
            )
            .map_err(|e| format!("invalid stage_network_config params: {e}"))?;
            let committed_marker = crate::net_config_store::read_trial(ctx.nvs)
                .filter(|trial| trial.phase == NetworkTrialPhase::Committed);
            let _ = crate::net_config_store::reconcile_terminal_state(ctx.nvs);
            let active = committed_marker
                .map(|trial| trial.candidate)
                .or_else(|| {
                    crate::net_config_store::read_net_config(ctx.nvs).and_then(|raw| {
                        heartwood_common::net_config::parse_net_config(&raw).ok()
                    })
                })
                .ok_or("active network config unavailable")?;
            let candidate =
                apply_remote_net_config_patch(&active, &params.patch).map_err(str::to_string)?;
            let revision = crate::net_config_store::stage_trial(
                ctx.nvs,
                params.base_revision,
                &params.transaction_id,
                &candidate,
            )?;
            log::info!(
                "[relay] staged network trial {} at revision {}",
                params.transaction_id,
                revision
            );
            show_network_feedback(
                ctx,
                NetworkDisplayState::Saving,
                true,
                Some(Duration::from_secs(2)),
            );
            Ok(serde_json::json!({
                "transaction_id": params.transaction_id,
                "revision": revision,
                "phase": "staged",
                "staged": true,
            }))
        }

        "activate_network_config" => {
            if !is_device_op {
                return Err("network configuration is a device-level operation and requires the device operator".into());
            }
            if !network_activation_source_allowed(s.recv_timeout_on) {
                return Err(
                    "activate_network_config requires a relay session with bounded reads".into(),
                );
            }
            match masters::pin_unlock_required_after_reboot(ctx.nvs, ctx.masters) {
                Ok(false) => {}
                Ok(true) => {
                    return Err(
                        "activate_network_config unavailable: reboot requires local PIN unlock"
                            .into(),
                    );
                }
                Err(_) => {
                    return Err(
                        "activate_network_config unavailable: could not verify PIN reboot safety"
                            .into(),
                    );
                }
            }
            let params: NetworkConfigTransactionParams = serde_json::from_value(
                req.get("params")
                    .cloned()
                    .ok_or("activate_network_config requires params")?,
            )
            .map_err(|e| format!("invalid activate_network_config params: {e}"))?;
            crate::net_config_store::activate_trial(
                ctx.nvs,
                &params.transaction_id,
                params.revision,
            )?;
            let trial = crate::net_config_store::read_trial(ctx.nvs)
                .ok_or("network trial disappeared after activation")?;
            ctx.network_restart_at = Some(Instant::now() + NETWORK_RESTART_DELAY);
            log::info!(
                "[relay] activated network trial {} at revision {}; restart scheduled",
                params.transaction_id,
                trial.accepted_revision
            );
            show_network_feedback(ctx, NetworkDisplayState::JoiningWifi, true, None);
            Ok(serde_json::json!({
                "transaction_id": params.transaction_id,
                "revision": trial.accepted_revision,
                "phase": "trying",
                "rebooting": true,
            }))
        }

        "commit_network_config" => {
            if !is_device_op {
                return Err("network configuration is a device-level operation and requires the device operator".into());
            }
            let params: NetworkConfigTransactionParams = serde_json::from_value(
                req.get("params")
                    .cloned()
                    .ok_or("commit_network_config requires params")?,
            )
            .map_err(|e| format!("invalid commit_network_config params: {e}"))?;
            if let Some(marker) = crate::net_config_store::read_trial(ctx.nvs)
                .filter(|trial| trial.phase == NetworkTrialPhase::Committed)
            {
                if marker.transaction_id != params.transaction_id {
                    return Err("network transaction id mismatch".into());
                }
                if marker.accepted_revision != params.revision {
                    return Err("network transaction revision mismatch".into());
                }
                let _ = crate::net_config_store::reconcile_terminal_state(ctx.nvs);
                ctx.network_trial_id = None;
                ctx.network_trial_deadline = None;
                show_network_feedback(
                    ctx,
                    NetworkDisplayState::Online,
                    true,
                    Some(Duration::from_secs(2)),
                );
                return Ok(serde_json::json!({
                    "transaction_id": params.transaction_id,
                    "revision": params.revision,
                    "phase": "committed",
                    "committed": true,
                }));
            }
            let _ = crate::net_config_store::reconcile_terminal_state(ctx.nvs)?;
            let trial = match crate::net_config_store::read_trial(ctx.nvs) {
                Some(trial) => trial,
                None => {
                    if let Some(last) = crate::net_config_store::read_terminal(ctx.nvs) {
                        if last.transaction_id == params.transaction_id
                            && last.revision == params.revision
                            && last.outcome
                                == heartwood_common::net_config::NetworkTerminalOutcome::Committed
                        {
                            ctx.network_trial_id = None;
                            ctx.network_trial_deadline = None;
                            show_network_feedback(
                                ctx,
                                NetworkDisplayState::Online,
                                true,
                                Some(Duration::from_secs(2)),
                            );
                            return Ok(serde_json::json!({
                                "transaction_id": params.transaction_id,
                                "revision": params.revision,
                                "phase": "committed",
                                "committed": true,
                            }));
                        }
                    }
                    return Err("no network trial pending".into());
                }
            };
            if trial.transaction_id != params.transaction_id {
                return Err("network transaction id mismatch".into());
            }
            if trial.accepted_revision != params.revision {
                return Err("network transaction revision mismatch".into());
            }
            if ctx.network_trial_id.as_deref() != Some(params.transaction_id.as_str())
                || trial.phase != NetworkTrialPhase::Trying
                || trial.attempts != 1
            {
                return Err("network trial is not active on this boot".into());
            }
            if !network_commit_source_allowed(s.pinned, &s.url, &trial.candidate.relays) {
                return Err("network commit must arrive through a candidate primary relay".into());
            }
            let revision = trial.accepted_revision;
            crate::net_config_store::commit_trial(
                ctx.nvs,
                &params.transaction_id,
                params.revision,
            )?;
            ctx.network_trial_id = None;
            ctx.network_trial_deadline = None;
            log::info!(
                "[relay] committed network trial {} at revision {}",
                params.transaction_id,
                revision
            );
            show_network_feedback(
                ctx,
                NetworkDisplayState::Online,
                true,
                Some(Duration::from_secs(2)),
            );
            Ok(serde_json::json!({
                "transaction_id": params.transaction_id,
                "revision": revision,
                "phase": "committed",
                "committed": true,
            }))
        }

        "abort_network_config" => {
            if !is_device_op {
                return Err("network configuration is a device-level operation and requires the device operator".into());
            }
            let params: NetworkConfigTransactionParams = serde_json::from_value(
                req.get("params")
                    .cloned()
                    .ok_or("abort_network_config requires params")?,
            )
            .map_err(|e| format!("invalid abort_network_config params: {e}"))?;
            if let Some(marker) = crate::net_config_store::read_trial(ctx.nvs)
                .filter(|trial| trial.phase == NetworkTrialPhase::Committed)
            {
                if marker.transaction_id != params.transaction_id {
                    return Err("network transaction id mismatch".into());
                }
                if marker.accepted_revision != params.revision {
                    return Err("network transaction revision mismatch".into());
                }
                let _ = crate::net_config_store::reconcile_terminal_state(ctx.nvs);
                ctx.network_trial_id = None;
                ctx.network_trial_deadline = None;
                return Err("network transaction is already committed".into());
            }
            let _ = crate::net_config_store::reconcile_terminal_state(ctx.nvs)?;
            let trial = match crate::net_config_store::read_trial(ctx.nvs) {
                Some(trial) => trial,
                None => {
                    if let Some(last) = crate::net_config_store::read_terminal(ctx.nvs) {
                        if last.transaction_id == params.transaction_id
                            && last.revision == params.revision
                            && last.outcome
                                == heartwood_common::net_config::NetworkTerminalOutcome::Aborted
                        {
                            show_network_feedback(
                                ctx,
                                NetworkDisplayState::Cancelled,
                                true,
                                Some(Duration::from_secs(2)),
                            );
                            return Ok(serde_json::json!({
                                "transaction_id": params.transaction_id,
                                "revision": params.revision,
                                "phase": "aborted",
                                "aborted": true,
                                "rebooting": false,
                            }));
                        }
                        if last.transaction_id == params.transaction_id
                            && last.revision == params.revision
                            && last.outcome
                                == heartwood_common::net_config::NetworkTerminalOutcome::Committed
                        {
                            ctx.network_trial_id = None;
                            ctx.network_trial_deadline = None;
                            return Err("network transaction is already committed".into());
                        }
                    }
                    return Err("no network trial pending".into());
                }
            };
            if trial.transaction_id != params.transaction_id {
                return Err("network transaction id mismatch".into());
            }
            if trial.accepted_revision != params.revision {
                return Err("network transaction revision mismatch".into());
            }
            let revision = trial.accepted_revision;
            let live_candidate =
                ctx.network_trial_id.as_deref() == Some(params.transaction_id.as_str());
            crate::net_config_store::abort_trial(ctx.nvs, &params.transaction_id, params.revision)?;
            ctx.network_trial_id = None;
            ctx.network_trial_deadline = None;
            // Cancels a not-yet-fired activation restart. Only a device
            // currently running B needs to reboot back to A after abort.
            ctx.network_restart_at = live_candidate.then(|| Instant::now() + NETWORK_RESTART_DELAY);
            log::info!(
                "[relay] aborted network trial {} at revision {}",
                params.transaction_id,
                revision
            );
            show_network_feedback(
                ctx,
                if live_candidate {
                    NetworkDisplayState::RollingBack
                } else {
                    NetworkDisplayState::Cancelled
                },
                true,
                (!live_candidate).then_some(Duration::from_secs(2)),
            );
            Ok(serde_json::json!({
                "transaction_id": params.transaction_id,
                "revision": revision,
                "phase": "aborted",
                "aborted": true,
                "rebooting": live_candidate,
            }))
        }

        // Derive a named child identity from the ADDRESSED master's tree root
        // and store it as a new master. No key material crosses the wire — the
        // device already holds the root, the operator only names the branch —
        // so this is safe over WiFi where key IMPORT (provision) is not.
        // Mutation-challenge protected like every other mutation. A successful
        // store schedules the standard deferred restart so the relay
        // re-subscribes with the fresh master set after the response publishes.
        "derive_identity" => {
            if !is_device_op {
                return Err("derive_identity adds an identity and requires the device operator".into());
            }
            let name = req
                .pointer("/params/name")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .ok_or("derive_identity requires params.name")?;
            heartwood_common::validate::validate_raw_derive_purpose(name)?;

            let parent = &ctx.masters[master_idx];
            if parent.locked {
                return Err("parent identity is PIN-locked".into());
            }
            let (child_secret, child_pubkey) =
                crate::nip46_handler::derive_identity(&parent.secret, parent.mode, name, 0)?;

            // Idempotent: the same name from the same root is the same key.
            if let Some(existing) = ctx.masters.iter().find(|m| m.pubkey == child_pubkey) {
                log::info!("[relay] mgmt: derive_identity '{name}' already in slot {}", existing.slot);
                return Ok(serde_json::json!({
                    "slot": existing.slot,
                    "label": existing.label,
                    "npub_hex": hex_encode(&existing.pubkey),
                    "parent_slot": master_slot,
                    "purpose": name,
                    "existing": true,
                }));
            }

            let stored = crate::provision::store_master(
                ctx.nvs,
                *child_secret,
                name.to_string(),
                heartwood_common::types::MasterMode::Bunker,
                ctx.secp,
            )?;
            log::info!(
                "[relay] mgmt: derived identity '{name}' from slot {master_slot} into slot {}",
                stored.slot
            );
            ctx.network_restart_at = Some(Instant::now() + NETWORK_RESTART_DELAY);
            Ok(serde_json::json!({
                "slot": stored.slot,
                "label": stored.label,
                "npub_hex": hex_encode(&stored.pubkey),
                "parent_slot": master_slot,
                "purpose": name,
                "existing": false,
                "note": "signer restarts shortly to serve the new identity",
            }))
        }

        // Provision a new master over the relay: the counterpart of the USB
        // PROVISION frame for operators managing a shelf signer remotely. The
        // secret arrives inside the NIP-44 envelope encrypted end-to-end under
        // the operator⇄master conversation key — the relay and every network
        // hop carry only ciphertext. Mutation-challenge protected; idempotent
        // by pubkey; a successful store schedules the deferred restart so the
        // relay re-subscribes with the fresh master set.
        "provision_identity" => {
            if !is_device_op {
                return Err("provision_identity adds an identity and requires the device operator".into());
            }
            let mode_byte = req
                .pointer("/params/mode")
                .and_then(|v| v.as_u64())
                .ok_or("provision_identity requires params.mode (0 bunker, 1 tree-mnemonic, 2 tree-nsec)")? as u8;
            let mode = heartwood_common::types::MasterMode::from_u8(mode_byte)
                .ok_or("unknown provision mode byte")?;
            let label = req
                .pointer("/params/label")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .ok_or("provision_identity requires params.label")?
                .to_string();
            let secret_hex = req
                .pointer("/params/secret_hex")
                .and_then(|v| v.as_str())
                .ok_or("provision_identity requires params.secret_hex")?;
            let mut secret: [u8; 32] = hex_decode(secret_hex)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or("secret_hex must be 64 hex characters")?;

            let keypair = secp256k1::Keypair::from_seckey_slice(ctx.secp, &secret)
                .map_err(|_| "invalid secret key".to_string())?;
            let (xonly, _) = keypair.x_only_public_key();
            let pubkey = xonly.serialize();

            if let Some(existing) = ctx.masters.iter().find(|m| m.pubkey == pubkey) {
                secret.iter_mut().for_each(|b| *b = 0);
                log::info!("[relay] mgmt: provision_identity already in slot {}", existing.slot);
                return Ok(serde_json::json!({
                    "slot": existing.slot,
                    "label": existing.label,
                    "npub_hex": hex_encode(&existing.pubkey),
                    "existing": true,
                }));
            }

            let stored = crate::provision::store_master(ctx.nvs, secret, label, mode, ctx.secp)?;
            log::info!(
                "[relay] mgmt: provisioned '{}' into slot {} (mode {mode_byte})",
                stored.label,
                stored.slot
            );
            ctx.network_restart_at = Some(Instant::now() + NETWORK_RESTART_DELAY);
            Ok(serde_json::json!({
                "slot": stored.slot,
                "label": stored.label,
                "npub_hex": hex_encode(&stored.pubkey),
                "existing": false,
                "note": "signer restarts shortly to serve the new identity",
            }))
        }

        "create_client" | "create_client_v2" => {
            let is_v2 = method == "create_client_v2";
            let mut exact_policy = if is_v2 {
                Some(exact_policy_from_request(req)?)
            } else {
                None
            };
            // D2 persona-addressed mint: v2-only, so a legacy create_client
            // errors rather than silently minting a master-addressed slot
            // when the operator asked for a persona endpoint.
            if !is_v2 && req.pointer("/params/identity").is_some() {
                return Err("params.identity requires create_client_v2".into());
            }
            let addressed = identity_param(req, ctx.masters, ctx.personas, master_idx)?;
            let endpoint_hex = match &addressed {
                AddressedIdentity::Master => master_hex.clone(),
                AddressedIdentity::Persona { hex, .. } => hex.clone(),
            };
            // A persona-addressed slot defaults its child-wrap binding to the
            // addressed persona unless the operator bound something explicitly.
            if let (Some(policy), AddressedIdentity::Persona { hex, .. }) =
                (exact_policy.as_mut(), &addressed)
            {
                if policy.bound_identity.is_none() {
                    policy.bound_identity = Some(hex.clone());
                }
            }
            let label = req
                .pointer("/params/label")
                .and_then(|v| v.as_str())
                .unwrap_or("relay-client")
                .to_string();

            // Fresh secrets need fresh entropy — fail closed like the USB
            // connslot path if the boot-time RNG self-test didn't pass.
            if !crate::entropy::rng_ok() {
                log::error!("[relay] mgmt: create_client refused: RNG self-test failed this boot");
                return Err("RNG self-test failed this boot — refusing to mint secrets".into());
            }

            // Slot secret from the hardware RNG (never leaves except in the URI).
            let mut secret_bytes = [0u8; 32];
            crate::fill_random(&mut secret_bytes);
            let secret_hex = hex_encode(&secret_bytes);
            secret_bytes.iter_mut().for_each(|b| *b = 0);

            // Optional: grant signing authority in the same call so the operator
            // can provision a ready-to-sign shelf client in one round-trip. This
            // is the op_mgmt-authority-for-physical-button substitution.
            let auto_sign = exact_policy
                .as_ref()
                .map(|policy| policy.signing_approved)
                .unwrap_or_else(|| {
                    req.pointer("/params/approve_signing")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                });

            let slot_snapshot = ctx.policy_engine.snapshot_slot_state(master_slot);
            let created = match exact_policy {
                Some(policy) => ctx.policy_engine.create_slot_with_exact_policy(
                    master_slot,
                    label.clone(),
                    secret_hex.clone(),
                    policy,
                ),
                None => {
                    ctx.policy_engine
                        .create_slot(master_slot, label.clone(), secret_hex.clone())
                }
            };
            match created {
                Some(index) => {
                    if auto_sign && !is_v2 {
                        ctx.policy_engine.upgrade_to_signing(master_slot, index);
                    }
                    persist_slot_mutation_or_rollback(
                        ctx,
                        master_slot,
                        slot_snapshot,
                        "client creation",
                    )?;
                    let bunker_uri =
                        mgmt::bunker_uri(&endpoint_hex, &ctx.relays, Some(&secret_hex));
                    log::info!(
                        "[relay] mgmt: created client slot {index} ({label}){}",
                        if auto_sign {
                            " [signing pre-approved]"
                        } else {
                            ""
                        }
                    );
                    let note = if auto_sign {
                        "signing pre-approved by operator — client auto-signs once it connects with the secret"
                    } else {
                        "first sign_event needs approval — call approve_signing or one physical PRG press"
                    };
                    let applied = ctx
                        .policy_engine
                        .list_slots(master_slot)
                        .iter()
                        .find(|slot| slot.slot_index == index);
                    let secret_fingerprint = mgmt::credential_fingerprint(&secret_hex);
                    Ok(serde_json::json!({
                        "slot_index": index,
                        "label": label,
                        "secret": secret_hex,
                        "secret_fingerprint": secret_fingerprint,
                        "npub_hex": endpoint_hex,
                        "bunker_uri": bunker_uri,
                        "signing_approved": auto_sign,
                        "policy_version": if is_v2 { Some(2u8) } else { None },
                        "allowed_methods": applied.map(|slot| slot.allowed_methods.clone()).unwrap_or_default(),
                        "allowed_kinds": applied.map(|slot| slot.allowed_kinds.clone()).unwrap_or_default(),
                        "auto_approve": applied.map(|slot| slot.auto_approve).unwrap_or(false),
                        "note": note,
                    }))
                }
                None => Err("create_slot failed (slot table full?)".into()),
            }
        }

        // Client-initiated pairing (nostrconnect://): the app already told us its
        // pubkey, relay and a one-time secret, so we bind a slot to that pubkey
        // and publish the connect ACK — a NIP-46 response whose result echoes the
        // secret. The ACK goes out on the relay the app listens on: a served
        // relay when they overlap, otherwise the signer DIALS the app's relay as
        // a pinned session (params.relay, capacity permitting) and keeps serving
        // it so the pairing outlives the handshake.
        // The device has no wall-clock, so the operator (SPA) supplies created_at.
        "nostrconnect" | "nostrconnect_v2" => {
            let is_v2 = method == "nostrconnect_v2";
            let mut exact_policy = if is_v2 {
                Some(exact_policy_from_request(req)?)
            } else {
                None
            };
            // D2 persona-addressed pairing: v2-only, same fail-closed rule as
            // create_client.
            if !is_v2 && req.pointer("/params/identity").is_some() {
                return Err("params.identity requires nostrconnect_v2".into());
            }
            let addressed = identity_param(req, ctx.masters, ctx.personas, master_idx)?;
            let endpoint_hex = match &addressed {
                AddressedIdentity::Master => master_hex.clone(),
                AddressedIdentity::Persona { hex, .. } => hex.clone(),
            };
            if let (Some(policy), AddressedIdentity::Persona { hex, .. }) =
                (exact_policy.as_mut(), &addressed)
            {
                if policy.bound_identity.is_none() {
                    policy.bound_identity = Some(hex.clone());
                }
            }
            let client_hex = req
                .pointer("/params/client_pubkey")
                .and_then(|v| v.as_str())
                .ok_or("nostrconnect requires params.client_pubkey")?;
            let client_bytes: [u8; 32] = hex_decode(client_hex)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or("client_pubkey must be 32-byte hex")?;
            let secret = req
                .pointer("/params/secret")
                .and_then(|v| v.as_str())
                .ok_or("nostrconnect requires params.secret")?
                .to_string();
            let created_at = req
                .pointer("/params/created_at")
                .and_then(|v| v.as_u64())
                .ok_or("nostrconnect requires params.created_at")?;
            let label = req
                .pointer("/params/label")
                .and_then(|v| v.as_str())
                .unwrap_or("nostrconnect app")
                .to_string();
            let auto_sign = exact_policy
                .as_ref()
                .map(|policy| policy.signing_approved)
                .unwrap_or_else(|| {
                    req.pointer("/params/approve_signing")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                });
            let allowed_kinds: Vec<u64> = if let Some(policy) = &exact_policy {
                policy.allowed_kinds.clone()
            } else {
                req.pointer("/params/allowed_kinds")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|k| k.as_u64()).collect())
                    .unwrap_or_default()
            };
            // The app's relay from its nostrconnect URI. Optional: absent means
            // the SPA established overlap and the arriving session carries it.
            let client_relay = req
                .pointer("/params/relay")
                .and_then(|v| v.as_str())
                .map(|r| r.trim().to_string())
                .filter(|r| !r.is_empty());

            // Where will the ACK go? Resolve BEFORE creating the slot so a
            // failed dial leaves no half-paired state behind.
            enum AckTarget {
                Arriving,
                Other(usize),
                Dial(String),
            }
            // The named relay is where the APP listens — the ACK must land
            // there. The arriving session is only the OPERATOR's path to us;
            // being "in the primary rotation" is not enough, because the
            // rotation serves one relay at a time and the app may not watch
            // the one currently connected (seen live: ACK published to the
            // arriving session while the app listened elsewhere → the pairing
            // hung at 'verifying approval' despite a saved slot).
            let ack_target = match &client_relay {
                None => AckTarget::Arriving,
                Some(r) if same_relay(r, &s.url) => AckTarget::Arriving,
                Some(r) => match pool.others.iter().position(|o| same_relay(&o.url, r)) {
                    Some(i) => AckTarget::Other(i),
                    None => AckTarget::Dial(r.clone()),
                },
            };
            if let AckTarget::Dial(url) = &ack_target {
                if !url.starts_with("wss://") {
                    return Err("relay must be wss://".into());
                }
                if 1 + pool.others.len() >= MAX_SESSIONS {
                    return Err("relay_capacity: signer already serves its maximum relays".into());
                }
                // A dial for a relay that is ALREADY pinned (session currently
                // down — a re-pair while the pinned link is between retries)
                // reuses that pin rather than counting as a new one; only a
                // dial for a different relay is capacity-checked. The adoption
                // block below updates the matching entry in place, so a slot
                // never gains a second PinnedRelay.
                let reusing_pin = pool.pinned.iter().any(|p| same_relay(&p.url, url));
                if !reusing_pin && pool.pinned.len() >= MAX_SESSIONS - 1 {
                    return Err("relay_capacity: a pinned relay is already configured".into());
                }
                // Operator-driven retries against a dead relay would otherwise
                // re-run the ~10s blocking dial back to back: the exponential
                // backoff only throttles the automatic reconnect loop, which
                // has no state until a pin actually lands.
                if let Some((u, t)) = &ctx.dial_cooldown {
                    if same_relay(u, url) && t.elapsed() < PINNED_BACKOFF {
                        return Err(
                            "relay_dial_failed: a dial to this relay just failed; retry shortly"
                                .into(),
                        );
                    }
                }
                // A session without a recv timeout blocks the loop on quiet
                // reads; a second socket would multiply that stall, so refuse
                // to grow the pool while any live session runs degraded.
                if !s.recv_timeout_on || pool.others.iter().any(|o| !o.recv_timeout_on) {
                    return Err(
                        "relay_dial_failed: signer relay link is degraded (no recv timeout)".into(),
                    );
                }
                // Heap guard: a second mbedTLS session needs ~40-50KB of often
                // fragmented heap, and an allocation failure deep inside the
                // TLS stack can abort the chip (observed as a reset on the
                // no-PSRAM T-Display, 2026-07-08). Refuse gracefully instead.
                let free = unsafe { esp_idf_svc::sys::esp_get_free_heap_size() };
                let largest = unsafe {
                    esp_idf_svc::sys::heap_caps_get_largest_free_block(
                        esp_idf_svc::sys::MALLOC_CAP_8BIT,
                    )
                };
                if free < DIAL_MIN_FREE_HEAP || largest < DIAL_MIN_LARGEST_BLOCK {
                    return Err(format!(
                        "relay_dial_failed: not enough free memory for a second relay session (free {free} B, largest block {largest} B); pair on a shared relay instead"
                    ));
                }
            }

            // Re-pairing dedupe: a client retrying with the same keypair (or
            // pairing again after a reinstall) rebinds its existing slot rather
            // than minting a duplicate — retries must not fill the slot table.
            let existing_index = ctx
                .policy_engine
                .find_slot_by_pubkey(master_slot, client_hex)
                .map(|slot| slot.slot_index);
            // Capture the complete master table, not just the target. Pubkey
            // uniqueness can move this client out of another slot, so every
            // failed pairing path must restore the whole authority state.
            let slot_snapshot = ctx.policy_engine.snapshot_slot_state(master_slot);

            // Capacity check BEFORE the expensive dial, so a full table cannot
            // waste a complete TLS + WS handshake.
            if existing_index.is_none()
                && ctx.policy_engine.list_slots(master_slot).len()
                    >= heartwood_common::policy::MAX_CONNECT_SLOTS as usize
            {
                return Err("create_slot failed (slot table full)".into());
            }

            // Own the ACK authoring secret up front so publishing below needs
            // no live borrow of ctx while the slot table is mutated. The app
            // pins its signer from the ACK's author, so a persona-addressed
            // pairing must author as that persona — re-derived here; a master
            // pairing authors as the master exactly as before.
            let ack_secret: zeroize::Zeroizing<[u8; 32]> = match &addressed {
                AddressedIdentity::Master => {
                    zeroize::Zeroizing::new(ctx.masters[master_idx].secret)
                }
                AddressedIdentity::Persona { purpose, index, .. } => {
                    let owning = &ctx.masters[master_idx];
                    crate::nip46_handler::derive_identity(
                        &owning.secret,
                        owning.mode,
                        purpose,
                        *index,
                    )
                    .map_err(|e| format!("identity key derivation: {e}"))?
                    .0
                }
            };
            // Hex shape is not enough: validate/lift the x-only key and derive
            // the ACK conversation key before dialling or touching slot RAM.
            // No fallible key operation may strand an orphan authority change.
            let ck = nip44::get_conversation_key(&ack_secret, &client_bytes)
                .map_err(|e| format!("conversation key: {e}"))?;

            // Fresh secrets need fresh entropy — fail closed like the USB
            // connslot path if the boot-time RNG self-test didn't pass.
            if !crate::entropy::rng_ok() {
                log::error!("[relay] nostrconnect refused: RNG self-test failed this boot");
                return Err("RNG self-test failed this boot — refusing to mint secrets".into());
            }

            // A slot secret is still minted (bunker parity), even though this slot
            // is bound by pubkey rather than by a secret handshake.
            let mut secret_bytes = [0u8; 32];
            crate::fill_random(&mut secret_bytes);
            let slot_secret = hex_encode(&secret_bytes);
            secret_bytes.iter_mut().for_each(|b| *b = 0);

            // Dial the app's relay first (when needed): the expensive, fallible
            // step. Only a successful dial mutates any state. Free-heap logging
            // brackets the dial while the two-session model beds in on the
            // no-PSRAM boards.
            let mut dialled: Option<RelaySession> = None;
            if let AckTarget::Dial(url) = &ack_target {
                let heap = unsafe { esp_idf_svc::sys::esp_get_free_heap_size() };
                log::info!("[relay] nostrconnect: dialling client relay {url} (free heap {heap})");
                dialled = Some(match connect_relay(url, true, ctx) {
                    Ok(ns) => {
                        ctx.dial_cooldown = None;
                        ns
                    }
                    Err(e) => {
                        ctx.dial_cooldown = Some((url.clone(), Instant::now()));
                        return Err(e);
                    }
                });
                let heap = unsafe { esp_idf_svc::sys::esp_get_free_heap_size() };
                log::info!("[relay] nostrconnect: dial ok (free heap {heap})");
            }

            let index = match existing_index {
                Some(i) => {
                    // Rebind: v2 replaces the complete policy as one validated
                    // unit; legacy keeps its historical partial-kind behavior.
                    if let Some(policy) = &exact_policy {
                        ctx.policy_engine.update_slot(
                            master_slot,
                            i,
                            Some(label.clone()),
                            None,
                            None,
                            None,
                        );
                        if let Err(error) = ctx.policy_engine.set_exact_slot_policy(
                            master_slot,
                            i,
                            policy.allowed_methods.clone(),
                            policy.allowed_kinds.clone(),
                            policy.auto_approve,
                        ) {
                            ctx.policy_engine.restore_slot_state(slot_snapshot);
                            return Err(error);
                        }
                        ctx.policy_engine.set_slot_family_flags(
                            master_slot,
                            i,
                            policy.escalate,
                            policy.petition_on_deny,
                            policy.audit_child_wrap,
                            policy.bound_identity.clone(),
                        );
                    } else {
                        ctx.policy_engine.update_slot(
                            master_slot,
                            i,
                            Some(label.clone()),
                            None,
                            if allowed_kinds.is_empty() {
                                None
                            } else {
                                Some(allowed_kinds.clone())
                            },
                            None,
                        );
                    }
                    log::info!("[relay] nostrconnect: rebinding existing slot {i}");
                    i
                }
                None => {
                    let i = if let Some(policy) = &exact_policy {
                        ctx.policy_engine.create_slot_with_exact_policy(
                            master_slot,
                            label.clone(),
                            slot_secret,
                            policy.clone(),
                        )
                    } else {
                        ctx.policy_engine
                            .create_slot(master_slot, label.clone(), slot_secret)
                    }
                    .ok_or("create_slot failed (slot table full?)")?;
                    ctx.policy_engine
                        .assign_pubkey_to_slot(master_slot, i, client_hex.to_string());
                    if !is_v2 && !allowed_kinds.is_empty() {
                        ctx.policy_engine.update_slot(
                            master_slot,
                            i,
                            None,
                            None,
                            Some(allowed_kinds.clone()),
                            None,
                        );
                    }
                    i
                }
            };
            if auto_sign && !is_v2 {
                ctx.policy_engine.upgrade_to_signing(master_slot, index);
            }

            // Publish the connect ACK to the app, authored by the addressed
            // identity.
            let mut id_bytes = [0u8; 8];
            crate::fill_random(&mut id_bytes);
            let ack =
                serde_json::json!({ "id": hex_encode(&id_bytes), "result": secret }).to_string();
            let joined_relay = dialled.is_some();
            let ack_tls = match (&ack_target, dialled.as_mut()) {
                (AckTarget::Other(i), _) => &mut pool.others[*i].tls,
                (_, Some(ns)) => &mut ns.tls,
                _ => &mut s.tls,
            };
            if let Err(e) = sign_and_publish(
                ack_tls,
                ctx.secp,
                &ack_secret,
                &ck,
                client_hex,
                NIP46_KIND,
                created_at,
                ack,
            ) {
                // The client never saw its secret and no slot write was
                // attempted, so restoring the complete RAM snapshot is enough.
                ctx.policy_engine.restore_slot_state(slot_snapshot);
                return Err(e);
            }

            // Persist a newly joined route before the slot authority that needs
            // it. If this write fails, NVS still contains the prior slot table,
            // so rolling RAM back is enough to keep the ACK from granting a
            // volatile/reboot-fragile pairing.
            let pinned_before = dialled.as_ref().map(|_| pool.pinned.clone());
            if let Some(ns) = dialled.as_ref() {
                match pool.pinned.iter_mut().find(|p| same_relay(&p.url, &ns.url)) {
                    Some(p) => {
                        p.ms = master_slot;
                        p.si = index;
                        p.next_attempt = Instant::now();
                        p.fails = 0;
                    }
                    None => pool.pinned.push(PinnedRelay {
                        url: ns.url.clone(),
                        ms: master_slot,
                        si: index,
                        next_attempt: Instant::now(),
                        fails: 0,
                    }),
                }
                if !save_pinned(ctx.nvs, pool.pinned) {
                    ctx.policy_engine.restore_slot_state(slot_snapshot);
                    let pin_rollback_durable = if let Some(before) = pinned_before.as_ref() {
                        *pool.pinned = before.clone();
                        save_pinned(ctx.nvs, pool.pinned)
                    } else {
                        true
                    };
                    return if pin_rollback_durable {
                        Err("could not persist the app relay; pairing was not applied".into())
                    } else {
                        Err("fatal storage error: could not restore the prior app relay configuration; take the device offline for USB recovery".into())
                    };
                }
            }

            // The app has received its ACK, but management does not report
            // success until the complete policy is durable. If NVS rejects the
            // write, restore RAM and the prior pin; boot-time pruning is an
            // additional fail-closed guard if pin rollback itself cannot write.
            if !ctx.policy_engine.persist_slots(ctx.nvs, master_slot) {
                let slot_rollback_durable = ctx
                    .policy_engine
                    .restore_slot_state_durably(ctx.nvs, slot_snapshot);
                let pin_rollback_durable = if let Some(before) = pinned_before.as_ref() {
                    *pool.pinned = before.clone();
                    save_pinned(ctx.nvs, pool.pinned)
                } else {
                    true
                };
                return if slot_rollback_durable && pin_rollback_durable {
                    Err("could not persist nostrconnect policy; pairing was not applied".into())
                } else {
                    Err("fatal storage error: could not restore prior pairing state; take the device offline for USB recovery".into())
                };
            }

            // Both pin and policy are durable; only now adopt the live socket.
            if let Some(ns) = dialled {
                pool.others.push(ns);
                // Split the recv timeout across the grown session set. The
                // arriving session is not in `others`, hence the +1 and the
                // separate call on `s`.
                let n = (pool.others.len() + 1) as i64;
                for o in pool.others.iter_mut() {
                    if o.recv_timeout_on {
                        let _ = set_recv_timeout(&mut o.tls, RECV_TIMEOUT_MS / n);
                    }
                }
                if s.recv_timeout_on {
                    let _ = set_recv_timeout(&mut s.tls, RECV_TIMEOUT_MS / n);
                }
            }

            log::info!(
                "[relay] nostrconnect: bound slot {index} to client {}…, ACK published{}{}",
                &client_hex[..client_hex.len().min(16)],
                if joined_relay {
                    " [joined client relay]"
                } else {
                    ""
                },
                if auto_sign {
                    " [signing pre-approved]"
                } else {
                    ""
                }
            );
            let applied = ctx
                .policy_engine
                .find_slot_by_pubkey(master_slot, client_hex);
            Ok(serde_json::json!({
                "slot_index": index,
                "client_pubkey": client_hex,
                "identity": endpoint_hex,
                "secret_fingerprint": applied
                    .map(|slot| mgmt::credential_fingerprint(&slot.secret))
                    .unwrap_or_default(),
                "signing_approved": auto_sign,
                "joined_relay": joined_relay,
                "policy_version": if is_v2 { Some(2u8) } else { None },
                "allowed_methods": applied.map(|slot| slot.allowed_methods.clone()).unwrap_or_default(),
                "allowed_kinds": applied.map(|slot| slot.allowed_kinds.clone()).unwrap_or_default(),
                "auto_approve": applied.map(|slot| slot.auto_approve).unwrap_or(false),
                "note": if joined_relay {
                    "connect ACK published; the signer joined the app's relay and will keep serving it"
                } else {
                    "connect ACK published; the app is paired on this relay"
                },
            }))
        }

        "approve_signing" => {
            // Operator grants a slot signing authority — substitutes op_mgmt's
            // cryptographic authority for the physical button on the wifi tier
            // (see relay-mediated-management design). Destructive ops stay USB.
            let slot_index =
                req.pointer("/params/slot_index")
                    .and_then(|v| v.as_u64())
                    .ok_or("approve_signing requires params.slot_index")? as u8;
            let target = ctx
                .policy_engine
                .list_slots(master_slot)
                .iter()
                .find(|slot| slot.slot_index == slot_index)
                .ok_or_else(|| format!("no such slot: {slot_index}"))?;
            let secret_fingerprint = require_expected_slot_fingerprint(req, target)?;
            if target.strict_permissions {
                return Err(
                    "approve_signing is legacy-only; replace the exact v2 policy instead".into(),
                );
            }
            let slot_snapshot = ctx.policy_engine.snapshot_slot_state(master_slot);
            if ctx
                .policy_engine
                .upgrade_to_signing(master_slot, slot_index)
            {
                persist_slot_mutation_or_rollback(
                    ctx,
                    master_slot,
                    slot_snapshot,
                    "signing approval",
                )?;
                log::info!("[relay] mgmt: slot {slot_index} upgraded to signing (operator)");
                Ok(serde_json::json!({
                    "slot_index": slot_index,
                    "secret_fingerprint": secret_fingerprint,
                    "signing_approved": true,
                }))
            } else {
                Err(format!("no such slot: {slot_index}"))
            }
        }

        "list_clients" => {
            let clients: Vec<serde_json::Value> = ctx
                .policy_engine
                .list_slots(master_slot)
                .iter()
                .map(mgmt::client_summary)
                .collect();
            Ok(serde_json::json!({ "clients": clients }))
        }

        "client_uri" => {
            let slot_index = req
                .pointer("/params/slot_index")
                .and_then(|v| v.as_u64())
                .ok_or("client_uri requires params.slot_index")? as u8;
            let slot = ctx
                .policy_engine
                .list_slots(master_slot)
                .iter()
                .find(|s| s.slot_index == slot_index)
                .ok_or_else(|| format!("no such slot: {slot_index}"))?;
            let secret_fingerprint = require_expected_slot_fingerprint(req, slot)?;
            // D2: optional persona-addressed URI for an existing slot. The
            // method name is unversioned, so older firmware ignores the
            // param — operators must gate on the `pairing_identity_v1`
            // capability before relying on it.
            let addressed = identity_param(req, ctx.masters, ctx.personas, master_idx)?;
            let endpoint_hex = match &addressed {
                AddressedIdentity::Master => master_hex.clone(),
                AddressedIdentity::Persona { hex, .. } => hex.clone(),
            };
            Ok(serde_json::json!({
                "slot_index": slot_index,
                "secret_fingerprint": secret_fingerprint,
                "identity": endpoint_hex,
                "bunker_uri": mgmt::bunker_uri(&endpoint_hex, &ctx.relays, Some(&slot.secret)),
            }))
        }

        // Enumerate every identity this master serves (itself + its personas)
        // with a ready-to-paste bunker URI — the wifi-standalone analogue of the
        // sidecar's `bunker-uris.json` manifest. Closes the discovery gap: the
        // operator no longer has to hand-build a persona URI from a known npub.
        //
        // Discovery only — the URIs carry NO secret. Authorisation is orthogonal:
        // the `#p` pubkey selects the signing identity, while a client is bound to
        // a policy slot by the per-client secret from `create_client`. (One secret
        // shared across identities would make distinct client keys collide on a
        // single slot.) Until a client is bound to a signing-approved slot the
        // first sign_event needs a physical PRG press; safe methods auto-approve.
        "list_identities" => {
            // EVERY identity the signer serves — all masters plus all derived
            // personas — not just the addressed one. The signer answers NIP-46
            // for all of them, so the operator's inventory should match; each
            // master is itself a management target (address it by its pubkey).
            // Precomputed to keep the policy-engine borrow out of the masters
            // iterator below.
            // A delegated per-identity operator sees only the identity it was
            // granted; the device operator sees the whole inventory.
            let app_counts: Vec<usize> = ctx
                .masters
                .iter()
                .filter(|m| is_device_op || m.slot == master_slot)
                .map(|m| ctx.policy_engine.list_slots(m.slot).len())
                .collect();
            let mut identities: Vec<serde_json::Value> = ctx
                .masters
                .iter()
                .filter(|m| is_device_op || m.slot == master_slot)
                .zip(app_counts)
                .map(|(m, apps)| {
                    let pk_hex = hex_encode(&m.pubkey);
                    let uri = mgmt::bunker_uri(&pk_hex, &ctx.relays, None);
                    serde_json::json!({
                        "label": m.label,
                        "kind": "master",
                        "slot": m.slot,
                        "npub_hex": pk_hex,
                        "bunker_uri": uri,
                        "addressed": m.slot == master_slot,
                        "apps": apps,
                        "operator": m.operator.map(|op| hex_encode(&op)),
                    })
                })
                .collect();
            let master_count = identities.len();
            for p in ctx.personas.iter() {
                if !(is_device_op || p.master_slot == master_slot) {
                    continue;
                }
                let pk_hex = hex_encode(&p.pubkey);
                let label = p.name.clone().unwrap_or_else(|| p.purpose.clone());
                let uri = mgmt::bunker_uri(&pk_hex, &ctx.relays, None);
                identities.push(serde_json::json!({
                    "label": label,
                    "kind": "persona",
                    "slot": p.master_slot,
                    "purpose": p.purpose.clone(),
                    "index": p.index,
                    "npub_hex": pk_hex,
                    "bunker_uri": uri,
                }));
            }
            let persona_count = identities.len() - master_count;
            log::info!("[relay] mgmt: list_identities → {master_count} master(s) + {persona_count} persona(s)");
            Ok(serde_json::json!({
                "identities": identities,
                "note": "discovery only — URIs carry no secret; for unattended signing bind a client with create_client (use its secret) or approve the first sign_event with a physical PRG press",
            }))
        }

        // Revoke a client slot (operator-authorised — same authority as create).
        "revoke_client" => {
            let slot_index =
                req.pointer("/params/slot_index")
                    .and_then(|v| v.as_u64())
                    .ok_or("revoke_client requires params.slot_index")? as u8;
            let target = ctx
                .policy_engine
                .list_slots(master_slot)
                .iter()
                .find(|slot| slot.slot_index == slot_index)
                .ok_or_else(|| format!("no such slot: {slot_index}"))?;
            let secret_fingerprint = require_expected_slot_fingerprint(req, target)?;
            let slot_snapshot = ctx.policy_engine.snapshot_slot_state(master_slot);
            if ctx.policy_engine.revoke_slot(master_slot, slot_index) {
                persist_slot_mutation_or_rollback(
                    ctx,
                    master_slot,
                    slot_snapshot,
                    "client revocation",
                )?;
                log::info!("[relay] mgmt: revoked client slot {slot_index} (operator)");
                Ok(serde_json::json!({
                    "slot_index": slot_index,
                    "secret_fingerprint": secret_fingerprint,
                    "revoked": true,
                }))
            } else {
                Err(format!("no such slot: {slot_index}"))
            }
        }

        // Update a client slot's label / policy. Legacy slots retain the
        // historical partial-update/sign_event filter. Strict slots merge
        // omitted fields with their current ceiling, then replace the complete
        // exact policy through the same validator used at v2 creation.
        "update_client" => {
            let slot_index =
                req.pointer("/params/slot_index")
                    .and_then(|v| v.as_u64())
                    .ok_or("update_client requires params.slot_index")? as u8;
            let target = ctx
                .policy_engine
                .list_slots(master_slot)
                .iter()
                .find(|slot| slot.slot_index == slot_index)
                .cloned()
                .ok_or_else(|| format!("no such slot: {slot_index}"))?;
            let secret_fingerprint = require_expected_slot_fingerprint(req, &target)?;
            let label = req
                .pointer("/params/label")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let methods = if target.strict_permissions {
                match req.pointer("/params/allowed_methods") {
                    None => None,
                    Some(value) => {
                        let values = value
                            .as_array()
                            .ok_or("allowed_methods must be an array")?;
                        let mut parsed = Vec::with_capacity(values.len());
                        for value in values {
                            parsed.push(
                                value
                                    .as_str()
                                    .ok_or("allowed_methods must contain only strings")?
                                    .to_string(),
                            );
                        }
                        Some(parsed)
                    }
                }
            } else {
                req.pointer("/params/allowed_methods")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
            };
            let kinds = if target.strict_permissions {
                match req.pointer("/params/allowed_kinds") {
                    None => None,
                    Some(value) => {
                        let values = value
                            .as_array()
                            .ok_or("allowed_kinds must be an array")?;
                        let mut parsed = Vec::with_capacity(values.len());
                        for value in values {
                            parsed.push(
                                value
                                    .as_u64()
                                    .ok_or("allowed_kinds must contain only unsigned integers")?,
                            );
                        }
                        Some(parsed)
                    }
                }
            } else {
                req.pointer("/params/allowed_kinds")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
            };
            let auto = if target.strict_permissions {
                match req.pointer("/params/auto_approve") {
                    None => None,
                    Some(value) => Some(
                        value
                            .as_bool()
                            .ok_or("auto_approve must be a boolean")?,
                    ),
                }
            } else {
                req.pointer("/params/auto_approve")
                    .and_then(|v| v.as_bool())
            };
            let slot_snapshot = ctx.policy_engine.snapshot_slot_state(master_slot);
            let updated = if target.strict_permissions {
                ctx.policy_engine.set_exact_slot_policy(
                    master_slot,
                    slot_index,
                    methods.unwrap_or(target.allowed_methods),
                    kinds.unwrap_or(target.allowed_kinds),
                    auto.unwrap_or(target.auto_approve),
                )?;
                // Family-bunker C3 flags: absent params keep the slot's
                // existing values, matching the per-field merge rule above.
                ctx.policy_engine.set_slot_family_flags(
                    master_slot,
                    slot_index,
                    req.pointer("/params/escalate")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(target.escalate),
                    req.pointer("/params/petition_on_deny")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(target.petition_on_deny),
                    req.pointer("/params/audit_child_wrap")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(target.audit_child_wrap),
                    req.pointer("/params/bound_identity")
                        .and_then(|v| v.as_str())
                        .filter(|s| is_hex64(s))
                        .map(|s| s.to_ascii_lowercase())
                        .or(target.bound_identity),
                );
                ctx.policy_engine
                    .update_slot(master_slot, slot_index, label, None, None, None)
            } else {
                ctx.policy_engine
                    .update_slot(master_slot, slot_index, label, methods, kinds, auto)
            };
            if updated {
                persist_slot_mutation_or_rollback(
                    ctx,
                    master_slot,
                    slot_snapshot,
                    "client update",
                )?;
                log::info!("[relay] mgmt: updated client slot {slot_index} (operator)");
                Ok(serde_json::json!({
                    "slot_index": slot_index,
                    "secret_fingerprint": secret_fingerprint,
                    "updated": true,
                }))
            } else {
                Err(format!("no such slot: {slot_index}"))
            }
        }

        // Delegate (or un-delegate) management of THIS identity to a
        // per-identity operator. Device-operator only: sharing an operator for
        // one identity must never let that delegate re-delegate or reach the
        // owner's other identities. Absent/empty operator clears the delegation,
        // returning the identity to device-operator-only management.
        "set_identity_operator" => {
            if !is_device_op {
                return Err(
                    "set_identity_operator requires the device operator".into(),
                );
            }
            let raw = req
                .pointer("/params/operator")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let new_op: Option<[u8; 32]> = match raw {
                None => None,
                Some(hex) => Some(
                    hex_decode(hex)
                        .ok()
                        .and_then(|v| v.try_into().ok())
                        .ok_or("operator must be 32-byte hex")?,
                ),
            };
            match &new_op {
                Some(op) => crate::masters::set_master_operator(ctx.nvs, master_slot, op)?,
                None => crate::masters::clear_master_operator(ctx.nvs, master_slot)?,
            }
            // The in-memory master list is immutable here; the delegation is
            // read at boot, so schedule the same restart that provisioning a
            // master uses to reload the roster with the new operator.
            ctx.network_restart_at = Some(Instant::now() + NETWORK_RESTART_DELAY);
            log::info!(
                "[relay] mgmt: identity slot {master_slot} operator {}",
                if new_op.is_some() { "delegated" } else { "cleared" }
            );
            Ok(serde_json::json!({
                "slot": master_slot,
                "delegated": new_op.is_some(),
                "note": "signer restarts shortly to apply the operator change",
            }))
        }

        // The cable-free twin of the USB SET_IDENTITY_META (0x5b) frame:
        // Sapwood resolves the kind-0 and shrinks the picture in-browser,
        // then hands over ready Rgb565 bytes (base64 inside the NIP-44
        // ciphertext). The signer still never fetches or decodes images.
        "set_identity_meta" => {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            let name = req
                .pointer("/params/name")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .unwrap_or("");
            if name.is_empty() || name.len() > 255 {
                return Err("name must be 1-255 bytes".into());
            }
            let w = req
                .pointer("/params/w")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let h = req
                .pointer("/params/h")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if !(1..=255).contains(&w) || !(1..=255).contains(&h) {
                return Err("avatar dimensions must be 1-255".into());
            }
            let avatar = B64
                .decode(
                    req.pointer("/params/avatar_b64")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                )
                .map_err(|e| format!("avatar_b64: {e}"))?;
            if avatar.len() != (w as usize) * (h as usize) * 2 {
                return Err(format!("avatar length {} != w*h*2", avatar.len()));
            }
            crate::identity_meta::save(ctx.nvs, master_slot, name, w as u8, h as u8, &avatar)?;
            log::info!(
                "[relay] mgmt: identity meta stored for slot {master_slot}: '{name}' {w}x{h}"
            );
            // Refresh the single-master identity card, as the USB path does.
            // Redraw straight from the values in hand — reloading from NVS here
            // allocated a fresh avatar buffer at the request's peak heap use,
            // which is exactly when a fragmented mid-TLS heap says no.
            // Never wakes a blanked panel — operator config, not a user request.
            if ctx.masters.len() == 1 && ctx.display_on {
                let npub = heartwood_common::encoding::encode_npub(&ctx.masters[0].pubkey);
                crate::oled::show_npub(
                    ctx.display,
                    Some(name),
                    &npub,
                    Some((w as u8, h as u8, avatar.as_slice())),
                );
            }
            Ok(serde_json::json!({ "ok": true, "name": name, "w": w, "h": h }))
        }

        // Runtime log verbosity. Quiet drops logging to warnings — on boards
        // whose activity LED is wired to the log UART (the T-Display's blue
        // light), this is the "turn the flashing light off" control. Persisted
        // and applied immediately; the confirmation logs at WARN so it is
        // visible either way.
        "set_log_level" => {
            if !is_device_op {
                return Err("changing the device log level is a device-level operation and requires the device operator".into());
            }
            let quiet = req
                .pointer("/params/quiet")
                .and_then(|v| v.as_bool())
                .ok_or("set_log_level requires params.quiet (bool)")?;
            crate::log_quiet::write(ctx.nvs, quiet)?;
            crate::log_quiet::apply(quiet);
            log::warn!(
                "[relay] logging set to {}",
                if quiet { "quiet (warnings only)" } else { "normal (info)" }
            );
            Ok(serde_json::json!({ "quiet": quiet }))
        }

        "get_status" => {
            let capabilities = serde_json::json!([
                    "client_policy_v2",
                    // Schema addendum §1.5 family flags (escalate,
                    // petition_on_deny, audit_child_wrap, bound_identity)
                    // accepted on create_client_v2 / nostrconnect_v2 /
                    // update_client — the C3 compiler push feature-detects
                    // on this entry.
                    "client_policy_flags_v1",
                    // D2 persona-addressed pairing: create_client_v2 /
                    // nostrconnect_v2 / client_uri accept params.identity
                    // (an identity this master serves) and mint the pairing
                    // addressed to it, defaulting bound_identity to a persona
                    // endpoint.
                    "pairing_identity_v1",
                    "atomic_nostrconnect_policy_v2",
                    "staged_network_config_v1",
                    "mutation_challenge_v1",
                    "resolve_approval_v1",
                    // Per-identity operator delegation: set_identity_operator
                    // scopes a shared operator key to a single identity; the
                    // device operator still manages every identity.
                    "per_identity_operator_v1",
                    // Bearer-note locker served over heartwood_note_*
                    // extensions (gated methods pinned always-button, held
                    // through the deferred-approval machinery).
                    "note_locker_v1",
                    // Bearer notes as gift wraps: heartwood_note_send seals
                    // on-device, and a kind-1059 to a master npub puts a
                    // RECEIVE card up.
                    "note_wrap_v1"
            ]);
            // A delegate (per-identity operator) sees only what it needs to
            // feature-detect and manage its own identity — never the
            // device-wide audit ring, relay topology, storage inventory, or an
            // enumeration of the owner's other identities.
            if !is_device_op {
                return Ok(serde_json::json!({
                    "master_npub_hex": master_hex,
                    "mode": "wifi-standalone",
                    "capabilities": capabilities,
                    "slots": ctx.policy_engine.list_slots(master_slot).len(),
                    "version": env!("CARGO_PKG_VERSION"),
                    "board": crate::board::BOARD,
                }));
            }
            let mut relays_live = vec![s.url.clone()];
            relays_live.extend(pool.others.iter().map(|o| o.url.clone()));
            Ok(serde_json::json!({
                "master_count": ctx.masters.len(),
                "master_npub_hex": master_hex,
                "mode": "wifi-standalone",
                "relay": ctx.relay_url,
                "capabilities": capabilities,
                "relays_live": relays_live,
                "relays_pinned": pool.pinned.iter().map(|p| p.url.clone()).collect::<Vec<_>>(),
                "slots": ctx.policy_engine.list_slots(master_slot).len(),
                "audit": sign_audit_json(ctx),
                // Reboot attribution: managers show "up 3h, last restart:
                // software" so a crash-reboot is visible instead of silently
                // wiping the RAM audit and looking like relay flakiness.
                "uptime_s": crate::uptime_s(),
                "last_reset": crate::reset_reason_str(),
                "crashed_during": crate::crash_context(),
                // Live memory health: total free and the largest single block.
                // A largest block much smaller than free means a fragmented
                // heap — the condition behind the bulk-decrypt crashes.
                "free_heap": unsafe { esp_idf_svc::sys::esp_get_free_heap_size() },
                "largest_free_block": unsafe {
                    esp_idf_svc::sys::heap_caps_get_largest_free_block(esp_idf_svc::sys::MALLOC_CAP_8BIT)
                } as u32,
                "log_quiet": crate::log_quiet::read(ctx.nvs),
                // Identity & app storage share one NVS entry table; the
                // manager's storage gauge is driven from this (null when the
                // stats API fails, so "unknown" is not "empty").
                "nvs": crate::nvs_stats::as_json(),
                "max_personas": crate::personas::MAX_PERSONAS,
                // Running firmware, so managers can show version state over
                // WiFi too — the FIRMWARE_INFO frame only answers over USB.
                "version": env!("CARGO_PKG_VERSION"),
                "board": crate::board::BOARD,
            }))
        }

        // C4 verdict (schema §1.4). Every case resolves cleanly: an unknown
        // or reboot-cleared park is a no-op with an honest `applied`, never
        // an error. Single-guardian scope — only this master's parks resolve.
        "resolve_approval" => {
            let park_id = req
                .pointer("/params/park")
                .and_then(|v| v.as_str())
                .ok_or("resolve_approval requires params.park")?
                .to_string();
            let action_str = req
                .pointer("/params/action")
                .and_then(|v| v.as_str())
                .ok_or("resolve_approval requires params.action")?;
            let action = heartwood_common::escalate::parse_verdict_action(action_str)
                .ok_or("params.action must be approve-once, approve-remember or deny")?;
            let window = heartwood_common::escalate::clamp_window(
                req.pointer("/params/window").and_then(|v| v.as_u64()),
            );

            let park_idx = ctx
                .parks
                .iter()
                .position(|p| p.park_id == park_id && p.master_slot == master_slot);
            let park_live = park_idx.is_some();
            let tombstone = ctx
                .park_tombstones
                .iter()
                .find(|t| t.park_id == park_id && t.master_slot == master_slot)
                .cloned();

            let mut completed = false;
            let mut allow_installed = false;
            let mut policy_written = false;
            match action {
                heartwood_common::escalate::VerdictAction::ApproveOnce => {
                    if let Some(idx) = park_idx {
                        let park = ctx.parks.remove(idx);
                        // complete_parked installs the allow first, so even a
                        // failed completion leaves the retry window in place.
                        allow_installed = true;
                        completed = complete_parked(&mut s.tls, ctx, park, window);
                    } else if let Some(t) = tombstone {
                        ctx.policy_engine.install_transient_allow(
                            master_slot,
                            t.client_hex,
                            t.key,
                            window,
                        );
                        allow_installed = true;
                    }
                }
                heartwood_common::escalate::VerdictAction::ApproveRemember => {
                    let policy = exact_policy_from_request(req)?;
                    let client_hex = park_idx
                        .map(|idx| ctx.parks[idx].client_hex.clone())
                        .or_else(|| tombstone.as_ref().map(|t| t.client_hex.clone()));
                    if let Some(client_hex) = client_hex {
                        if let Some(slot_index) = ctx
                            .policy_engine
                            .find_slot_by_pubkey(master_slot, &client_hex)
                            .map(|slot| slot.slot_index)
                        {
                            let snapshot = ctx.policy_engine.snapshot_slot_state(master_slot);
                            ctx.policy_engine
                                .set_exact_slot_policy(
                                    master_slot,
                                    slot_index,
                                    policy.allowed_methods.clone(),
                                    policy.allowed_kinds.clone(),
                                    policy.auto_approve,
                                )
                                .map_err(|e| format!("policy write: {e}"))?;
                            ctx.policy_engine.set_slot_family_flags(
                                master_slot,
                                slot_index,
                                policy.escalate,
                                policy.petition_on_deny,
                                policy.audit_child_wrap,
                                policy.bound_identity.clone(),
                            );
                            persist_slot_mutation_or_rollback(
                                ctx,
                                master_slot,
                                snapshot,
                                "resolve_approval policy",
                            )?;
                            policy_written = true;
                        } else {
                            log::warn!(
                                "[relay] resolve_approval: client slot no longer exists"
                            );
                        }
                    }
                    if let Some(idx) = ctx
                        .parks
                        .iter()
                        .position(|p| p.park_id == park_id && p.master_slot == master_slot)
                    {
                        let park = ctx.parks.remove(idx);
                        // A short allow guarantees the completion dispatch is
                        // silent even where the written policy is narrower
                        // than this exact ask; the policy is the durable half.
                        completed = complete_parked(
                            &mut s.tls,
                            ctx,
                            park,
                            heartwood_common::escalate::WINDOW_DEFAULT_SECS,
                        );
                    }
                }
                heartwood_common::escalate::VerdictAction::Deny => {
                    if let Some(idx) = park_idx {
                        let park = ctx.parks.remove(idx);
                        deny_parked(&mut s.tls, ctx, park);
                    }
                }
            }
            ctx.park_tombstones.retain(|t| t.park_id != park_id);
            let applied = heartwood_common::escalate::applied_value(
                action,
                completed,
                allow_installed,
                policy_written,
            );
            Ok(serde_json::json!({
                "park": if park_live { "live" } else { "expired" },
                "applied": applied,
            }))
        }

        other => Err(format!("unknown method: {other}")),
    }
}

/// Re-encrypt `response_json` to `recipient_hex`, build + sign a `kind` envelope
/// authored by the resolved identity (master or persona), and publish it. The
/// author pubkey is recomputed from `signing_secret` (never trusted from input),
/// so the envelope is authored by the addressed identity itself. A transport
/// failure propagates.
#[allow(clippy::too_many_arguments)]
fn sign_and_publish(
    tls: &mut Tls,
    secp: &Arc<Secp256k1<SignOnly>>,
    signing_secret: &[u8; 32],
    conversation_key: &[u8; 32],
    recipient_hex: &str,
    kind: u64,
    created_at: u64,
    response_json: String,
) -> Result<(), String> {
    let response_len = response_json.len();
    crate::crash_crumb::set(&format!("relay encrypt kind {kind} {response_len}B"));
    let nonce = random_nonce_32();
    let ciphertext = nip44::encrypt_owned(conversation_key, response_json, &nonce)
        .map_err(|e| format!("encrypt: {e}"))?;
    crate::crash_crumb::set(&format!("relay envelope kind {kind}"));

    let keypair = Keypair::from_seckey_slice(secp, signing_secret)
        .map_err(|_| "invalid signing secret".to_string())?;
    let (xonly, _) = keypair.x_only_public_key();

    let unsigned = UnsignedEvent {
        pubkey: hex_encode(&xonly.serialize()),
        created_at,
        kind,
        tags: vec![vec!["p".to_string(), recipient_hex.to_string()]],
        content: ciphertext,
    };
    let event_id = nip46::compute_event_id(&unsigned);
    let sig = sign::sign_hash(secp, signing_secret, &event_id).map_err(|e| format!("sign: {e}"))?;

    let signed = SignedEvent {
        id: hex_encode(&event_id),
        pubkey: unsigned.pubkey,
        created_at: unsigned.created_at,
        kind: unsigned.kind,
        tags: unsigned.tags,
        content: unsigned.content,
        sig: hex_encode(&sig),
    };
    let event_len = ws_send_event(tls, &signed)?;
    log::info!(
        "[relay] published kind:{kind} response ({} bytes)",
        event_len
    );
    Ok(())
}

/// Serialise and mask an EVENT command in one allocation. The generic
/// `ws_send` path first builds a JSON String and then copies it into a masked
/// frame; for a large NIP-46 response that second full copy is avoidable.
fn ws_send_event(tls: &mut Tls, event: &SignedEvent) -> Result<usize, String> {
    const MAX_HEADER_LEN: usize = 14;
    let mut frame = Vec::with_capacity(
        MAX_HEADER_LEN
            .saturating_add(event.content.len())
            .saturating_add(768),
    );
    frame.resize(MAX_HEADER_LEN, 0);
    serde_json::to_writer(&mut frame, &("EVENT", event))
        .map_err(|e| format!("serialise: {e}"))?;

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

    frame[0] = 0x80 | OP_TEXT;
    let mask_offset = header_len - 4;
    if payload_len < 126 {
        frame[1] = 0x80 | payload_len as u8;
    } else if payload_len < 65_536 {
        frame[1] = 0x80 | 126;
        frame[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        frame[1] = 0x80 | 127;
        frame[2..10].copy_from_slice(&(payload_len as u64).to_be_bytes());
    }
    let mask = esp_random().to_le_bytes();
    frame[mask_offset..header_len].copy_from_slice(&mask);
    for (index, byte) in frame[header_len..].iter_mut().enumerate() {
        *byte ^= mask[index & 3];
    }

    crate::crash_crumb::set(&format!("relay websocket kind {} {}B", event.kind, payload_len));
    tls.write_all(&frame).map_err(|e| format!("ws send: {e:?}"))?;
    Ok(payload_len)
}

fn snippet(raw: &[u8], n: usize) -> String {
    String::from_utf8_lossy(&raw[..raw.len().min(n)]).into_owned()
}

/// 32-byte random NIP-44 nonce via `fill_random` (true entropy in both tiers).
fn random_nonce_32() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    crate::fill_random(&mut nonce);
    nonce
}

// --- Minimal RFC 6455 over EspTls ---

const OP_TEXT: u8 = 0x1;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// A decoded inbound WebSocket message (owned, so handling it can borrow the
/// connection mutably to publish a reply without aliasing the read buffer).
enum WsMsg {
    Text(Vec<u8>),
    Ping(Vec<u8>),
    Pong,
    Close,
    Other,
}

fn ws_handshake(tls: &mut Tls, host: &str, started: Instant) -> Result<(), String> {
    let mut socket_mode = NonblockingSocketGuard::enter(tls)
        .map_err(|e| format!("ws upgrade nonblocking setup: {e}"))?;
    let result = ws_handshake_nonblocking(tls, host, started);
    let restored = socket_mode
        .restore()
        .map_err(|e| format!("ws upgrade socket flags restore: {e}"));
    match (result, restored) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(restore_error)) => Err(format!("{error}; {restore_error}")),
    }
}

fn ws_handshake_nonblocking(tls: &mut Tls, host: &str, started: Instant) -> Result<(), String> {
    // A fixed Sec-WebSocket-Key is fine for a client that doesn't verify the
    // Accept header — security is TLS + NIP-44, not the WS nonce. (RFC example.)
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    let mut unwritten = req.as_bytes();
    while !unwritten.is_empty() {
        ensure_upgrade_deadline(started)?;
        let result = tls.write(unwritten);
        match upgrade_io_action(started, &result) {
            DeadlineIoAction::Progress(written) => unwritten = &unwritten[written..],
            DeadlineIoAction::Retry => FreeRtos::delay_ms(5),
            DeadlineIoAction::Closed => return Err("ws req: zero-length write".into()),
            DeadlineIoAction::Failed => {
                let detail = result
                    .err()
                    .map(|error| format!("{error:?}"))
                    .unwrap_or_else(|| "unknown nonblocking write failure".into());
                return Err(format!("ws req: {detail}"));
            }
            DeadlineIoAction::DeadlineExceeded => {
                return Err("ws upgrade deadline exceeded".into());
            }
        }
    }

    let mut buf = [0u8; 1024];
    let mut n = 0usize;
    loop {
        ensure_upgrade_deadline(started)?;
        let result = tls.read(&mut buf[n..]);
        let r = match upgrade_io_action(started, &result) {
            DeadlineIoAction::Progress(read) => read,
            DeadlineIoAction::Retry => {
                FreeRtos::delay_ms(5);
                continue;
            }
            DeadlineIoAction::Closed => return Err("ws handshake: eof".into()),
            DeadlineIoAction::Failed => {
                let detail = result
                    .err()
                    .map(|error| format!("{error:?}"))
                    .unwrap_or_else(|| "unknown nonblocking read failure".into());
                return Err(format!("ws resp: {detail}"));
            }
            DeadlineIoAction::DeadlineExceeded => {
                return Err("ws upgrade deadline exceeded".into());
            }
        };
        n += r;
        if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if n == buf.len() {
            return Err("ws handshake: headers too large".into());
        }
    }
    let resp = core::str::from_utf8(&buf[..n]).unwrap_or("");
    if !resp.contains(" 101 ") {
        return Err(format!(
            "ws handshake not 101: {}",
            &resp[..resp.len().min(64)]
        ));
    }
    ensure_upgrade_deadline(started)?;
    Ok(())
}

fn ensure_upgrade_deadline(started: Instant) -> Result<(), String> {
    if heartwood_common::deadline::remaining_timeout_ms(WS_UPGRADE_TIMEOUT, started.elapsed())
        .is_none()
    {
        Err("ws upgrade deadline exceeded".into())
    } else {
        Ok(())
    }
}

fn upgrade_io_action(
    started: Instant,
    result: &Result<usize, esp_idf_svc::sys::EspError>,
) -> DeadlineIoAction {
    let event = match result {
        Ok(transferred) => NonblockingIoEvent::Progress(*transferred),
        Err(error) if retryable_tls_io_error(&error) => NonblockingIoEvent::WouldBlock,
        Err(_) => NonblockingIoEvent::Failed,
    };
    deadline_io_action(WS_UPGRADE_TIMEOUT, started.elapsed(), event)
}

/// EspTls forwards negative raw ESP-IDF/mbedTLS read/write results unchanged.
/// WANT_READ/WANT_WRITE are already negative; errno constants are positive and
/// therefore match only in their negated form. Positive EWOULDBLOCK belongs to
/// EspTls's separate async-connect API and is not a read/write retry here.
fn retryable_tls_io_error(error: &esp_idf_svc::sys::EspError) -> bool {
    retryable_tls_io_code(
        error.code(),
        esp_idf_svc::sys::ESP_TLS_ERR_SSL_WANT_READ,
        esp_idf_svc::sys::ESP_TLS_ERR_SSL_WANT_WRITE,
        esp_idf_svc::sys::EAGAIN as i32,
        esp_idf_svc::sys::EWOULDBLOCK as i32,
    )
}

/// Send a masked client frame (RFC 6455 §5.3 mandates client→server masking).
fn ws_send(tls: &mut Tls, opcode: u8, payload: &[u8]) -> Result<(), String> {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | opcode); // FIN + opcode
    let len = payload.len();
    if len < 126 {
        frame.push(0x80 | len as u8);
    } else if len < 65536 {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    let mask = esp_random().to_le_bytes();
    frame.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[i & 3]);
    }
    tls.write_all(&frame).map_err(|e| format!("ws send: {e:?}"))
}

/// One timed read into the accumulation buffer. Returns the number of bytes
/// appended; `0` means the recv timeout fired with no data (a normal idle tick),
/// which lets the caller ping / check the silence deadline. A real socket error
/// or EOF propagates and triggers a reconnect.
fn pump(tls: &mut Tls, rx: &mut Vec<u8>) -> Result<usize, String> {
    // Rolling activity marker: this is where the loop spends its idle time
    // (blocked in the TLS read). If a panic strikes inside mbedTLS here — the
    // suspect for the healthy-memory crashes since dynamic buffers landed —
    // the next boot reports "relay reading" instead of a blank breadcrumb.
    crate::crash_crumb::set("relay reading");
    let mut tmp = [0u8; 1024];
    match tls.read(&mut tmp) {
        Ok(0) => Err("relay closed (eof)".into()),
        Ok(n) => {
            rx.extend_from_slice(&tmp[..n]);
            Ok(n)
        }
        Err(e) => {
            // SO_RCVTIMEO surfaces as WANT_READ/WANT_WRITE — not an error, just
            // "nothing yet". mbedTLS resumes any partial record on the next read.
            let c = e.code();
            if c == esp_idf_svc::sys::ESP_TLS_ERR_SSL_WANT_READ
                || c == esp_idf_svc::sys::ESP_TLS_ERR_SSL_WANT_WRITE
            {
                Ok(0)
            } else {
                Err(format!("ws read: {e:?}"))
            }
        }
    }
}

/// Pop one complete WebSocket frame from the front of `rx` if fully buffered.
/// `Ok(None)` means "need more bytes". An oversize frame is SKIPPED, not fatal —
/// see below. Server→client frames are unmasked per RFC 6455, but we honour the
/// mask bit.
///
/// `skip` carries the bytes still owed from an over-cap frame across calls,
/// since one can span several reads.
fn try_parse(rx: &mut Vec<u8>, skip: &mut usize) -> Result<Option<WsMsg>, String> {
    // Finish discarding an oversize frame before looking for the next header,
    // otherwise its body would be parsed as one.
    if *skip > 0 {
        let n = (*skip).min(rx.len());
        rx.drain(0..n);
        *skip -= n;
        if *skip > 0 {
            return Ok(None); // more of the doomed frame still to come
        }
    }
    if rx.len() < 2 {
        return Ok(None);
    }
    let opcode = rx[0] & 0x0F;
    let masked = rx[1] & 0x80 != 0;
    let mut len = (rx[1] & 0x7F) as usize;
    let mut off = 2;
    if len == 126 {
        if rx.len() < 4 {
            return Ok(None);
        }
        len = u16::from_be_bytes([rx[2], rx[3]]) as usize;
        off = 4;
    } else if len == 127 {
        if rx.len() < 10 {
            return Ok(None);
        }
        let declared = u64::from_be_bytes(rx[2..10].try_into().unwrap());
        // `usize` is 32 bits on this chip, so a declared length above u32 would
        // TRUNCATE — 0x1_0000_0000 would read as a 0-byte frame and desync the
        // stream against a body that is still arriving. No relay sends one
        // legitimately, so treat it as a broken peer rather than trying to
        // resync. Anything merely over the cap falls through to the skip below,
        // which is the path a >64KB event addressed to us takes.
        if declared > u32::MAX as u64 {
            return Err(format!("ws frame length {declared} is not credible"));
        }
        len = declared as usize;
        off = 10;
    }
    if len > MAX_WS_FRAME {
        // Drop the frame, KEEP the session.
        //
        // This used to return Err, which `session_step` propagates as "the
        // session is dead". That handed anyone a remote off-switch: the
        // subscription is `{"kinds":[24133],"#p":[<our pubkeys>]}`, and our
        // pubkey is public — it is the host of every bunker URI we issue. So
        // any unauthenticated party could publish an over-cap kind-24133 event
        // p-tagged to us and knock us off the relay, before a single byte was
        // decrypted or the sender was even looked at. The primary session then
        // fails over to a DIFFERENT relay (relay_idx advances) and a pinned one
        // backs off 15s doubling to 600s; either way the client watching the
        // old relay sees silence. Worse, the subscription is `limit:0` with no
        // `since`, so every request published during the gap is lost for good
        // rather than replayed on reconnect.
        //
        // Nothing about the STREAM is broken here, only this one message: the
        // header tells us exactly where the next frame starts. So skip it. The
        // body may not have arrived yet, hence `skip` carries the remainder.
        let total = off + if masked { 4 } else { 0 } + len;
        let n = total.min(rx.len());
        rx.drain(0..n);
        *skip = total - n;
        log::warn!("[relay] skipping oversize frame ({len}B > {MAX_WS_FRAME}B cap); session kept");
        // Counts as activity so the silence watchdog doesn't then trip, and
        // lets session_step reclaim any rx capacity the frame forced.
        return Ok(Some(WsMsg::Other));
    }
    let mask = if masked {
        if rx.len() < off + 4 {
            return Ok(None);
        }
        let m = [rx[off], rx[off + 1], rx[off + 2], rx[off + 3]];
        off += 4;
        Some(m)
    } else {
        None
    };
    if rx.len() < off + len {
        return Ok(None); // payload not fully arrived yet
    }
    let mut payload = rx[off..off + len].to_vec();
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i & 3];
        }
    }
    rx.drain(0..off + len);
    Ok(Some(match opcode {
        OP_TEXT => WsMsg::Text(payload),
        OP_PING => WsMsg::Ping(payload),
        OP_PONG => WsMsg::Pong,
        OP_CLOSE => WsMsg::Close,
        _ => WsMsg::Other,
    }))
}

fn tls_socket_fd(tls: &Tls) -> Result<core::ffi::c_int, String> {
    use esp_idf_svc::sys;
    let mut fd: core::ffi::c_int = -1;
    let result = unsafe { sys::esp_tls_get_conn_sockfd(tls.context_handle() as *mut _, &mut fd) };
    if result != sys::ESP_OK || fd < 0 {
        Err(format!("get sockfd failed (err {result}, fd {fd})"))
    } else {
        Ok(fd)
    }
}

/// Scoped nonblocking mode for the HTTP Upgrade only. `lwip_fcntl(F_GETFL)`
/// gives us the socket's exact original flags; every exit explicitly restores
/// them, with Drop as a second best-effort guard if restoration itself fails.
struct NonblockingSocketGuard {
    fd: core::ffi::c_int,
    original_flags: core::ffi::c_int,
    restored: bool,
}

impl NonblockingSocketGuard {
    fn enter(tls: &Tls) -> Result<Self, String> {
        use esp_idf_svc::sys;
        let fd = tls_socket_fd(tls)?;
        let original_flags = unsafe { sys::lwip_fcntl(fd, sys::F_GETFL as i32, 0) };
        if original_flags < 0 {
            return Err(format!("fcntl F_GETFL failed (rc {original_flags})"));
        }
        let nonblocking_flags = original_flags | sys::O_NONBLOCK as i32;
        let result = unsafe { sys::lwip_fcntl(fd, sys::F_SETFL as i32, nonblocking_flags) };
        if result != 0 {
            return Err(format!("fcntl F_SETFL O_NONBLOCK failed (rc {result})"));
        }
        Ok(Self {
            fd,
            original_flags,
            restored: false,
        })
    }

    fn restore(&mut self) -> Result<(), String> {
        if self.restored {
            return Ok(());
        }
        let result = unsafe {
            esp_idf_svc::sys::lwip_fcntl(
                self.fd,
                esp_idf_svc::sys::F_SETFL as i32,
                self.original_flags,
            )
        };
        if result != 0 {
            return Err(format!("fcntl F_SETFL restore failed (rc {result})"));
        }
        self.restored = true;
        Ok(())
    }
}

impl Drop for NonblockingSocketGuard {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            log::error!("[relay] TLS socket flag restore failed: {error}");
        }
    }
}

/// Apply a receive timeout to the live TLS socket so the steady-state relay
/// pump periodically returns to its ping, silence, trial, and USB work.
fn set_socket_timeout(
    tls: &mut Tls,
    option: i32,
    option_name: &str,
    ms: i64,
) -> Result<(), String> {
    use esp_idf_svc::sys;
    let fd = tls_socket_fd(tls)?;
    let tv = sys::timeval {
        tv_sec: (ms / 1000) as _,
        tv_usec: ((ms % 1000) * 1000) as _,
    };
    let rc = unsafe {
        sys::lwip_setsockopt(
            fd,
            sys::SOL_SOCKET as i32,
            option,
            &tv as *const _ as *const core::ffi::c_void,
            core::mem::size_of::<sys::timeval>() as sys::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!("setsockopt {option_name} failed (rc {rc})"));
    }
    Ok(())
}

fn set_recv_timeout(tls: &mut Tls, ms: i64) -> Result<(), String> {
    set_socket_timeout(tls, esp_idf_svc::sys::SO_RCVTIMEO as i32, "SO_RCVTIMEO", ms)
}

fn set_send_timeout(tls: &mut Tls, ms: i64) -> Result<(), String> {
    set_socket_timeout(tls, esp_idf_svc::sys::SO_SNDTIMEO as i32, "SO_SNDTIMEO", ms)
}

fn esp_random() -> u32 {
    unsafe { esp_idf_svc::sys::esp_random() }
}
