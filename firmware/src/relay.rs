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
use esp_idf_hal::gpio::{Input, PinDriver};
use esp_idf_hal::modem::Modem;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::nvs::{EspNvs, NvsDefault};
use esp_idf_svc::tls::{Config as TlsConfig, EspTls, InternalSocket, KeepAliveConfig};
use esp_idf_svc::wifi::{
    AuthMethod, BlockingWifi, ClientConfiguration, Configuration as WifiConfig, EspWifi,
    PmfConfiguration,
};
use secp256k1::{Keypair, Secp256k1, SignOnly};

use heartwood_common::deadline::{
    deadline_io_action, retryable_tls_io_code, DeadlineIoAction, NonblockingIoEvent,
};
use heartwood_common::frame::Frame;
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
    FRAME_TYPE_GENERATE_IDENTITY, FRAME_TYPE_GET_NET_CONFIG, FRAME_TYPE_NACK,
    FRAME_TYPE_NIP46_REQUEST, FRAME_TYPE_NIP46_RESPONSE, FRAME_TYPE_OTA_BEGIN,
    FRAME_TYPE_OTA_CHUNK, FRAME_TYPE_OTA_FINISH, FRAME_TYPE_PATCH_NET_CONFIG, FRAME_TYPE_PROVISION,
    FRAME_TYPE_DERIVE_IDENTITY,
    FRAME_TYPE_PROVISION_LIST, FRAME_TYPE_PROVISION_REMOVE, FRAME_TYPE_RESTORE_IDENTITY,
    FRAME_TYPE_SESSION_AUTH, FRAME_TYPE_SET_BRIDGE_SECRET, FRAME_TYPE_SET_IDENTITY_META,
    FRAME_TYPE_SET_NET_CONFIG, FRAME_TYPE_SET_OPERATOR, FRAME_TYPE_SET_PIN,
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
/// `masters`/`secp`/`button_pin` are shared refs; the rest are exclusive.
/// `'d` (display) and `'b` (button) stay independent — like the USB path —
/// so the `main` call site needn't prove the two peripherals share a lifetime.
struct SignCtx<'a, 'd, 'b> {
    masters: &'a [LoadedMaster],
    secp: &'a Arc<Secp256k1<SignOnly>>,
    display: &'a mut Display<'d>,
    button_pin: &'a PinDriver<'b, Input>,
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
    masters: &[LoadedMaster],
    personas: &mut Vec<crate::personas::LoadedPersona>,
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'d>,
    button_pin: &PinDriver<'b, Input>,
    policy_engine: &mut PolicyEngine,
    identity_caches: &mut Vec<IdentityCache>,
    nvs: &mut EspNvs<NvsDefault>,
    op_mgmt: Option<[u8; 32]>,
    network_trial_id: Option<String>,
    usb: &mut SerialPort<'_>,
) -> ! {
    log::info!(
        "[relay] WiFi-standalone: SSID={:?}, {} relay(s), {} master(s), mgmt={}",
        cfg.ssid,
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

    let (auth, pmf_cfg) = if cfg.password.is_empty() {
        (AuthMethod::None, PmfConfiguration::NotCapable)
    } else {
        // ESP-IDF treats auth_method as a minimum-strength scan threshold.
        // WPA2 therefore admits WPA2 and stronger WPA3 APs, while the nominal
        // WPA2/WPA3 mixed value collapses to a WPA3 minimum and rejects pure
        // WPA2. PMF optional supplies the WPA3 requirement without excluding a
        // WPA2 AP that does not advertise PMF.
        (
            AuthMethod::WPA2Personal,
            PmfConfiguration::Capable { required: false },
        )
    };
    wifi.set_configuration(&WifiConfig::Client(ClientConfiguration {
        ssid: cfg.ssid.as_str().try_into().expect("relay: ssid too long"),
        password: cfg
            .password
            .as_str()
            .try_into()
            .expect("relay: pass too long"),
        auth_method: auth,
        pmf_cfg,
        ..Default::default()
    }))
    .expect("relay: wifi config");
    wifi.start().expect("relay: wifi start");

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

    let network_trial_deadline = network_trial_id
        .as_ref()
        .map(|_| Instant::now() + NETWORK_TRIAL_TIMEOUT);
    let mut ctx = SignCtx {
        masters,
        secp,
        display,
        button_pin,
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
        dial_cooldown: None,
        network_trial_id,
        network_trial_deadline,
        network_restart_at: None,
        network_runtime: NetworkRuntimeStatus::starting(),
        network_display_restore_at: None,
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
        network_state_tick(&mut ctx);
        if ctx.network_restart_at.is_some() {
            // A management response already scheduled a restart. Do not enter
            // any socket read (including another session's degraded blocking
            // read) before the deadline is serviced at the top of the loop.
            FreeRtos::delay_ms(20);
            continue;
        }
        // Every relay session depends on the station link; restore it before
        // attempting any relay dial.
        if !wifi.is_up().unwrap_or(false) {
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
                FreeRtos::delay_ms(20);
            }
            continue;
        }

        // Wake the panel promptly on a BOOT-button press, and serve USB, once
        // per pass regardless of how many sessions are live or connecting.
        if !ctx.display_on && ctx.button_pin.is_low() {
            crate::oled::wake_display(ctx.display);
            ctx.display_on = true;
            ctx.last_activity = Instant::now();
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

        // Ensure the primary session (rotates over the configured set).
        if !sessions.iter().any(|s| !s.pinned) && Instant::now() >= primary_next {
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
        }
    }
}

/// Apply delayed network restarts only from the outer relay loop, after the
/// management handler has returned and its encrypted response has been sent.
/// A live candidate that is never committed is aborted and rebooted back to A.
fn network_state_tick(ctx: &mut SignCtx) {
    let now = Instant::now();
    if ctx
        .network_display_restore_at
        .map(|deadline| now >= deadline)
        .unwrap_or(false)
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
fn build_sub_req(ctx: &SignCtx) -> String {
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
    if ctx.op_mgmt.is_some() {
        format!(
            r##"["REQ","hw",{{"kinds":[{NIP46_KIND}],"#p":[{nip46_p_list}],"limit":0}},{{"kinds":[{MGMT_KIND}],"#p":[{master_p_list}],"limit":0}},{profile_filter}]"##
        )
    } else {
        format!(
            r##"["REQ","hw",{{"kinds":[{NIP46_KIND}],"#p":[{nip46_p_list}],"limit":0}},{profile_filter}]"##
        )
    }
}

/// Open one relay session: TLS → WS handshake → recv timeout → subscribe.
fn connect_relay(url: &str, pinned: bool, ctx: &mut SignCtx) -> Result<RelaySession, String> {
    let host = relay_host(url).to_string();
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
    if !recv_timeout_on && (pinned || ctx.network_trial_id.is_some()) {
        return Err(if pinned {
            "pinned relay needs a recv timeout (would starve the primary)".into()
        } else {
            "network trial needs a recv timeout (rollback deadline must remain live)".into()
        });
    }

    // A send timeout bounds how long a publish to a stalled peer can hold the
    // loop (see SEND_TIMEOUT_MS). Failure degrades to blocking sends — same
    // posture as the recv timeout above — but on lwIP both use one setsockopt
    // path, so if the recv timeout landed this one will too.
    if let Err(e) = set_send_timeout(&mut tls, SEND_TIMEOUT_MS) {
        log::warn!("[relay] send-timeout unavailable ({e}); blocking sends");
    }

    let sub_req = build_sub_req(ctx);
    ws_send(&mut tls, OP_TEXT, sub_req.as_bytes())?;
    log::info!(
        "[relay] subscribed on {url}: {} master(s) + {} persona(s), mgmt={}",
        ctx.masters.len(),
        ctx.personas.len(),
        if ctx.op_mgmt.is_some() { "on" } else { "off" }
    );

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
    })
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
    if let Some(msg) = try_parse(&mut s.rx)? {
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
    let frame = match crate::protocol::try_read_frame(usb, 0) {
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
        // NVS. The signer never fetches/decodes images itself.
        FRAME_TYPE_SET_IDENTITY_META => {
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

        FRAME_TYPE_PROVISION_LIST => crate::provision::handle_list(usb, ctx.masters, ctx.personas, Some(ctx.policy_engine)),

        // Plaintext NIP-46 — only when the bridge is not authenticated (mirrors
        // the USB-only loop). Uses the first master, like the tethered path.
        FRAME_TYPE_NIP46_REQUEST => {
            if ctx.policy_engine.bridge_authenticated || ctx.masters.is_empty() {
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            } else {
                let master_secret = ctx.masters[0].secret;
                let master_label = ctx.masters[0].label.clone();
                let master_mode = ctx.masters[0].mode;
                let master_slot = ctx.masters[0].slot;
                let response_json = crate::nip46_handler::handle_request(
                    &frame,
                    &master_secret,
                    &master_label,
                    master_mode,
                    master_slot,
                    ctx.secp,
                    ctx.display,
                    ctx.button_pin,
                    ctx.policy_engine,
                    ctx.identity_caches,
                    None,
                );
                crate::protocol::write_frame(
                    usb,
                    FRAME_TYPE_NIP46_RESPONSE,
                    response_json.as_bytes(),
                );
                ctx.policy_engine.persist_slots(ctx.nvs, master_slot);
            }
        }

        // Encrypted NIP-46 (bridge transport) — requires an authenticated bridge.
        FRAME_TYPE_ENCRYPTED_REQUEST => {
            if !ctx.policy_engine.bridge_authenticated {
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            } else {
                crate::transport::handle_encrypted_request(
                    usb,
                    &frame,
                    ctx.masters,
                    ctx.personas,
                    ctx.secp,
                    ctx.display,
                    ctx.button_pin,
                    ctx.policy_engine,
                    ctx.identity_caches,
                    ctx.nvs,
                );
            }
        }

        // Deprecated inline-envelope signing — explicit reject like the USB loop.
        FRAME_TYPE_SIGN_ENVELOPE => crate::protocol::write_frame(usb, FRAME_TYPE_NACK, &[]),

        FRAME_TYPE_SESSION_AUTH => {
            crate::session::handle_auth(usb, &frame.payload, ctx.nvs, ctx.policy_engine)
        }
        FRAME_TYPE_SET_BRIDGE_SECRET => crate::session::handle_set_bridge_secret(
            usb,
            &frame.payload,
            ctx.nvs,
            ctx.policy_engine,
            ctx.display,
            ctx.button_pin,
        ),

        // Network reconfig — the handler reboots into the new mode itself on a
        // wifi save (and simply persists a radio-off save).
        FRAME_TYPE_SET_NET_CONFIG => crate::net_config_store::handle_set_net_config(
            usb,
            &frame.payload,
            ctx.nvs,
            ctx.display,
            ctx.button_pin,
        ),

        FRAME_TYPE_GET_NET_CONFIG => {
            crate::net_config_store::handle_get_net_config(usb, ctx.nvs, ctx.network_runtime)
        }

        FRAME_TYPE_PATCH_NET_CONFIG => crate::net_config_store::handle_patch_net_config(
            usb,
            &frame.payload,
            ctx.nvs,
            ctx.display,
            ctx.button_pin,
        ),

        FRAME_TYPE_SET_OPERATOR => crate::net_config_store::handle_set_operator(
            usb,
            &frame.payload,
            ctx.nvs,
            ctx.display,
            ctx.button_pin,
            true,
        ),

        FRAME_TYPE_SET_PIN => crate::pin::handle_set_pin(
            usb,
            &frame.payload,
            ctx.nvs,
            ctx.masters,
            ctx.display,
            ctx.button_pin,
        ),

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
            ctx.button_pin,
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
                    ctx.button_pin,
                );
            }
        }
        FRAME_TYPE_BACKUP_IMPORT_REQUEST => crate::backup::handle_import(
            usb,
            &frame.payload,
            ctx.masters,
            ctx.policy_engine,
            ctx.nvs,
            ctx.display,
            ctx.button_pin,
        ),

        // OTA — the finish handler verifies the image and reboots into it.
        FRAME_TYPE_OTA_BEGIN => crate::ota::handle_ota_begin(
            usb,
            &frame.payload,
            ctx.display,
            ctx.button_pin,
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
            let provisioned = match frame.frame_type {
                FRAME_TYPE_GENERATE_IDENTITY => crate::provision::handle_generate(
                    usb,
                    &frame,
                    ctx.nvs,
                    ctx.secp,
                    ctx.display,
                    ctx.button_pin,
                ),
                FRAME_TYPE_RESTORE_IDENTITY => crate::provision::handle_restore(
                    // `None`: restore over USB while already in Wi-Fi relay mode
                    // keeps the single-button gesture picker (the relay context
                    // doesn't carry the second button). The primary restore
                    // paths in main.rs get the T-Display two-button picker.
                    usb,
                    &frame,
                    ctx.nvs,
                    ctx.secp,
                    ctx.display,
                    ctx.button_pin,
                    None,
                ),
                _ => crate::provision::handle_add(usb, &frame, ctx.nvs, ctx.secp, ctx.display),
            };
            if provisioned.is_some() {
                reboot_after_state_change("master added");
            }
        }

        // Derive a named child on-device and store it as a new master. A
        // master-set change like PROVISION, so reboot to re-subscribe; an
        // idempotent re-derive (existing slot) returns None and needs none.
        FRAME_TYPE_DERIVE_IDENTITY => {
            if crate::provision::handle_derive(usb, &frame, ctx.nvs, ctx.secp, ctx.display, ctx.masters)
                .is_some()
            {
                reboot_after_state_change("identity derived");
            }
        }
        FRAME_TYPE_PROVISION_REMOVE => {
            if frame.payload.len() == 1 {
                let slot = frame.payload[0];
                match crate::masters::remove_master(ctx.nvs, slot) {
                    Ok(()) => {
                        crate::oled::show_error(ctx.display, &format!("Removed slot {slot}"));
                        crate::protocol::write_frame(usb, FRAME_TYPE_ACK, &[]);
                        reboot_after_state_change("master removed");
                    }
                    Err(e) => {
                        log::error!("[relay] remove master slot {slot} failed: {e}");
                        crate::protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
                        if crate::masters::removal_pending(ctx.nvs) {
                            reboot_after_state_change("master removal recovery pending");
                        }
                    }
                }
            } else {
                crate::protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
            }
        }
        // Factory reset wipes NVS and reboots inside the handler.
        FRAME_TYPE_FACTORY_RESET => {
            crate::provision::handle_factory_reset(usb, ctx.nvs, ctx.display, ctx.button_pin)
        }

        // 0x55 — scan nearby WiFi APs. Reuses the relay's own started driver when
        // it is lent (WiFi up but idle); mid-connection the caller passes `None`
        // and we decline, so a diagnostic scan never bumps a live signing link.
        FRAME_TYPE_WIFI_SCAN_REQUEST => match wifi {
            Some(w) => crate::wifi_scan::respond(usb, w),
            None => crate::protocol::write_frame(usb, FRAME_TYPE_NACK, &[]),
        },

        other => {
            log::warn!("[relay] USB frame 0x{other:02x} not recognised");
            crate::protocol::write_frame(usb, FRAME_TYPE_NACK, b"unknown frame");
        }
    }
}

/// Parse one inbound relay message (`["EVENT",sub,ev]` / `EOSE` / `OK` / …).
fn handle_relay_msg(
    s: &mut RelaySession,
    raw: &[u8],
    ctx: &mut SignCtx,
    pool: &mut RelayPool,
) -> Result<(), String> {
    let mut v: serde_json::Value = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(_) => {
            log::warn!("[relay] non-JSON frame ({} bytes)", raw.len());
            return Ok(());
        }
    };
    if !v.is_array() {
        return Ok(());
    }
    let tag = v.get(0).and_then(|x| x.as_str()).unwrap_or("").to_string();
    match tag.as_str() {
        "EVENT" => {
            set_network_runtime(
                ctx,
                NetworkRuntimeStage::Online,
                true,
                true,
                NetworkRuntimeError::None,
            );
            if let Some(ev_val) = v.get_mut(2) {
                // `take` instead of `clone`: a set_identity_meta event is ~17KB
                // of JSON, and cloning its parsed Value briefly doubled that on
                // a heap already carrying the TLS session — enough to OOM-abort
                // a classic ESP32 (observed as rst:0xc on the T-Display).
                let ev_val = ev_val.take();
                drop(v); // free the (now-gutted) envelope before the deep parse
                match serde_json::from_value::<SignedEvent>(ev_val) {
                    Ok(ev) => process_event(s, &ev, ctx, pool)?,
                    Err(e) => log::warn!("[relay] bad EVENT json: {e}"),
                }
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
    ev: &SignedEvent,
    ctx: &mut SignCtx,
    pool: &mut RelayPool,
) -> Result<(), String> {
    if let Err(e) = nip46::verify_signed_event(ev) {
        log::warn!("[relay] invalid Nostr EVENT ({e}); ignoring");
        return Ok(());
    }

    // Our own kind-0 profile: cache the name and refresh the idle identity
    // screen. This is not a user request, so it must never wake a blanked panel.
    if ev.kind == 0 {
        handle_profile_event(ev, ctx);
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

    if ev.kind == MGMT_KIND {
        match masters::find_by_pubkey(ctx.masters, &target_pk) {
            Some(master_idx) => handle_mgmt_event(s, ev, ctx, master_idx, pool),
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
        handle_nip46_event(&mut s.tls, ev, ctx, &target_pk)
    }
}

fn client_label(ctx: &SignCtx, master_slot: u8, client_hex: &str) -> String {
    ctx.policy_engine
        .find_slot_by_pubkey(master_slot, client_hex)
        .map(|s| s.label.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("client {}", &client_hex[..client_hex.len().min(8)]))
}

fn sign_audit_draft(plaintext: &str, label: String, client_hex: &str) -> Option<SignAuditDraft> {
    let req = nip46::parse_request(plaintext.as_bytes()).ok()?;
    let method = req.method.clone();
    match method.as_str() {
        "sign_event" => {
            let event = nip46::parse_unsigned_event(&req.params).ok()?;
            let (kind, preview) = nip46::event_display_summary(&event, 80);
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
    ctx.sign_audit
        .iter()
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

/// NIP-46 signing path (kind 24133): resolve the addressed identity → decrypt →
/// `handle_request` → re-encrypt → sign + publish. Mirrors the USB
/// `transport::handle_encrypted_request`, including per-persona routing.
fn handle_nip46_event(
    tls: &mut Tls,
    ev: &SignedEvent,
    ctx: &mut SignCtx,
    target_pk: &[u8; 32],
) -> Result<(), String> {
    // Resolve the addressed identity to its signing key. A master signs with its
    // own secret; a persona re-derives its key from the owning master and uses
    // that key for BOTH the NIP-44 transport and the envelope signature — so one
    // connection == one identity, exactly as the USB path does. `label`/`mode`/
    // `slot` are the owning master's (personas share the master's policy slot).
    // All resolved values are owned, so no `ctx` borrow is held past this block.
    let (signing_secret, label, mode, slot, is_persona) =
        if let Some(midx) = masters::find_by_pubkey(ctx.masters, target_pk) {
            let m = &ctx.masters[midx];
            (
                zeroize::Zeroizing::new(m.secret),
                m.label.clone(),
                m.mode,
                m.slot,
                false,
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
                Ok((secret, _pk)) => (secret, owning.label.clone(), owning.mode, owning.slot, true),
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
    log::info!(
        "[relay] decrypted request ({} bytes) from {}… for {}{}",
        plaintext.len(),
        &ev.pubkey[..ev.pubkey.len().min(8)],
        label,
        if is_persona { " (persona)" } else { "" }
    );
    let audit = sign_audit_draft(&plaintext, client_label(ctx, slot, &ev.pubkey), &ev.pubkey);

    let inner = Frame {
        frame_type: FRAME_TYPE_NIP46_REQUEST,
        payload: plaintext.into_bytes(),
    };

    // Only connect binding and first-sign TOFU can change durable slot
    // authority. Snapshot those uncommon requests before dispatch so an NVS
    // failure can roll RAM back without cloning the slot table on every
    // unattended auto-sign.
    let parsed_request = nip46::parse_request(&inner.payload).ok();
    let request_id = parsed_request
        .as_ref()
        .map(|request| request.id.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let slot_snapshot = parsed_request.as_ref().and_then(|request| {
        let method = nip46::Nip46Method::from_str(&request.method);
        let event_kind = if matches!(method, nip46::Nip46Method::SignEvent) {
            nip46::parse_unsigned_event(&request.params)
                .ok()
                .map(|event| event.kind)
        } else {
            None
        };
        let tier = ctx
            .policy_engine
            .check(slot, &ev.pubkey, &method, event_kind);
        crate::nip46_handler::request_may_mutate_slot_state(request, tier)
            .then(|| ctx.policy_engine.snapshot_slot_state(slot))
    });

    // Breadcrumb the in-flight request so a crash while handling it is
    // attributable on the next boot. Cleared right after the handler returns;
    // it only survives if the chip resets before that (panic/watchdog).
    if let Some(req) = &parsed_request {
        let mut crumb = format!("relay {}", req.method);
        if matches!(nip46::Nip46Method::from_str(&req.method), nip46::Nip46Method::SignEvent) {
            if let Ok(ev) = nip46::parse_unsigned_event(&req.params) {
                crumb.push_str(&format!(" kind {}", ev.kind));
            }
        }
        crumb.push_str(&format!(" from {}", &ev.pubkey[..ev.pubkey.len().min(8)]));
        crate::crash_crumb::set(&crumb);
    } else {
        crate::crash_crumb::set("relay request (unparsed)");
    }

    // Dispatch — same handler as the USB path. sign_event is ButtonRequired
    // until the slot is physically button-upgraded; auto-approve covers the
    // safe methods and post-upgrade signing.
    let mut response_json = crate::nip46_handler::handle_request(
        &inner,
        &signing_secret,
        &label,
        mode,
        slot,
        ctx.secp,
        ctx.display,
        ctx.button_pin,
        ctx.policy_engine,
        ctx.identity_caches,
        Some(&client_pubkey),
    );
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

    // Persist any identities derived during this request (e.g. via
    // heartwood_derive_persona) to the registry, so they survive reboot and
    // become addressable by their own bunker URI — picked up by the `#p`
    // subscription on the next (re)connect. Mirrors the USB path.
    if let Some(cache) = ctx.identity_caches.iter().find(|c| c.master_slot == slot) {
        let fresh: Vec<(String, u32, Option<String>, [u8; 32])> = cache
            .identities
            .iter()
            .filter(|id| !crate::personas::contains_pubkey(ctx.personas, &id.public_key))
            .map(|id| {
                (
                    id.purpose.clone(),
                    id.index,
                    id.persona_name.clone(),
                    id.public_key,
                )
            })
            .collect();
        for (purpose, index, name, pubkey) in fresh {
            if crate::personas::add(ctx.nvs, slot, &purpose, index, name.as_deref(), &pubkey)
                .is_ok()
            {
                ctx.personas.push(crate::personas::LoadedPersona {
                    master_slot: slot,
                    purpose,
                    index,
                    name,
                    pubkey,
                });
            }
        }
    }

    // The publish (re-encrypt + inline envelope sign) is the other crash-prone
    // step on a fragmented no-PSRAM heap, so keep the breadcrumb set across it.
    let published = sign_and_publish(
        tls,
        ctx.secp,
        &signing_secret,
        &conversation_key,
        &ev.pubkey,
        NIP46_KIND,
        ev.created_at,
        &response_json,
    );
    // Handled without a crash — retire the breadcrumb.
    crate::crash_crumb::clear();
    published
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
    let op_mgmt = match ctx.op_mgmt {
        Some(k) => k,
        None => {
            log::warn!("[relay] kind 24134 but no operator configured; ignoring");
            return Ok(());
        }
    };

    // SECURITY CRUX: the command runs only if it comes from the baked operator
    // key. NIP-44 (below) already makes forgery impossible — a third party can't
    // encrypt under the device⇄operator conversation key without the operator
    // secret — and this author gate is the explicit authority check on top.
    // The rule itself is `mgmt::is_operator`, unit-tested on the host.
    let author: [u8; 32] = match hex_decode(&ev.pubkey).ok().and_then(|v| v.try_into().ok()) {
        Some(a) => a,
        None => return Ok(()),
    };
    if !mgmt::is_operator(&author, &op_mgmt) {
        log::warn!(
            "[relay] mgmt from non-operator {}…; rejecting",
            &ev.pubkey[..ev.pubkey.len().min(16)]
        );
        return Ok(());
    }

    // Conversation key is master ⇄ op_mgmt. Scope the borrow so `ctx` is free
    // for the mutable dispatch below.
    let conversation_key = {
        let master = &ctx.masters[master_idx];
        match nip44::get_conversation_key(&master.secret, &op_mgmt) {
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
        dispatch_mgmt(&method, &req, s, ctx, master_idx, pool)
    })();

    let response_json = match dispatch_result {
        Ok(result) => serde_json::json!({ "id": id, "result": result }).to_string(),
        Err(e) => serde_json::json!({ "id": id, "error": e }).to_string(),
    };

    let master = &ctx.masters[master_idx];
    sign_and_publish(
        &mut s.tls,
        ctx.secp,
        &master.secret,
        &conversation_key,
        &ev.pubkey,
        MGMT_KIND,
        ev.created_at,
        &response_json,
    )
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

    validate_exact_slot_policy(methods, kinds, auto_approve).map_err(str::to_string)
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
            let name = req
                .pointer("/params/name")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .ok_or("derive_identity requires params.name")?;
            heartwood_common::validate::validate_purpose(name)?;

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
            let exact_policy = if is_v2 {
                Some(exact_policy_from_request(req)?)
            } else {
                None
            };
            let label = req
                .pointer("/params/label")
                .and_then(|v| v.as_str())
                .unwrap_or("relay-client")
                .to_string();

            // Slot secret from the hardware RNG (never leaves except in the URI).
            let mut secret_bytes = [0u8; 32];
            unsafe {
                esp_idf_svc::sys::esp_fill_random(
                    secret_bytes.as_mut_ptr() as *mut core::ffi::c_void,
                    32,
                );
            }
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
                    let bunker_uri = mgmt::bunker_uri(&master_hex, &ctx.relays, Some(&secret_hex));
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
                        "npub_hex": master_hex,
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
            let exact_policy = if is_v2 {
                Some(exact_policy_from_request(req)?)
            } else {
                None
            };
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

            // Copy the master secret up front (it is Copy) so publishing the ACK
            // below needs no live borrow of ctx while the slot table is mutated.
            let master_secret = ctx.masters[master_idx].secret;
            // Hex shape is not enough: validate/lift the x-only key and derive
            // the ACK conversation key before dialling or touching slot RAM.
            // No fallible key operation may strand an orphan authority change.
            let ck = nip44::get_conversation_key(&master_secret, &client_bytes)
                .map_err(|e| format!("conversation key: {e}"))?;

            // A slot secret is still minted (bunker parity), even though this slot
            // is bound by pubkey rather than by a secret handshake.
            let mut secret_bytes = [0u8; 32];
            unsafe {
                esp_idf_svc::sys::esp_fill_random(
                    secret_bytes.as_mut_ptr() as *mut core::ffi::c_void,
                    32,
                );
            }
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

            // Publish the connect ACK to the app, authored by this master.
            let mut id_bytes = [0u8; 8];
            unsafe {
                esp_idf_svc::sys::esp_fill_random(
                    id_bytes.as_mut_ptr() as *mut core::ffi::c_void,
                    8,
                );
            }
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
                &master_secret,
                &ck,
                client_hex,
                NIP46_KIND,
                created_at,
                &ack,
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
            Ok(serde_json::json!({
                "slot_index": slot_index,
                "secret_fingerprint": secret_fingerprint,
                "bunker_uri": mgmt::bunker_uri(&master_hex, &ctx.relays, Some(&slot.secret)),
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
            let app_counts: Vec<usize> = ctx
                .masters
                .iter()
                .map(|m| ctx.policy_engine.list_slots(m.slot).len())
                .collect();
            let mut identities: Vec<serde_json::Value> = ctx
                .masters
                .iter()
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
                    })
                })
                .collect();
            let master_count = identities.len();
            for p in ctx.personas.iter() {
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
            let mut relays_live = vec![s.url.clone()];
            relays_live.extend(pool.others.iter().map(|o| o.url.clone()));
            Ok(serde_json::json!({
                "master_count": ctx.masters.len(),
                "master_npub_hex": master_hex,
                "mode": "wifi-standalone",
                "relay": ctx.relay_url,
                "capabilities": [
                    "client_policy_v2",
                    "atomic_nostrconnect_policy_v2",
                    "staged_network_config_v1",
                    "mutation_challenge_v1"
                ],
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
                "log_quiet": crate::log_quiet::read(ctx.nvs),
                // Running firmware, so managers can show version state over
                // WiFi too — the FIRMWARE_INFO frame only answers over USB.
                "version": env!("CARGO_PKG_VERSION"),
                "board": crate::board::BOARD,
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
    response_json: &str,
) -> Result<(), String> {
    let nonce = random_nonce_32();
    let ciphertext = nip44::encrypt(conversation_key, response_json, &nonce)
        .map_err(|e| format!("encrypt: {e}"))?;

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
    let event_json = serde_json::to_string(&signed).map_err(|e| format!("serialise: {e}"))?;

    ws_send(
        tls,
        OP_TEXT,
        format!(r#"["EVENT",{event_json}]"#).as_bytes(),
    )?;
    log::info!(
        "[relay] published kind:{kind} response ({} bytes)",
        event_json.len()
    );
    Ok(())
}

fn snippet(raw: &[u8], n: usize) -> String {
    String::from_utf8_lossy(&raw[..raw.len().min(n)]).into_owned()
}

/// 32-byte random NIP-44 nonce from the ESP-IDF hardware RNG.
fn random_nonce_32() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    unsafe {
        esp_idf_svc::sys::esp_fill_random(nonce.as_mut_ptr() as *mut core::ffi::c_void, 32);
    }
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
/// `Ok(None)` means "need more bytes"; an oversize frame is an error (reconnect).
/// Server→client frames are unmasked per RFC 6455, but we honour the mask bit.
fn try_parse(rx: &mut Vec<u8>) -> Result<Option<WsMsg>, String> {
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
        len = u64::from_be_bytes(rx[2..10].try_into().unwrap()) as usize;
        off = 10;
    }
    if len > MAX_WS_FRAME {
        return Err(format!("ws frame {len}B exceeds {MAX_WS_FRAME}B cap"));
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
