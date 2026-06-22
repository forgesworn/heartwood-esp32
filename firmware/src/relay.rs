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
//! Increments 1–3 (done): wifi up → TLS → RFC-6455 handshake → subscribe by
//! master pubkey → on EVENT, decrypt/sign/publish → answer pings.
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
};
use secp256k1::{Keypair, Secp256k1, SignOnly};

use heartwood_common::frame::Frame;
use heartwood_common::hex::{hex_decode, hex_encode};
use heartwood_common::mgmt;
use heartwood_common::net_config::NetConfig;
use heartwood_common::nip44;
use heartwood_common::nip46::{self, SignedEvent, UnsignedEvent};
use heartwood_common::types::{
    FRAME_TYPE_CONNSLOT_CREATE, FRAME_TYPE_CONNSLOT_LIST, FRAME_TYPE_CONNSLOT_REVOKE,
    FRAME_TYPE_CONNSLOT_UPDATE, FRAME_TYPE_CONNSLOT_URI, FRAME_TYPE_NACK,
    FRAME_TYPE_NIP46_REQUEST, FRAME_TYPE_PROVISION_LIST, FRAME_TYPE_SESSION_AUTH,
    FRAME_TYPE_SET_BRIDGE_SECRET,
};

use crate::identity_cache::IdentityCache;
use crate::masters::{self, LoadedMaster};
use crate::oled::Display;
use crate::policy::PolicyEngine;
use crate::serial::SerialPort;
use crate::sign;

type Tls = EspTls<InternalSocket>;

const TLS_PORT: u16 = 443;
/// NIP-46 request/response event kind (also the inline envelope kind).
const NIP46_KIND: u64 = 24133;
/// Relay-management event kind (distinct permission boundary from NIP-46).
/// Requests are authenticated to the baked operator key (`op_mgmt`).
const MGMT_KIND: u64 = 24134;
/// Bound on the management replay seen-set (recent request ids).
const SEEN_MAX: usize = 64;
/// NVS key the management replay seen-set is persisted under, so a captured
/// command cannot be replayed after the device reboots.
const MGMT_SEEN_KEY: &str = "mgmt_seen";
/// Initial capacity of the inbound byte-accumulation buffer.
const READ_BUF: usize = 8192;
/// Largest single inbound WS frame we'll accept; bigger ⇒ drop + reconnect.
const MAX_WS_FRAME: usize = 16384;
/// `SO_RCVTIMEO` for the read loop — how long a `read` blocks before returning
/// "no data yet" so the loop can ping / check the silence deadline.
const RECV_TIMEOUT_MS: i64 = 1000;
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
    /// Operator pubkey authorised for kind-24134 management (`None` disables it).
    op_mgmt: Option<[u8; 32]>,
    /// Full relay URL (e.g. `wss://relay.trotters.cc`) — used to build bunker URIs.
    relay_url: String,
    /// Bounded replay seen-set of recent management request ids.
    seen: Vec<String>,
    /// OLED power state — false once blanked for burn-in protection.
    display_on: bool,
    /// Last time a real request touched the screen (drives the blank timeout).
    last_activity: Instant,
}

/// Host out of a `wss://`/`ws://` relay URL (scheme, port and path stripped).
fn relay_host(url: &str) -> &str {
    let h = url.trim_start_matches("wss://").trim_start_matches("ws://");
    let h = h.split('/').next().unwrap_or(h);
    h.split(':').next().unwrap_or(h)
}

/// Bring up wifi and serve the relay forever. Never returns.
#[allow(clippy::too_many_arguments)]
pub fn run_wifi_standalone<'d, 'b>(
    modem: Modem,
    cfg: &NetConfig,
    masters: &[LoadedMaster],
    secp: &Arc<Secp256k1<SignOnly>>,
    display: &mut Display<'d>,
    button_pin: &PinDriver<'b, Input>,
    policy_engine: &mut PolicyEngine,
    identity_caches: &mut Vec<IdentityCache>,
    nvs: &mut EspNvs<NvsDefault>,
    op_mgmt: Option<[u8; 32]>,
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

    let auth = if cfg.password.is_empty() {
        AuthMethod::None
    } else {
        AuthMethod::WPA2Personal
    };
    wifi.set_configuration(&WifiConfig::Client(ClientConfiguration {
        ssid: cfg.ssid.as_str().try_into().expect("relay: ssid too long"),
        password: cfg.password.as_str().try_into().expect("relay: pass too long"),
        auth_method: auth,
        ..Default::default()
    }))
    .expect("relay: wifi config");
    wifi.start().expect("relay: wifi start");

    let relay_url = cfg.relays.first().cloned().unwrap_or_default();
    let host = relay_host(&relay_url).to_string();

    // Restore the replay seen-set from NVS so a command captured off the relay
    // cannot be replayed across a reboot (within the SEEN_MAX window).
    let seen = load_mgmt_seen(nvs);
    if !seen.is_empty() {
        log::info!("[relay] restored {} management replay id(s) from NVS", seen.len());
    }

    let mut ctx = SignCtx {
        masters,
        secp,
        display,
        button_pin,
        policy_engine,
        identity_caches,
        nvs,
        op_mgmt,
        relay_url: relay_url.clone(),
        seen,
        display_on: true,
        last_activity: Instant::now(),
    };

    loop {
        if let Err(e) = wifi.connect().and_then(|_| wifi.wait_netif_up()) {
            log::error!("[relay] wifi connect failed: {e:?}; retry in 3s");
            FreeRtos::delay_ms(3000);
            continue;
        }
        log::info!("[relay] wifi up");

        if host.is_empty() {
            log::error!("[relay] no relay configured");
            FreeRtos::delay_ms(10_000);
            continue;
        }

        match serve_relay(&host, &mut ctx, usb) {
            Ok(()) => log::info!("[relay] connection closed; reconnecting"),
            Err(e) => log::error!("[relay] {e}; reconnecting in 3s"),
        }
        FreeRtos::delay_ms(3000);
    }
}

/// One relay session: TLS → WS handshake → subscribe → read/dispatch loop.
fn serve_relay(host: &str, ctx: &mut SignCtx, usb: &mut SerialPort<'_>) -> Result<(), String> {
    let mut tls = EspTls::new().map_err(|e| format!("tls init: {e:?}"))?;
    let mut tls_cfg = TlsConfig::new();
    tls_cfg.common_name = Some(host);
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
    tls.connect(host, TLS_PORT, &tls_cfg)
        .map_err(|e| format!("tls connect {host}: {e:?}"))?;
    log::info!("[relay] TLS connected to {host}:{TLS_PORT}");

    ws_handshake(&mut tls, host)?;
    log::info!("[relay] websocket open");

    // From here on, reads are paced by a recv timeout (handshake above was
    // blocking) so the loop wakes every RECV_TIMEOUT_MS to ping / check silence.
    // If this fails we degrade to blocking reads (still functional for single
    // round-trips, just without the WS-ping/silence layer) rather than tearing
    // the session down — TCP keepalive still guards against a dead socket.
    let recv_timeout_on = match set_recv_timeout(&mut tls, RECV_TIMEOUT_MS) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("[relay] recv-timeout unavailable ({e}); blocking reads, TCP-keepalive only");
            false
        }
    };

    // Subscribe for NIP-46 (24133) — and management (24134) when an operator is
    // configured — p-tagged to any of our master pubkeys (the master pubkey is
    // both the bunker address and the v1 management address). limit:0 → no
    // stored replay, live stream only.
    let p_list = ctx
        .masters
        .iter()
        .map(|m| format!("\"{}\"", hex_encode(&m.pubkey)))
        .collect::<Vec<_>>()
        .join(",");
    let kinds = if ctx.op_mgmt.is_some() {
        format!("{NIP46_KIND},{MGMT_KIND}")
    } else {
        format!("{NIP46_KIND}")
    };
    let req = format!(r##"["REQ","hw",{{"kinds":[{kinds}],"#p":[{p_list}],"limit":0}}]"##);
    ws_send(&mut tls, OP_TEXT, req.as_bytes())?;
    log::info!(
        "[relay] subscribed: kinds=[{kinds}] for {} master pubkey(s)",
        ctx.masters.len()
    );

    let mut rx: Vec<u8> = Vec::with_capacity(READ_BUF);
    let mut last_rx = Instant::now();
    let mut last_ping = Instant::now();
    let mut last_resub = Instant::now();
    loop {
        // Drain every complete frame already buffered before reading more.
        if let Some(msg) = try_parse(&mut rx)? {
            match msg {
                WsMsg::Text(p) => handle_relay_msg(&mut tls, &p, ctx)?,
                WsMsg::Ping(p) => ws_send(&mut tls, OP_PONG, &p)?,
                WsMsg::Close => return Ok(()),
                WsMsg::Pong | WsMsg::Other => {}
            }
            // Handling a sign_event can block ~30s on the button; treat that as
            // activity so the silence deadline doesn't trip right after.
            last_rx = Instant::now();
            continue;
        }

        // No full frame — one read. With the recv timeout this returns 0 after
        // RECV_TIMEOUT_MS of quiet; without it (degraded) it blocks until data.
        if pump(&mut tls, &mut rx)? > 0 {
            last_rx = Instant::now();
            continue;
        }

        // Idle tick (only reachable when the recv timeout is active): keep the
        // relay link warm, refresh the subscription, and bail if it's gone quiet.
        if recv_timeout_on {
            let now = Instant::now();
            if now.duration_since(last_ping) >= PING_INTERVAL {
                ws_send(&mut tls, OP_PING, b"hw")?;
                last_ping = now;
            }
            // Periodic re-REQ: self-heals a subscription the relay dropped
            // silently (connection still alive, so silence never trips).
            if now.duration_since(last_resub) >= RESUB_INTERVAL {
                ws_send(&mut tls, OP_TEXT, req.as_bytes())?;
                last_resub = now;
                log::debug!("[relay] re-subscribed (keepalive)");
            }
            if now.duration_since(last_rx) >= SILENCE_LIMIT {
                return Err("relay silent (no data/pong); reconnecting".into());
            }
            // Burn-in protection: blank the OLED after inactivity; a PRG press
            // wakes it (a request also wakes it, via process_event).
            if ctx.display_on && now.duration_since(ctx.last_activity) >= DISPLAY_TIMEOUT {
                crate::oled::sleep_display(ctx.display);
                ctx.display_on = false;
            } else if !ctx.display_on && ctx.button_pin.is_low() {
                crate::oled::wake_display(ctx.display);
                ctx.display_on = true;
                ctx.last_activity = now;
            }
        }

        // Also serve USB management while in wifi mode, so the device can be
        // managed over the cable as well as its relay. Non-blocking: a quiet
        // poll returns immediately and never delays the relay/signing path.
        poll_usb_mgmt(usb, ctx);
    }
}

/// Serve one USB management frame while the relay loop runs, so a
/// wifi-standalone signer can be managed over the cable too. Non-blocking — a
/// quiet poll returns at once. Only the management subset is accepted: anything
/// that changes the master set (which the live relay subscription is built
/// from) or streams firmware is rejected with a hint to use USB-only mode.
fn poll_usb_mgmt(usb: &mut SerialPort<'_>, ctx: &mut SignCtx) {
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
        FRAME_TYPE_PROVISION_LIST => crate::provision::handle_list(usb, ctx.masters),
        FRAME_TYPE_SESSION_AUTH => {
            crate::session::handle_auth(usb, &frame.payload, ctx.nvs, ctx.policy_engine)
        }
        FRAME_TYPE_SET_BRIDGE_SECRET => crate::session::handle_set_bridge_secret(
            usb, &frame.payload, ctx.nvs, ctx.policy_engine, ctx.display, ctx.button_pin,
        ),
        FRAME_TYPE_CONNSLOT_CREATE => {
            crate::connslot::handle_create(usb, &frame, ctx.policy_engine, ctx.masters, ctx.nvs)
        }
        FRAME_TYPE_CONNSLOT_LIST => crate::connslot::handle_list(usb, &frame, ctx.policy_engine),
        FRAME_TYPE_CONNSLOT_UPDATE => crate::connslot::handle_update(
            usb, &frame, ctx.policy_engine, ctx.nvs, ctx.display, ctx.button_pin,
        ),
        FRAME_TYPE_CONNSLOT_REVOKE => {
            crate::connslot::handle_revoke(usb, &frame, ctx.policy_engine, ctx.nvs)
        }
        FRAME_TYPE_CONNSLOT_URI => {
            crate::connslot::handle_uri(usb, &frame, ctx.policy_engine, ctx.masters)
        }
        other => {
            log::warn!("[relay] USB frame 0x{other:02x} unsupported in wifi mode");
            crate::protocol::write_frame(
                usb,
                FRAME_TYPE_NACK,
                b"wifi mode: hold PRG at boot for USB-only operations",
            );
        }
    }
}

/// Parse one inbound relay message (`["EVENT",sub,ev]` / `EOSE` / `OK` / …).
fn handle_relay_msg(tls: &mut Tls, raw: &[u8], ctx: &mut SignCtx) -> Result<(), String> {
    let v: serde_json::Value = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(_) => {
            log::warn!("[relay] non-JSON frame ({} bytes)", raw.len());
            return Ok(());
        }
    };
    let arr = match v.as_array() {
        Some(a) => a,
        None => return Ok(()),
    };
    match arr.first().and_then(|x| x.as_str()) {
        Some("EVENT") => {
            if let Some(ev_val) = arr.get(2) {
                match serde_json::from_value::<SignedEvent>(ev_val.clone()) {
                    Ok(ev) => process_event(tls, &ev, ctx)?,
                    Err(e) => log::warn!("[relay] bad EVENT json: {e}"),
                }
            }
        }
        Some("EOSE") => log::info!("[relay] EOSE — live, waiting for requests"),
        Some("OK") => log::info!("[relay] OK: {}", snippet(raw, 120)),
        Some("NOTICE") => log::warn!("[relay] NOTICE: {}", snippet(raw, 160)),
        // The relay closed our subscription (limit, error, policy). The WS stays
        // open so silence-detection won't fire — propagate so we reconnect and
        // re-subscribe cleanly rather than sit with a dead subscription.
        Some("CLOSED") => {
            log::warn!("[relay] CLOSED: {}; reconnecting", snippet(raw, 160));
            return Err("relay closed our subscription".into());
        }
        _ => {}
    }
    Ok(())
}

/// Route an inbound EVENT by kind. Errors specific to one request are logged
/// and swallowed (return `Ok`) so a single bad request never drops the session;
/// only transport errors propagate to trigger a reconnect.
fn process_event(tls: &mut Tls, ev: &SignedEvent, ctx: &mut SignCtx) -> Result<(), String> {
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

    // Which of our masters is this addressed to? (`p` tag → master pubkey).
    let master_idx = ev
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == "p")
        .find_map(|t| {
            let pk: [u8; 32] = hex_decode(&t[1]).ok()?.try_into().ok()?;
            masters::find_by_pubkey(ctx.masters, &pk)
        });
    let master_idx = match master_idx {
        Some(i) => i,
        None => {
            log::warn!("[relay] EVENT not addressed to a known master; ignoring");
            return Ok(());
        }
    };

    if ev.kind == MGMT_KIND {
        handle_mgmt_event(tls, ev, ctx, master_idx)
    } else {
        handle_nip46_event(tls, ev, ctx, master_idx)
    }
}

/// NIP-46 signing path (kind 24133): decrypt → `handle_request` → re-encrypt →
/// sign + publish. Mirrors the USB `transport::handle_encrypted_request`.
fn handle_nip46_event(
    tls: &mut Tls,
    ev: &SignedEvent,
    ctx: &mut SignCtx,
    master_idx: usize,
) -> Result<(), String> {
    // `masters` is a shared ref (Copy), so `master` is independent of the
    // exclusive borrows of the other ctx fields used below.
    let master = &ctx.masters[master_idx];

    // The event author is the remote client.
    let client_pubkey: [u8; 32] = match hex_decode(&ev.pubkey).ok().and_then(|v| v.try_into().ok()) {
        Some(pk) => pk,
        None => {
            log::warn!("[relay] EVENT has invalid author pubkey; ignoring");
            return Ok(());
        }
    };

    let conversation_key = match nip44::get_conversation_key(&master.secret, &client_pubkey) {
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
        "[relay] decrypted request ({} bytes) from {}… for {}",
        plaintext.len(),
        &ev.pubkey[..ev.pubkey.len().min(8)],
        master.label
    );

    let inner = Frame {
        frame_type: FRAME_TYPE_NIP46_REQUEST,
        payload: plaintext.into_bytes(),
    };

    // Dispatch — same handler as the USB path. sign_event is ButtonRequired
    // until the slot is physically button-upgraded; auto-approve covers the
    // safe methods and post-upgrade signing.
    let response_json = crate::nip46_handler::handle_request(
        &inner,
        &master.secret,
        &master.label,
        master.mode,
        master.slot,
        ctx.secp,
        ctx.display,
        ctx.button_pin,
        ctx.policy_engine,
        ctx.identity_caches,
        Some(&client_pubkey),
    );
    ctx.policy_engine.persist_slots(ctx.nvs, master.slot);

    sign_and_publish(
        tls,
        ctx.secp,
        master,
        &conversation_key,
        &ev.pubkey,
        NIP46_KIND,
        ev.created_at,
        &response_json,
    )
}

/// Load the persisted management replay seen-set from NVS. Absent/corrupt ⇒
/// empty (fail open to an empty set — replay protection rebuilds as commands
/// arrive; it never blocks a legitimate fresh command).
fn load_mgmt_seen(nvs: &mut EspNvs<NvsDefault>) -> Vec<String> {
    let mut buf = [0u8; 8192];
    match nvs.get_blob(MGMT_SEEN_KEY, &mut buf) {
        Ok(Some(data)) => serde_json::from_slice::<Vec<String>>(data).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Persist the management replay seen-set to NVS after accepting a command.
/// Management is rare (config changes), so the write rate is far below any NVS
/// wear concern — unlike per-signing state, this is safe to write each time.
fn persist_mgmt_seen(nvs: &mut EspNvs<NvsDefault>, seen: &[String]) {
    match serde_json::to_string(seen) {
        Ok(json) => {
            if let Err(e) = nvs.set_blob(MGMT_SEEN_KEY, json.as_bytes()) {
                log::error!("[relay] persist mgmt seen-set: {e:?}");
            }
        }
        Err(e) => log::error!("[relay] serialise mgmt seen-set: {e}"),
    }
}

/// Relay-management path (kind 24134): authenticate the author against the
/// baked operator key, decrypt, replay-guard, dispatch, then sign + publish.
fn handle_mgmt_event(
    tls: &mut Tls,
    ev: &SignedEvent,
    ctx: &mut SignCtx,
    master_idx: usize,
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
    let id = req.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Replay guard. The id checked here is the *inner* request id — it lives
    // inside the NIP-44 ciphertext, so it cannot be forged or altered without
    // the operator secret. The seen-set is bounded and persisted to NVS, so a
    // command captured off the relay can't be replayed after a reboot either.
    // (No created_at/NIP-40 window: the device has no trusted wall-clock, and
    // the persisted inner-id set already closes the replay path.)
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
    persist_mgmt_seen(ctx.nvs, &ctx.seen);
    log::info!("[relay] mgmt request: method={method} id={id} (operator authenticated)");

    let response_json = match dispatch_mgmt(&method, &req, ctx, master_idx) {
        Ok(result) => serde_json::json!({ "id": id, "result": result }).to_string(),
        Err(e) => serde_json::json!({ "id": id, "error": e }).to_string(),
    };

    let master = &ctx.masters[master_idx];
    sign_and_publish(
        tls,
        ctx.secp,
        master,
        &conversation_key,
        &ev.pubkey,
        MGMT_KIND,
        ev.created_at,
        &response_json,
    )
}

/// Execute one authenticated management method. Maps onto the same
/// connslot/policy operations as the USB path. `create_client` mirrors
/// `CONNSLOT_CREATE`; trust-root/seed changes are deliberately NOT exposed.
fn dispatch_mgmt(
    method: &str,
    req: &serde_json::Value,
    ctx: &mut SignCtx,
    master_idx: usize,
) -> Result<serde_json::Value, String> {
    // Extract owned master facts before borrowing policy_engine mutably.
    let master_slot = ctx.masters[master_idx].slot;
    let master_hex = hex_encode(&ctx.masters[master_idx].pubkey);

    match method {
        "create_client" => {
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
            let auto_sign = req
                .pointer("/params/approve_signing")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            match ctx.policy_engine.create_slot(master_slot, label.clone(), secret_hex.clone()) {
                Some(index) => {
                    if auto_sign {
                        ctx.policy_engine.upgrade_to_signing(master_slot, index);
                    }
                    ctx.policy_engine.persist_slots(ctx.nvs, master_slot);
                    let bunker_uri =
                        format!("bunker://{master_hex}?relay={}&secret={secret_hex}", ctx.relay_url);
                    log::info!(
                        "[relay] mgmt: created client slot {index} ({label}){}",
                        if auto_sign { " [signing pre-approved]" } else { "" }
                    );
                    let note = if auto_sign {
                        "signing pre-approved by operator — client auto-signs once it connects with the secret"
                    } else {
                        "first sign_event needs approval — call approve_signing or one physical PRG press"
                    };
                    Ok(serde_json::json!({
                        "slot_index": index,
                        "label": label,
                        "secret": secret_hex,
                        "npub_hex": master_hex,
                        "bunker_uri": bunker_uri,
                        "signing_approved": auto_sign,
                        "note": note,
                    }))
                }
                None => Err("create_slot failed (slot table full?)".into()),
            }
        }

        "approve_signing" => {
            // Operator grants a slot signing authority — substitutes op_mgmt's
            // cryptographic authority for the physical button on the wifi tier
            // (see relay-mediated-management design). Destructive ops stay USB.
            let slot_index = req
                .pointer("/params/slot_index")
                .and_then(|v| v.as_u64())
                .ok_or("approve_signing requires params.slot_index")? as u8;
            if ctx.policy_engine.upgrade_to_signing(master_slot, slot_index) {
                ctx.policy_engine.persist_slots(ctx.nvs, master_slot);
                log::info!("[relay] mgmt: slot {slot_index} upgraded to signing (operator)");
                Ok(serde_json::json!({
                    "slot_index": slot_index,
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
                .map(|s| {
                    serde_json::json!({
                        "slot_index": s.slot_index,
                        "label": s.label,
                        "auto_approve": s.auto_approve,
                        "signing_approved": s.signing_approved,
                        "current_pubkey": s.current_pubkey,
                        "allowed_kinds": s.allowed_kinds,
                        "allowed_methods": s.allowed_methods,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "clients": clients }))
        }

        // Revoke a client slot (operator-authorised — same authority as create).
        "revoke_client" => {
            let slot_index = req
                .pointer("/params/slot_index")
                .and_then(|v| v.as_u64())
                .ok_or("revoke_client requires params.slot_index")? as u8;
            if ctx.policy_engine.revoke_slot(master_slot, slot_index) {
                ctx.policy_engine.persist_slots(ctx.nvs, master_slot);
                log::info!("[relay] mgmt: revoked client slot {slot_index} (operator)");
                Ok(serde_json::json!({ "slot_index": slot_index, "revoked": true }))
            } else {
                Err(format!("no such slot: {slot_index}"))
            }
        }

        // Update a client slot's label / kind restrictions / auto-approve.
        // update_slot enforces the sign_event security filter internally, so the
        // operator cannot grant signing this way (only the button / approve_signing).
        "update_client" => {
            let slot_index = req
                .pointer("/params/slot_index")
                .and_then(|v| v.as_u64())
                .ok_or("update_client requires params.slot_index")? as u8;
            let label = req
                .pointer("/params/label")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let methods = req
                .pointer("/params/allowed_methods")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect());
            let kinds = req
                .pointer("/params/allowed_kinds")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_u64()).collect());
            let auto = req.pointer("/params/auto_approve").and_then(|v| v.as_bool());
            if ctx
                .policy_engine
                .update_slot(master_slot, slot_index, label, methods, kinds, auto)
            {
                ctx.policy_engine.persist_slots(ctx.nvs, master_slot);
                log::info!("[relay] mgmt: updated client slot {slot_index} (operator)");
                Ok(serde_json::json!({ "slot_index": slot_index, "updated": true }))
            } else {
                Err(format!("no such slot: {slot_index}"))
            }
        }

        "get_status" => Ok(serde_json::json!({
            "master_count": ctx.masters.len(),
            "master_npub_hex": master_hex,
            "mode": "wifi-standalone",
            "relay": ctx.relay_url,
            "slots": ctx.policy_engine.list_slots(master_slot).len(),
        })),

        other => Err(format!("unknown method: {other}")),
    }
}

/// Re-encrypt `response_json` to `recipient_hex`, build + sign a `kind` envelope
/// authored by the master, and publish it. The author pubkey is recomputed from
/// the secret (never trusted from input). A transport failure propagates.
#[allow(clippy::too_many_arguments)]
fn sign_and_publish(
    tls: &mut Tls,
    secp: &Arc<Secp256k1<SignOnly>>,
    master: &LoadedMaster,
    conversation_key: &[u8; 32],
    recipient_hex: &str,
    kind: u64,
    created_at: u64,
    response_json: &str,
) -> Result<(), String> {
    let nonce = random_nonce_32();
    let ciphertext = nip44::encrypt(conversation_key, response_json, &nonce)
        .map_err(|e| format!("encrypt: {e}"))?;

    let keypair = Keypair::from_seckey_slice(secp, &master.secret)
        .map_err(|_| "invalid master secret".to_string())?;
    let (xonly, _) = keypair.x_only_public_key();

    let unsigned = UnsignedEvent {
        pubkey: hex_encode(&xonly.serialize()),
        created_at,
        kind,
        tags: vec![vec!["p".to_string(), recipient_hex.to_string()]],
        content: ciphertext,
    };
    let event_id = nip46::compute_event_id(&unsigned);
    let sig = sign::sign_hash(secp, &master.secret, &event_id).map_err(|e| format!("sign: {e}"))?;

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

    ws_send(tls, OP_TEXT, format!(r#"["EVENT",{event_json}]"#).as_bytes())?;
    log::info!("[relay] published kind:{kind} response ({} bytes)", event_json.len());
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

fn ws_handshake(tls: &mut Tls, host: &str) -> Result<(), String> {
    // A fixed Sec-WebSocket-Key is fine for a client that doesn't verify the
    // Accept header — security is TLS + NIP-44, not the WS nonce. (RFC example.)
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    tls.write_all(req.as_bytes())
        .map_err(|e| format!("ws req: {e:?}"))?;

    let mut buf = [0u8; 1024];
    let mut n = 0usize;
    loop {
        let r = tls
            .read(&mut buf[n..])
            .map_err(|e| format!("ws resp: {e:?}"))?;
        if r == 0 {
            return Err("ws handshake: eof".into());
        }
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
        return Err(format!("ws handshake not 101: {}", &resp[..resp.len().min(64)]));
    }
    Ok(())
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

/// Apply a receive timeout (`SO_RCVTIMEO`) to the live TLS socket so the read
/// loop wakes periodically without busy-spinning. Affects recv only — writes
/// stay blocking, so `ws_send`/`write_all` are unchanged.
fn set_recv_timeout(tls: &mut Tls, ms: i64) -> Result<(), String> {
    use esp_idf_svc::sys;
    let mut fd: core::ffi::c_int = -1;
    let r = unsafe { sys::esp_tls_get_conn_sockfd(tls.context_handle() as *mut _, &mut fd) };
    if r != sys::ESP_OK || fd < 0 {
        return Err(format!("get sockfd failed (err {r}, fd {fd})"));
    }
    let tv = sys::timeval {
        tv_sec: (ms / 1000) as _,
        tv_usec: ((ms % 1000) * 1000) as _,
    };
    let rc = unsafe {
        sys::lwip_setsockopt(
            fd,
            sys::SOL_SOCKET as i32,
            sys::SO_RCVTIMEO as i32,
            &tv as *const _ as *const core::ffi::c_void,
            core::mem::size_of::<sys::timeval>() as sys::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!("setsockopt SO_RCVTIMEO failed (rc {rc})"));
    }
    Ok(())
}

fn esp_random() -> u32 {
    unsafe { esp_idf_svc::sys::esp_random() }
}
