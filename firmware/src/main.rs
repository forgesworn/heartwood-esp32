// firmware/src/main.rs
//
// Heartwood ESP32 -- Phase 4 boot flow (multi-master).
//
// Boot sequence:
//   1. Initialise peripherals (LED, Vext, OLED, button, serial port, NVS)
//   2. Load all masters from NVS via masters::load_all
//   3. If no masters: show "No masters -- provision me", wait for provision frame
//   4. Create secp256k1 context (shared Arc)
//   5. Show boot screen (single master -> npub, multiple -> count)
//   6. Create PolicyEngine (empty until bridge authenticates)
//   7. Enter frame dispatch loop
//
// Board selection: exactly one of the `heltec-v3` or `heltec-v4` cargo
// features must be active. The Heltec V4 routes USB-C to the ESP32-S3 native
// USB pins (GPIO19/20) and we use the USB-Serial-JTAG peripheral. The Heltec
// V3 routes USB-C through a CP2102 bridge chip to UART0 (GPIO43 TX /
// GPIO44 RX). Both boards expose the same frame protocol through the
// `serial::SerialPort` wrapper.

#[cfg(not(any(feature = "heltec-v3", feature = "heltec-v4", feature = "tdisplay", feature = "c6")))]
compile_error!(
    "heartwood-esp32 requires exactly one board feature: `heltec-v3`, \
     `heltec-v4`, `tdisplay`, or `c6`. Did you build with `--no-default-features` \
     and forget to pick a board?"
);

#[cfg(any(
    all(feature = "heltec-v3", feature = "heltec-v4"),
    all(feature = "heltec-v3", feature = "tdisplay"),
    all(feature = "heltec-v3", feature = "c6"),
    all(feature = "heltec-v4", feature = "tdisplay"),
    all(feature = "heltec-v4", feature = "c6"),
    all(feature = "tdisplay", feature = "c6"),
))]
compile_error!(
    "board features `heltec-v3`, `heltec-v4`, `tdisplay` and `c6` are mutually \
     exclusive -- enable exactly one."
);

mod approval;
mod backup;
mod board;
mod button;
mod confirm;
mod connslot;
mod entropy;
mod entropy_game;
mod identity_cache;
mod identity_meta;
mod layout;
mod log_quiet;
mod crash_crumb;
mod management_challenge;
mod palette;
mod masters;
mod nip46_handler;
mod notes;
mod personas;
mod nvs;
mod nvs_stats;
mod cat_sprites;
mod oled;
mod ota;
mod pin;
mod persistent_wipe;
mod policy;
mod protocol;
mod provision;
mod release_key;
mod serial;
mod net_config_store;
mod boot_config;
#[cfg(feature = "st7789")]
mod st7789;
#[cfg(feature = "c6")]
mod jd9853;
mod relay;
mod session;
mod sign;
mod transport;
mod wdt;
mod wifi_scan;

use esp_idf_hal::peripherals::Peripherals;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long the display stays on after the last activity before sleeping.
const DISPLAY_TIMEOUT: Duration = Duration::from_secs(30);

/// Polling interval for the idle loop — short enough for responsive button
/// wake, long enough not to busy-spin the CPU.
const IDLE_POLL_MS: u32 = 50;

use heartwood_common::encoding::encode_npub;
use heartwood_common::types::{
    FRAME_TYPE_ACK, FRAME_TYPE_ENCRYPTED_REQUEST, FRAME_TYPE_FACTORY_RESET, FRAME_TYPE_NACK,
    FRAME_TYPE_SIGN_ENVELOPE,
    FRAME_TYPE_NIP46_REQUEST, FRAME_TYPE_NIP46_RESPONSE, FRAME_TYPE_OTA_BEGIN,
    FRAME_TYPE_OTA_CHUNK, FRAME_TYPE_OTA_FINISH, FRAME_TYPE_PIN_UNLOCK,
    FRAME_TYPE_PROVISION, FRAME_TYPE_PROVISION_LIST, FRAME_TYPE_PROVISION_REMOVE,
    FRAME_TYPE_DERIVE_IDENTITY,
    FRAME_TYPE_GENERATE_IDENTITY, FRAME_TYPE_RESTORE_IDENTITY,
    FRAME_TYPE_FIRMWARE_INFO, FRAME_TYPE_FIRMWARE_INFO_RESPONSE,
    FRAME_TYPE_SESSION_ACK, FRAME_TYPE_SESSION_AUTH, FRAME_TYPE_SET_BRIDGE_SECRET, FRAME_TYPE_SET_PIN,
    FRAME_TYPE_VAULT_SET, FRAME_TYPE_VAULT_UNLOCK, FRAME_TYPE_NOTE_CMD,
    FRAME_TYPE_CONNSLOT_CREATE, FRAME_TYPE_CONNSLOT_LIST, FRAME_TYPE_CONNSLOT_UPDATE,
    FRAME_TYPE_CONNSLOT_REVOKE, FRAME_TYPE_CONNSLOT_URI,
    FRAME_TYPE_BACKUP_EXPORT_REQUEST, FRAME_TYPE_BACKUP_IMPORT_REQUEST,
    FRAME_TYPE_SET_NET_CONFIG, FRAME_TYPE_SET_IDENTITY_META,
    FRAME_TYPE_GET_NET_CONFIG, FRAME_TYPE_PATCH_NET_CONFIG, FRAME_TYPE_SET_OPERATOR,
    FRAME_TYPE_WIFI_SCAN_REQUEST,
};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use secp256k1::Secp256k1;

/// JSON for a FIRMWARE_INFO_RESPONSE — the running firmware version, board,
/// uptime, why the chip last reset, the signing size ceiling, and live heap.
/// Read-only and secret-free, so it is answered over USB in any mode. The reset
/// reason lets a manager (and an alpha tester) tell a deliberate restart from a
/// crash.
///
/// `max_sign_bytes` is the structural ceiling for this board, and
/// `max_sign_bytes_object` the higher one a client earns by sending `params[0]`
/// as a JSON object AND asking for `sign_event_compact`. Both are advertised
/// because the difference is the client's to claim: it is the cost of the two
/// escape/echo copies, not of the hardware, and a manager that showed only the
/// first would understate what the signer can do. `free_heap` and
/// `largest_block` are the runtime half of the same question: a request inside
/// the structural limit can still be refused when the heap is fragmented, and
/// `relay::response_transportable` needs one contiguous block a little over the
/// base64-expanded response size. Exposing both means a size sweep can record
/// the heap curve instead of only pass/fail, and a manager can show why a
/// request that worked yesterday is refused today. Neither is a secret: they
/// are allocator statistics, not contents.
pub fn firmware_info_json() -> String {
    let crash = crash_context()
        .map(|op| format!(",\"crashed_during\":{}", json_string(op)))
        .unwrap_or_default();
    let free_heap = unsafe { esp_idf_svc::sys::esp_get_free_heap_size() };
    let largest_block = unsafe {
        esp_idf_svc::sys::heap_caps_get_largest_free_block(esp_idf_svc::sys::MALLOC_CAP_8BIT)
    };
    // Identity & app storage share one NVS entry table; the manager's storage
    // gauge is driven from these. Omitted (not zeroed) when the API fails so
    // "unknown" stays distinguishable from "empty".
    let nvs_stats = crate::nvs_stats::read()
        .map(|s| {
            format!(
                ",\"nvs_used_entries\":{},\"nvs_free_entries\":{},\
                 \"nvs_total_entries\":{},\"max_personas\":{}",
                s.used_entries,
                s.free_entries,
                s.total_entries,
                personas::MAX_PERSONAS,
            )
        })
        .unwrap_or_default();
    format!(
        "{{\"version\":\"{}\",\"board\":\"{}\",\"uptime_s\":{},\"last_reset\":\"{}\",\
         \"max_sign_bytes\":{},\"max_sign_bytes_object\":{},\
         \"free_heap\":{},\"largest_block\":{}{}{}}}",
        env!("CARGO_PKG_VERSION"),
        board::BOARD,
        uptime_s(),
        reset_reason_str(),
        board::MAX_SIGN_BYTES,
        board::MAX_SIGN_BYTES_OBJECT,
        free_heap,
        largest_block,
        crash,
        nvs_stats,
    )
}

/// Minimal JSON string escaping for the small, non-secret breadcrumb labels.
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Seconds since boot (esp_timer starts at reset).
pub fn uptime_s() -> u64 {
    (unsafe { esp_idf_svc::sys::esp_timer_get_time() } / 1_000_000) as u64
}

/// One page of the idle info carousel in the USB-bridged loop. Page 0 is the
/// boot status card; short presses cycle the network and device pages. The
/// radio is off by definition here — the WiFi tier runs its own loop — so the
/// network page reports the dormant stored network, not a live link.
pub fn draw_idle_page(
    page: u8,
    display: &mut oled::Display<'_>,
    master_count: u8,
    nvs: &mut esp_idf_svc::nvs::EspNvs<esp_idf_svc::nvs::NvsDefault>,
) {
    match page {
        1 => {
            let cfg = net_config_store::read_net_config(nvs)
                .and_then(|raw| heartwood_common::net_config::parse_net_config(&raw).ok());
            let ssid = cfg
                .as_ref()
                .filter(|c| !c.ssid.is_empty())
                .map(|c| c.ssid.as_str());
            oled::show_info_network(display, "USB bridge", ssid, "radio off");
        }
        2 => oled::show_info_device(
            display,
            env!("CARGO_PKG_VERSION"),
            board::BOARD,
            uptime_s(),
        ),
        _ => oled::show_boot(display, master_count),
    }
}

/// Human-attributable cause of the last chip reset. "software-restart" covers
/// the deliberate reboots (identity changes, network activation, removals);
/// panic/watchdog/brownout are the crashes worth investigating.
pub fn reset_reason_str() -> &'static str {
    use esp_idf_svc::sys::*;
    let reason = unsafe { esp_reset_reason() };
    match reason {
        r if r == esp_reset_reason_t_ESP_RST_POWERON => "power-on",
        r if r == esp_reset_reason_t_ESP_RST_EXT => "external-reset",
        r if r == esp_reset_reason_t_ESP_RST_SW => "software-restart",
        r if r == esp_reset_reason_t_ESP_RST_PANIC => "panic",
        r if r == esp_reset_reason_t_ESP_RST_INT_WDT => "interrupt-watchdog",
        r if r == esp_reset_reason_t_ESP_RST_TASK_WDT => "task-watchdog",
        r if r == esp_reset_reason_t_ESP_RST_WDT => "watchdog",
        r if r == esp_reset_reason_t_ESP_RST_DEEPSLEEP => "deep-sleep-wake",
        r if r == esp_reset_reason_t_ESP_RST_BROWNOUT => "brownout",
        // ESP-IDF 5.x added these two. Without them a native-USB board (the V4
        // and the C6 both drive USB-Serial-JTAG) reports "unknown" for the
        // single most likely reset it will ever see, which is precisely the
        // case this field exists to name. Observed on a V4 during the
        // 2026-08-06 size sweep, where "unknown" left a host-triggered reset
        // indistinguishable from a firmware crash.
        r if r == esp_reset_reason_t_ESP_RST_USB => "usb-peripheral-reset",
        r if r == esp_reset_reason_t_ESP_RST_JTAG => "jtag-reset",
        _ => "unknown",
    }
}

/// Whether the last reset was a crash (not a planned restart or power event).
fn reset_was_crash() -> bool {
    matches!(
        reset_reason_str(),
        "panic" | "interrupt-watchdog" | "task-watchdog" | "watchdog" | "brownout"
    )
}

use std::sync::OnceLock;

/// The operation in flight when the signer last crashed, resolved once at boot
/// from the RTC breadcrumb. `Some` only after a crash reset that left a valid
/// crumb; reported in telemetry so the owner sees "crashed on: <op>".
static CRASH_CONTEXT: OnceLock<Option<String>> = OnceLock::new();

/// Resolve the crash context once, at boot. If the last reset was a crash and
/// a breadcrumb survived, keep it; otherwise clear any stale crumb so a later
/// clean restart never inherits it. One planned restart is also attributed:
/// the relay-health watchdog reboots deliberately (deaf signer, heap rot) and
/// records why — its crumb rides the software reset so get_status can answer
/// "why did my signer restart" without a serial console.
fn init_crash_context() {
    let ctx = if reset_was_crash() {
        crash_crumb::take()
    } else if reset_reason_str() == "software-restart" {
        crash_crumb::take().filter(|op| op.starts_with("relay watchdog"))
    } else {
        crash_crumb::clear();
        None
    };
    if let Some(op) = &ctx {
        if op.starts_with("relay watchdog") {
            log::warn!("Planned recovery restart: {op}");
        } else {
            log::error!("Recovered from a crash during: {op}");
        }
    }
    let _ = CRASH_CONTEXT.set(ctx);
}

/// The operation the signer was doing when it last crashed, if known.
pub fn crash_context() -> Option<&'static str> {
    CRASH_CONTEXT.get().and_then(|o| o.as_deref())
}

/// Fill `buf` with hardware-RNG bytes, guaranteeing a true entropy source for
/// the draw.
///
/// `esp_random()`/`esp_fill_random()` are only a true RNG while a hardware
/// entropy source is live — the RF radio (Wi-Fi/BT) or the SAR-ADC noise
/// source. Key material is generated at provision time, *before* the Wi-Fi
/// stack starts, so the radio is still off; without this the master seed and
/// connection-slot secrets would come from output ESP-IDF classifies as merely
/// pseudo-random. `bootloader_random_enable()` switches the ADC noise source on
/// for the draw; we disable it again so it can't clash with a later ADC/Wi-Fi
/// user. Safe here because nothing else touches the SAR ADC during provisioning.
pub fn fill_random_strong(buf: &mut [u8]) {
    unsafe {
        esp_idf_svc::sys::bootloader_random_enable();
        esp_idf_svc::sys::esp_fill_random(buf.as_mut_ptr() as *mut core::ffi::c_void, buf.len());
        esp_idf_svc::sys::bootloader_random_disable();
    }
}

/// Whether the RF entropy source is live. Set once the WiFi driver is
/// started (wifi-standalone mode); stays false in the radio-off USB tier.
static RADIO_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Mark the RF entropy source live. Called from the relay task right after
/// `wifi.start()` — from then on `esp_fill_random` is a true RNG.
pub fn set_radio_active() {
    RADIO_ACTIVE.store(true, Ordering::Relaxed);
}

/// Fill `buf` with cryptographically secure random bytes, guaranteeing a true
/// entropy source in either operating tier.
///
/// With the radio up, plain `esp_fill_random` is hardware TRNG output. In the
/// radio-off USB tier it would degrade to a boot-seeded PRNG, so we route
/// through `fill_random_strong` to draw from the SAR-ADC noise source instead.
/// (The ADC bracket is safe there: radios are disabled and nothing else on
/// the board touches the SAR ADC.) Every security-relevant draw — nonces,
/// IVs, salts, secrets, aux_rand — should use this, not raw `esp_fill_random`.
pub fn fill_random(buf: &mut [u8]) {
    if RADIO_ACTIVE.load(Ordering::Relaxed) {
        unsafe {
            esp_idf_svc::sys::esp_fill_random(buf.as_mut_ptr() as *mut core::ffi::c_void, buf.len());
        }
    } else {
        fill_random_strong(buf);
    }
}

/// A malformed/unrecoverable removal journal blocks every signing path, but it
/// must not make the device permanently unserviceable. Offer a deliberate
/// physical hold-to-wipe escape; never erase automatically on recovery error.
fn offer_removal_recovery_wipe(
    display: &mut oled::Display<'_>,
    buttons: &crate::button::Buttons<'_>,
) {
    let approval = approval::run_approval_loop(display, buttons, 30, |d, remaining| {
        oled::show_sign_request(d, "RECOVERY", 0, "WIPE ALL DATA?", remaining);
    });
    if !matches!(approval, approval::ApprovalResult::Approved) {
        return;
    }

    oled::show_error(display, "Erasing...");
    loop {
        crate::wdt::feed();
        match persistent_wipe::erase_all() {
            Ok(()) => {
                oled::show_error(display, "Reset complete\nRebooting...");
                esp_idf_hal::delay::FreeRtos::delay_ms(1000);
                unsafe { esp_idf_svc::sys::esp_restart() }
            }
            Err(e) => {
                log::error!("Physical removal-recovery wipe failed: {e}");
                oled::show_error(display, "ERASE FAILED\nRetrying...");
                esp_idf_hal::delay::FreeRtos::delay_ms(2000);
            }
        }
    }
}

fn main() {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("Heartwood ESP32 — Phase 4 (multi-master)");
    log::info!("Last reset: {}", reset_reason_str());
    init_crash_context();
    wdt::init();

    let peripherals = Peripherals::take().expect("failed to take peripherals");

    // --- Board hardware bring-up ---
    // All board-specific pin/peripheral wiring (LED, display power, display,
    // host transport, button(s)) lives in `board::bringup`; everything below
    // is board-agnostic. Housekeeping pins (LED, OLED power) are kept driven
    // inside `bringup`, so only handles the firmware actively uses come back.
    let board::Hw {
        mut display,
        serial: mut usb,
        // A approves/selects; B (where the board has one, e.g. the T-Display)
        // cancels/backs and drives the two-button restore picker.
        buttons,
        modem,
    } = board::bringup(peripherals);
    log::info!("Board bring-up complete ({})", board::BOARD);

    // --- Boot animation ---
    oled::show_boot_animation(&mut display);

    // --- NVS init ---
    let nvs_partition = EspDefaultNvsPartition::take().expect("failed to take NVS partition");
    let mut nvs =
        EspNvs::new(nvs_partition.clone(), "heartwood", true).expect("NVS namespace init failed");

    // Bearer-note locker (own namespace; never fatal — a broken locker must
    // not take the signer down, it just reports unavailable and refuses).
    notes::init(nvs_partition);

    // --- RNG self-test ---
    // Prove the hardware entropy source is actually in the call path (the
    // Coldcard July 2026 failure mode: correct TRNG code, silently unused).
    // On failure the device keeps serving existing keys but refuses all fresh
    // key/secret generation — fail closed where new entropy matters.
    entropy::boot_self_test(&mut nvs);

    // Apply the persisted log verbosity before the chatty phases start. Quiet
    // mode calms boards whose activity LED is wired to the log UART.
    log_quiet::apply(log_quiet::read(&nvs));

    // A master removal spans several NVS keys. Resume its durable journal
    // before loading any seed, persona, policy, or display metadata so a power
    // cut can never expose a half-shifted authority map to a signing path.
    loop {
        match masters::resume_pending_removal(&mut nvs) {
            Ok(()) => break,
            Err(e) => {
                log::error!("Master-removal recovery failed: {e}");
                // No seed/policy/persona has loaded yet. Remain fail-closed,
                // retry recovery, and give the owner a physical 2-second PRG
                // hold escape to the same complete factory wipe.
                offer_removal_recovery_wipe(&mut display, &buttons);
            }
        }
    }

    // The one-time persona-registry layout migration (five keys per entry →
    // packed chunks) and any interrupted persona removal resume here, after
    // the master-removal recovery (whose journal may predate the packed
    // layout) and before anything loads personas. Same fail-closed retry
    // model as above.
    loop {
        match personas::migrate_if_needed(&mut nvs)
            .and_then(|()| personas::resume_pending_removal(&mut nvs))
        {
            Ok(()) => break,
            Err(e) => {
                log::error!("Persona-registry recovery failed: {e}");
                offer_removal_recovery_wipe(&mut display, &buttons);
            }
        }
    }

    // --- Load masters ---
    let mut loaded_masters = masters::load_all(&nvs);
    log::info!("Loaded {} master(s) from NVS", loaded_masters.len());

    // --- Load personas (per-identity registry; signing keys re-derived on use) ---
    let mut loaded_personas = personas::load_all(&nvs);
    log::info!("Loaded {} persona(s) from NVS", loaded_personas.len());

    // --- Flash-time config seed (web flasher — Raspberry Pi Imager model) ---
    // Seed NVS from the `config` partition whenever the flashed blob differs from
    // what we last seeded (CRC changed) — so re-flashing is authoritative (e.g.
    // adding an operator key). USB `SET_NET_CONFIG` changes NVS but not the
    // partition, so its CRC is unchanged and those edits persist across reboots.
    // Missing/blank/invalid partition → no-op.
    if let Some((json, crc)) = boot_config::read_flash_config() {
        if net_config_store::read_seeded_crc(&nvs) != Some(crc) {
            if heartwood_common::net_config::parse_net_config(&json).is_ok() {
                match net_config_store::bump_network_revision(&mut nvs)
                    .and_then(|_| net_config_store::cancel_trial(&mut nvs))
                    .and_then(|_| net_config_store::write_net_config(&mut nvs, &json))
                {
                    Ok(()) => {
                        net_config_store::write_seeded_crc(&mut nvs, crc);
                        log::info!("Seeded net config from `config` partition (crc {crc:08x})");
                    }
                    Err(e) => log::warn!("Flash-config seed failed: {e}"),
                }
            } else {
                log::warn!("Flash-time config partition holds invalid NetConfig JSON — ignoring");
            }
        }
    }

    // --- Boot-time network config read ---
    let boot_net_cfg = net_config_store::prepare_boot_net_config(&mut nvs);
    let trial_transaction_id = boot_net_cfg.trial_transaction_id;
    let mut net_cfg = boot_net_cfg.config;
    if let Some(cfg) = &net_cfg {
        log::info!(
            "net config present: mode={:?}, {} relay(s)",
            cfg.device_mode(),
            cfg.relays.len()
        );
    }

    // If no masters are provisioned, wait for a provision frame before continuing.
    if loaded_masters.is_empty() {
        log::info!("No masters provisioned — entering provision-wait mode");
        oled::show_provision_wait(&mut display);

        loop {
            // A fully blocking read starves the task watchdog on an idle
            // serial line — an untouched unprovisioned board rebooted every
            // watchdog period and wiped whatever card was on screen (#65).
            // Poll with a bounded wait and feed between windows instead.
            let frame = loop {
                wdt::feed();
                if let Some(frame) = protocol::try_read_frame(&mut usb, 1000) {
                    break frame;
                }
            };
            match frame.frame_type {
                FRAME_TYPE_FIRMWARE_INFO => {
                    protocol::write_frame(
                        &mut usb,
                        FRAME_TYPE_FIRMWARE_INFO_RESPONSE,
                        firmware_info_json().as_bytes(),
                    );
                }
                FRAME_TYPE_PROVISION | FRAME_TYPE_GENERATE_IDENTITY | FRAME_TYPE_RESTORE_IDENTITY => {
                    // Show the "working" screen before the (one-time, slowish)
                    // secp context build so generation feedback covers it too.
                    if frame.frame_type == FRAME_TYPE_GENERATE_IDENTITY {
                        oled::show_generating(&mut display);
                    }
                    // secp context not yet created — build a temporary one for the
                    // provision/generate/restore handler to validate/derive the key.
                    let secp = Arc::new(Secp256k1::signing_only());
                    let provisioned = match frame.frame_type {
                        FRAME_TYPE_GENERATE_IDENTITY => {
                            provision::handle_generate(&mut usb, &frame, &mut nvs, &secp, &mut display, &buttons)
                        }
                        FRAME_TYPE_RESTORE_IDENTITY => {
                            provision::handle_restore(&mut usb, &frame, &mut nvs, &secp, &mut display, &buttons)
                        }
                        _ => provision::handle_add(&mut usb, &frame, &mut nvs, &secp, &mut display),
                    };
                    if let Some(master) = provisioned {
                        loaded_masters.push(master);
                        log::info!("First master provisioned — continuing boot");
                        // A wifi-configured device leaves the USB path the moment
                        // it has a master and runs the relay loop instead. Reboot
                        // cleanly so the wifi/relay stack initialises from a fresh
                        // boot rather than a half-set-up transition — this removes
                        // the manual reset the operator otherwise had to do, and
                        // the "USB stopped responding" confusion. The provision
                        // ACK was already sent by handle_add; delay briefly so it
                        // flushes to the host before we restart.
                        let wifi_armed = net_cfg
                            .as_ref()
                            .map(|c| {
                                c.device_mode()
                                    == heartwood_common::net_config::DeviceMode::Wifi
                            })
                            .unwrap_or(false);
                        if wifi_armed {
                            log::info!("Wifi-standalone configured — rebooting into signer mode");
                            oled::show_provisioned(&mut display);
                            esp_idf_hal::delay::FreeRtos::delay_ms(800);
                            unsafe { esp_idf_svc::sys::esp_restart() };
                        }
                        break;
                    }
                    // handle_add sent a NACK; wait for the next frame.
                }
                // Staged network config before the first identity (#66):
                // words-first ordering is not required — a provisioning flow
                // can push WiFi + relays up front. Still button-confirmed;
                // no reboot (an unprovisioned board would only boot back to
                // this screen). The wifi_armed check on provision picks the
                // staged config up and reboots into signer mode then.
                FRAME_TYPE_SET_NET_CONFIG => {
                    if let Some(cfg) = net_config_store::handle_set_net_config(
                        &mut usb,
                        &frame.payload,
                        &mut nvs,
                        &mut display,
                        &buttons,
                        false,
                    ) {
                        net_cfg = Some(cfg);
                    }
                    oled::show_provision_wait(&mut display);
                }
                // Read-only state probe, so setup tooling can sequence itself
                // (revision for later patches, mode, relay count).
                FRAME_TYPE_GET_NET_CONFIG => {
                    net_config_store::handle_get_net_config(
                        &mut usb,
                        &mut nvs,
                        heartwood_common::net_config::NetworkRuntimeStatus::radio_off(),
                    );
                }
                _ => {
                    log::warn!(
                        "Expected provision frame, got type 0x{:02x}",
                        frame.frame_type
                    );
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, b"no identity: provision first");
                }
            }
        }
    }

    // --- PIN/vault lock ---
    // If the seeds are encrypted at rest, the device stays locked until the
    // correct PIN (PIN_UNLOCK) or host-held vault key (VAULT_UNLOCK, over an
    // authenticated bridge session) is provided. All other frames are
    // rejected, except PROVISION_LIST / FIRMWARE_INFO which are safe (no
    // secret material exposed).
    //
    // A WiFi-standalone device with an operator configured skips this
    // USB-only loop entirely: the relay path runs its own locked phase that
    // serves the remote vault delivery AND the USB unlock frames.
    let wifi_unlock_path = net_cfg.as_ref().is_some_and(|cfg| {
        cfg.device_mode() == heartwood_common::net_config::DeviceMode::Wifi
            && cfg.op_mgmt_pubkey().is_some()
            && !cfg.relays.is_empty()
    });
    if pin::is_locked(&loaded_masters) && !wifi_unlock_path {
        log::info!("At-rest encryption active — seeds encrypted, waiting for unlock");
        oled::show_error(&mut display, "Locked\nAwait unlock...");

        // Load the persisted failed-attempt counter so the wipe threshold
        // survives power cycles (attacker cannot reset by rebooting).
        let mut failed_attempts: u8 = match pin::read_failed_attempts(&nvs) {
            Ok(count) => count,
            Err(e) => {
                log::error!("PIN-attempt state invalid ({e}) — wiping fail-closed");
                oled::show_error(&mut display, "PIN STATE ERROR\nWIPING...");
                pin::wipe_and_reboot(&mut usb, &mut display);
            }
        };
        if failed_attempts >= pin::MAX_FAILED_ATTEMPTS {
            log::error!("PIN wipe threshold persisted across reboot — completing wipe");
            oled::show_error(&mut display, "PIN LOCKED\nWIPING...");
            pin::wipe_and_reboot(&mut usb, &mut display);
        }
        if failed_attempts > 0 {
            log::warn!("PIN: {} failed attempt(s) carried over from previous boot", failed_attempts);
        }
        // Vault unlock requires bridge authentication, but the policy engine
        // does not exist yet in the locked loop — track it locally.
        let mut vault_authed = false;
        loop {
            // Same idle-line watchdog starvation as the provision wait (#65):
            // a locked USB-bridged board left alone must sit on the locked
            // screen indefinitely, not watchdog-cycle every period.
            let frame = loop {
                wdt::feed();
                if let Some(frame) = protocol::try_read_frame(&mut usb, 1000) {
                    break frame;
                }
            };
            match frame.frame_type {
                FRAME_TYPE_PIN_UNLOCK => {
                    if pin::handle_pin_unlock(
                        &mut usb,
                        &frame.payload,
                        &mut nvs,
                        &mut loaded_masters,
                        &mut failed_attempts,
                        &mut display,
                    ) {
                        // Same proven secret unwraps the note key (and
                        // self-heals any torn sealed state) — one extra
                        // PBKDF2 run.
                        notes::sync_sealed(&frame.payload);
                        break; // Unlocked — seeds now in RAM, continue boot.
                    }
                }
                FRAME_TYPE_SESSION_AUTH => {
                    match session::verify_bridge_secret(&frame.payload, &nvs) {
                        Some(true) => {
                            vault_authed = true;
                            protocol::write_frame(&mut usb, FRAME_TYPE_SESSION_ACK, &[0x00]);
                        }
                        Some(false) => {
                            vault_authed = false;
                            protocol::write_frame(&mut usb, FRAME_TYPE_SESSION_ACK, &[0x01]);
                        }
                        None => {
                            protocol::write_frame(&mut usb, FRAME_TYPE_SESSION_ACK, &[0x02]);
                        }
                    }
                }
                FRAME_TYPE_VAULT_UNLOCK => {
                    if !vault_authed {
                        log::warn!("VAULT_UNLOCK rejected — bridge not authenticated");
                        protocol::write_frame(&mut usb, FRAME_TYPE_NACK, b"bridge auth required");
                        continue;
                    }
                    if pin::handle_vault_unlock(
                        &mut usb,
                        &frame.payload,
                        &mut nvs,
                        &mut loaded_masters,
                        &mut display,
                    ) {
                        // Same proven secret unwraps the note key (and
                        // self-heals any torn sealed state) — one extra
                        // PBKDF2 run.
                        notes::sync_sealed(&frame.payload);
                        break; // Unlocked — seeds now in RAM, continue boot.
                    }
                }
                FRAME_TYPE_PROVISION_LIST => {
                    // Allow listing masters even when locked — no secrets exposed,
                    // only public npubs, which is acceptable. The policy engine
                    // is not built yet, so app counts are omitted here.
                    provision::handle_list(&mut usb, &loaded_masters, &loaded_personas, None);
                }
                FRAME_TYPE_FIRMWARE_INFO => {
                    protocol::write_frame(
                        &mut usb,
                        FRAME_TYPE_FIRMWARE_INFO_RESPONSE,
                        firmware_info_json().as_bytes(),
                    );
                }
                FRAME_TYPE_FACTORY_RESET => {
                    // A locked device MUST stay resettable: if the unlock
                    // secret is lost (vault key orphaned, PIN forgotten), the
                    // button-gated wipe is the only way back to a restorable
                    // state. Reset changes no authority — it destroys it — and
                    // always requires the physical hold.
                    provision::handle_factory_reset(
                        &mut usb,
                        &mut nvs,
                        &mut display,
                        &buttons,
                    );
                }
                FRAME_TYPE_NOTE_CMD => {
                    // Locked exception: get_info only (counts and storage
                    // state, no secrets) so the wallet can say "locked
                    // device" rather than "broken device". Everything else
                    // NACKs with a reason.
                    notes::handle_note_cmd_frame_locked(&mut usb, &frame.payload);
                }
                _ => {
                    log::warn!("Device locked — rejecting frame type 0x{:02x}", frame.frame_type);
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                }
            }
        }
    }

    // --- secp256k1 context — created once and shared via Arc ---
    // ~130 KB on the heap. Shared with signing threads to avoid repeated
    // allocations on the ESP32's constrained heap.
    let secp = Arc::new(Secp256k1::signing_only());

    // --- Per-master identity caches ---
    // Populated on demand by heartwood extension methods
    // (heartwood_derive, heartwood_switch, heartwood_list_identities,
    // heartwood_recover).
    let mut identity_caches: Vec<identity_cache::IdentityCache> = loaded_masters
        .iter()
        .map(|m| identity_cache::IdentityCache::new(m.slot))
        .collect();

    // --- Boot screen ---
    // Single master: show its npub. Multiple masters: show the count.
    if loaded_masters.len() == 1 {
        let master = &loaded_masters[0];
        let npub = encode_npub(&master.pubkey);
        log::info!("Boot with master[0]: label={} npub={}", master.label, npub);
        let meta = identity_meta::load(&nvs, master.slot);
        let (name, avatar) = match &meta {
            Some(m) => (Some(m.name.as_str()), Some((m.w, m.h, m.avatar.as_slice()))),
            None => (None, None),
        };
        oled::show_npub(&mut display, name, &npub, avatar);
    } else {
        log::info!("Boot with {} masters", loaded_masters.len());
        oled::show_boot(&mut display, loaded_masters.len() as u8);
    }

    // --- Policy engine (load persisted TOFU policies from NVS) ---
    let mut policy_engine = policy::PolicyEngine::load_from_nvs(&mut nvs, loaded_masters.len() as u8);

    // --- OTA rollback guard ---
    // If this boot was triggered by an OTA update, mark the firmware as valid
    // so the rollback safety net is cancelled.  If this is a normal (non-OTA)
    // boot the call is a no-op and the error code is ignored.
    unsafe {
        let err = esp_idf_svc::sys::esp_ota_mark_app_valid_cancel_rollback();
        if err == esp_idf_svc::sys::ESP_OK {
            log::info!("OTA: firmware marked as valid (rollback cancelled)");
        } else {
            log::info!("OTA: not an OTA boot or already confirmed ({})", err);
        }
    }

    // --- WiFi-standalone (Plan 2): relay signing loop ---
    // In wifi mode the device handles NIP-46 over its own outbound relay
    // connection AND serves the full USB command set over the cable (see
    // relay::poll_usb) — so the cable stays completely usable without any mode
    // switch. The old "hold PRG at boot to force USB" escape hatch is therefore
    // gone: USB is always live, even while wifi is down (a bad SSID/relay can be
    // fixed over the cable). `mode=usb` remains the explicit radio-off tier and
    // falls through to the dispatch loop below. Never returns once entered.
    if let Some(cfg) = &net_cfg {
        if cfg.device_mode() == heartwood_common::net_config::DeviceMode::Wifi
            && !loaded_masters.is_empty()
        {
            log::info!("WiFi-standalone mode — entering relay loop");
            let op_mgmt = cfg.op_mgmt_pubkey();
            relay::run_wifi_standalone(
                modem,
                cfg,
                &mut loaded_masters,
                &mut loaded_personas,
                &secp,
                &mut display,
                &buttons,
                &mut policy_engine,
                &mut identity_caches,
                &mut nvs,
                op_mgmt,
                trial_transaction_id,
                &mut usb,
            );
        }
    }

    // --- OTA session state ---
    let mut ota_session: Option<ota::OtaSession> = None;

    // --- WiFi-scan event loop (radio-off tier) ---
    // Taken lazily on the first scan request and cached: `EspSystemEventLoop`
    // can only be taken once, and a device that never scans should not take it
    // at all. In USB-only mode nothing else has taken it (the relay path, which
    // does, diverges before this loop), so the first take here always succeeds.
    let mut scan_sysloop: Option<EspSystemEventLoop> = None;

    // --- Display power management ---
    // Track the timestamp of the last activity (frame received or button press).
    // After DISPLAY_TIMEOUT of inactivity the OLED panel is switched off to
    // prevent burn-in and save power.  Any frame arriving or a short PRG
    // button press will wake it again.
    let mut last_activity = Instant::now();
    let mut display_on = true;
    // Idle info carousel: waking shows page 0 (status); further short presses
    // cycle network and device pages. Sleep resets to page 0.
    let mut idle_page: u8 = 0;

    // --- Frame dispatch loop ---
    log::info!("Entering frame dispatch loop");
    loop {
        // Poll for an incoming frame with a short timeout so we can also check
        // the button state and display timeout while idle.
        let frame = loop {
            wdt::feed();
            match protocol::try_read_frame(&mut usb, IDLE_POLL_MS) {
                Some(f) => {
                    // A frame arrived — mark activity and ensure the display is on.
                    last_activity = Instant::now();
                    if !display_on {
                        oled::wake_display(&mut display);
                        display_on = true;
                        log::info!("Display woken by incoming frame");
                    }
                    break f;
                }
                None => {
                    // No frame this tick — check for display timeout and button.

                    // Signing requests always wake the display (handled above when
                    // the frame arrives).  Between frames, check elapsed idle time.
                    if display_on && last_activity.elapsed() >= DISPLAY_TIMEOUT {
                        oled::sleep_display(&mut display);
                        display_on = false;
                        idle_page = 0;
                        log::info!("Display slept after {}s idle", DISPLAY_TIMEOUT.as_secs());
                    }

                    // Advance held signing confirmations; restore the idle
                    // card once the last hold expires.
                    if display_on && confirm::service(&mut display) {
                        idle_page = 0;
                        draw_idle_page(idle_page, &mut display, loaded_masters.len() as u8, &mut nvs);
                    }

                    // PRG button press (active-low GPIO 0) wakes the display.
                    // Wake on the press itself, not the release: a CH9102/CP2102
                    // bridge can pin GPIO 0 low after a web-serial flash until
                    // the cable is re-plugged, and requiring a release made the
                    // device look dead in that state. Waking on press also feels
                    // more immediate on a healthy button.
                    if buttons.a.is_low() {
                        last_activity = Instant::now();
                        if !display_on {
                            oled::wake_display(&mut display);
                            display_on = true;
                            idle_page = 0;
                            log::info!("Display woken by button press");
                        } else if confirm::dismiss() {
                            // A press while a signing confirmation is held
                            // dismisses the run early, back to the idle card.
                            idle_page = 0;
                        } else {
                            // Awake: a short press pages through the idle
                            // info carousel (status / network / device).
                            idle_page = (idle_page + 1) % 3;
                        }
                        draw_idle_page(idle_page, &mut display, loaded_masters.len() as u8, &mut nvs);
                        let press_start = Instant::now();
                        // Drain the press, capping at 1.9 s so a long-hold that
                        // belongs to an imminent signing request is not consumed.
                        while buttons.a.is_low()
                            && press_start.elapsed() < Duration::from_millis(1900)
                        {
                            wdt::feed();
                            esp_idf_hal::delay::FreeRtos::delay_ms(20);
                        }
                    }
                }
            }
        };

        let frame_type = frame.frame_type;
        match frame_type {
            // 0x01 — add a master (host-derived) / 0x57 — self-generate on-device
            // / 0x58 — restore an existing 12-word phrase via the on-device picker
            FRAME_TYPE_PROVISION | FRAME_TYPE_GENERATE_IDENTITY | FRAME_TYPE_RESTORE_IDENTITY => {
                let provisioned = match frame.frame_type {
                    FRAME_TYPE_GENERATE_IDENTITY => {
                        provision::handle_generate(&mut usb, &frame, &mut nvs, &secp, &mut display, &buttons)
                    }
                    FRAME_TYPE_RESTORE_IDENTITY => {
                        provision::handle_restore(&mut usb, &frame, &mut nvs, &secp, &mut display, &buttons)
                    }
                    _ => provision::handle_add(&mut usb, &frame, &mut nvs, &secp, &mut display),
                };
                if let Some(master) = provisioned {
                    loaded_masters.push(master);
                }
            }

            // 0x60 — derive a named child identity on-device from an existing
            // master's tree root. No secret enters or leaves the host.
            FRAME_TYPE_DERIVE_IDENTITY => {
                if let Some(master) = provision::handle_derive(
                    &mut usb,
                    &frame,
                    &mut nvs,
                    &secp,
                    &mut display,
                    &loaded_masters,
                ) {
                    loaded_masters.push(master);
                }
            }

            // 0x59 — firmware version query (read-only, no secrets)
            FRAME_TYPE_FIRMWARE_INFO => {
                protocol::write_frame(
                    &mut usb,
                    FRAME_TYPE_FIRMWARE_INFO_RESPONSE,
                    firmware_info_json().as_bytes(),
                );
            }

            // 0x5B — Sapwood-provisioned display metadata (name + avatar). Stored
            // in NVS; the signer never fetches/decodes images itself.
            FRAME_TYPE_SET_IDENTITY_META => {
                let ok = identity_meta::handle_frame(&frame.payload, &loaded_masters, &mut nvs);
                protocol::write_frame(&mut usb, if ok { FRAME_TYPE_ACK } else { FRAME_TYPE_NACK }, &[]);
                // Refresh the single-master identity card with the new avatar.
                if ok && loaded_masters.len() == 1 {
                    let m = &loaded_masters[0];
                    let npub = encode_npub(&m.pubkey);
                    let meta = identity_meta::load(&nvs, m.slot);
                    let (name, avatar) = match &meta {
                        Some(im) => (Some(im.name.as_str()), Some((im.w, im.h, im.avatar.as_slice()))),
                        None => (None, None),
                    };
                    oled::show_npub(&mut display, name, &npub, avatar);
                }
            }

            // 0x02 — plaintext NIP-46 request (only if bridge NOT authenticated)
            FRAME_TYPE_NIP46_REQUEST => {
                if policy_engine.bridge_authenticated {
                    log::warn!("Plaintext NIP-46 rejected — bridge is authenticated; use encrypted channel");
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                } else if loaded_masters.is_empty() {
                    log::warn!("NIP-46 request with no masters loaded");
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                } else {
                    // Use the first loaded master for plaintext requests.
                    let master = &loaded_masters[0];
                    let response_json = nip46_handler::handle_request(
                        frame,
                        &master.secret,
                        &master.label,
                        master.mode,
                        master.slot,
                        &secp,
                        &mut display,
                        &buttons,
                        &mut policy_engine,
                        &mut identity_caches,
                        None,
                        &mut nvs,
                        &mut loaded_personas,
                    );
                    protocol::write_nip46_response(
                        &mut usb,
                        FRAME_TYPE_NIP46_RESPONSE,
                        response_json,
                    );
                    // Persist slots if TOFU may have added one.
                    if !loaded_masters.is_empty() {
                        policy_engine.persist_slots(&mut nvs, loaded_masters[0].slot);
                        // And any identities derived during the request, so a
                        // persona created over the plaintext cable survives
                        // reboot exactly as the encrypted and relay paths do.
                        transport::persist_fresh_identities(
                            &mut nvs,
                            &identity_caches,
                            &mut loaded_personas,
                            loaded_masters[0].slot,
                        );
                    }
                    // Leave a held signing confirmation readable — the poll
                    // loop restores the idle card when the hold expires.
                    if !confirm::active() {
                        oled::show_boot(&mut display, loaded_masters.len() as u8);
                    }
                }
            }

            // 0x04 — remove a master (button-confirmed on the device)
            FRAME_TYPE_PROVISION_REMOVE => {
                if provision::handle_remove(
                    &mut usb,
                    &frame,
                    &mut nvs,
                    &mut loaded_masters,
                    &mut display,
                    &buttons,
                ) {
                    // Policies, personas, identity metadata, and identity
                    // caches are all slot-indexed. Reload them from the
                    // completed journal transaction before signing again.
                    esp_idf_hal::delay::FreeRtos::delay_ms(400);
                    unsafe { esp_idf_svc::sys::esp_restart() }
                }
            }

            // 0x05 — list masters (and personas)
            FRAME_TYPE_PROVISION_LIST => {
                provision::handle_list(&mut usb, &loaded_masters, &loaded_personas, Some(&policy_engine));
            }

            // 0x10 — encrypted NIP-46 request (NIP-44 transport layer)
            FRAME_TYPE_ENCRYPTED_REQUEST => {
                if !policy_engine.bridge_authenticated {
                    log::warn!("Encrypted request rejected — bridge not authenticated");
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                } else {
                    transport::handle_encrypted_request(
                        &mut usb,
                        &frame,
                        &loaded_masters,
                        &mut loaded_personas,
                        &secp,
                        &mut display,
                        &buttons,
                        &mut policy_engine,
                        &mut identity_caches,
                        &mut nvs,
                    );
                }
            }

            // 0x34 — SIGN_ENVELOPE (deprecated: envelope signing now happens
            // inline during handle_encrypted_request). Kept as a NACK handler
            // so stale daemon versions get an explicit rejection.
            FRAME_TYPE_SIGN_ENVELOPE => {
                log::warn!("SIGN_ENVELOPE is deprecated — envelope signing is now inline");
                protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
            }

            // 0x21 — bridge authentication
            FRAME_TYPE_SESSION_AUTH => {
                session::handle_auth(
                    &mut usb,
                    &frame.payload,
                    &nvs,
                    &mut policy_engine,
                );
            }

            // 0x23 — set bridge secret
            FRAME_TYPE_SET_BRIDGE_SECRET => {
                session::handle_set_bridge_secret(
                    &mut usb,
                    &frame.payload,
                    &mut nvs,
                    &policy_engine,
                    &mut display,
                    &buttons,
                );
            }

            // 0x54 — set WiFi-standalone network config
            FRAME_TYPE_SET_NET_CONFIG => {
                net_config_store::handle_set_net_config(
                    &mut usb,
                    &frame.payload,
                    &mut nvs,
                    &mut display,
                    &buttons,
                    true,
                );
            }

            FRAME_TYPE_GET_NET_CONFIG => {
                net_config_store::handle_get_net_config(
                    &mut usb,
                    &mut nvs,
                    heartwood_common::net_config::NetworkRuntimeStatus::radio_off(),
                );
            }

            FRAME_TYPE_PATCH_NET_CONFIG => {
                net_config_store::handle_patch_net_config(
                    &mut usb,
                    &frame.payload,
                    &mut nvs,
                    &mut display,
                    &buttons,
                );
            }

            FRAME_TYPE_SET_OPERATOR => {
                net_config_store::handle_set_operator(
                    &mut usb,
                    &frame.payload,
                    &mut nvs,
                    &mut display,
                    &buttons,
                    false,
                );
            }

            // 0x24 — factory reset
            FRAME_TYPE_FACTORY_RESET => {
                provision::handle_factory_reset(
                    &mut usb,
                    &mut nvs,
                    &mut display,
                    &buttons,
                );
            }

            // 0x25 — set/change/clear boot PIN (encrypts/decrypts the seeds)
            FRAME_TYPE_SET_PIN => {
                let changed = pin::handle_set_pin(
                    &mut usb,
                    &frame.payload,
                    &mut nvs,
                    &loaded_masters,
                    &mut display,
                    &buttons,
                );
                if changed {
                    if frame.payload.is_empty() {
                        notes::disable_sealing();
                    } else {
                        notes::sync_sealed(&frame.payload);
                    }
                }
            }

            // 0x62 — set/clear the host-held vault key (re-wraps the seeds)
            FRAME_TYPE_VAULT_SET => {
                let changed = pin::handle_vault_set(
                    &mut usb,
                    &frame.payload,
                    &mut nvs,
                    &loaded_masters,
                    policy_engine.bridge_authenticated,
                    &mut display,
                    &buttons,
                );
                if changed {
                    if frame.payload.is_empty() {
                        notes::disable_sealing();
                    } else {
                        notes::sync_sealed(&frame.payload);
                    }
                }
            }

            // 0x63 — vault unlock in the main loop is a no-op (the device is
            // already unlocked to be here); NACK so host bugs are visible.
            FRAME_TYPE_VAULT_UNLOCK => {
                log::warn!("VAULT_UNLOCK received while already unlocked");
                protocol::write_frame(&mut usb, FRAME_TYPE_NACK, b"already unlocked");
            }

            // 0x70 — bearer-note locker command (lnurl-vault JSON protocol;
            // gated commands run the shared approval loop). The locked USB
            // loop never reaches here, so a locked device NACKs these
            // frames — fail closed, per the goal doc.
            FRAME_TYPE_NOTE_CMD => {
                notes::handle_note_cmd_frame(&mut usb, &frame.payload, &mut display, &buttons);
            }

            // 0x40 -- create a connection slot
            FRAME_TYPE_CONNSLOT_CREATE => {
                connslot::handle_create(&mut usb, &frame, &mut policy_engine, &loaded_masters, &mut nvs);
            }

            // 0x42 -- list connection slots (secrets redacted)
            FRAME_TYPE_CONNSLOT_LIST => {
                connslot::handle_list(&mut usb, &frame, &mut policy_engine);
            }

            // 0x44 -- update a connection slot (requires button confirmation)
            FRAME_TYPE_CONNSLOT_UPDATE => {
                connslot::handle_update(&mut usb, &frame, &mut policy_engine, &mut nvs, &mut display, &buttons);
            }

            // 0x46 -- revoke a connection slot
            FRAME_TYPE_CONNSLOT_REVOKE => {
                connslot::handle_revoke(&mut usb, &frame, &mut policy_engine, &mut nvs);
            }

            // 0x48 -- get bunker URI for a connection slot
            FRAME_TYPE_CONNSLOT_URI => {
                connslot::handle_uri(&mut usb, &frame, &mut policy_engine, &loaded_masters);
            }

            // 0x50 -- backup export (dump all slots + bridge secret)
            FRAME_TYPE_BACKUP_EXPORT_REQUEST => {
                if !policy_engine.bridge_authenticated {
                    log::warn!("Backup export rejected -- bridge not authenticated");
                    protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                    continue;
                }
                backup::handle_export(
                    &mut usb,
                    &loaded_masters,
                    &policy_engine,
                    &nvs,
                    &mut display,
                    &buttons,
                );
            }

            // 0x52 -- backup import (restore slots + bridge secret)
            FRAME_TYPE_BACKUP_IMPORT_REQUEST => {
                backup::handle_import(
                    &mut usb,
                    &frame.payload,
                    &loaded_masters,
                    &mut policy_engine,
                    &mut nvs,
                    &mut display,
                    &buttons,
                );
            }

            // 0x30 -- OTA begin (sends size + expected SHA-256, triggers approval)
            FRAME_TYPE_OTA_BEGIN => {
                ota::handle_ota_begin(
                    &mut usb,
                    &frame.payload,
                    &mut display,
                    &buttons,
                    &mut ota_session,
                );
            }

            // 0x31 — OTA chunk (offset + data)
            FRAME_TYPE_OTA_CHUNK => {
                ota::handle_ota_chunk(
                    &mut usb,
                    &frame.payload,
                    &mut display,
                    &mut ota_session,
                );
            }

            // 0x32 — OTA finish (verify hash, reboot)
            FRAME_TYPE_OTA_FINISH => {
                ota::handle_ota_finish(
                    &mut usb,
                    &mut display,
                    &mut ota_session,
                );
            }

            // 0x55 — scan nearby WiFi APs (setup aid). Radio-off tier: the radio
            // is brought up only for this scan and powered straight back down, no
            // connection is made, and nothing inbound is served — remote attack
            // surface stays zero. A physical, cabled request only.
            FRAME_TYPE_WIFI_SCAN_REQUEST => {
                if scan_sysloop.is_none() {
                    scan_sysloop = EspSystemEventLoop::take().ok();
                }
                match &scan_sysloop {
                    Some(sl) => wifi_scan::respond_on_demand(&mut usb, sl),
                    None => {
                        log::error!("wifi scan: system event loop unavailable");
                        protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
                    }
                }
            }

            // Unknown frame — NACK
            _ => {
                log::warn!("Unknown frame type: 0x{:02x}", frame.frame_type);
                protocol::write_frame(&mut usb, FRAME_TYPE_NACK, &[]);
            }
        }

        // Reset activity timestamp after every handler returns.  This is
        // especially important after sign_event, which can hold the button
        // loop for up to 30 seconds -- without this reset the display would
        // sleep immediately after the user finishes approving a request.
        last_activity = Instant::now();

        // Return to the idle screen after non-OTA requests so the OLED doesn't
        // stay stuck on "SIGNED" or other transient confirmation screens.
        // Skip for OTA frames -- the OTA handler manages its own progress display,
        // and redrawing between chunks slows the transfer and generates log noise.
        if !matches!(frame_type,
            FRAME_TYPE_OTA_BEGIN | FRAME_TYPE_OTA_CHUNK | FRAME_TYPE_OTA_FINISH
        ) {
            oled::show_awaiting(&mut display);
        }
    }
}
