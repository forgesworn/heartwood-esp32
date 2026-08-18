# Heartwood ESP32

Hardware signing device for Nostr on a Heltec WiFi LoRa 32 (ESP32-S3). Both the V3 (CP2102 UART bridge) and V4 (native USB-Serial-JTAG) boards are supported from the same codebase via the `heltec-v3` / `heltec-v4` cargo features. See `firmware/src/serial.rs` for the transport abstraction. The operating mode is selected at runtime from the NVS network config (`NetConfig.mode`), not a build flag:

- **USB-bridged mode** (default) — USB-attached to a Pi, holds master secrets, all radios disabled; the Pi handles networking.
- **WiFi-standalone mode** (opt-in) — the ESP32 joins WiFi and talks to Nostr relays directly, running the full NIP-46 signing loop on-chip with no Pi. Enabled only when provisioned with an SSID + relay list; the USB cable stays fully live in parallel. See `firmware/src/relay.rs`.
- **Portable mode** (roadmap, not built) — battery-powered, holds a child key, BLE for phone signing.

## Security model

- **Physical approval required** — OLED shows the request, button press to sign. No silent signing. Applies in every mode, including WiFi-standalone.
- **USB-bridged mode (high-assurance default):** all radios disabled, USB serial only. Pi compromise is survivable — keys live on the ESP32, and in device-decrypts mode the Pi only ever sees ciphertext.
- **WiFi-standalone mode (opt-in convenience tier):** WiFi *is* enabled and the device reaches relays directly — a deliberately larger attack surface, accepted in exchange for dropping the Pi. Keys still never leave the chip, NIP-44 is still decrypted on-device, and every signature is still button-gated. Relay-side device management (kind 24134) is authenticated to a provisioned operator pubkey and replay-protected. Don't enable this tier where the USB high-assurance model is required.
- **Portable mode** (roadmap, not built) — would enable only BLE (short range) and hold a child key, never the master.
- **JTAG disabled** in production firmware to prevent debug-port key extraction.

## Feature flags & mode selection

Operating mode (USB-bridged vs WiFi-standalone) is selected **at runtime** from `NetConfig.mode` in NVS (`common/src/net_config.rs`: `"usb"` default, `"wifi"` opt-in) — it is **not** a cargo feature. Cargo features select the board (`heltec-v3` / `heltec-v4`) and the crypto backend (`k256-backend` for host tools/tests, `secp256k1-backend` for firmware — see Known issues below). The future `portable` (BLE) tier is not built.

## Current state

Phase 5 (flash-once production) complete (2026-04-03). Seven crates: `common/` (shared crypto + frame protocol + NIP-46 types + NIP-44/NIP-04 encryption + policy types), `firmware/` (ESP32), `provision/` (host CLI), `sign-test/` (signing test harness), `heartwoodd/` (Pi-side daemon -- Soft and Hard modes), `ota/` (Pi-side serial OTA tool), `sapwood/` (web management UI, separate repo). Multi-master NVS storage (up to 8 masters, three provisioning modes: bunker/tree-mnemonic/tree-nsec). On-device NIP-44 transport encryption -- the Pi is zero-trust in Hard mode, only sees ciphertext (including sign_event responses). Connection slot policies (NVS-persisted on ESP32, Argon2id keyfile on Pi). Full NIP-46 method set (16 methods: 8 standard + 8 heartwood extensions; proof methods stubbed, `heartwood_capabilities` advertises the served set per signer). Connect secret validation per NIP-46 spec. Serial OTA with SHA-256 verification and automatic rollback. Factory reset with button confirmation. Firmware uses libsecp256k1 (C FFI) for all signing.

Heartwood Soft mode: `heartwoodd` runs standalone on a Pi with no ESP32. Keys encrypted at rest with Argon2id + XChaCha20-Poly1305, unlocked via Sapwood. Policy-based auto-approve with Sapwood approval queue for out-of-policy requests. Same management API, same Sapwood UI, same NIP-46 signing -- just software-backed instead of hardware-backed.

Encrypted backup/restore of connection slots and policies via Sapwood -- auto-snapshots after slot changes, manual export/import, Argon2id + XChaCha20-Poly1305 encrypted backup file, physical button confirmation on restore. Dedicated backup passphrase (default "heartwood", changeable via Sapwood). Works in both Hard and Soft modes.

Encrypted at rest on-device (opt-in): either a human PIN (P5, wipes after 5 failures) or a host-held 32-byte vault key (VAULT_SET 0x62 / VAULT_UNLOCK 0x63) that heartwoodd or Sapwood delivers — unattended reboot with ciphertext on flash. WiFi-standalone locked devices announce a per-boot ephemeral unlock pubkey (kind 24135) and receive the vault key live from the operator (kind 24136). Spec: docs/specs/2026-08-08-encrypted-at-rest-unlock-design.md.

Field-test feedback landed 2026-08-14 (see docs/plans/2026-08-14-field-test-feedback-triage.md): approval loop hardened (B button = explicit cancel on two-button boards with on-screen hints, debounce, terminal "request expired" card so a stale countdown can never wedge the screen, 45 s browser-driven windows), wake-on-press (a serial bridge pinning GPIO 0 after a web flash no longer makes the device look dead), paged idle carousel (identity / network / device pages on short press), multiple prioritised WiFi networks (`NetConfig.networks` fallback list, per-SSID password `keep`, join-loop rotation incl. the locked vault-unlock phase, which previously never associated the station), and a `demo-game` bin (`scripts/build-firmware.sh demo`) — a branded board-check jump-and-duck game for pre-flashing handed-out T-Displays, deliberately not the signer. Sapwood gained the network-list editor, an app-only quick USB update for factory-layout boards, an update banner, and post-flash DTR/RTS release.

Family-bunker Phase 1 landed 2026-08-14 (signet-plans design doc §11.2): the persona registry moved to packed NVS chunks (`pc{c}` + `pcnt`, codec + power-cut models host-tested in `common/src/persona_pack.rs`) with a journalled one-time boot migration from the `p{n}_*` keys; per-board caps (Heltec 8/32, T-Display 8/64); NVS entry stats in FIRMWARE_INFO and get_status for the Sapwood storage gauge; derive refuses cleanly ("identity storage full") with policy headroom reserved; and `heartwood_remove_persona` / `heartwood_rename_persona` NIP-46 extensions (journalled removal, registry-only). Checklist section 9 ran and CP1 signed off 2026-08-14. C4 escalation + C5 audit rail landed 2026-08-15 as v0.17.0 (checklist section 11; button-free half benched); CP2 joint gate closed 2026-08-15 (checklist section 10 records the ack, Path A findings tracked as #64–#66). `get_status.capabilities` advertises `client_policy_flags_v1` for the C3 compiler push and `pairing_identity_v1` for the D2 persona-addressed pairing mint (`params.identity` on `create_client_v2` / `nostrconnect_v2` / `client_uri`; hardware verify is checklist §11b item 11 — needs the bench operator install, one button press, see scripts/set-operator.mjs).

CP2's Path A findings are closed on our side: #65 (idle watchdog reboot on an unprovisioned board) and #67 (derive answering success while the registry write failed) landed 2026-08-16, as did #66 (the first-boot setup screen now accepts a staged `SET_NET_CONFIG` before the first identity, and NACKs everything else with a reason). #64 followed the same day: in WiFi-standalone mode an interactive ask no longer blocks the relay loop. `nip46_handler::dispatch` takes an `ApprovalDecision` and hands a `Deferred` caller the ask back instead of putting the card up itself; relay.rs holds it the way a C4 park is held, the button sampler thread measures the hold so a loop running at ~1 Hz can judge one, and same-client asks for the same identity collapse onto one card whose single hold answers the batch (caps and admission rule host-tested in `common/src/approval_queue.rs`). Replies are stamped via `common/src/reply_clock.rs` for when they are sent rather than when the ask arrived. The USB tier deliberately keeps the blocking loop — the host is waiting on the reply frame. None of it is bench-run: checklist section 12.

Bearer-note locker landed 2026-08-18 (all five phases device-side; design and
per-phase record in docs/plans/2026-08-18-note-locker-goal.md): heartwood
custodies LUD-25 (LNURLcash) bearer notes as a sidecar to signing — the
browser wallet (a dni/lnurl-wallet fork, branch heartwood-transport) does all
mint HTTP, the device generates replacement secrets and discloses only their
SHA-256 until the mint confirms, and every plaintext export needs the button.
Lifecycle model + wire protocol host-tested in common/src/{note_store,
note_cmd}.rs (power-cut torture pins persist-before-disclose); USB surface is
one frame pair (NOTE_CMD 0x70 / NOTE_RESP 0x71, lnurl-vault's JSON command
set verbatim, bench driver scripts/note-cmd.mjs); notes are sealed at rest
under a random note key wrapped by the same PIN/vault secret as the seeds
(common/src/note_seal.rs, nk blob in the hw_notes namespace, one extra PBKDF2
at unlock, notes::sync_sealed converges every torn state and never deletes
what it cannot read). Relay path: heartwood_note_* NIP-46 extensions
(advertised note_locker_v1), gated methods pinned ButtonRequired ahead of the
generic extension gate so no slot policy can silence a disclosure, riding the
#64 deferred machinery. Notes are deliberately NOT in backups (restore onto
two boards = double-spend); destructive commands (mark_spent/discard/rename/
delete) are button-gated like lnurl-vault gates them. WiFi tier NACKs the USB
note frames (use the relay methods) and refuses at-rest changes while notes
are held. Nothing bench-run: checklist section 13.

Next: bench the note locker (checklist section 13) and the remaining hardware verification of the encrypted-at-rest flows (USB auto-unlock and Hard-mode signing passed on real hardware 2026-08-13; see docs/HARDWARE-TEST-CHECKLIST.md section 7), the 2026-08-14 fixes and features (checklist section 8, not yet bench-run), and the Soft-mode approval path (fixed 2026-08-08: approvals were re-queued and the signed envelope dropped). Task watchdog landed 2026-08-08 (60 s, panic → crash crumb, fed by every blocking loop). JTAG disable is deliberately excluded — it requires eFuse burning, which permanently locks the chip (see docs/memory/feedback_no_efuse.md); physical security is the model. Sapwood tier badge/unlock/approvals/backup UI is in the sapwood repo.

## Build & flash

Five crates — build each from its own directory:

```bash
cd common && cargo test                    # shared crypto tests
cd common && cargo test --features nip46   # NIP-46 + event ID tests
cd provision && cargo build                # host CLI tool
cd sign-test && cargo build                # signing test harness
cd heartwoodd && cargo build               # Pi-side daemon (Soft or Hard mode)
cd ota && cargo build                      # Pi-side serial OTA tool
cd firmware && cargo build                 # ESP32 firmware (needs ESP toolchain)
cd firmware && espflash flash target/xtensa-esp32s3-espidf/debug/heartwood-esp32
```

Requires the ESP Rust toolchain for firmware: `espup install`, then `source ~/export-esp.sh`.

## Conventions

- British English in all prose and comments
- No secrets in logs, serial output, or display — npub only
- Zeroize all private key material after use
- Git commits: `type: description` (feat:, fix:, docs:, refactor:, test:, chore:)
- No `Co-Authored-By` lines in commits
- Private docs (plans, session memory) live in gitignored directories

## Frozen protocol

The nsec-tree derivation MUST match heartwood-core byte-for-byte. The test vector in `common/src/derive.rs` asserts this. The mnemonic derivation path (`m/44'/1237'/727'/0'/0'`) is tested in `provision/src/main.rs`. If derivation logic changes, update both repos.

## GPIO pin assignments (Heltec V3 and V4)

Common to both boards:

| Function | GPIO | Verified |
|----------|------|----------|
| OLED SDA | 17 | Yes -- Heltec factory test, Meshtastic |
| OLED SCL | 18 | Yes -- Heltec factory test, Meshtastic |
| OLED RST | 21 | Yes -- must stay HIGH after init or display blanks |
| Vext (OLED power) | 36 | Yes -- active LOW, must be set before I2C init |
| White LED | 35 | Yes -- active HIGH |
| PRG button | 0 | Active LOW, internal pull-up |
| LoRa NSS | 8 | Not yet used |
| LoRa RST | 12 | Not yet used |
| LoRa DIO1 | 14 | Not yet used |

Board-specific (host transport):

| Board | Mechanism | GPIO |
|-------|-----------|------|
| V4 | Native USB-Serial-JTAG | 19 (D-), 20 (D+) |
| V3 | UART0 via CP2102 bridge | 43 (TX), 44 (RX) |

V4-only (not present on V3):

| Function | GPIO | Verified |
|----------|------|----------|
| GNSS TX | 34 | Not yet used |
| GNSS RX | 33 | Not yet used |

**PSRAM uses GPIO 26-32 on the V4 (S3R2).** V3 (S3FN8) has no PSRAM. Never drive those pins on V4.

## Known issues

### k256 LoadStoreAlignment on Xtensa (RESOLVED)

k256's field arithmetic does unaligned memory accesses that hang on Xtensa LX7.
No amount of thread/alignment tricks fixes it reliably — `SigningKey::from_bytes()`
hangs deterministically, with one-off successes depending on exact binary layout.

**Resolution:** Firmware now uses the `secp256k1` crate (C FFI wrapping Bitcoin
Core's libsecp256k1) which is alignment-safe on all architectures. The `common`
crate has a feature flag: `k256-backend` (default, for host tools/tests) and
`secp256k1-backend` (for firmware). Both backends produce identical outputs —
verified by the frozen test vector in `common/src/derive.rs`.

## Dependencies

All crypto crates are no_std-compatible but we use the ESP-IDF std framework:

| Crate | Why |
|-------|-----|
| secp256k1 | libsecp256k1 C FFI — BIP-340 Schnorr (firmware) |
| k256 | secp256k1 pure Rust — BIP-340 Schnorr (host tools/tests) |
| hmac + sha2 | HMAC-SHA256 child key derivation |
| zeroize | Deterministic secret cleanup |
| bech32 | npub encoding |
| bip39 + bip32 | Mnemonic derivation (provision CLI only) |
| crc32fast | Serial protocol integrity |
| esp-idf-svc + esp-idf-hal | ESP-IDF std framework (I2C, GPIO, NVS, logging) |
| ssd1306 + embedded-graphics | OLED driver and text rendering |
