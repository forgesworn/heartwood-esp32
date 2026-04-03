# Heartwood ESP32

A hardware signing device for Nostr, built on the **Heltec WiFi LoRa 32 V4** (ESP32-S3R2). Holds nsec-tree key material, derives child identities, and signs on request — private keys never leave the chip. OLED shows what you're signing, physical button to approve.

Two deployment modes from the same codebase:

### Home HSM — USB-attached to a Raspberry Pi

```
Internet ← Tor ← Pi (networking) ← USB serial → ESP32 (master secret + signing)
                                                    ├── OLED (show request)
                                                    └── Button (approve/deny)
```

Holds the **master secret** (mnemonic root). All radios disabled. The Pi running [heartwood-device](https://github.com/forgesworn/heartwood) handles networking (Tor, NIP-46, relays). The ESP32 handles cryptography. Even if the Pi is fully compromised, an attacker cannot extract keys or sign without physical button access. Same architecture as Ledger/Trezor but for Nostr.

### Portable signer — battery-powered, BLE to phone

```
Phone app ← BLE GATT → ESP32 (child key + signing)
                          ├── OLED (show request)
                          └── Button (approve/deny)
```

Holds a **child key** derived by the home HSM (`purpose="device/mobile"`). Only BLE enabled — short range, requires physical proximity. If lost or compromised, burn that branch on the HSM and derive a new one at the next index. The master secret and all other branches are untouched.

### Key hierarchy

```
Master secret (home HSM)
├── persona/social       — public Nostr identity
├── persona/forgesworn   — project identity
├── client/bray          — NIP-46 client key
├── device/mobile-0      — portable signer #0 ← child key lives here
├── device/mobile-1      — replacement if #0 is compromised
└── ...
```

The nsec-tree hierarchy means each device gets its own branch. Compromise of a child never threatens the root or siblings.

## Hardware

| Component | Detail |
|-----------|--------|
| Board | Heltec WiFi LoRa 32 V4 |
| Chip | ESP32-S3R2 (Xtensa LX7 dual-core, 240 MHz) |
| PSRAM | 2MB quad-SPI |
| Flash | 16MB |
| OLED | 128x64 SSD1306 (I2C: SDA=GPIO17, SCL=GPIO18, RST=GPIO21, addr 0x3C) |
| GNSS | L76K (available for portable mode) |
| LoRa | SX1262 (never initialised — no use case for signing) |
| WiFi | ESP32-S3 built-in (disabled in both modes) |
| BLE | ESP32-S3 built-in (portable mode only) |
| USB | USB-C (power + serial to Pi in HSM mode) |
| Battery | JST PH 2.0 connector + charging circuit (portable mode) |
| Button | PRG button (signing approval) |

## Setup

Install the ESP Rust toolchain:

```bash
cargo install espup ldproxy espflash
espup install
source ~/export-esp.sh
```

## Build

Three independent crates — build each from its own directory:

```bash
cd common && cargo test                    # shared crypto tests
cd provision && cargo build                # host CLI tool
cd firmware && cargo build                 # ESP32 firmware (needs ESP toolchain)
```

## Flash & provision

```bash
cd firmware && espflash flash target/xtensa-esp32s3-espidf/debug/heartwood-esp32
```

Wait for OLED to show "Awaiting secret...", then:

```bash
cd provision && cargo run -- --port /dev/cu.usbserial-*
```

Enter mnemonic and passphrase when prompted. After ACK, the device reboots with the stored identity.

Subsequent boots display the master npub immediately (no provisioning needed).

## Test vector

| Parameter | Value |
|-----------|-------|
| Root secret | `[0x01, 0x02, ..., 0x20]` (32 bytes, sequential) |
| Root path | Raw secret → SigningKey (no HMAC intermediate) |
| Purpose | `persona/test` |
| Index | `0` |
| Expected child npub | `npub1rx8u4wk9ytu8aak4f9wcaqdgk0lj4rjhdu4j9n7dj2mg68l9cdqs2fjf2t` |

This must match heartwood-core's output for the same inputs. The nsec-tree derivation is:

```
context = b"nsec-tree\0" || b"persona/test" || 0x00 || 0x00000000
child_secret = HMAC-SHA256(key=root_secret, msg=context)
child_pubkey = SigningKey(child_secret).verifying_key()
npub = bech32_encode("npub", child_pubkey)
```

## GPIO safety

Verified against Heltec factory test code, Meshtastic firmware, and ESPHome configs:

- **GPIO 17, 18, 21** — confirmed correct for the V4 OLED. No conflict with PSRAM/flash.
- **PSRAM pins** on ESP32-S3R2 are GPIO 26–32 (quad-SPI). Nowhere near our I2C pins.
- **GPIO 33–37** are free on this board (only reserved on octal PSRAM variants like S3R8).

## Structure

```
common/                     Shared crypto, frame protocol, NIP-46 types
  src/
    lib.rs, derive.rs, encoding.rs, types.rs, hex.rs, frame.rs, nip46.rs
firmware/                   ESP32 firmware (NIP-46 signing bunker)
  src/
    main.rs               Boot flow → frame dispatch loop
    sign.rs               BIP-340 Schnorr signing/verification
    nvs.rs                NVS read/write for root secret
    provision.rs          Provisioning handler (type 0x01)
    protocol.rs           Serial frame reader/writer
    nip46_handler.rs      NIP-46 dispatch (sign_event, get_public_key)
    button.rs             PRG button (GPIO 0) — long hold approve, short deny
    oled.rs               OLED display helpers
  build.rs, sdkconfig.defaults, rust-toolchain.toml, .cargo/config.toml
provision/                  Host CLI tool
  src/
    main.rs               Mnemonic → secret → serial push
sign-test/                  Signing test harness
  src/
    main.rs               Send NIP-46 requests over serial, display responses
```

## Roadmap

### Phase 1 — Prove the crypto (current spike)

- [x] nsec-tree HMAC-SHA256 derivation on ESP32-S3
- [x] bech32 npub encoding
- [x] Runtime assertion against heartwood-core test vectors
- [x] Display npub on OLED
- [x] Sign a dummy 32-byte hash and display the signature

### Phase 2 — Provisioning

- [x] CLI tool to derive 32-byte root secret from mnemonic + passphrase (offline PC)
- [x] NVS storage for root secret (plaintext — encryption deferred, see excluded)
- [x] First-boot provisioning mode: accept root secret over USB serial
- [x] Subsequent boots read from NVS, skip provisioning
- [x] Show master npub on OLED after boot

### Phase 3 — USB signing oracle

- [x] NIP-46 JSON-RPC over serial (ESP32 is the bunker, Pi is a transport bridge)
- [x] Unified frame protocol: `[magic][type][length][payload][crc32]`
- [x] OLED shows what you're signing (identity, event kind, content preview, countdown)
- [x] Physical button: long hold (>=2s) to approve, short press to deny, 30s timeout
- [x] Per-request child key derivation with Heartwood extension field
- [x] Test harness CLI (`sign-test/`) for end-to-end validation
- [ ] Flash and verify end-to-end signing flow on hardware
- [ ] Integration with heartwood-device on the Pi (new serial transport for NIP-46)

### Phase 4 — Hardening (HSM mode)

- [ ] Disable all wireless radios in firmware (WiFi, BLE, LoRa)
- [ ] Rate limiting (max signs per minute)
- [ ] Audit log on OLED (last N signing events)
- [ ] Zeroize on repeated failed auth attempts
- [ ] `cargo deny` setup — licence checking, security advisories, crate bans

### Phase 5 — Portable signer

- [ ] Cargo feature flags: `hsm` (default, USB-only) vs `portable` (BLE, battery)
- [ ] HSM provisions a child key onto the portable device (`device/mobile-N`)
- [ ] BLE GATT service: NIP-46 request/response profile
- [ ] Phone pairs to device over BLE
- [ ] OLED shows signing request details, button to approve/deny
- [ ] Battery management: deep sleep between requests, wake on BLE connect
- [ ] Child key revocation: HSM increments index, re-provisions replacement device

### Phase 6 — Portable extras (stretch)

- [ ] GPS location stamp on signed events (opt-in, portable mode only)
- [ ] QR code display of npub on OLED
- [ ] Multi-identity: carry several child keys, select on OLED before signing

### Deliberately excluded

- **WiFi signing** — full TCP/IP stack is a liability on any key-holding device. WiFi is never enabled in either mode.
- **Master secret on portable device** — only child keys leave the home HSM. If the portable device is lost, the damage is one branch.
- **LoRa signing** — signing is a response to a request, and the requester needs internet anyway. LoRa solves a problem that doesn't exist for this use case. The SX1262 is never initialised (safe without antenna).
- **Flash encryption / eFuse burning** — permanently locks the chip to one firmware, prevents reuse (e.g. Meshtastic), and risks bricking if anything goes wrong. Physical security is the protection model instead. May revisit on a dedicated production unit.
