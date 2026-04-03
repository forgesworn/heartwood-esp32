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
| LoRa | SX1262 (reserved for future use) |
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

```bash
cargo build
```

## Flash & monitor

```bash
espflash flash --monitor target/xtensa-esp32s3-espidf/debug/heartwood-esp32
```

Serial output will show:
```
Heartwood ESP32 — nsec-tree signing token spike
Root npub: npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m
Child npub: npub1rx8u4wk9ytu8aak4f9wcaqdgk0lj4rjhdu4j9n7dj2mg68l9cdqs2fjf2t
Protocol vector verified — npub matches heartwood-core
npub displayed on OLED
```

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
Cargo.toml              ESP-IDF std project
build.rs                embuild sysenv
sdkconfig.defaults      ESP32-S3, PSRAM, 16KB stack
rust-toolchain.toml     esp channel
.cargo/config.toml      xtensa-esp32s3-espidf target
src/
  main.rs               Entry point: init OLED, derive, display
  derive.rs             HMAC-SHA256 child derivation (matches heartwood-core)
  encoding.rs           bech32 npub encoding
  types.rs              TreeRoot, Identity structs
```

## Roadmap

### Phase 1 — Prove the crypto (current spike)

- [x] nsec-tree HMAC-SHA256 derivation on ESP32-S3
- [x] bech32 npub encoding
- [x] Runtime assertion against heartwood-core test vectors
- [x] Display npub on OLED
- [ ] Sign a dummy 32-byte hash and display the signature

### Phase 2 — Provisioning

- [ ] CLI tool to derive 32-byte root secret from mnemonic + passphrase (offline PC)
- [ ] NVS storage for root secret (encrypted flash partition)
- [ ] First-boot provisioning mode: accept root secret over USB serial
- [ ] Subsequent boots read from NVS, skip provisioning
- [ ] Show master npub on OLED after boot

### Phase 3 — USB signing oracle

- [ ] Serial protocol: Pi sends signing requests, ESP32 responds with signatures
- [ ] OLED shows what you're signing (event kind, content preview, target pubkey)
- [ ] Physical button to approve/deny each request
- [ ] Integration with heartwood-device on the Pi (new serial transport for NIP-46)
- [ ] Timeout: unsigned requests expire after N seconds

### Phase 4 — Hardening (HSM mode)

- [ ] Disable all wireless radios in firmware (WiFi, BLE, LoRa)
- [ ] Disable JTAG debugging
- [ ] Rate limiting (max signs per minute)
- [ ] Audit log on OLED (last N signing events)
- [ ] Tamper detection (voltage glitch monitoring if feasible)
- [ ] Zeroize on repeated failed auth attempts

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
- [ ] LoRa relay: phone has no signal, ESP32 reaches a home relay node via SX1262
- [ ] Multi-identity: carry several child keys, select on OLED before signing

### Deliberately excluded

- **WiFi signing** — full TCP/IP stack is a liability on any key-holding device. WiFi is never enabled in either mode.
- **Master secret on portable device** — only child keys leave the home HSM. If the portable device is lost, the damage is one branch.
