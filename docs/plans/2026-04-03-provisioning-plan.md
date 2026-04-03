# Phase 2 — Provisioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure into three independent crates and add USB serial provisioning — mnemonic-derived root secret stored in NVS, displayed on OLED.

**Architecture:** Three independent crates (not a workspace — firmware targets xtensa, others target host). `common` holds shared crypto logic. `firmware` is the ESP32 binary. `provision` is the host CLI that derives from a mnemonic and sends the secret over serial.

**Tech Stack:** Rust, ESP-IDF (v5.2), k256 (BIP-340), bip39/bip32 (mnemonic derivation), esp-idf-svc (NVS), ssd1306 (OLED), stdin/stdout (USB-Serial-JTAG)

---

## File Map

### New files

| File | Responsibility |
|------|----------------|
| `common/Cargo.toml` | Shared crate — crypto deps, no ESP deps |
| `common/src/lib.rs` | Re-exports modules |
| `common/src/derive.rs` | HMAC-SHA256 child derivation (moved from `src/`) |
| `common/src/encoding.rs` | bech32 npub encoding (moved from `src/`) |
| `common/src/types.rs` | TreeRoot, Identity, constants incl. MNEMONIC_PATH (moved from `src/`) |
| `common/src/hex.rs` | hex_encode utility (extracted from `src/sign.rs`) |
| `firmware/Cargo.toml` | ESP32 crate — depends on common |
| `firmware/build.rs` | embuild sysenv (moved from root) |
| `firmware/sdkconfig.defaults` | ESP32-S3 config (moved from root) |
| `firmware/rust-toolchain.toml` | ESP toolchain (moved from root) |
| `firmware/.cargo/config.toml` | xtensa target config (moved from root) |
| `firmware/src/main.rs` | Boot flow: NVS check → provision or display (rewritten) |
| `firmware/src/sign.rs` | BIP-340 signing (moved from `src/`, updated imports) |
| `firmware/src/nvs.rs` | NVS read/write for root secret |
| `firmware/src/provision.rs` | Serial provisioning protocol (ESP32 side) |
| `firmware/src/oled.rs` | OLED display helpers |
| `provision/Cargo.toml` | Host CLI tool — bip39, bip32, serialport |
| `provision/src/main.rs` | Mnemonic → secret → serial push |

### Deleted files

| File | Reason |
|------|--------|
| `src/main.rs` | Moved to `firmware/src/main.rs` |
| `src/derive.rs` | Moved to `common/src/derive.rs` |
| `src/encoding.rs` | Moved to `common/src/encoding.rs` |
| `src/types.rs` | Moved to `common/src/types.rs` |
| `src/sign.rs` | Moved to `firmware/src/sign.rs` |
| `Cargo.toml` | Replaced by per-crate Cargo.toml files |
| `build.rs` | Moved to `firmware/build.rs` |
| `rust-toolchain.toml` | Moved to `firmware/rust-toolchain.toml` |
| `.cargo/config.toml` | Moved to `firmware/.cargo/config.toml` |
| `sdkconfig.defaults` | Moved to `firmware/sdkconfig.defaults` |

### Constants

| Name | Value | Location |
|------|-------|----------|
| `DOMAIN_PREFIX` | `b"nsec-tree\0"` | `common/src/types.rs` |
| `MNEMONIC_PATH` | `"m/44'/1237'/727'/0'/0'"` | `common/src/types.rs` |
| `MAGIC_BYTES` | `[0x48, 0x57]` | `common/src/types.rs` |
| `ACK` | `0x06` | `common/src/types.rs` |
| `NACK` | `0x15` | `common/src/types.rs` |
| `PROVISION_FRAME_LEN` | `38` | `common/src/types.rs` |
| `NVS_NAMESPACE` | `"heartwood"` | `firmware/src/nvs.rs` |
| `NVS_KEY` | `"root_secret"` | `firmware/src/nvs.rs` |

### Test Vectors

| Name | Value | Location |
|------|-------|----------|
| Phase 1 — raw bytes | secret `[0x01..0x20]`, purpose `"persona/test"`, index 0, expected child npub `npub1rx8u4wk9ytu8aak4f9wcaqdgk0lj4rjhdu4j9n7dj2mg68l9cdqs2fjf2t` | `common/src/derive.rs` tests |
| Phase 2 — mnemonic | mnemonic `"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"`, passphrase `""`, expected master npub `npub186c5ke7vjsk98z8qx4ctdrggsl2qlu627g6xvg6yumrj5c5c6etqcfaclx` | `provision/src/main.rs` tests |

---

## Task 1: Create the common crate

**Files:**
- Create: `common/Cargo.toml`
- Create: `common/src/lib.rs`
- Create: `common/src/derive.rs` (from `src/derive.rs`)
- Create: `common/src/encoding.rs` (from `src/encoding.rs`)
- Create: `common/src/types.rs` (from `src/types.rs`)
- Create: `common/src/hex.rs` (extracted from `src/sign.rs`)

- [ ] **Step 1: Create common/Cargo.toml**

```toml
[package]
name = "heartwood-common"
version = "0.1.0"
edition = "2021"
description = "Shared crypto for heartwood-esp32 — derivation, encoding, types"

[dependencies]
k256 = { version = "0.13", default-features = false, features = ["schnorr", "arithmetic"] }
hmac = { version = "0.12", default-features = false }
sha2 = { version = "0.10", default-features = false }
zeroize = { version = "1", default-features = false, features = ["derive"] }
bech32 = { version = "0.11", default-features = false }

[dev-dependencies]
```

- [ ] **Step 2: Create common/src/lib.rs**

```rust
pub mod derive;
pub mod encoding;
pub mod hex;
pub mod types;
```

- [ ] **Step 3: Create common/src/types.rs**

Copy from `src/types.rs` and add the new constants:

```rust
// common/src/types.rs
//
// Shared types and constants for heartwood-esp32.

use zeroize::Zeroize;

/// HMAC domain prefix: "nsec-tree\0" as bytes.
pub const DOMAIN_PREFIX: &[u8] = b"nsec-tree\0";

/// BIP-32 derivation path for mnemonic root.
/// Matches heartwood-core exactly.
pub const MNEMONIC_PATH: &str = "m/44'/1237'/727'/0'/0'";

/// Serial provisioning magic bytes ("HW").
pub const MAGIC_BYTES: [u8; 2] = [0x48, 0x57];

/// Serial ACK byte.
pub const ACK: u8 = 0x06;

/// Serial NACK byte.
pub const NACK: u8 = 0x15;

/// Total provisioning frame length: 2 magic + 32 secret + 4 CRC32.
pub const PROVISION_FRAME_LEN: usize = 38;

/// Master tree root. Owns the secret; zeroes on drop.
pub struct TreeRoot {
    secret: zeroize::Zeroizing<[u8; 32]>,
    pub master_npub: String,
}

impl TreeRoot {
    pub fn new(secret: zeroize::Zeroizing<[u8; 32]>, master_npub: String) -> Self {
        Self { secret, master_npub }
    }

    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Explicitly destroy the root, zeroising the secret.
    pub fn destroy(mut self) {
        self.secret.zeroize();
    }
}

/// A derived child identity.
pub struct Identity {
    pub npub: String,
    pub private_key: zeroize::Zeroizing<[u8; 32]>,
    pub public_key: [u8; 32],
    pub purpose: String,
    pub index: u32,
}

impl Identity {
    /// Zero the private key bytes.
    pub fn zeroize(&mut self) {
        self.private_key.zeroize();
    }
}
```

- [ ] **Step 4: Create common/src/derive.rs**

Copy from `src/derive.rs`, update imports to use `crate::`:

```rust
// common/src/derive.rs
//
// nsec-tree child key derivation via HMAC-SHA256.
// Matches heartwood-core byte-for-byte.

use hmac::{Hmac, Mac};
use k256::schnorr::SigningKey;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::encoding::encode_npub;
use crate::types::{Identity, TreeRoot, DOMAIN_PREFIX};

type HmacSha256 = Hmac<Sha256>;

/// Create a TreeRoot directly from a 32-byte secret (no HMAC intermediate).
pub fn create_tree_root(secret: &[u8; 32]) -> Result<TreeRoot, &'static str> {
    let signing_key =
        SigningKey::from_bytes(secret).map_err(|_| "invalid secret key")?;
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes: [u8; 32] = verifying_key.to_bytes().into();
    let npub = encode_npub(&pubkey_bytes);
    Ok(TreeRoot::new(zeroize::Zeroizing::new(*secret), npub))
}

/// Build the HMAC context message for child key derivation.
fn build_context(purpose: &str, index: u32) -> Vec<u8> {
    let purpose_bytes = purpose.as_bytes();
    let mut msg = Vec::with_capacity(DOMAIN_PREFIX.len() + purpose_bytes.len() + 1 + 4);
    msg.extend_from_slice(DOMAIN_PREFIX);
    msg.extend_from_slice(purpose_bytes);
    msg.push(0x00);
    msg.extend_from_slice(&index.to_be_bytes());
    msg
}

/// Derive a child identity from a TreeRoot.
pub fn derive(root: &TreeRoot, purpose: &str, index: u32) -> Result<Identity, &'static str> {
    let secret = root.secret();
    let mut current_index = index;

    loop {
        let context = build_context(purpose, current_index);

        let mut mac =
            HmacSha256::new_from_slice(secret).map_err(|_| "HMAC init failed")?;
        mac.update(&context);
        let result = mac.finalize();
        let mut derived: [u8; 32] = result.into_bytes().into();

        match SigningKey::from_bytes(&derived) {
            Ok(signing_key) => {
                let verifying_key = signing_key.verifying_key();
                let public_key: [u8; 32] = verifying_key.to_bytes().into();

                return Ok(Identity {
                    npub: encode_npub(&public_key),
                    private_key: zeroize::Zeroizing::new(derived),
                    public_key,
                    purpose: String::from(purpose),
                    index: current_index,
                });
            }
            Err(_) => {
                derived.zeroize();
                if current_index == u32::MAX {
                    return Err("index overflow: no valid key found");
                }
                current_index += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Phase 1 test vector — must match heartwood-core byte-for-byte.
    #[test]
    fn test_child_derivation_matches_heartwood_core() {
        let root_secret: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];

        let root = create_tree_root(&root_secret).unwrap();
        let identity = derive(&root, "persona/test", 0).unwrap();

        assert_eq!(
            identity.npub,
            "npub1rx8u4wk9ytu8aak4f9wcaqdgk0lj4rjhdu4j9n7dj2mg68l9cdqs2fjf2t",
            "derived npub does not match heartwood-core"
        );
    }
}
```

- [ ] **Step 5: Create common/src/encoding.rs**

Copy from `src/encoding.rs` unchanged:

```rust
// common/src/encoding.rs
//
// bech32 npub encoding. Matches heartwood-core byte-for-byte.

use bech32::{Bech32, Hrp};

/// Encode a 32-byte public key as a Nostr `npub1...` bech32 string.
pub fn encode_npub(public_key: &[u8; 32]) -> String {
    let hrp = Hrp::parse("npub").expect("valid hrp");
    bech32::encode::<Bech32>(hrp, public_key).expect("valid encoding")
}
```

- [ ] **Step 6: Create common/src/hex.rs**

Extract `hex_encode` from `src/sign.rs`:

```rust
// common/src/hex.rs
//
// Hex encoding utility.

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Encode bytes as lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize]);
        s.push(HEX_CHARS[(b & 0x0f) as usize]);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0xab]), "00ffab");
        assert_eq!(hex_encode(&[]), "");
    }
}
```

- [ ] **Step 7: Run common tests**

Run: `cd common && cargo test`

Expected:
```
running 2 tests
test derive::tests::test_child_derivation_matches_heartwood_core ... ok
test hex::tests::test_hex_encode ... ok
```

- [ ] **Step 8: Commit**

```bash
git add common/
git commit -m "feat: create common crate with shared derivation and encoding"
```

---

## Task 2: Move firmware into firmware/ subdirectory

**Files:**
- Create: `firmware/Cargo.toml`
- Move: `build.rs` → `firmware/build.rs`
- Move: `sdkconfig.defaults` → `firmware/sdkconfig.defaults`
- Move: `rust-toolchain.toml` → `firmware/rust-toolchain.toml`
- Move: `.cargo/config.toml` → `firmware/.cargo/config.toml`
- Move: `src/sign.rs` → `firmware/src/sign.rs`
- Move: `src/main.rs` → `firmware/src/main.rs` (temporary — will be rewritten in Task 5)
- Delete: `src/derive.rs`, `src/encoding.rs`, `src/types.rs` (now in common)
- Delete: root `Cargo.toml` (replaced by firmware/Cargo.toml)

- [ ] **Step 1: Create firmware directory structure**

```bash
mkdir -p firmware/src firmware/.cargo
```

- [ ] **Step 2: Create firmware/Cargo.toml**

```toml
[package]
name = "heartwood-esp32"
version = "0.1.0"
edition = "2021"
description = "nsec-tree signing device firmware for Heltec WiFi LoRa 32 V4"

[dependencies]
heartwood-common = { path = "../common" }

# Crypto (for signing — derivation is in common)
k256 = { version = "0.13", default-features = false, features = ["schnorr", "arithmetic"] }
signature = { version = "2", default-features = false }
zeroize = { version = "1", default-features = false, features = ["derive"] }

# Serial protocol
crc32fast = "1"

# ESP-IDF std framework
esp-idf-svc = { version = "0.49", features = ["binstart"] }
esp-idf-hal = "0.44"

# OLED display
ssd1306 = "0.9"
embedded-graphics = "0.8"

# Logging
log = "0.4"

[build-dependencies]
embuild = "0.32"
```

- [ ] **Step 3: Move build files**

```bash
mv build.rs firmware/build.rs
mv sdkconfig.defaults firmware/sdkconfig.defaults
mv rust-toolchain.toml firmware/rust-toolchain.toml
mv .cargo/config.toml firmware/.cargo/config.toml
rmdir .cargo
```

- [ ] **Step 4: Move src/sign.rs to firmware**

Copy `src/sign.rs` to `firmware/src/sign.rs`, updating `hex_encode` to use common:

```rust
// firmware/src/sign.rs
//
// BIP-340 Schnorr signing and verification via k256.

use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use signature::hazmat::{PrehashSigner, PrehashVerifier};

/// Sign a 32-byte hash with a BIP-340 Schnorr key. Returns a 64-byte signature.
pub fn sign_hash(private_key: &[u8; 32], hash: &[u8; 32]) -> Result<[u8; 64], &'static str> {
    let signing_key =
        SigningKey::from_bytes(private_key).map_err(|_| "invalid signing key")?;
    let sig: Signature = signing_key
        .sign_prehash(hash)
        .map_err(|_| "signing failed")?;
    Ok(sig.to_bytes())
}

/// Verify a BIP-340 Schnorr signature against a public key and hash.
pub fn verify_signature(
    public_key: &[u8; 32],
    hash: &[u8; 32],
    sig_bytes: &[u8; 64],
) -> Result<(), &'static str> {
    let vk =
        VerifyingKey::from_bytes(public_key).map_err(|_| "invalid verifying key")?;
    let sig = Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| "invalid signature bytes")?;
    vk.verify_prehash(hash, &sig)
        .map_err(|_| "signature verification failed")
}
```

- [ ] **Step 5: Create temporary firmware/src/main.rs**

A placeholder that verifies common compiles with firmware. This will be fully rewritten in Task 5.

```rust
// firmware/src/main.rs — temporary, rewritten in Task 5

mod sign;

use heartwood_common::derive;
use heartwood_common::hex;

fn main() {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("Heartwood ESP32 — Phase 2 (provisioning)");

    // Smoke test: derive from test vector to prove common crate works
    let test_secret: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    let root = derive::create_tree_root(&test_secret).expect("root creation failed");
    log::info!("Root npub: {}", root.master_npub);

    let identity = derive::derive(&root, "persona/test", 0).expect("derivation failed");
    log::info!("Child npub: {}", identity.npub);
    log::info!("Hex test: {}", hex::hex_encode(&[0xde, 0xad]));

    root.destroy();

    loop {
        esp_idf_hal::delay::FreeRtos::delay_ms(1000);
    }
}
```

- [ ] **Step 6: Delete old files**

```bash
rm -rf src/
rm Cargo.toml
rm Cargo.lock
```

- [ ] **Step 7: Verify structure**

```bash
ls -la firmware/
ls -la firmware/src/
ls -la firmware/.cargo/
ls -la common/
ls -la common/src/
```

Expected: all files in place, no orphans in root.

- [ ] **Step 8: Verify common still compiles**

Run: `cd common && cargo test`

Expected: all tests pass (same as Task 1 Step 7).

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "refactor: move firmware to firmware/ subdirectory, use common crate"
```

---

## Task 3: Create provision CLI — mnemonic derivation

**Files:**
- Create: `provision/Cargo.toml`
- Create: `provision/src/main.rs`

- [ ] **Step 1: Create provision/Cargo.toml**

```toml
[package]
name = "heartwood-provision"
version = "0.1.0"
edition = "2021"
description = "Provisioning CLI for heartwood-esp32 — derives root secret from mnemonic"

[dependencies]
heartwood-common = { path = "../common" }

# BIP-39 / BIP-32 derivation
bip39 = "2"
bip32 = "0.5"

# Serial communication
serialport = "4"
crc32fast = "1"

# User input
rpassword = "5"

# Crypto cleanup
zeroize = { version = "1", features = ["derive"] }

# CLI
clap = { version = "4", features = ["derive"] }
```

- [ ] **Step 2: Write provision/src/main.rs with derivation and test**

```rust
// provision/src/main.rs
//
// Provisioning CLI: mnemonic → root secret → serial push to ESP32.

use std::io::{self, Read, Write};
use std::time::Duration;

use clap::Parser;
use zeroize::Zeroize;

use heartwood_common::derive::create_tree_root;
use heartwood_common::hex::hex_encode;
use heartwood_common::types::{MAGIC_BYTES, MNEMONIC_PATH, ACK, NACK, PROVISION_FRAME_LEN};

#[derive(Parser)]
#[command(name = "heartwood-provision")]
#[command(about = "Provision a heartwood-esp32 device with a root secret")]
struct Cli {
    /// Serial port (e.g. /dev/ttyUSB0 or /dev/cu.usbserial-*)
    #[arg(short, long)]
    port: String,

    /// Baud rate (default 115200)
    #[arg(short, long, default_value_t = 115200)]
    baud: u32,
}

/// Derive 32-byte root secret from a BIP-39 mnemonic + optional passphrase.
///
/// Path: mnemonic → BIP-39 seed (PBKDF2) → BIP-32 at m/44'/1237'/727'/0'/0' → 32 bytes.
/// Matches heartwood-core exactly.
fn derive_root_secret(mnemonic: &str, passphrase: &str) -> Result<[u8; 32], String> {
    let parsed: bip39::Mnemonic = mnemonic
        .parse()
        .map_err(|_| "invalid mnemonic".to_string())?;

    let seed = zeroize::Zeroizing::new(parsed.to_seed(passphrase));

    let master = bip32::XPrv::new(*seed)
        .map_err(|e| format!("BIP-32 master key failed: {e}"))?;

    let path: bip32::DerivationPath = MNEMONIC_PATH
        .parse()
        .map_err(|e| format!("invalid derivation path: {e}"))?;

    let child = path
        .iter()
        .try_fold(master, |key, child_num| key.derive_child(child_num))
        .map_err(|e| format!("BIP-32 derivation failed: {e}"))?;

    let mut private_key_bytes = zeroize::Zeroizing::new(child.to_bytes());
    let result: [u8; 32] = *private_key_bytes;
    private_key_bytes.zeroize();

    Ok(result)
}

/// Build the 38-byte provisioning frame: [magic][secret][crc32].
fn build_frame(secret: &[u8; 32]) -> [u8; PROVISION_FRAME_LEN] {
    let crc = crc32fast::hash(secret);
    let mut frame = [0u8; PROVISION_FRAME_LEN];
    frame[0..2].copy_from_slice(&MAGIC_BYTES);
    frame[2..34].copy_from_slice(secret);
    frame[34..38].copy_from_slice(&crc.to_be_bytes());
    frame
}

fn main() {
    let cli = Cli::parse();

    // Read mnemonic (hidden input)
    let mnemonic = rpassword::prompt_password("Enter mnemonic: ")
        .expect("failed to read mnemonic");

    // Read passphrase (hidden input, optional)
    let passphrase = rpassword::prompt_password("Enter passphrase (empty for none): ")
        .expect("failed to read passphrase");

    // Derive root secret
    let mut root_secret = derive_root_secret(&mnemonic, &passphrase)
        .expect("derivation failed");

    // Show master npub for confirmation
    let root = create_tree_root(&root_secret).expect("invalid root secret");
    println!("\nDerived master npub: {}", root.master_npub);
    root.destroy();

    // Confirm
    print!("Send to device? [y/N]: ");
    io::stdout().flush().unwrap();
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm).unwrap();
    if confirm.trim().to_lowercase() != "y" {
        root_secret.zeroize();
        println!("Aborted.");
        return;
    }

    // Build frame and send
    let frame = build_frame(&root_secret);
    root_secret.zeroize();

    println!("Opening {}...", cli.port);
    let mut port = serialport::new(&cli.port, cli.baud)
        .timeout(Duration::from_secs(30))
        .open()
        .unwrap_or_else(|e| {
            eprintln!("Failed to open serial port: {e}");
            std::process::exit(1);
        });

    // Wait a moment for device to be ready
    std::thread::sleep(Duration::from_secs(2));

    println!("Sending...");
    port.write_all(&frame).expect("failed to write to serial port");
    port.flush().expect("failed to flush serial port");

    // Scan for ACK/NACK byte.
    // ESP-IDF log output shares the same USB-Serial-JTAG channel, so we may
    // see log text before the response byte. Read byte-by-byte and look for
    // our protocol bytes.
    let mut byte = [0u8; 1];
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if std::time::Instant::now() > deadline {
            eprintln!("Timeout waiting for response from device.");
            std::process::exit(1);
        }
        match port.read(&mut byte) {
            Ok(1) => match byte[0] {
                ACK => {
                    println!("ACK received. Root secret provisioned.");
                    break;
                }
                NACK => {
                    eprintln!("NACK received — device rejected the secret (CRC error or NVS write failure).");
                    std::process::exit(1);
                }
                _ => {} // skip log output bytes
            },
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
            Err(e) => {
                eprintln!("Serial read error: {e}");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Phase 2 test vector — standard BIP-39 test mnemonic through full derivation path.
    /// Must produce the same result as heartwood-core's from_mnemonic().
    #[test]
    fn test_mnemonic_derivation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let root_secret = derive_root_secret(mnemonic, "").unwrap();
        let root = create_tree_root(&root_secret).unwrap();

        assert_eq!(
            root.master_npub,
            "npub186c5ke7vjsk98z8qx4ctdrggsl2qlu627g6xvg6yumrj5c5c6etqcfaclx",
            "mnemonic derivation does not match expected npub"
        );

        assert_eq!(
            hex_encode(&root_secret),
            "cc92d213b5eccd19eb85c12c2cf6fd168f27c2cc347c51a7c4c62ac67795fc65",
            "derived secret does not match expected hex"
        );

        root.destroy();
    }

    /// Passphrase changes the derived secret.
    #[test]
    fn test_mnemonic_with_passphrase_differs() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let without = derive_root_secret(mnemonic, "").unwrap();
        let with = derive_root_secret(mnemonic, "test-passphrase").unwrap();

        assert_ne!(without, with, "passphrase must change the derived secret");
    }

    /// Frame structure: [0x48, 0x57] + 32 bytes + CRC32 big-endian = 38 bytes.
    #[test]
    fn test_build_frame() {
        let secret = [0xaa; 32];
        let frame = build_frame(&secret);

        assert_eq!(frame.len(), PROVISION_FRAME_LEN);
        assert_eq!(&frame[0..2], &MAGIC_BYTES);
        assert_eq!(&frame[2..34], &secret);

        // CRC32 of the secret must match
        let expected_crc = crc32fast::hash(&secret);
        let frame_crc = u32::from_be_bytes([frame[34], frame[35], frame[36], frame[37]]);
        assert_eq!(frame_crc, expected_crc);
    }
}
```

- [ ] **Step 3: Run provision tests**

Run: `cd provision && cargo test`

Expected:
```
running 3 tests
test tests::test_mnemonic_derivation ... ok
test tests::test_mnemonic_with_passphrase_differs ... ok
test tests::test_build_frame ... ok
```

- [ ] **Step 4: Verify provision CLI builds**

Run: `cd provision && cargo build`

Expected: compiles successfully.

- [ ] **Step 5: Commit**

```bash
git add provision/
git commit -m "feat: add provisioning CLI with mnemonic derivation and serial protocol"
```

---

## Task 4: Add NVS module to firmware

**Files:**
- Create: `firmware/src/nvs.rs`

- [ ] **Step 1: Create firmware/src/nvs.rs**

```rust
// firmware/src/nvs.rs
//
// NVS storage for root secret. Plaintext NVS — encryption deferred.

use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};

const NVS_NAMESPACE: &str = "heartwood";
const NVS_KEY: &str = "root_secret";

/// Read the root secret from NVS. Returns None if not provisioned.
pub fn read_root_secret(
    nvs_partition: EspDefaultNvsPartition,
) -> Result<(EspNvs<NvsDefault>, Option<[u8; 32]>), &'static str> {
    let nvs = EspNvs::new(nvs_partition, NVS_NAMESPACE, true)
        .map_err(|_| "failed to open NVS namespace")?;

    let mut buf = [0u8; 32];
    match nvs.get_blob(NVS_KEY, &mut buf) {
        Ok(Some(bytes)) => {
            if bytes.len() == 32 {
                Ok((nvs, Some(buf)))
            } else {
                Ok((nvs, None))
            }
        }
        Ok(None) => Ok((nvs, None)),
        Err(_) => Ok((nvs, None)),
    }
}

/// Write the root secret to NVS.
pub fn write_root_secret(
    nvs: &mut EspNvs<NvsDefault>,
    secret: &[u8; 32],
) -> Result<(), &'static str> {
    nvs.set_blob(NVS_KEY, secret)
        .map_err(|_| "failed to write root secret to NVS")
}
```

- [ ] **Step 2: Commit**

```bash
git add firmware/src/nvs.rs
git commit -m "feat: add NVS module for root secret storage"
```

---

## Task 5: Add serial provisioning to firmware

**Files:**
- Create: `firmware/src/provision.rs`

- [ ] **Step 1: Create firmware/src/provision.rs**

```rust
// firmware/src/provision.rs
//
// Serial provisioning protocol (ESP32 side).
// Reads from stdin (USB-Serial-JTAG on Heltec V4) for a 38-byte frame.

use heartwood_common::types::{ACK, MAGIC_BYTES, NACK};

/// Listen on stdin for a provisioning frame. Blocks until a valid frame is received.
/// Returns the 32-byte root secret.
///
/// Uses stdin/stdout because the Heltec V4's USB-C connects to the ESP32-S3's
/// USB-Serial-JTAG peripheral, not UART0. ESP-IDF maps stdin/stdout to this
/// peripheral automatically — no GPIO pin configuration needed.
pub fn wait_for_secret() -> [u8; 32] {
    use std::io::{Read, Write};

    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();

    loop {
        // Wait for first magic byte
        let mut byte = [0u8; 1];
        if stdin.read_exact(&mut byte).is_ok() && byte[0] == MAGIC_BYTES[0] {
            // Check second magic byte
            if stdin.read_exact(&mut byte).is_ok() && byte[0] == MAGIC_BYTES[1] {
                // Read remaining 36 bytes (32 secret + 4 CRC)
                let mut payload = [0u8; 36];
                if stdin.read_exact(&mut payload).is_ok() {
                    let secret = &payload[0..32];
                    let frame_crc = u32::from_be_bytes([payload[32], payload[33], payload[34], payload[35]]);
                    let computed_crc = crc32fast::hash(secret);

                    if frame_crc == computed_crc {
                        // Send ACK before logging — log output shares stdout
                        // and would push the ACK byte further from where the
                        // CLI expects it.
                        let _ = stdout.write_all(&[ACK]);
                        let _ = stdout.flush();
                        log::info!("Provisioning frame received — CRC OK");
                        let mut result = [0u8; 32];
                        result.copy_from_slice(secret);
                        return result;
                    } else {
                        log::warn!("Provisioning frame CRC mismatch");
                        let _ = stdout.write_all(&[NACK]);
                        let _ = stdout.flush();
                    }
                }
            }
        }
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add firmware/src/provision.rs
git commit -m "feat: add serial provisioning protocol to firmware"
```

---

## Task 6: Extract OLED helpers from firmware

**Files:**
- Create: `firmware/src/oled.rs`

- [ ] **Step 1: Create firmware/src/oled.rs**

```rust
// firmware/src/oled.rs
//
// OLED display helpers for the Heltec V4 built-in SSD1306 (128x64).

use embedded_graphics::mono_font::ascii::FONT_5X8;
use embedded_graphics::mono_font::MonoTextStyleBuilder;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::text::Text;
use esp_idf_hal::delay::FreeRtos;
use esp_idf_hal::gpio::{AnyOutputPin, PinDriver};
use esp_idf_hal::i2c::I2cDriver;
use ssd1306::mode::BufferedGraphicsMode;
use ssd1306::prelude::*;
use ssd1306::rotation::DisplayRotation;
use ssd1306::size::DisplaySize128x64;
use ssd1306::I2CDisplayInterface;
use ssd1306::Ssd1306;

/// 128px / 5px per char = 25 chars per line.
const CHARS_PER_LINE: usize = 25;

pub type Display<'a> = Ssd1306<
    ssd1306::prelude::I2CInterface<I2cDriver<'a>>,
    DisplaySize128x64,
    BufferedGraphicsMode<DisplaySize128x64>,
>;

/// Initialise the OLED: reset pin toggle, I2C setup, display init.
pub fn init<'a>(
    i2c: I2cDriver<'a>,
    rst_pin: AnyOutputPin,
) -> Display<'a> {
    // Toggle reset pin
    let mut rst = PinDriver::output(rst_pin).expect("RST pin");
    rst.set_low().ok();
    FreeRtos::delay_ms(10);
    rst.set_high().ok();
    FreeRtos::delay_ms(10);

    let interface = I2CDisplayInterface::new(i2c);
    let mut display = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate0)
        .into_buffered_graphics_mode();
    display.init().expect("OLED init failed");
    display.clear_buffer();
    display
}

/// Display an npub on the OLED, split across lines.
pub fn show_npub(display: &mut Display<'_>, npub: &str) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    let mut y = 8i32;
    let mut pos = 0;
    while pos < npub.len() {
        let end = core::cmp::min(pos + CHARS_PER_LINE, npub.len());
        let line = &npub[pos..end];
        Text::new(line, Point::new(0, y), text_style)
            .draw(display)
            .ok();
        y += 10;
        pos = end;
    }

    display.flush().expect("OLED flush failed");
}

/// Display "Awaiting secret..." on the OLED.
pub fn show_awaiting(display: &mut Display<'_>) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    Text::new("Awaiting secret...", Point::new(0, 30), text_style)
        .draw(display)
        .ok();

    display.flush().expect("OLED flush failed");
}

/// Display an error message on the OLED.
pub fn show_error(display: &mut Display<'_>, msg: &str) {
    display.clear_buffer();
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_5X8)
        .text_color(BinaryColor::On)
        .build();

    Text::new(msg, Point::new(0, 30), text_style)
        .draw(display)
        .ok();

    display.flush().expect("OLED flush failed");
}
```

- [ ] **Step 2: Commit**

```bash
git add firmware/src/oled.rs
git commit -m "feat: extract OLED display helpers"
```

---

## Task 7: Rewrite firmware boot flow

**Files:**
- Modify: `firmware/src/main.rs` (full rewrite)

- [ ] **Step 1: Rewrite firmware/src/main.rs**

```rust
// firmware/src/main.rs
//
// Heartwood ESP32 — boot flow.
// Checks NVS for a stored root secret. If found, derives master npub and
// displays it. If not found, enters provisioning mode and waits for the
// secret over USB serial.

mod nvs;
mod oled;
mod provision;
mod sign;

use esp_idf_hal::i2c::{I2cConfig, I2cDriver};
use esp_idf_hal::prelude::*;
use esp_idf_svc::nvs::EspDefaultNvsPartition;

use heartwood_common::derive;

fn main() {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("Heartwood ESP32 — Phase 2 (provisioning)");

    let peripherals = Peripherals::take().expect("failed to take peripherals");

    // --- OLED init ---
    let i2c_config = I2cConfig::new().baudrate(400.kHz().into());
    let i2c = I2cDriver::new(
        peripherals.i2c0,
        peripherals.pins.gpio17, // SDA
        peripherals.pins.gpio18, // SCL
        &i2c_config,
    )
    .expect("I2C init failed");

    let mut display = oled::init(i2c, peripherals.pins.gpio21.into());

    // --- NVS: check for stored secret ---
    let nvs_partition = EspDefaultNvsPartition::take().expect("failed to take NVS partition");
    let (mut nvs, stored_secret) = nvs::read_root_secret(nvs_partition)
        .expect("NVS read failed");

    let root_secret = match stored_secret {
        Some(secret) => {
            log::info!("Booted with stored identity");
            secret
        }
        None => {
            log::info!("No stored secret — entering provisioning mode");
            oled::show_awaiting(&mut display);

            // Read from stdin — ESP-IDF maps this to USB-Serial-JTAG on the Heltec V4.
            // No UART driver or GPIO pins needed.
            let secret = provision::wait_for_secret();

            // Store in NVS
            match nvs::write_root_secret(&mut nvs, &secret) {
                Ok(()) => log::info!("Provisioned — identity stored in NVS"),
                Err(e) => {
                    log::error!("NVS write failed: {e}");
                    oled::show_error(&mut display, "NVS write failed");
                    loop {
                        esp_idf_hal::delay::FreeRtos::delay_ms(1000);
                    }
                }
            }

            secret
        }
    };

    // --- Derive and display master npub ---
    let root = derive::create_tree_root(&root_secret).expect("root creation failed");
    log::info!("Master npub: {}", root.master_npub);

    oled::show_npub(&mut display, &root.master_npub);

    root.destroy();

    // Idle loop — display stays on
    loop {
        esp_idf_hal::delay::FreeRtos::delay_ms(1000);
    }
}
```

- [ ] **Step 2: Verify firmware structure is complete**

```bash
ls firmware/src/
```

Expected: `main.rs  nvs.rs  oled.rs  provision.rs  sign.rs`

- [ ] **Step 3: Verify firmware compiles (requires ESP toolchain)**

Run: `cd firmware && cargo build`

If the ESP toolchain is not installed, this is expected to fail. Install with:
```bash
cargo install espup ldproxy espflash
espup install
source ~/export-esp.sh
```

Then retry `cd firmware && cargo build`.

- [ ] **Step 4: Commit**

```bash
git add firmware/src/main.rs
git commit -m "feat: rewrite firmware boot flow with NVS check and provisioning"
```

---

## Task 8: Update documentation

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update README.md**

Update the Build, Structure, and Phase 2 sections to reflect the new crate layout:

- Build commands now reference `cd firmware && cargo build` and `cd provision && cargo build`
- Structure section shows the three-crate layout
- Phase 2 items are checked off
- Flash command: `cd firmware && espflash flash --monitor target/xtensa-esp32s3-espidf/debug/heartwood-esp32`

Update the Structure section:
```
common/                     Shared crypto (derivation, encoding, types)
  src/
    lib.rs, derive.rs, encoding.rs, types.rs, hex.rs
firmware/                   ESP32 firmware
  src/
    main.rs               Boot flow: NVS check → provision or display
    sign.rs               BIP-340 Schnorr signing/verification
    nvs.rs                NVS read/write for root secret
    provision.rs          Serial provisioning protocol (ESP32 side)
    oled.rs               OLED display helpers
  build.rs, sdkconfig.defaults, rust-toolchain.toml, .cargo/config.toml
provision/                  Host CLI tool
  src/
    main.rs               Mnemonic → secret → serial push
```

Update the Build section:
```bash
cd common && cargo test                    # run shared crate tests
cd provision && cargo build                # build provisioning CLI
cd firmware && cargo build                 # build ESP32 firmware (needs ESP toolchain)
cd firmware && espflash flash --monitor target/xtensa-esp32s3-espidf/debug/heartwood-esp32
```

Check off Phase 2 items:
```
### Phase 2 — Provisioning
- [x] CLI tool to derive 32-byte root secret from mnemonic + passphrase (offline PC)
- [x] NVS storage for root secret (encrypted flash partition)
- [x] First-boot provisioning mode: accept root secret over USB serial
- [x] Subsequent boots read from NVS, skip provisioning
- [x] Show master npub on OLED after boot
```

- [ ] **Step 2: Update CLAUDE.md**

Update the Build & flash section to reflect the new crate structure:

```
## Build & flash

Three independent crates — build each from its own directory:

    cd common && cargo test                    # shared crypto tests
    cd provision && cargo build                # host CLI tool
    cd firmware && cargo build                 # ESP32 firmware (needs ESP toolchain)
    cd firmware && espflash flash --monitor target/xtensa-esp32s3-espidf/debug/heartwood-esp32

Requires the ESP Rust toolchain for firmware: `espup install`, then `source ~/export-esp.sh`.
```

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: update for Phase 2 three-crate structure"
```

---

## Task 9: End-to-end verification

- [ ] **Step 1: Run all host tests**

```bash
cd common && cargo test && cd ../provision && cargo test
```

Expected: all tests pass.

- [ ] **Step 2: Build firmware (if ESP toolchain available)**

```bash
cd firmware && source ~/export-esp.sh && cargo build
```

Expected: compiles for xtensa-esp32s3-espidf.

- [ ] **Step 3: Flash and test provisioning (if device connected)**

Flash the firmware (without `--monitor` so the port is released after flashing):
```bash
cd firmware && espflash flash target/xtensa-esp32s3-espidf/debug/heartwood-esp32
```

The device reboots after flashing. Wait a few seconds for boot, then confirm the OLED shows `Awaiting secret...`.

Run the provision CLI:
```bash
cd provision && cargo run -- --port /dev/cu.usbserial-*
```

Enter mnemonic: `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`
Enter passphrase: (empty)
Confirm: `y`

Expected:
- CLI shows: `Derived master npub: npub186c5ke7vjsk98z8qx4ctdrggsl2qlu627g6xvg6yumrj5c5c6etqcfaclx`
- CLI shows: `ACK received. Root secret provisioned.`
- Serial monitor shows: `Provisioned — identity stored in NVS`
- OLED displays the master npub

- [ ] **Step 4: Reboot device to verify NVS persistence**

Power-cycle the device. Expected:
- Serial shows: `Booted with stored identity`
- Serial shows: `Master npub: npub186c5ke7vjsk98z8qx4ctdrggsl2qlu627g6xvg6yumrj5c5c6etqcfaclx`
- OLED shows the same npub

- [ ] **Step 5: Final commit if any fixes were needed**

```bash
git add -A
git commit -m "fix: adjustments from end-to-end testing"
```
