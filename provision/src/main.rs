// provision/src/main.rs
//
// Provisioning CLI: mnemonic → root secret → serial push to ESP32.

use std::io::{self, Read, Write};
use std::time::Duration;

use clap::Parser;
use zeroize::Zeroize;

use heartwood_common::derive::create_tree_root;
use heartwood_common::frame;
use heartwood_common::types::{MNEMONIC_PATH, FRAME_TYPE_ACK, FRAME_TYPE_NACK, FRAME_TYPE_PROVISION};

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

    /// Label for this master (e.g. "primary", "ForgeSworn")
    #[arg(short, long, default_value = "default")]
    label: String,

    /// Provisioning mode: tree-mnemonic (default), tree-nsec, bunker
    #[arg(short, long, default_value = "tree-mnemonic")]
    mode: String,
}

/// Decode an nsec1... bech32 string to 32 raw secret bytes.
fn decode_nsec(nsec: &str) -> Result<[u8; 32], String> {
    use bech32::primitives::decode::CheckedHrpstring;
    use bech32::Bech32;

    let parsed = CheckedHrpstring::new::<Bech32>(nsec)
        .map_err(|e| format!("invalid nsec bech32: {e}"))?;

    let hrp = parsed.hrp();
    if hrp.as_str() != "nsec" {
        return Err(format!("expected nsec prefix, got {}", hrp));
    }

    let data: Vec<u8> = parsed.byte_iter().collect();
    if data.len() != 32 {
        return Err(format!("nsec decoded to {} bytes, expected 32", data.len()));
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&data);
    Ok(secret)
}

/// Derive an nsec-tree root from a raw nsec via HMAC-SHA256.
/// Matches heartwood-core's from_nsec() — the nsec bytes are HMACed
/// with the nsec-tree domain prefix to produce a new root.
fn nsec_to_tree_root(nsec_bytes: &[u8; 32]) -> Result<[u8; 32], String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(b"nsec-tree\0")
        .map_err(|_| "HMAC init failed".to_string())?;
    mac.update(nsec_bytes);
    let result = mac.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&result.into_bytes());
    Ok(root)
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

/// Build the provisioning frame using the unified frame protocol.
///
/// Extended format: [mode_u8][label_len_u8][label...][secret_32]
/// Legacy format (label="default", mode=tree-mnemonic): just [secret_32]
fn build_provision_frame(secret: &[u8; 32], label: &str, mode: &str) -> Vec<u8> {
    let mode_byte: u8 = match mode {
        "bunker" => 0,
        "tree-mnemonic" => 1,
        "tree-nsec" => 2,
        _ => 1, // default to tree-mnemonic
    };

    // Use extended format if label is not "default" or mode is not tree-mnemonic.
    if label == "default" && mode_byte == 1 {
        // Legacy format — bare 32-byte secret.
        frame::build_frame(FRAME_TYPE_PROVISION, secret)
            .expect("provision frame should never exceed max payload")
    } else {
        // Extended format: [mode][label_len][label...][secret]
        let label_bytes = label.as_bytes();
        let label_len = label_bytes.len().min(32) as u8;
        let mut payload = Vec::with_capacity(2 + label_len as usize + 32);
        payload.push(mode_byte);
        payload.push(label_len);
        payload.extend_from_slice(&label_bytes[..label_len as usize]);
        payload.extend_from_slice(secret);
        frame::build_frame(FRAME_TYPE_PROVISION, &payload)
            .expect("provision frame should never exceed max payload")
    }
}

fn main() {
    let cli = Cli::parse();

    // Derive the 32-byte secret based on provisioning mode.
    let mut root_secret = match cli.mode.as_str() {
        "bunker" => {
            // Raw nsec — stored as-is, no tree derivation.
            let nsec = rpassword::prompt_password("Enter nsec (nsec1...): ")
                .expect("failed to read nsec");
            let secret = decode_nsec(nsec.trim()).expect("invalid nsec");
            println!("\nMode: bunker (raw nsec, no tree derivation)");
            secret
        }
        "tree-nsec" => {
            // Existing nsec → HMAC → tree root.
            let nsec = rpassword::prompt_password("Enter nsec (nsec1...): ")
                .expect("failed to read nsec");
            let nsec_bytes = decode_nsec(nsec.trim()).expect("invalid nsec");
            let secret = nsec_to_tree_root(&nsec_bytes).expect("tree-nsec derivation failed");
            println!("\nMode: tree-nsec (nsec → HMAC → tree root)");
            secret
        }
        "tree-mnemonic" | _ => {
            // BIP-39 mnemonic → BIP-32 derivation → root secret.
            let mnemonic = rpassword::prompt_password("Enter mnemonic: ")
                .expect("failed to read mnemonic");
            let passphrase = rpassword::prompt_password("Enter passphrase (empty for none): ")
                .expect("failed to read passphrase");
            let secret = derive_root_secret(&mnemonic, &passphrase)
                .expect("derivation failed");
            println!("\nMode: tree-mnemonic (BIP-39 → BIP-32 → tree root)");
            secret
        }
    };

    // Show the pubkey for confirmation.
    // For bunker mode, this is the npub of the raw nsec.
    // For tree modes, this is the master npub of the tree root.
    let root = create_tree_root(&root_secret).expect("invalid root secret");
    println!("Pubkey: {}", root.master_npub);
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
    let frame = build_provision_frame(&root_secret, &cli.label, &cli.mode);
    root_secret.zeroize();

    println!("Opening {}...", cli.port);
    let mut port = serialport::new(&cli.port, cli.baud)
        .timeout(Duration::from_secs(30))
        .open()
        .unwrap_or_else(|e| {
            eprintln!("Failed to open serial port: {e}");
            std::process::exit(1);
        });

    // Disable DTR/RTS — toggling these resets the ESP32-S3 USB-Serial-JTAG
    port.write_data_terminal_ready(false).ok();
    port.write_request_to_send(false).ok();

    // Wait for device to be ready (may have just rebooted from port open)
    println!("Waiting for device...");
    std::thread::sleep(Duration::from_secs(4));

    println!("Sending...");
    port.write_all(&frame).expect("failed to write to serial port");
    port.flush().expect("failed to flush serial port");

    // Read the framed ACK/NACK response.
    // The firmware sends a full frame (magic + type + length + CRC).
    // ESP-IDF log output shares the same USB-Serial-JTAG channel, so we
    // accumulate bytes and try to parse a frame.
    let mut buf: Vec<u8> = Vec::new();
    let mut read_chunk = [0u8; 256];
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if std::time::Instant::now() > deadline {
            eprintln!("Timeout waiting for response from device.");
            std::process::exit(1);
        }
        match port.read(&mut read_chunk) {
            Ok(n) if n > 0 => buf.extend_from_slice(&read_chunk[..n]),
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
            Err(e) => {
                eprintln!("Serial read error: {e}");
                std::process::exit(1);
            }
        }
        // Try to parse a frame from accumulated bytes.
        match frame::parse_frame(&buf) {
            Ok(f) if f.frame_type == FRAME_TYPE_ACK => {
                println!("ACK received. Master '{}' provisioned.", cli.label);
                break;
            }
            Ok(f) if f.frame_type == FRAME_TYPE_NACK => {
                eprintln!("NACK received — device rejected the provision (CRC error or NVS write failure).");
                std::process::exit(1);
            }
            Ok(f) => {
                eprintln!("Unexpected frame type: 0x{:02x}", f.frame_type);
                std::process::exit(1);
            }
            Err(frame::FrameError::TooShort) => {} // keep reading
            Err(_) => {
                // Bad frame — skip to next magic bytes.
                if let Some(pos) = buf.windows(2).position(|w| w == &[0x48, 0x57]) {
                    if pos > 0 {
                        buf.drain(..pos);
                    }
                } else {
                    buf.clear();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heartwood_common::hex::hex_encode;

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
        let with_pass = derive_root_secret(mnemonic, "test-passphrase").unwrap();

        assert_ne!(without, with_pass, "passphrase must change the derived secret");
    }

    /// Frame structure: 2 magic + 1 type + 2 length + 32 payload + 4 CRC = 41 bytes.
    #[test]
    fn test_build_provision_frame() {
        let secret = [0xaa; 32];
        let frame_bytes = build_provision_frame(&secret, "default", "tree-mnemonic");

        // New format: 2 magic + 1 type + 2 length + 32 payload + 4 CRC = 41
        assert_eq!(frame_bytes.len(), 41);
        let parsed = frame::parse_frame(&frame_bytes).unwrap();
        assert_eq!(parsed.frame_type, FRAME_TYPE_PROVISION);
        assert_eq!(parsed.payload, secret);
    }
}
