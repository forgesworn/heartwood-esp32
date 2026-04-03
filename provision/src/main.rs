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
/// Format: [0x48 0x57][0x01][0x00 0x20][secret_32][crc_4] = 41 bytes.
fn build_provision_frame(secret: &[u8; 32]) -> Vec<u8> {
    frame::build_frame(FRAME_TYPE_PROVISION, secret)
        .expect("provision frame should never exceed max payload")
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
    let frame = build_provision_frame(&root_secret);
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
                FRAME_TYPE_ACK => {
                    println!("ACK received. Root secret provisioned.");
                    break;
                }
                FRAME_TYPE_NACK => {
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
        let frame_bytes = build_provision_frame(&secret);

        // New format: 2 magic + 1 type + 2 length + 32 payload + 4 CRC = 41
        assert_eq!(frame_bytes.len(), 41);
        let parsed = frame::parse_frame(&frame_bytes).unwrap();
        assert_eq!(parsed.frame_type, FRAME_TYPE_PROVISION);
        assert_eq!(parsed.payload, secret);
    }
}
