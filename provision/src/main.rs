// provision/src/main.rs
//
// Device management CLI for heartwood-esp32.
//
// Subcommands:
//   provision      -- push a master secret (mnemonic, nsec, or bunker)
//   list-clients   -- list TOFU-approved clients for a master slot
//   revoke-client  -- revoke a TOFU-approved client
//   update-client  -- update a client's approval policy

use std::io::{self, Write};
use std::time::Duration;

use clap::{Parser, Subcommand};
use zeroize::Zeroize;

use heartwood_common::derive::create_tree_root;
use heartwood_common::frame;
use heartwood_common::policy::ClientPolicy;
use heartwood_common::types::{
    FRAME_TYPE_ACK, FRAME_TYPE_NACK, FRAME_TYPE_POLICY_LIST_REQUEST,
    FRAME_TYPE_POLICY_LIST_RESPONSE, FRAME_TYPE_POLICY_REVOKE, FRAME_TYPE_POLICY_UPDATE,
    FRAME_TYPE_PROVISION, MNEMONIC_PATH,
};

#[derive(Parser)]
#[command(name = "heartwood-provision")]
#[command(about = "Manage a heartwood-esp32 device")]
struct Cli {
    /// Serial port (e.g. /dev/ttyUSB0 or /dev/cu.usbserial-*)
    #[arg(short, long)]
    port: String,

    /// Baud rate (default 115200)
    #[arg(short, long, default_value_t = 115200)]
    baud: u32,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Provision a master secret onto the device
    Provision {
        /// Label for this master (e.g. "primary")
        #[arg(short, long, default_value = "default")]
        label: String,

        /// Provisioning mode: tree-mnemonic (default), tree-nsec, bunker
        #[arg(short, long, default_value = "tree-mnemonic")]
        mode: String,
    },

    /// List TOFU-approved clients for a master slot
    ListClients {
        /// Master slot index (0-based)
        #[arg(long, default_value_t = 0)]
        master_slot: u8,
    },

    /// Revoke a TOFU-approved client
    RevokeClient {
        /// Master slot index (0-based)
        #[arg(long, default_value_t = 0)]
        master_slot: u8,

        /// Client public key (64-char hex)
        #[arg(long)]
        client: String,
    },

    /// Update a client's approval policy
    UpdateClient {
        /// Master slot index (0-based)
        #[arg(long, default_value_t = 0)]
        master_slot: u8,

        /// Client public key (64-char hex)
        #[arg(long)]
        client: String,

        /// Human-readable label for the client
        #[arg(long)]
        label: Option<String>,

        /// Disable auto-approval (require button press)
        #[arg(long)]
        no_auto_approve: bool,

        /// Comma-separated list of allowed event kinds for sign_event
        #[arg(long, value_delimiter = ',')]
        allowed_kinds: Option<Vec<u64>>,

        /// Comma-separated list of allowed NIP-46 methods
        #[arg(long, value_delimiter = ',')]
        allowed_methods: Option<Vec<String>>,
    },
}

// ---------------------------------------------------------------------------
// Serial helpers
// ---------------------------------------------------------------------------

/// Open a serial port with standard settings for the ESP32.
fn open_serial(port: &str, baud: u32) -> Box<dyn serialport::SerialPort> {
    let mut port = serialport::new(port, baud)
        .timeout(Duration::from_secs(30))
        .open()
        .unwrap_or_else(|e| {
            eprintln!("Failed to open serial port: {e}");
            std::process::exit(1);
        });

    // Disable DTR/RTS -- toggling these resets the ESP32-S3 USB-Serial-JTAG.
    port.write_data_terminal_ready(false).ok();
    port.write_request_to_send(false).ok();
    port
}

/// Send a frame and wait for a response of an expected type (or ACK/NACK).
/// Returns the parsed response frame.
fn send_and_receive(
    port: &mut dyn serialport::SerialPort,
    frame_bytes: &[u8],
    expected_response_type: u8,
) -> frame::Frame {
    port.write_all(frame_bytes).expect("failed to write to serial port");
    port.flush().expect("failed to flush serial port");

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
        match frame::parse_frame(&buf) {
            Ok(f) if f.frame_type == expected_response_type
                || f.frame_type == FRAME_TYPE_ACK
                || f.frame_type == FRAME_TYPE_NACK =>
            {
                return f;
            }
            Ok(f) => {
                eprintln!("Unexpected frame type: 0x{:02x}", f.frame_type);
                std::process::exit(1);
            }
            Err(frame::FrameError::TooShort) => {} // keep reading
            Err(_) => {
                // Bad frame -- skip to next magic bytes.
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

// ---------------------------------------------------------------------------
// Crypto helpers (unchanged from original)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Frame builders
// ---------------------------------------------------------------------------

/// Build a provisioning frame.
///
/// Extended format: [mode_u8][label_len_u8][label...][secret_32]
/// Legacy format (label="default", mode=tree-mnemonic): just [secret_32]
fn build_provision_frame(secret: &[u8; 32], label: &str, mode: &str) -> Vec<u8> {
    let mode_byte: u8 = match mode {
        "bunker" => 0,
        "tree-mnemonic" => 1,
        "tree-nsec" => 2,
        _ => 1,
    };

    if label == "default" && mode_byte == 1 {
        frame::build_frame(FRAME_TYPE_PROVISION, secret)
            .expect("provision frame should never exceed max payload")
    } else {
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

/// Build a POLICY_LIST_REQUEST frame.
fn build_policy_list_frame(master_slot: u8) -> Vec<u8> {
    frame::build_frame(FRAME_TYPE_POLICY_LIST_REQUEST, &[master_slot])
        .expect("policy list frame should never exceed max payload")
}

/// Build a POLICY_REVOKE frame.
fn build_policy_revoke_frame(master_slot: u8, client_pubkey_hex: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(65);
    payload.push(master_slot);
    payload.extend_from_slice(client_pubkey_hex.as_bytes());
    frame::build_frame(FRAME_TYPE_POLICY_REVOKE, &payload)
        .expect("policy revoke frame should never exceed max payload")
}

/// Build a POLICY_UPDATE frame.
fn build_policy_update_frame(master_slot: u8, policy: &ClientPolicy) -> Vec<u8> {
    let json = serde_json::to_vec(policy).expect("failed to serialise ClientPolicy");
    let mut payload = Vec::with_capacity(1 + json.len());
    payload.push(master_slot);
    payload.extend_from_slice(&json);
    frame::build_frame(FRAME_TYPE_POLICY_UPDATE, &payload)
        .expect("policy update frame should never exceed max payload")
}

// ---------------------------------------------------------------------------
// Subcommand handlers
// ---------------------------------------------------------------------------

fn handle_provision(port_name: &str, baud: u32, label: &str, mode: &str) {
    let mut root_secret = match mode {
        "bunker" => {
            let nsec = rpassword::prompt_password("Enter nsec (nsec1...): ")
                .expect("failed to read nsec");
            let secret = decode_nsec(nsec.trim()).expect("invalid nsec");
            println!("\nMode: bunker (raw nsec, no tree derivation)");
            secret
        }
        "tree-nsec" => {
            let nsec = rpassword::prompt_password("Enter nsec (nsec1...): ")
                .expect("failed to read nsec");
            let nsec_bytes = decode_nsec(nsec.trim()).expect("invalid nsec");
            let secret = nsec_to_tree_root(&nsec_bytes).expect("tree-nsec derivation failed");
            println!("\nMode: tree-nsec (nsec -> HMAC -> tree root)");
            secret
        }
        "tree-mnemonic" | _ => {
            let mnemonic = rpassword::prompt_password("Enter mnemonic: ")
                .expect("failed to read mnemonic");
            let passphrase = rpassword::prompt_password("Enter passphrase (empty for none): ")
                .expect("failed to read passphrase");
            let secret = derive_root_secret(&mnemonic, &passphrase)
                .expect("derivation failed");
            println!("\nMode: tree-mnemonic (BIP-39 -> BIP-32 -> tree root)");
            secret
        }
    };

    let root = create_tree_root(&root_secret).expect("invalid root secret");
    println!("Pubkey: {}", root.master_npub);
    root.destroy();

    print!("Send to device? [y/N]: ");
    io::stdout().flush().unwrap();
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm).unwrap();
    if confirm.trim().to_lowercase() != "y" {
        root_secret.zeroize();
        println!("Aborted.");
        return;
    }

    let frame_bytes = build_provision_frame(&root_secret, label, mode);
    root_secret.zeroize();

    println!("Opening {}...", port_name);
    let mut port = open_serial(port_name, baud);

    println!("Waiting for device...");
    std::thread::sleep(Duration::from_secs(4));

    println!("Sending...");
    let response = send_and_receive(&mut *port, &frame_bytes, FRAME_TYPE_ACK);

    match response.frame_type {
        FRAME_TYPE_ACK => println!("ACK received. Master '{}' provisioned.", label),
        FRAME_TYPE_NACK => {
            eprintln!("NACK received -- device rejected the provision (CRC error or NVS write failure).");
            std::process::exit(1);
        }
        other => {
            eprintln!("Unexpected frame type: 0x{:02x}", other);
            std::process::exit(1);
        }
    }
}

fn handle_list_clients(port_name: &str, baud: u32, master_slot: u8) {
    println!("Opening {}...", port_name);
    let mut port = open_serial(port_name, baud);

    println!("Waiting for device...");
    std::thread::sleep(Duration::from_secs(2));

    let frame_bytes = build_policy_list_frame(master_slot);
    println!("Requesting client list for master slot {}...", master_slot);
    let response = send_and_receive(&mut *port, &frame_bytes, FRAME_TYPE_POLICY_LIST_RESPONSE);

    match response.frame_type {
        FRAME_TYPE_POLICY_LIST_RESPONSE => {
            match serde_json::from_slice::<Vec<ClientPolicy>>(&response.payload) {
                Ok(policies) if policies.is_empty() => {
                    println!("No approved clients for master slot {}.", master_slot);
                }
                Ok(policies) => {
                    println!("{} approved client(s) for master slot {}:\n", policies.len(), master_slot);
                    for (i, p) in policies.iter().enumerate() {
                        println!("  [{}] pubkey: {}", i, p.client_pubkey);
                        if !p.label.is_empty() {
                            println!("      label:  {}", p.label);
                        }
                        println!("      auto:   {}", if p.auto_approve { "yes" } else { "no" });
                        if !p.allowed_methods.is_empty() {
                            println!("      methods: {}", p.allowed_methods.join(", "));
                        }
                        if !p.allowed_kinds.is_empty() {
                            let kinds: Vec<String> = p.allowed_kinds.iter().map(|k| k.to_string()).collect();
                            println!("      kinds:  {}", kinds.join(", "));
                        }
                        println!();
                    }
                }
                Err(e) => {
                    eprintln!("Failed to parse policy list: {e}");
                    std::process::exit(1);
                }
            }
        }
        FRAME_TYPE_NACK => {
            eprintln!("Device rejected the request (NACK).");
            std::process::exit(1);
        }
        other => {
            eprintln!("Unexpected frame type: 0x{:02x}", other);
            std::process::exit(1);
        }
    }
}

fn handle_revoke_client(port_name: &str, baud: u32, master_slot: u8, client: &str) {
    if client.len() != 64 {
        eprintln!("Client pubkey must be 64 hex characters, got {}", client.len());
        std::process::exit(1);
    }

    println!("Opening {}...", port_name);
    let mut port = open_serial(port_name, baud);

    println!("Waiting for device...");
    std::thread::sleep(Duration::from_secs(2));

    let frame_bytes = build_policy_revoke_frame(master_slot, client);
    println!("Revoking client {}...", &client[..16]);
    let response = send_and_receive(&mut *port, &frame_bytes, FRAME_TYPE_ACK);

    match response.frame_type {
        FRAME_TYPE_ACK => println!("Client revoked."),
        FRAME_TYPE_NACK => {
            eprintln!("Device rejected the revocation (client not found or NVS error).");
            std::process::exit(1);
        }
        other => {
            eprintln!("Unexpected frame type: 0x{:02x}", other);
            std::process::exit(1);
        }
    }
}

fn handle_update_client(
    port_name: &str,
    baud: u32,
    master_slot: u8,
    client: &str,
    label: Option<&str>,
    no_auto_approve: bool,
    allowed_kinds: Option<&[u64]>,
    allowed_methods: Option<&[String]>,
) {
    if client.len() != 64 {
        eprintln!("Client pubkey must be 64 hex characters, got {}", client.len());
        std::process::exit(1);
    }

    let policy = ClientPolicy {
        client_pubkey: client.to_string(),
        label: label.unwrap_or("").to_string(),
        allowed_methods: allowed_methods
            .map(|m| m.to_vec())
            .unwrap_or_default(),
        allowed_kinds: allowed_kinds
            .map(|k| k.to_vec())
            .unwrap_or_default(),
        auto_approve: !no_auto_approve,
    };

    println!("Opening {}...", port_name);
    let mut port = open_serial(port_name, baud);

    println!("Waiting for device...");
    std::thread::sleep(Duration::from_secs(2));

    let frame_bytes = build_policy_update_frame(master_slot, &policy);
    println!("Updating client {}...", &client[..16]);
    let response = send_and_receive(&mut *port, &frame_bytes, FRAME_TYPE_ACK);

    match response.frame_type {
        FRAME_TYPE_ACK => println!("Client policy updated."),
        FRAME_TYPE_NACK => {
            eprintln!("Device rejected the update (invalid JSON or NVS error).");
            std::process::exit(1);
        }
        other => {
            eprintln!("Unexpected frame type: 0x{:02x}", other);
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Command::Provision { label, mode } => {
            handle_provision(&cli.port, cli.baud, label, mode);
        }
        Command::ListClients { master_slot } => {
            handle_list_clients(&cli.port, cli.baud, *master_slot);
        }
        Command::RevokeClient { master_slot, client } => {
            handle_revoke_client(&cli.port, cli.baud, *master_slot, client);
        }
        Command::UpdateClient {
            master_slot,
            client,
            label,
            no_auto_approve,
            allowed_kinds,
            allowed_methods,
        } => {
            handle_update_client(
                &cli.port,
                cli.baud,
                *master_slot,
                client,
                label.as_deref(),
                *no_auto_approve,
                allowed_kinds.as_deref(),
                allowed_methods.as_deref(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heartwood_common::hex::hex_encode;

    /// Phase 2 test vector -- standard BIP-39 test mnemonic through full derivation path.
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

        assert_eq!(frame_bytes.len(), 41);
        let parsed = frame::parse_frame(&frame_bytes).unwrap();
        assert_eq!(parsed.frame_type, FRAME_TYPE_PROVISION);
        assert_eq!(parsed.payload, secret);
    }

    // --- Policy management frame tests ---

    #[test]
    fn test_build_policy_list_frame() {
        let frame_bytes = build_policy_list_frame(2);
        let parsed = frame::parse_frame(&frame_bytes).unwrap();
        assert_eq!(parsed.frame_type, FRAME_TYPE_POLICY_LIST_REQUEST);
        assert_eq!(parsed.payload, vec![2]);
    }

    #[test]
    fn test_build_policy_revoke_frame() {
        let pubkey = "a".repeat(64);
        let frame_bytes = build_policy_revoke_frame(0, &pubkey);
        let parsed = frame::parse_frame(&frame_bytes).unwrap();
        assert_eq!(parsed.frame_type, FRAME_TYPE_POLICY_REVOKE);
        assert_eq!(parsed.payload.len(), 65);
        assert_eq!(parsed.payload[0], 0);
        assert_eq!(&parsed.payload[1..], pubkey.as_bytes());
    }

    #[test]
    fn test_build_policy_update_frame() {
        let policy = ClientPolicy {
            client_pubkey: "b".repeat(64),
            label: "Test Client".to_string(),
            allowed_methods: vec!["sign_event".to_string()],
            allowed_kinds: vec![1, 7],
            auto_approve: true,
        };
        let frame_bytes = build_policy_update_frame(1, &policy);
        let parsed = frame::parse_frame(&frame_bytes).unwrap();
        assert_eq!(parsed.frame_type, FRAME_TYPE_POLICY_UPDATE);
        assert_eq!(parsed.payload[0], 1);

        // The rest is JSON -- round-trip it.
        let decoded: ClientPolicy = serde_json::from_slice(&parsed.payload[1..]).unwrap();
        assert_eq!(decoded.client_pubkey, "b".repeat(64));
        assert_eq!(decoded.label, "Test Client");
        assert!(decoded.auto_approve);
        assert_eq!(decoded.allowed_kinds, vec![1, 7]);
        assert_eq!(decoded.allowed_methods, vec!["sign_event"]);
    }

    #[test]
    fn test_policy_list_response_parsing() {
        // Simulate what the firmware would send back.
        let policies = vec![
            ClientPolicy {
                client_pubkey: "c".repeat(64),
                label: "Nostrudel".to_string(),
                allowed_methods: vec!["sign_event".to_string(), "get_public_key".to_string()],
                allowed_kinds: vec![],
                auto_approve: true,
            },
            ClientPolicy {
                client_pubkey: "d".repeat(64),
                label: "".to_string(),
                allowed_methods: vec![],
                allowed_kinds: vec![1],
                auto_approve: false,
            },
        ];
        let json = serde_json::to_vec(&policies).unwrap();
        let frame_bytes = frame::build_frame(FRAME_TYPE_POLICY_LIST_RESPONSE, &json).unwrap();
        let parsed = frame::parse_frame(&frame_bytes).unwrap();
        assert_eq!(parsed.frame_type, FRAME_TYPE_POLICY_LIST_RESPONSE);

        let decoded: Vec<ClientPolicy> = serde_json::from_slice(&parsed.payload).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].label, "Nostrudel");
        assert!(!decoded[1].auto_approve);
    }
}
