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
use heartwood_common::hex::hex_encode;
use heartwood_common::policy::ClientPolicy;
use heartwood_common::types::{
    FRAME_TYPE_ACK, FRAME_TYPE_NACK, FRAME_TYPE_POLICY_LIST_REQUEST,
    FRAME_TYPE_POLICY_LIST_RESPONSE, FRAME_TYPE_POLICY_REVOKE, FRAME_TYPE_POLICY_UPDATE,
    FRAME_TYPE_PROVISION, FRAME_TYPE_PROVISION_LIST, FRAME_TYPE_PROVISION_LIST_RESPONSE,
    FRAME_TYPE_SET_BRIDGE_SECRET, MNEMONIC_PATH,
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
    /// Provision an EXISTING master secret onto the device (restore from a
    /// recovery phrase, an nsec, or a 24-word key backup made by Sapwood).
    /// RUN OFFLINE — the key must never touch a networked machine. The secret
    /// is read interactively, never from argv.
    Provision {
        /// Label for this master (e.g. "primary")
        #[arg(short, long, default_value = "default")]
        label: String,

        /// Provisioning mode: tree-mnemonic (default), tree-nsec, bunker
        #[arg(short, long, default_value = "tree-mnemonic")]
        mode: String,

        /// Also pair this 32-byte bridge secret (64 hex) with the device.
        #[arg(long)]
        bridge_secret: Option<String>,

        /// Generate a fresh bridge secret, set it on the device, and print it
        /// (put the printed value in the bridge daemon's bridge.secret file).
        #[arg(long)]
        gen_bridge_secret: bool,
    },

    /// Generate a FRESH key on this (offline) host, show the recovery phrase to
    /// write down, then provision it. The phrase is shown once and never written
    /// to disk. RUN OFFLINE.
    Generate {
        /// Label for this master (e.g. "primary")
        #[arg(short, long, default_value = "default")]
        label: String,

        /// Recovery phrase length: 12 (128-bit) or 24 (256-bit).
        #[arg(long, default_value_t = 12)]
        words: u8,

        /// Also pair this 32-byte bridge secret (64 hex) with the device.
        #[arg(long)]
        bridge_secret: Option<String>,

        /// Generate a fresh bridge secret, set it on the device, and print it.
        #[arg(long)]
        gen_bridge_secret: bool,
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

/// Decode a pasted key: an nsec1... string, or the 24 backup words Sapwood
/// writes out at import. The words are the key's own 32 bytes used as BIP-39
/// entropy — NOT a seed to derive from — so decoding restores the identical
/// key and npub. A 12-word phrase carries only 128 bits and can never hold an
/// existing key; those are seeds and belong in tree-mnemonic mode.
fn decode_key_input(input: &str) -> Result<[u8; 32], String> {
    let input = input.trim();
    if !input.contains(char::is_whitespace) {
        return decode_nsec(input);
    }

    let words: Vec<&str> = input.split_whitespace().collect();
    if words.len() != 24 {
        return Err(format!(
            "a key backup is exactly 24 words (got {}); a 12-word phrase is a seed, use tree-mnemonic mode",
            words.len()
        ));
    }
    let mut phrase = words.join(" ").to_lowercase();
    let parsed: bip39::Mnemonic = phrase
        .parse()
        .map_err(|_| "not a valid 24-word key backup (unknown word or bad checksum)".to_string())?;
    phrase.zeroize();

    let mut entropy = parsed.to_entropy();
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&entropy);
    entropy.zeroize();
    Ok(secret)
}

/// Derive an nsec-tree root from a raw nsec via HMAC-SHA256.
///
/// Matches PROTOCOL.md §1.2 and the reference implementations in
/// `nsec-tree/src/root-nsec.ts` and `heartwood-core/src/root.rs`:
///
///   tree_root = HMAC-SHA256(key = nsec_bytes, msg = utf8("nsec-tree-root"))
///
/// A previous version of this function used the DOMAIN_PREFIX
/// (`b"nsec-tree\0"`) as the HMAC key and the nsec as the message, producing
/// a byte-for-byte divergent tree root from every other nsec-tree
/// implementation. Devices provisioned via `tree-nsec` mode with that broken
/// version must be re-provisioned to match the reference implementations.
fn nsec_to_tree_root(nsec_bytes: &[u8; 32]) -> Result<[u8; 32], String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(nsec_bytes)
        .map_err(|_| "HMAC init failed".to_string())?;
    mac.update(b"nsec-tree-root");
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

/// Build a SET_BRIDGE_SECRET frame (payload = the 32-byte secret).
fn build_set_bridge_secret_frame(secret: &[u8; 32]) -> Vec<u8> {
    frame::build_frame(FRAME_TYPE_SET_BRIDGE_SECRET, secret)
        .expect("bridge-secret frame should never exceed max payload")
}

/// Build a PROVISION_LIST frame (empty payload) — asks the device for its identity.
fn build_provision_list_frame() -> Vec<u8> {
    frame::build_frame(FRAME_TYPE_PROVISION_LIST, &[])
        .expect("provision-list frame should never exceed max payload")
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

/// Decode a 64-char hex string into 32 bytes.
fn decode_hex32(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "invalid hex".to_string())?;
    }
    Ok(out)
}

/// Resolve the bridge secret from the CLI flags: an explicit `--bridge-secret`
/// hex, or a freshly generated one (`--gen-bridge-secret`, printed so the
/// operator can copy it into the bridge daemon's `bridge.secret` file), or none.
fn resolve_bridge_secret(bridge_secret: &Option<String>, gen: bool) -> Option<[u8; 32]> {
    if bridge_secret.is_some() && gen {
        eprintln!("Pass only one of --bridge-secret / --gen-bridge-secret.");
        std::process::exit(1);
    }
    if let Some(hex) = bridge_secret {
        Some(decode_hex32(hex).unwrap_or_else(|e| {
            eprintln!("invalid --bridge-secret: {e}");
            std::process::exit(1);
        }))
    } else if gen {
        let mut s = [0u8; 32];
        getrandom::getrandom(&mut s).expect("OS entropy for bridge secret");
        println!("\nGenerated bridge secret — put this in the bridge daemon's bridge.secret file:");
        println!("  {}\n", hex_encode(&s));
        Some(s)
    } else {
        None
    }
}

/// Send the derived root to the device, optionally pair a bridge secret, and
/// read the npub back to confirm. Zeroises `root_secret` before opening the port.
fn finish_provisioning(
    port_name: &str,
    baud: u32,
    root_secret: &mut [u8; 32],
    label: &str,
    mode: &str,
    bridge_secret: Option<[u8; 32]>,
    expected_npub: &str,
) {
    let frame_bytes = build_provision_frame(root_secret, label, mode);
    root_secret.zeroize();

    println!("\n⚠  Run this on an OFFLINE computer — the key must never touch a networked machine.");
    println!("Opening {port_name}...");
    let mut port = open_serial(port_name, baud);

    println!("Waiting for device...");
    std::thread::sleep(Duration::from_secs(4));

    println!("Hold the device's button to approve the new key when it prompts...");
    let response = send_and_receive(&mut *port, &frame_bytes, FRAME_TYPE_ACK);
    if response.frame_type != FRAME_TYPE_ACK {
        eprintln!("Device rejected the seed (NACK, or the button was not held in time).");
        std::process::exit(1);
    }
    println!("✓ Seed provisioned (master '{label}').");

    if let Some(mut bs) = bridge_secret {
        let bs_frame = build_set_bridge_secret_frame(&bs);
        bs.zeroize();
        println!("Pairing the bridge secret...");
        let r = send_and_receive(&mut *port, &bs_frame, FRAME_TYPE_ACK);
        if r.frame_type != FRAME_TYPE_ACK {
            eprintln!("Device rejected the bridge secret.");
            std::process::exit(1);
        }
        println!("✓ Bridge secret paired.");
    }

    // Read the device's identity back to confirm it matches what we derived.
    let r = send_and_receive(
        &mut *port,
        &build_provision_list_frame(),
        FRAME_TYPE_PROVISION_LIST_RESPONSE,
    );
    if r.frame_type == FRAME_TYPE_PROVISION_LIST_RESPONSE {
        let npub = serde_json::from_slice::<serde_json::Value>(&r.payload).ok().and_then(|v| {
            v.get(0).and_then(|m| m.get("npub")).and_then(|n| n.as_str()).map(String::from)
        });
        match npub.as_deref() {
            Some(n) if n == expected_npub => println!("✓ Device confirms identity: {n}"),
            Some(n) => eprintln!("⚠ Device reports {n}, but we derived {expected_npub} — mismatch!"),
            None => eprintln!("⚠ Could not read the device's identity back to confirm."),
        }
    }
}

fn handle_provision(
    port_name: &str,
    baud: u32,
    label: &str,
    mode: &str,
    bridge_secret: &Option<String>,
    gen_bridge_secret: bool,
) {
    let mut root_secret = match mode {
        "bunker" => {
            let key = rpassword::prompt_password("Enter nsec (nsec1...) or 24-word key backup: ")
                .expect("failed to read key");
            let secret = decode_key_input(&key).expect("invalid key");
            println!("\nMode: bunker (raw key, no tree derivation)");
            secret
        }
        "tree-nsec" => {
            let key = rpassword::prompt_password("Enter nsec (nsec1...) or 24-word key backup: ")
                .expect("failed to read key");
            let mut nsec_bytes = decode_key_input(&key).expect("invalid key");
            let secret = nsec_to_tree_root(&nsec_bytes).expect("tree-nsec derivation failed");
            nsec_bytes.zeroize();
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
    let npub = root.master_npub.clone();
    println!("Pubkey: {npub}");
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

    let bridge = resolve_bridge_secret(bridge_secret, gen_bridge_secret);
    finish_provisioning(port_name, baud, &mut root_secret, label, mode, bridge, &npub);
}

fn handle_generate(
    port_name: &str,
    baud: u32,
    label: &str,
    words: u8,
    bridge_secret: &Option<String>,
    gen_bridge_secret: bool,
) {
    let entropy_len = match words {
        12 => 16,
        24 => 32,
        n => {
            eprintln!("--words must be 12 or 24, got {n}");
            std::process::exit(1);
        }
    };
    let mut entropy = vec![0u8; entropy_len];
    getrandom::getrandom(&mut entropy).expect("OS entropy for key generation");
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy).expect("entropy -> mnemonic");
    entropy.zeroize();
    let phrase = mnemonic.to_string();

    println!("\n========================================================");
    println!("  WRITE THESE {words} WORDS DOWN — they are the ONLY backup of");
    println!("  this key. Do NOT photograph them or store them on any");
    println!("  networked computer. Anyone with them controls the signer.");
    println!("========================================================\n");
    for (i, w) in phrase.split_whitespace().enumerate() {
        println!("  {:>2}. {w}", i + 1);
    }
    print!("\nType 'yes' once you have written them down: ");
    io::stdout().flush().unwrap();
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm).unwrap();
    if confirm.trim().to_lowercase() != "yes" {
        println!("Aborted — nothing was provisioned.");
        return;
    }

    let mut root_secret = derive_root_secret(&phrase, "").expect("derivation failed");
    let root = create_tree_root(&root_secret).expect("invalid root secret");
    let npub = root.master_npub.clone();
    println!("\nPubkey: {npub}");
    root.destroy();

    let bridge = resolve_bridge_secret(bridge_secret, gen_bridge_secret);
    finish_provisioning(port_name, baud, &mut root_secret, label, "tree-mnemonic", bridge, &npub);
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
        Command::Provision { label, mode, bridge_secret, gen_bridge_secret } => {
            handle_provision(&cli.port, cli.baud, label, mode, bridge_secret, *gen_bridge_secret);
        }
        Command::Generate { label, words, bridge_secret, gen_bridge_secret } => {
            handle_generate(&cli.port, cli.baud, label, *words, bridge_secret, *gen_bridge_secret);
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

    /// Frozen nsec-tree vector (PROTOCOL.md §6.1 Vector 1): nsec_bytes = 0x01 × 32.
    ///
    /// The derived tree_root and its x-only master pubkey MUST match the
    /// frozen values in the canonical TypeScript implementation
    /// (`nsec-tree/test/vectors.test.ts`) and the Rust port
    /// (`heartwood-core/tests/full_vectors_test.rs`). If this test fails,
    /// provisioning a device via `tree-nsec` mode will produce keys that
    /// are incompatible with every other nsec-tree implementation.
    #[test]
    fn test_nsec_to_tree_root_matches_frozen_vector() {
        let nsec_bytes = [0x01u8; 32];
        let root_secret = nsec_to_tree_root(&nsec_bytes).expect("nsec_to_tree_root must succeed");

        assert_eq!(
            hex_encode(&root_secret),
            "8d2db9ce9548534e7ae924d05e311355e3a12744214c88e65b39fa2bf2df6d6f",
            "tree_root does not match PROTOCOL.md §6.1 Vector 1"
        );

        let root = create_tree_root(&root_secret).expect("invalid root secret");
        assert_eq!(
            root.master_npub,
            "npub13sp7q3awvrqpa9p2svm7w8ghudghlnrraekwl7qh8w7j8747vjwskvzy2u",
            "master npub does not match PROTOCOL.md §6.1 Vector 1"
        );
        root.destroy();
    }

    /// Frozen cross-implementation vector for the 24-word key backup: the words
    /// are the key's own bytes as BIP-39 entropy, so secret = scalar 1 encodes
    /// as 23 "abandon"s and a checksum word. MUST match sapwood's
    /// `keyToWords`/`wordsToKey` (`src/lib/restore.test.ts`) or a backup written
    /// down in the browser will not restore through this CLI.
    #[test]
    fn test_key_backup_words_match_frozen_vector() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon diesel";
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(decode_key_input(words).unwrap(), expected);
    }

    /// The same key as an nsec decodes identically through the shared entry point.
    #[test]
    fn test_key_input_accepts_nsec() {
        let nsec = "nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsmhltgl";
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(decode_key_input(nsec).unwrap(), expected);
    }

    /// Pasted words survive messy case and whitespace.
    #[test]
    fn test_key_backup_normalises_case_and_whitespace() {
        let words = "  ABANDON abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon\n abandon  DIESEL ";
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(decode_key_input(words).unwrap(), expected);
    }

    /// A 12-word phrase is a seed, not a key: it must be refused here so it
    /// cannot be silently misread as key material.
    #[test]
    fn test_key_backup_rejects_12_words() {
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(decode_key_input(twelve).is_err());
    }

    /// 24 words with a bad checksum are refused.
    #[test]
    fn test_key_backup_rejects_bad_checksum() {
        let junk = "abandon ".repeat(24);
        assert!(decode_key_input(junk.trim()).is_err());
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
