// ota-sign/src/main.rs
//
// OTA release signing tool. Host-side companion to the on-device verifier in
// firmware/src/ota.rs — both go through common/src/ota_sign.rs, so the signed
// message can never drift between the two.
//
//   heartwood-ota-sign keygen --out ota-release.seed
//       Generate a release keypair: the 64-hex seed goes to a private file
//       (keep it offline / in the OTA_SIGNING_SEED GitHub secret), the public
//       key is printed for firmware/ota-release-pubkey.hex.
//
//   heartwood-ota-sign sign --seed-env OTA_SIGNING_SEED --board heltec-v4 \
//       --image app-heltec-v4.bin --out app-heltec-v4.bin.sig
//       Sign an image's SHA-256 for one board. The board id must be the one
//       THE DEVICE reports (board::BOARD — e.g. "esp32c6", not the "c6"
//       release-asset name).
//
//   heartwood-ota-sign verify --pubkey firmware/ota-release-pubkey.hex \
//       --board heltec-v4 --image app-heltec-v4.bin --sig app-heltec-v4.bin.sig
//       Check a signature against the committed public key — run in CI after
//       signing so a seed/pubkey mismatch fails the release instead of
//       shipping an update no device will accept.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use heartwood_common::ota_sign::{ota_pubkey_from_seed, sign_ota_digest, verify_ota_signature};

#[derive(Parser)]
#[command(name = "heartwood-ota-sign")]
#[command(about = "Sign and verify heartwood-esp32 OTA firmware releases")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new release keypair (seed file + printed public key)
    Keygen {
        /// Where to write the 64-hex seed (refuses to overwrite)
        #[arg(long, default_value = "ota-release.seed")]
        out: PathBuf,
    },
    /// Print the public key for a seed
    Pubkey {
        /// Path to the seed file
        #[arg(long, conflicts_with = "seed_env")]
        seed: Option<PathBuf>,
        /// Name of an environment variable holding the seed
        #[arg(long)]
        seed_env: Option<String>,
    },
    /// Sign a firmware image's SHA-256 for one board
    Sign {
        /// Path to the seed file
        #[arg(long, conflicts_with = "seed_env")]
        seed: Option<PathBuf>,
        /// Name of an environment variable holding the seed (preferred in CI —
        /// keeps the secret off the filesystem and out of argv)
        #[arg(long)]
        seed_env: Option<String>,
        /// Board id as the DEVICE reports it (heltec-v4, heltec-v3, tdisplay, esp32c6, esp8266)
        #[arg(long)]
        board: String,
        /// Firmware image to sign
        #[arg(long)]
        image: PathBuf,
        /// Where to write the 128-hex signature (default: <image>.sig)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify an image signature against a public key
    Verify {
        /// 64-hex public key, or a path to a hex file (comment lines allowed)
        #[arg(long)]
        pubkey: String,
        /// Board id as the DEVICE reports it
        #[arg(long)]
        board: String,
        /// Firmware image the signature covers
        #[arg(long)]
        image: PathBuf,
        /// 128-hex signature, or a path to a .sig file
        #[arg(long)]
        sig: String,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Keygen { out } => keygen(&out),
        Command::Pubkey { seed, seed_env } => pubkey(seed.as_deref(), seed_env.as_deref()),
        Command::Sign { seed, seed_env, board, image, out } => {
            sign(seed.as_deref(), seed_env.as_deref(), &board, &image, out.as_deref())
        }
        Command::Verify { pubkey, board, image, sig } => verify(&pubkey, &board, &image, &sig),
    }
}

fn keygen(out: &Path) -> ExitCode {
    if out.exists() {
        eprintln!("error: {} already exists — refusing to overwrite a release seed", out.display());
        return ExitCode::FAILURE;
    }

    let mut seed = [0u8; 32];
    if let Err(e) = getrandom::getrandom(&mut seed) {
        eprintln!("error: could not gather entropy: {e}");
        return ExitCode::FAILURE;
    }

    let mut seed_hex = hex_encode(&seed);
    let pubkey_hex = hex_encode(&ota_pubkey_from_seed(&seed));
    seed.zeroize();

    if let Err(e) = write_private(out, &seed_hex) {
        seed_hex.zeroize();
        eprintln!("error: could not write {}: {e}", out.display());
        return ExitCode::FAILURE;
    }
    seed_hex.zeroize();

    println!("Seed written to {} — keep it OFFLINE and backed up; set it as the", out.display());
    println!("OTA_SIGNING_SEED GitHub Actions secret in heartwood-esp32.");
    println!();
    println!("Public key (paste into firmware/ota-release-pubkey.hex and commit):");
    println!("{pubkey_hex}");
    ExitCode::SUCCESS
}

fn pubkey(seed_path: Option<&Path>, seed_env: Option<&str>) -> ExitCode {
    match load_seed(seed_path, seed_env) {
        Ok(mut seed) => {
            println!("{}", hex_encode(&ota_pubkey_from_seed(&seed)));
            seed.zeroize();
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn sign(
    seed_path: Option<&Path>,
    seed_env: Option<&str>,
    board: &str,
    image: &Path,
    out: Option<&Path>,
) -> ExitCode {
    let mut seed = match load_seed(seed_path, seed_env) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let digest = match image_digest(image) {
        Ok(d) => d,
        Err(e) => {
            seed.zeroize();
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let sig_hex = hex_encode(&sign_ota_digest(&seed, board, &digest));
    seed.zeroize();

    let out_path = out
        .map(Path::to_path_buf)
        .unwrap_or_else(|| image.with_extension(sig_extension(image)));
    if let Err(e) = std::fs::write(&out_path, format!("{sig_hex}\n")) {
        eprintln!("error: could not write {}: {e}", out_path.display());
        return ExitCode::FAILURE;
    }

    println!("signed {} for {board}", image.display());
    println!("  sha256    {}", hex_encode(&digest));
    println!("  signature {} → {}", &sig_hex[..16], out_path.display());
    ExitCode::SUCCESS
}

fn verify(pubkey_arg: &str, board: &str, image: &Path, sig_arg: &str) -> ExitCode {
    let pubkey: [u8; 32] = match hex_or_file(pubkey_arg).and_then(|h| parse_hex(&h)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: bad public key: {e}");
            return ExitCode::FAILURE;
        }
    };
    let signature: [u8; 64] = match hex_or_file(sig_arg).and_then(|h| parse_hex(&h)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: bad signature: {e}");
            return ExitCode::FAILURE;
        }
    };
    let digest = match image_digest(image) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if verify_ota_signature(&pubkey, board, &digest, &signature) {
        println!("OK — {} verifies for {board}", image.display());
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "FAILED — {} does not verify for {board} (wrong key, wrong board, or tampered image)",
            image.display()
        );
        ExitCode::FAILURE
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load a 32-byte seed from a file or an environment variable. Exactly one
/// source must be given.
fn load_seed(path: Option<&Path>, env: Option<&str>) -> Result<[u8; 32], String> {
    let mut raw = match (path, env) {
        (Some(p), None) => std::fs::read_to_string(p)
            .map_err(|e| format!("could not read seed file {}: {e}", p.display()))?,
        (None, Some(var)) => std::env::var(var)
            .map_err(|_| format!("environment variable {var} is not set"))?,
        _ => return Err("provide exactly one of --seed or --seed-env".into()),
    };
    let result = strip_hex(&raw).and_then(|h| parse_hex::<32>(&h));
    raw.zeroize();
    result.map_err(|e| format!("bad seed: {e}"))
}

/// SHA-256 of a firmware image file.
fn image_digest(image: &Path) -> Result<[u8; 32], String> {
    let bytes = std::fs::read(image)
        .map_err(|e| format!("could not read image {}: {e}", image.display()))?;
    if bytes.is_empty() {
        return Err(format!("image {} is empty", image.display()));
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}

/// Accept either a hex string or a path to a file containing one.
fn hex_or_file(arg: &str) -> Result<String, String> {
    if Path::new(arg).exists() {
        let raw = std::fs::read_to_string(arg).map_err(|e| format!("could not read {arg}: {e}"))?;
        strip_hex(&raw)
    } else {
        strip_hex(arg)
    }
}

/// Strip comment lines and whitespace from hex input.
fn strip_hex(raw: &str) -> Result<String, String> {
    let hex: String = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .collect();
    if hex.is_empty() {
        return Err("no hex content found".into());
    }
    Ok(hex)
}

fn parse_hex<const N: usize>(hex: &str) -> Result<[u8; N], String> {
    if hex.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, hex.len()));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "non-hex characters in input".to_string())?;
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `app-heltec-v4.bin` → extension `bin.sig` so the default output is
/// `app-heltec-v4.bin.sig` (not `app-heltec-v4.sig`).
fn sig_extension(image: &Path) -> String {
    match image.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{ext}.sig"),
        None => "sig".into(),
    }
}

/// Write a secret file with owner-only permissions.
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, format!("{contents}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_roundtrip() {
        let hex = "00ff10a5".repeat(8);
        let bytes: [u8; 32] = parse_hex(&hex).unwrap();
        assert_eq!(hex_encode(&bytes), hex);
    }

    #[test]
    fn strip_hex_ignores_comments_and_whitespace() {
        let raw = "# a comment\n  deadbeef  \n# another\ncafe\n";
        assert_eq!(strip_hex(raw).unwrap(), "deadbeefcafe");
    }

    #[test]
    fn sig_extension_appends() {
        assert_eq!(sig_extension(Path::new("app-heltec-v4.bin")), "bin.sig");
        assert_eq!(sig_extension(Path::new("image")), "sig");
    }

    #[test]
    fn sign_and_verify_via_files() {
        let dir = std::env::temp_dir().join(format!("ota-sign-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let image = dir.join("app.bin");
        std::fs::write(&image, b"firmware bytes").unwrap();

        let seed = [3u8; 32];
        let digest = image_digest(&image).unwrap();
        let sig = sign_ota_digest(&seed, "heltec-v4", &digest);
        let pk = ota_pubkey_from_seed(&seed);
        assert!(verify_ota_signature(&pk, "heltec-v4", &digest, &sig));
        assert!(!verify_ota_signature(&pk, "tdisplay", &digest, &sig));

        std::fs::remove_dir_all(&dir).ok();
    }
}
