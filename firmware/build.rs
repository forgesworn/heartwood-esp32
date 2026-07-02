fn main() {
    // Rebuild if the partition table changes (cmake re-configure needed).
    let partitions = concat!(env!("CARGO_MANIFEST_DIR"), "/partitions.csv");
    println!("cargo:rerun-if-changed={partitions}");

    bake_ota_release_pubkey();

    // Rebuild if the active sdkconfig defaults list changes. This catches
    // board switches (heltec-v3 vs heltec-v4) that flip the env var without
    // changing any source file -- without this hook, `cargo build` might
    // reuse a stale CMake configure and silently ship the wrong board
    // binary.
    println!("cargo:rerun-if-env-changed=ESP_IDF_SDKCONFIG_DEFAULTS");

    // Rebuild if either board fragment changes. The shared defaults file is
    // already picked up by esp-idf-sys's own rerun logic.
    let v3 = concat!(env!("CARGO_MANIFEST_DIR"), "/sdkconfig.defaults.heltec-v3");
    let v4 = concat!(env!("CARGO_MANIFEST_DIR"), "/sdkconfig.defaults.heltec-v4");
    println!("cargo:rerun-if-changed={v3}");
    println!("cargo:rerun-if-changed={v4}");

    embuild::espidf::sysenv::output();
}

/// Bake the OTA release public key into the firmware as a const.
///
/// The key comes from `ota-release-pubkey.hex` (committed — public keys are
/// public), overridable with the `HEARTWOOD_OTA_PUBKEY` env var so a bench
/// build can trust a local dev key without touching the repo. The committed
/// placeholder (all zeros) is not a valid ed25519 point, so a firmware built
/// from it rejects every OTA — fail-closed until the real key lands.
fn bake_ota_release_pubkey() {
    let key_path = concat!(env!("CARGO_MANIFEST_DIR"), "/ota-release-pubkey.hex");
    println!("cargo:rerun-if-changed={key_path}");
    println!("cargo:rerun-if-env-changed=HEARTWOOD_OTA_PUBKEY");

    let raw = std::env::var("HEARTWOOD_OTA_PUBKEY").unwrap_or_else(|_| {
        std::fs::read_to_string(key_path)
            .expect("ota-release-pubkey.hex missing — the OTA release public key must be committed next to Cargo.toml")
    });
    // The file allows `#` comment lines and whitespace around the hex.
    let hex: String = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .collect();
    assert_eq!(
        hex.len(),
        64,
        "OTA release public key must be exactly 64 hex chars (32 bytes), got {}",
        hex.len()
    );
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .expect("OTA release public key contains non-hex characters")
        })
        .collect();

    let out = format!(
        "/// ed25519 public key that firmware images must be signed with (see ota.rs).\n\
         pub const OTA_RELEASE_PUBKEY: [u8; 32] = {bytes:?};\n"
    );
    let dest = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("ota_release_key.rs");
    std::fs::write(dest, out).expect("failed to write ota_release_key.rs");
}
