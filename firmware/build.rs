fn main() {
    // Rebuild if the partition table changes (cmake re-configure needed).
    let partitions = concat!(env!("CARGO_MANIFEST_DIR"), "/partitions.csv");
    println!("cargo:rerun-if-changed={partitions}");

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
