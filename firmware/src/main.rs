// firmware/src/main.rs — temporary, rewritten in Task 7

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
