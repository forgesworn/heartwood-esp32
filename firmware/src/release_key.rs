// firmware/src/release_key.rs
//
// The ed25519 public key every OTA image must be signed with. Generated at
// build time by build.rs from `ota-release-pubkey.hex` (or the
// `HEARTWOOD_OTA_PUBKEY` env override for bench builds against a dev key).
// The committed placeholder is all zeros — not a valid curve point — so a
// build without a real key rejects every OTA rather than accepting anything.

include!(concat!(env!("OUT_DIR"), "/ota_release_key.rs"));
