# OTA release signing

Every released firmware image is signed with an ed25519 **release key**; the
device refuses any OTA image the signature doesn't verify for. This page is
the key-custody runbook. The scheme itself (what exactly is signed, and why)
is documented in `common/src/ota_sign.rs` and the threat model in
`docs/SECURITY-MODEL.md`.

## The moving parts

| Piece | Where | Contains |
|---|---|---|
| Seed (private key) | `OTA_SIGNING_SEED` GitHub Actions secret + an offline backup | 64 hex chars — **secret** |
| Public key | `firmware/ota-release-pubkey.hex` (committed) | 64 hex chars — public |
| Signer | `ota-sign/` host tool, run by `release.yml` | keygen / sign / verify |
| Verifier | `firmware/src/ota.rs` via `common/src/ota_sign.rs` | checks at OTA_BEGIN + OTA_FINISH |

`release.yml` signs each board's `app-<board>.bin`, publishes the signature as
`app-<board>.bin.sig` and inside `version.json` (per-board `signature` field),
and then **verifies each signature against the committed public key** — a
seed/pubkey mismatch fails the release instead of shipping an update no device
would accept.

## One-time setup (before the first signed release)

On a trusted machine (ideally offline):

```sh
cd heartwood-esp32
cargo +stable run --manifest-path ota-sign/Cargo.toml -- keygen --out ota-release.seed
```

1. **Back up `ota-release.seed`** somewhere offline (it is created `0600`;
   treat it like an nsec). Losing it means devices in the field can never
   accept another OTA — there is no rotation path that doesn't involve a USB
   re-flash of every device.
2. Paste the printed public key into `firmware/ota-release-pubkey.hex`
   (replacing the all-zero placeholder) and commit.
3. Set the seed as the `OTA_SIGNING_SEED` repository secret:
   `gh secret set OTA_SIGNING_SEED < ota-release.seed`
4. Delete `ota-release.seed` from the working machine if it isn't the
   designated offline store.

Until this is done, releases **fail** at the signing step (missing secret),
and firmware built from the placeholder key refuses every OTA — both
fail-closed by design.

## Rotation / compromise

Rotating the key is a **two-release operation**, because devices only trust
the key their running firmware was built with:

1. Generate the new keypair; commit the new public key; ship release *N*
   signed with the **old** seed (devices still verify with the old key — this
   release carries the new baked-in key).
2. Swap `OTA_SIGNING_SEED` to the new seed; every release from *N+1* onwards
   is signed with the new key, which devices running *N* now verify.

Devices that skip release *N* must update through it (or re-flash over USB —
the flasher path doesn't check OTA signatures).

If the seed is **compromised**, the OTA path should be treated as untrusted
until the rotation completes: an attacker with the seed still needs the USB
cable and the physical button hold, so the blast radius is local, but rotate
promptly and note it in the release.

## Bench builds against a dev key

`build.rs` accepts `HEARTWOOD_OTA_PUBKEY=<64 hex>` to override the committed
public key, so a bench build can trust a locally generated dev key:

```sh
cargo run --manifest-path ota-sign/Cargo.toml -- keygen --out /tmp/dev.seed
export HEARTWOOD_OTA_PUBKEY=$(cargo run --manifest-path ota-sign/Cargo.toml -- pubkey --seed /tmp/dev.seed)
scripts/build-firmware.sh v4 --release   # firmware now trusts the dev key
cargo run --manifest-path ota-sign/Cargo.toml -- sign --seed /tmp/dev.seed \
  --board heltec-v4 --image my-app.bin   # writes my-app.bin.sig
```

The board id in `sign --board` must be the one **the device reports**
(`board::BOARD`): `heltec-v4`, `heltec-v3`, `tdisplay`, `esp32c6` — note the
C6 mismatch with its release-asset name (`c6`), which `release.yml` maps.

## Updating older devices

Firmware released before signature enforcement accepts only the legacy
36-byte `OTA_BEGIN`. Hosts handle this automatically: Sapwood retries the
legacy form when the signed one is rejected as a bad length, and
`heartwood-ota` has `--legacy-unsigned`. That update path is how a device
gets *into* enforcement; from then on, unsigned images are refused.
