# Opt-in note QR encoder evaluation

Local experiment, 17 November 2026. Base Heartwood revision: `ef13faf` on the
wrapped-account recovery branch. The separate embedded encoder is
`forgesworn-qr-embedded` 0.1.0. Its current QR revision and runtime snapshot
are recorded in `firmware/vendor/forgesworn-qr-embedded/VENDORED.json`. The
library is published on [crates.io](https://crates.io/crates/forgesworn-qr-embedded/0.1.0)
with [release artefacts and checks](https://github.com/forgesworn/qr/releases/tag/embedded-v0.1.0).
The vendor snapshot pins the released QR revision `85aec980b5c29f53a3c6d94b38d352fbe7237e97`.
This firmware integration remains unreleased and opt-in. The measurements
below used the earlier `forgesworn-qr-embedded-prototype` 0.0.0 snapshot; their
source and artefact hashes remain unchanged in the historical JSON record.
They are not fresh size measurements of the renamed 0.1.0 package.

`qr-compact` selects the dependency-free, fixed-buffer ForgeSworn encoder for
the existing offline bearer-note handover. Normal board builds retain
`qrcodegen-no-heap` 1.8.1. `qr-optimal` also selects the new encoder and enables
mixed-mode text planning for colour-panel URLs. The OLED always uses the raw
32-byte API at level L, fixed version 2. Colour panels use level L, automatic
version up to 8, without ECC boosting or ECI. The Heltec V3 continues to omit
the offline QR feature; this experiment does not enable it there.

The adapter is in `firmware/src/note_qr.rs`; `offline_qr.rs` retains its existing
physical confirmation, held-button, timeout, display-clearing, scaling and
quiet-field logic. Output may have a different valid mask from the old
encoder. Planning can reduce the symbol size for some mixed text. Nothing
adds a transport, logger, signer operation or a new copy of stored keys.
Borrowed input remains the caller's responsibility; ordinary buffer wiping
is not a whole-device erasure guarantee.

## Build and check

The local wrapper preserves normal board selection and accepts the opt-in
feature as an extra cargo argument:

```sh
bash scripts/build-firmware.sh tdisplay --release --features qr-compact
bash scripts/build-firmware.sh tdisplay --release --features qr-optimal
bash scripts/build-firmware.sh v4 --release --features qr-compact
bash scripts/build-firmware.sh c6 --release --features qr-compact
```

These commands build only. Do not use an image that exceeds its app slot.
The ordinary wrapper also replaces its board-tagged ELF copy; use the
comparison script below to retain separately named experimental images.

Host checks execute the actual adapter source without ESP-IDF or hardware:

```sh
python3 scripts/check-note-qr-vendor.py
cargo +stable test --locked --manifest-path firmware/qr-check/Cargo.toml --target-dir common/target --no-default-features
cargo +stable test --locked --manifest-path firmware/qr-check/Cargo.toml --target-dir common/target --features qr-compact
cargo +stable test --locked --manifest-path firmware/qr-check/Cargo.toml --target-dir common/target --features qr-optimal
```

They cover fixed v2 raw output, actual `note_url` construction for ordinary
and maximum stored hosts, the version ceiling, module bounds, explicit
cleanup, the compact API's automatic output wiping and optional planning.
The upstream embedded crate checks all 82 applicable existing ZXing matrices and
round trips, all version/level/mask combinations against the main encoder,
capacity boundaries and allocations. Its bundled tables match the original
encoder tables byte for byte. CI is configured for the three adapter host
configurations. [CI on the initial integration revision](https://github.com/forgesworn/heartwood-esp32/actions/runs/44090161232)
passed all 12 executed jobs; the C6 job was skipped by its existing workflow condition.

Refresh the vendor directory with the QR repository's
`rust/embedded/vendor.py`, after running its conformance checks. The source
crate has no development dependencies; its separate upstream conformance
harness holds the test oracles. The export disables local-snapshot publication,
omits the release profile and includes the MIT licence and specification.
This checkout compiles independently of any sibling QR checkout.
`check-note-qr-vendor.py` verifies recorded file
digests and the empty runtime dependency graph; it does not replace upstream
conformance tests or an independent review.

## Full firmware evidence

[Machine-readable measurements](qr-evaluation-2026-11-17.json) record app-image
bytes, ELF sections, public source/artifact SHA-256 digests in base64, compiler
identity, partition fit and available individual Xtensa frame sizes.
Writable-section totals include linker reservations and dummy sections; they
are not measurements of live RAM consumption.

The original `*-baseline` builds used the untouched firmware encoder at
`ef13faf`. `*-reference` builds use the new adapter with the old encoder;
`*-compact` and `*-optimal` use the same adapter source with their named
feature. All builds use release size optimisation, thin LTO and two build
workers on the installed Espressif toolchain, with the repository's std
size/backtrace options and normal board sdkconfig defaults. No signing or
flashing takes place.

| Board and encoder | App bytes | Saved against adapter reference | Actual app slot |
| --- | ---: | ---: | --- |
| T-Display reference | 2,335,472 | — | Fits 3 MiB |
| T-Display compact | 2,332,576 | 2,896 | Fits 3 MiB |
| T-Display optimal | 2,334,992 | 480 | Fits 3 MiB |
| Heltec V4 reference | 2,114,144 | — | Exceeds 2 MiB by 16,992 |
| Heltec V4 compact | 2,113,280 | 864 | Exceeds 2 MiB by 16,128 |
| ESP32-C6 reference | 2,282,752 | — | Fits 3 MiB |
| ESP32-C6 compact | 2,279,248 | 3,504 | Fits 3 MiB |

These full-firmware savings are modest. The larger standalone encoder-probe
savings in the QR repository do not predict the benefit after firmware LTO.
Ordinary hexadecimal note URLs remain version 5 in the host checks. The
deliberately numeric-heavy fixture reduces from version 6 to version 4 with
optimal planning; that fixture does not represent a typical random secret.

The local toolchain is older than CI's pinned Espressif 1.97.0.0; these are
local measurements of this exact branch, not predicted release sizes. The
original V4 baseline already exceeds its 2 MiB slot by 16,976 bytes. A smaller
candidate does not resolve that gate unless it actually fits. No partition,
flash size, logging ceiling or unrelated wrapped-recovery code was changed
to make the comparison pass.

Caller encoding buffers are 604 bytes with the old encoder, 602 bytes with
the compact API, and 1,582 bytes with optimal text planning. The new encoder
also has 57 bytes of local Reed-Solomon arrays. These numbers exclude scalar
locals, input, call frames, spills, display framebuffers and interrupts.
The optional planner is used only by colour-panel text; it is not allocated
for the OLED's raw secret.

| Linked build | Handover entry frame | Main encoder frame |
| --- | ---: | ---: |
| T-Display reference | 1,264 | 256 (`encode_codewords`) |
| T-Display compact | 1,264 | 304 (`encode_compact`) |
| T-Display optimal | 2,224 | 288 (`finish`), 240 (`encode_text`) |
| Heltec V4 reference | 1,264 | 256 (`encode_codewords`) |
| Heltec V4 compact | 1,264 | 304 (`encode_compact`) |

The compact variant does not reduce the observed handover entry frame. The
optimal variant adds 960 bytes there on this toolchain. Disassembly evidence
includes raw instruction words where Xtensa ELF mapping symbols prevent
objdump from displaying an `entry` mnemonic.

Individual frame sizes from Xtensa `entry` instructions are **not** additive
peak-stack bounds: LTO moves work between functions, some callees are shared,
and interrupts use the interrupted task's stack. RISC-V frame evidence is
not collected by this script. No FreeRTOS high-water marks, board latency or
physical scan results have been measured in this experiment.

To reproduce the paired measurements, with the existing ESP toolchain,
ESP-IDF sources and C compilers installed:

```sh
bash scripts/evaluate-note-qr.sh
# Or select only the named cases:
bash scripts/evaluate-note-qr.sh tdisplay-reference tdisplay-compact
```

This reuses `firmware/target`, writes logs and separately named ELFs/app images
under `firmware/target/qr-evaluation/`, and updates the JSON report. It never
opens USB. `espflash save-image` is used offline as CI uses it; the script
checks against the actual 3 MiB colour-panel or 2 MiB V4 app limit, rather than
the tool's default partition-size message. The local espflash panics parsing
the custom config partition when given the CSV, so the evaluation does not
pass that CSV to image conversion. Two failed CSV conversions produced no
image and are not measurements.

Local host verification passed all 14 adapter tests across the three feature
configurations, strict Clippy in each configuration, and 449 common-library
tests with `mnemonic-gen,cash` and the secp256k1 backend. The QR prototype's
82-vector conformance and broader encoder parity checks passed separately.
All seven paired firmware builds linked and converted offline; partition fit
is reported above rather than treated as a successful installation check.

For a future authorised disposable-board comparison, the exact pre-promotion compact T-Display
and C6 candidates and the optimal T-Display candidate are retained locally as
`firmware/target/qr-evaluation/{tdisplay-compact,tdisplay-optimal,c6-compact}.{elf,bin}`.
These still contain the prototype package identity; their digests are in the JSON report.
Rebuild the selected 0.1.0 configuration before testing the promoted package. Build logs are retained in the same
ignored directory. Reference and overflowing V4 image copies, and the new
C6 build cache, are removed after recording the evidence. Pre-existing
board-tagged ELFs are untouched. Generic Cargo release outputs may contain
an experimental feature build; use the named candidates or rebuild with the
intended board and features before any later installation.

## Physical acceptance still required

Keep both features experimental until a suitably provisioned disposable
board and explicit installation authority are available. The live T-Display
must not be reset or flashed as part of this local evaluation.

Use throwaway notes with the same payloads, scanner, brightness and display
settings for reference and candidate builds. Check the ordinary and longest
supported colour URLs, raw OLED v2 output, successful scanning and exact
payload readback, cancellation at both confirmations, dismissal by either
button, timeout clearing and rejection without a lingering QR. For planning,
include ordinary random-looking hexadecimal input and the deliberately
numeric-heavy fixture; do not infer typical savings from that latter case.

Capture `stack_free` before and after repeated entry, scan, dismiss and timeout
cycles, following `docs/HARDWARE-TEST-CHECKLIST.md` section 44. Record task
high-water marks and worst encoding/draw latency on each tested board. An
image must fit its actual partition before any such installation. Full host
checks, local linking and app-image conversion do not establish device or
owner acceptance.
