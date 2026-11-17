> Vendored runtime snapshot. Development and comparison commands below
> refer to the upstream QR repository. See VENDORED.json for exact source hashes.

# ForgeSworn QR Embedded

`forgesworn-qr-embedded` is an allocation-free, dependency-free `no_std` QR
encoder with fixed caller-owned buffers. It is a separate crate in the
[ForgeSworn QR repository](https://github.com/forgesworn/qr), using the same
[SPEC.md](SPEC.md), standard tables and conformance vectors as the full encoder.
It needs Rust 1.87 or newer and no allocator, operating system or display driver.

Add the package to your application, or use the source path or verified vendor
exporter below when working from a source checkout:

```toml
[dependencies]
forgesworn-qr-embedded = "0.1.0"
# Enable mixed-mode planning only when needed:
# forgesworn-qr-embedded = { version = "0.1.0", features = ["optimal"] }
```

The package has its own version lifecycle, independent of the full QR crate.
The runtime contains only the encoder, standard tables, licence and docs.
A separate unpublished conformance harness holds the main encoder and JSON
parser as test-only dependencies. No QR implementation has been added as a
runtime dependency. Heartwood's integration remains opt-in.

It supports versions 1–8, all four error-correction levels, raw byte input,
UTF-8 ECI and automatic or explicit masks. The default build offers
`encode_bytes` and `encode_simple_text`. Simple text uses one numeric,
alphanumeric or UTF-8 byte segment. The optional `optimal` feature adds
`encode_text` with the main encoder's optimal segmentation and exact matrix
contract, using a separate caller-owned `TextPlanner`. Raw bytes and simple
text never require a planner. There is no decoder or display-driver code.

```rust
use forgesworn_qr_embedded::{encode_bytes, Ecc, Options, Workspace, MODULE_BYTES};

let mut scratch = Workspace::new();
let mut output = [0u8; MODULE_BYTES];
let options = Options { ecc: Ecc::L, version: Some(2), ..Options::default() };
let code = encode_bytes(&[0xabu8; 32], &options, &mut scratch, &mut output).unwrap();
assert_eq!(code.size(), 25);
// Draw code.is_dark(x, y) through the board's existing display backend.
drop(code); // wipes output; scratch was already wiped before encode returned.
assert!(output.iter().all(|&b| b == 0));
```

With `optimal` enabled, construct `TextPlanner::new()` and call
`encode_text(text, &options, &mut planner, &mut scratch, &mut output)`.

The caller retains responsibility for input, quiet zones, scaling, display
clearing, physical confirmation and timeouts. Buffer wiping uses volatile
stores and a compiler fence, not a promise to erase compiler copies, stack
spills or registers. Destructors do not run after an abort or power loss and
can be bypassed by deliberately forgetting an object. See the precise
buffer contract in SPEC.md.

## Run the checks

From the repository root, reuse its Rust target directory:

```sh
cargo +stable test --locked --manifest-path rust/embedded/conformance/Cargo.toml --target-dir rust/target --no-default-features -- --nocapture
cargo +stable test --locked --manifest-path rust/embedded/conformance/Cargo.toml --target-dir rust/target --all-features -- --nocapture
cargo +stable run --locked --manifest-path rust/embedded/conformance/Cargo.toml --target-dir rust/target --features optimal --release --example compare
python3 scripts/check-embedded-package.py
```

To export or verify a consumer snapshot:

```sh
python3 rust/embedded/vendor.py /path/to/consumer/vendor/forgesworn-qr-embedded
python3 rust/embedded/vendor.py /path/to/consumer/vendor/forgesworn-qr-embedded --check
```

The export includes runtime code, its licence and specification, and a
`VENDORED.json` record of the base revision, local-change status and SHA-256
file digests in base64. Its manifest disables publication of the local snapshot
and omits the release profile; the consumer chooses its own profile. Run upstream
conformance tests before refreshing a snapshot.

Add `--release` to either test command to check the release build. The library
targets Rust 1.87; the conformance harness and example use the main crate as an
oracle and need Rust 1.96 or newer. `serde_json` is test-only. No other QR implementation
has been added as a dependency. Tests cover:

- All **82** existing ZXing vectors within versions 1–8, with exact matrices
  and decode round trips through the optimal API. Larger vectors are outside
  the embedded crate's scope and are not counted as passes.
- Matrix, mask and bit-count parity with the main encoder across every version,
  level, all eight explicit masks and automatic selection, binary input,
  mixed text, Unicode and deterministic generated cases. Simple text is
  compared against the main encoder with the corresponding single mode.
- Capacity, version ceilings, ECI, invalid options, scratch/output/planner
  wiping and a thread-local counting allocator observing zero allocations
  through successful encoding, drawing, dropping and rejected calls.

The full QR APIs and vectors are unchanged. CI checks both feature
configurations and the actual extracted crate, including a fresh dependency
consumer and Rust 1.87 builds. The specification and standard-table copies
must match their originals.
Library target builds need no ESP-IDF or connected board, using an installed
Espressif Rust toolchain and its Rust sources:

```sh
cargo +esp build --locked --manifest-path rust/embedded/Cargo.toml --target-dir rust/target --no-default-features --release --lib --target xtensa-esp32-none-elf -Zbuild-std=core -j 2
cargo +esp build --locked --manifest-path rust/embedded/Cargo.toml --target-dir rust/target --no-default-features --release --lib --target riscv32imac-unknown-none-elf -Zbuild-std=core -j 2
```

Add `--features optimal` to check that variant.

## Compact iteration, 17 November 2026

| Named caller buffers | Compact | With optimal text | Current Heartwood |
|---|---:|---:|---:|
| Scratch | 301 bytes | 301 bytes | 302 bytes |
| Output | 301 bytes | 301 bytes | 302 bytes |
| Planner | 0 | 980 bytes | 0 |
| Total | **602 bytes** | **1,582 bytes** | **604 bytes** |

The first prototype needed 2,377 bytes of caller buffers. This iteration reuses
scratch for interleaved codewords and then the reserved-module map. It applies,
scores and undoes mask candidates in the output instead of retaining more
matrix copies. Planning is optional and separate. The Reed-Solomon phase has
57 bytes of additional local arrays, wiped on drop. These figures exclude
input, metadata, call frames, compiler temporaries and display framebuffers;
**602 bytes is not a whole-stack bound**. The counting allocator observed zero
allocations in the tested compact and optimal paths.

[Recorded prototype comparison](https://github.com/forgesworn/qr/blob/main/rust/embedded/bench/results-2026-11-17.json) pins source and harness
hashes, compiler versions, symbol sizes, host timings and linked ELF section
sizes. Host: Apple M1, Rust 1.100.0. Architecture probes: Espressif Rust
1.87.0.0, size optimisation, thin LTO, one codegen unit and aborting panics.
Repository baseline: `dd88998`. These recorded measurements predate table bundling and the 0.1.0 package
identity. They retain the exact measured source hashes and are historical
evidence, not measurements of the renamed package.

Local checks passed in debug and release for both feature configurations,
including the documentation example. Strict Clippy passed with and without
`optimal`, as did formatting, generated-document freshness and the supported
main encoder's 11 regression tests. Both architecture probes linked with and
without `optimal`. These checks do not establish physical scan acceptance.

| Standalone linked code and constants | Existing encoder 1.8.1 | Compact | Optimal |
|---|---:|---:|---:|
| Classic ESP32 Xtensa | 18,998 bytes | 10,358 bytes | 12,958 bytes |
| ESP32-C6-compatible RISC-V | 18,970 bytes | 9,586 bytes | 12,392 bytes |

These are allocated, file-backed section totals from equivalent standalone
probes with synthetic linker scripts, not archive sizes, bootable firmware
or a Heartwood firmware-size delta. All buffers in these probes are on the
stack; their zero static-RAM section totals do not mean zero RAM use. Each
probe includes all three workloads below and reads every module before wiping
both buffers. The optimal probe uses the compact API for raw bytes.

The host comparison rotates engine order across nine batches of 200 calls,
after 20 warm-ups per engine and payload. It records the median, minimum and
maximum of batch means. Timing includes encoding, full module readout, buffer
creation and wiping. It excludes display I/O. Only three throwaway workloads
are measured; the numeric-heavy example deliberately demonstrates segmentation
and is not representative of random secrets. Host timings do not establish
ESP32 latency.

| Synthetic payload | Versions: baseline / compact / optimal | Baseline µs | Compact µs | Optimal µs |
|---|---|---:|---:|---:|
| 32 raw bytes | v2 / v2 / v2 | 324.2 | 165.9 | 174.6 |
| Ordinary hexadecimal note URL | v5 / v5 / v5 | 799.4 | 387.6 | 410.0 |
| Deliberately numeric-heavy note URL | v6 / v6 / v4 | 1137.2 | 495.7 | 346.5 |

All engines use level L, no ECC boosting and a version ceiling of 8. Raw input
is fixed at version 2. Different mask scoring can produce different valid
matrices between the external baseline and this encoder; exact matrix parity
is tested against our main encoder and existing ZXing vectors.

## Reproduce the external comparison

`bench/compare.py` compiles an explicitly supplied, already installed
`qrcodegen-no-heap` 1.8.1 source directly with `rustc`. It validates the source
against the cached crate archive and its package hash from Heartwood's lockfile.
It never downloads, vendors or adds that library as a Cargo dependency, and
that baseline is not used by the crate or its conformance tests.

```sh
python3 rust/embedded/bench/compare.py \
  --baseline-source /path/to/existing/qrcodegen-no-heap-1.8.1/src/lib.rs \
  --targets riscv32imac-unknown-none-elf xtensa-esp32-none-elf \
  --xtensa-bin /path/to/existing/xtensa-esp-elf/bin
```

The matching archive is inferred from Cargo's registry layout, or can be given
with `--baseline-archive`. Both compilers and target linkers must already be
installed. Output is written under `rust/target/embedded-comparison/`; retain
`report.json` before removing that task's generated output.

This is enough to justify a bounded Heartwood integration experiment: compact
encoding preserves the current caller-buffer budget, while optional planning
can reduce some mixed-text symbols. Before replacing its encoder, compare
full firmware size and actual on-board stack/latency, then physical scanning
on the OLED and colour panels using the same payloads and display settings.
No device was opened, flashed or reset. The local Heartwood adapter keeps
these features opt-in; its full firmware measurements and physical acceptance
requirements are recorded in that repository.

## Full firmware evidence and release

The pre-promotion Heartwood builds saved 2,896 app bytes on T-Display, 864 on
Heltec V4 and 3,504 on ESP32-C6 with compact encoding. Those savings are much
smaller than the standalone probes. The compact handover entry frame was
unchanged; optimal text added 960 bytes there on the measured Xtensa toolchain.
These are historical prototype measurements; package renaming can affect LTO
and is not a fresh size measurement. See Heartwood's
[exact evaluation record](https://github.com/forgesworn/heartwood-esp32/blob/main/docs/QR-ENCODER-EVALUATION.md).
Board latency, physical scanning and task high-water marks remain unmeasured.

The separate `release-rust-embedded.yml` workflow checks an existing
`embedded-v0.1.0` GitHub release tag, verifies the extracted package and defaults
to a dry run. Initial publication requires bootstrap authentication; later
releases use the crate's configured trusted publisher.
It does not publish the full QR crate or change its release version.
