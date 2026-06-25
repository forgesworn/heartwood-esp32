# ESP8266 feasibility spike — BIP-340 signing on xtensa-lx106

**Status: GO for a USB-tethered signer (with caveats).** Validated 2026-06-25.
The make-or-break — does the cryptography fit the ESP8266? — is proven. The
residual risk is the unmaintained bare-metal platform, **not** the crypto.

## The question

The design doc (`../docs/2026-06-24-multi-board-display-port.md` §6) gated the
ESP8266 on RAM: it feared a ~130 KB secp256k1 signing context and called the
board "likely infeasible". This spike answers: **can a `no_std` BIP-340 Schnorr
signer compile to the ESP8266 (Tensilica LX106) and fit its RAM/flash?**

## What this crate is

A `no_std` **`staticlib`** exporting two `extern "C"` entries that make the full
signer chain reachable (so it can be compiled and sized):

- `heartwood_derive_child` — HMAC-SHA256 child-key derivation (the
  `heartwood-common::derive` primitive).
- `heartwood_schnorr_sign` — deterministic BIP-340 Schnorr signature over a
  32-byte event id, pure-Rust `k256`.

It is a **compile + size probe, not runnable firmware.** `staticlib` skips the
final link deliberately, so we need neither the (archived) `xtensa-lx106-rt`
runtime, a linker script, nor `xtensa-lx106-gcc`. It isolates the one question
that mattered.

## Result (measured 2026-06-25)

| Metric | Value | Notes |
|---|---|---|
| Compiles for `xtensa-esp8266-none-elf` | ✅ | rustc 1.87 esp fork, `-Zbuild-std=core` |
| Allocator required | none | built `build-std=["core"]` — signing path is alloc-free |
| `std` / `getrandom` | none | deterministic; self-contained dependency tree |
| Flash, reachable code (LTO) | **~145 KB** | `text`; fits 4 MB flash with vast margin |
| Static RAM (`data`+`bss`) | **0 bytes** | precomputed basepoint table lives in flash |
| Runtime RAM, one sign | **<5 KB stack** | signing touches only `ecmult_gen`, never the verify table |

This **disproves the original RAM fear**: a sign-only secp256k1 context never
allocates the ~1 MB `ecmult` verify table — only the small generator table is
needed, and precomputation puts it in flash.

## The one real snag — the toolchain, not the crypto

`-Zbuild-std` first failed compiling `compiler_builtins`:

```
rustc-LLVM ERROR: Error while trying to spill A8 from class AR:
Cannot scavenge register without an emergency spill slot!
```

The weakly-maintained LX106 LLVM backend cannot register-allocate the rustc-1.87
f16/f128 soft-float intrinsics. Fixed by omitting them (firmware never uses
128-bit floats) — see `.cargo/config.toml`:

```
build-std-features = ["compiler-builtins-no-f16-f128", "compiler-builtins-mem"]
```

## Reproduce

```sh
# The esp toolchain (installed by espup) carries rustc 1.87 and, unlike upstream,
# still ships the xtensa-esp8266-none-elf target.
cargo +esp build --release

# Size it (host llvm-tools; llvm-size is target-agnostic and reads xtensa ELF):
#   rustup component add llvm-tools-preview
llvm-size --totals target/xtensa-esp8266-none-elf/release/libesp8266_spike.a
```

## Verdict and residual gates

The cryptography is **comfortably feasible.** The gates that remain are platform,
not crypto, and need hardware (or QEMU) to close:

1. **Runtime alignment (the real unknown).** Compiling ≠ running. Xtensa traps
   unaligned access, and `k256`/`crypto-bigint` have historically faulted on
   Xtensa. Must be confirmed on-device. The C `libsecp256k1` path sidesteps this
   but needs `xtensa-lx106-gcc` + cross-build wiring.
2. **Side channels.** `k256` warns it is unsuitable where multiplication is
   variable-time; the LX106 makes no constant-time guarantee. A key-holding
   signer should weigh this before production.
3. **Unmaintained glue.** `esp8266-hal` / `xtensa-lx106-rt` are archived
   (embedded-hal 0.2); `espflash` 3.x dropped the ESP8266 (use `esptool.py` or
   `cargo-espflash 2.1.0`). The display/button/boot glue is the unmaintained
   part — the crypto is not.
4. **No Wi-Fi, ever.** Closed ROM blob, no `esp-wifi` for the 8266. Fine for a
   USB-tethered signer; it can never join the WiFi-standalone relay path.

**Recommendation.** Feasible for a **USB-tethered signer**, but on a frozen
platform. The pragmatic substitute is the **ESP32-C3** — pin-compatible with the
ESP8266, same price, fully-supported *stable* Rust, RISC-V (no Xtensa alignment
risk), embedded-hal 1.0 — which clears gates 1–3 and reuses the ESP32-C6 RISC-V
`board.rs` work.
