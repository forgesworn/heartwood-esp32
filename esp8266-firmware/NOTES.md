# ESP8266 firmware scaffold — status & findings (2026-06-25)

Goal: turn the `esp8266-spike/` staticlib (proves the crypto compiles) into a real
`no_main` binary that **compiles and links** for `xtensa-esp8266-none-elf` on the
current `esp` toolchain — groundwork before on-hardware bring-up.

## Status: COMPILES AND LINKS into a flashable image. ✅

`cargo build --release` produces a valid `ELF 32-bit LSB executable, Tensilica Xtensa`
(entry `0x40100450`, `.vectors` at `0x40100000`, `.text` in IROM, `.bss` in DRAM) — the
whole stack (`core`, `compiler_builtins`, `xtensa-lx 0.7`, the patched `xtensa-lx-rt 0.12`,
`esp8266-hal 0.5.1`, this crate) compiles, and it links with the lx106 GNU toolchain.

**Still untested on hardware** — compiling+linking ≠ correct. The patched exception asm
and the original `k256` Xtensa-unaligned-access question are only verifiable by flashing a
real ESP8266.

### What was solved
- **Right runtime.** `esp8266-hal 0.5.1` uses the maintained **`xtensa-lx-rt 0.12` +
  `xtensa-lx 0.7`** (esp8266 feature) — NOT the dead `xtensa-lx106-rt 0.1.2` (removed
  `llvm_asm!`, uncompilable).
- **Release only.** `core`/`compiler_builtins` compile at `opt-level=z` but FAIL at
  `opt-level=0` (lx106 backend "Cannot scavenge register"). Always build `--release`.
- **Runtime port (vendored `xtensa-lx-rt`, via `[patch.crates-io]`):**
  1. naked-fn syntax — `asm!(..., options(noreturn))` → `naked_asm!` (13 sites) + the
     `core::arch::naked_asm` imports.
  2. assembler scope — `naked_asm!` emits each body as an isolated unit, so the
     `.set XT_STK_*` constants + `SAVE_CONTEXT`/`RESTORE_CONTEXT` macros (formerly in
     shared `global_asm!`) weren't visible. Fixed in `assembly_esp8266.rs` with an
     `.ifndef HW_CTX_DEFS` guard prepended to every body via a `naked_ctx_asm!` wrapper:
     the first-assembled body defines them once, the rest skip, shared scope makes them
     visible — order-independent (the original failure was an emission-order race).

### The linker (solved)
The link needs **`xtensa-lx106-elf-gcc`** (the ESP8266 GNU toolchain). espup does NOT
install it, there's no Homebrew formula, the esp32 `xtensa-esp-elf` binutils refuse the
lx106 objects (different baked-in xtensa core config — "cross-endian/merge target data"),
and `rust-lld` can't process the GNU-ld vector script (`exception.x` location counter). So
the answer is the real toolchain. Installed Espressif's prebuilt:

```
curl -L https://dl.espressif.com/dl/xtensa-lx106-elf-gcc8_4_0-esp-2020r3-macos.tar.gz \
  | tar -xz -C ~/.local
export PATH="$HOME/.local/xtensa-lx106-elf/bin:$PATH"
```

macOS builds are x86_64 → runs via Rosetta on Apple Silicon (confirmed: `ld` 2.31.1,
`gcc` 8.4.0). `.cargo/config.toml` now drives the link through `xtensa-lx106-elf-gcc`.

## Build
1. `source ~/export-esp.sh`
2. `export PATH="$HOME/.local/xtensa-lx106-elf/bin:$PATH"`  (the lx106 linker)
3. `cargo build --release` from this dir → links `target/xtensa-esp8266-none-elf/release/heartwood-esp8266`.
4. To flash: `esptool.py --chip esp8266 elf2image <elf>` then `write_flash`.

## Recommendation
The ESP8266 toolchain story is now fully mapped and the hard part (resurrecting the
runtime on a modern compiler) is done. Remaining: one cross-linker install, then
on-hardware bring-up. If hardware/effort is the constraint, **ESP32-C3** reaches the same
USB-tethered-signer goal on a modern, supported, *testable* toolchain (riscv-rt/esp-hal,
no asm archaeology), reusing the `board.rs` seam. The daemon contract
(`heartwood-bridge`, `0x10`→`0x35`) is identical for any chip — no daemon changes.

## Next on the firmware itself
Evolve `src/main.rs` from the idle stub → UART0 echo → HW frame codec → SESSION_AUTH →
PROVISION_LIST → the `0x10`→`0x35` inline-sign path.
