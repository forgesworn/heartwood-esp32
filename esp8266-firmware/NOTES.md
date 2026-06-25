# ESP8266 firmware scaffold — status & findings (2026-06-25)

Goal: turn the `esp8266-spike/` staticlib (proves the crypto compiles) into a real
`no_main` binary that **compiles and links** for `xtensa-esp8266-none-elf` on the
current `esp` toolchain — groundwork before on-hardware bring-up.

## Status: COMPILES. Runtime port done. Only the final link needs a toolchain install.

`cargo build --release` now compiles **everything** — `core`, `compiler_builtins`,
`xtensa-lx 0.7`, the (patched) `xtensa-lx-rt 0.12`, `esp8266-hal 0.5.1`, and this crate.
The build reaches the link step; the only remaining error is the missing **ESP8266 GNU
linker**, not a code problem.

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

### The one remaining step: the linker
The link needs **`xtensa-lx106-elf-gcc`** (Espressif ESP8266 GNU toolchain) — espup does
NOT install it and there's no Homebrew formula. `rust-lld` (no install) gets most of the
way but can't process the GNU-ld-style vector script (`exception.x`: "unable to move
location counter backward … .vectors exceeds available address space"). So:
- **To produce a flashable ELF:** install `xtensa-lx106-elf-gcc`, then switch
  `.cargo/config.toml` back to the gcc driver (`-nostartfiles`, `-Wl,-Tlink.x`).
- Or fix the linker scripts for lld (fiddler; `exception.x` / `memory.x` region maths).

**Note:** compiling ≠ correct. The exception-handler asm and the whole image are still
**runtime-untestable without a physical ESP8266** (a wrong edit compiles but hard-faults).
The Xtensa-unaligned-access question for `k256` (the original Phase-0 risk) is also still
open and on-hardware-only.

## Build
1. `source ~/export-esp.sh`
2. `cargo build --release` from this dir → compiles; link fails only on the missing gcc.

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
