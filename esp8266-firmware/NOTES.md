# ESP8266 tethered-signer firmware — status & findings (2026-06-25)

A complete bare-metal USB-tethered Nostr signer for the ESP8266 (xtensa-lx106): the device
half of the daemon-mediated path. It speaks the HW serial frame protocol to the
`heartwood-bridge` daemon, which couriers NIP-46 over the relays.

## Status: a COMPLETE signer that COMPILES + LINKS into a flashable image. ✅

`cargo build --release` produces a valid `ELF 32-bit Tensilica Xtensa` executable
(text ~172 KB in IROM, 24 KB heap in DRAM — fits the chip). Implemented:
- `SESSION_AUTH (0x21)` → `SESSION_ACK (0x22)` — constant-time 32-byte secret.
- `FIRMWARE_INFO (0x59)` → `0x5A` — version/board.
- `PROVISION_LIST (0x05)` → `0x07` — k256-derived npub identity (bech32, verified vector).
- `ENCRYPTED_REQUEST (0x10)` → `SIGN_ENVELOPE_RESPONSE (0x35)` — the inline sign path:
  NIP-44 decrypt → NIP-46 dispatch (get_public_key / sign_event / connect / ping) →
  re-encrypt → build & sign the kind:24133 envelope, all on-device, reusing
  `heartwood-common` (converted to no_std). The daemon never sees plaintext or keys.
- **Boot self-test (POST)** — validates k256 pubkey derivation, BIP-340 signing, and a
  NIP-44 round-trip against host-computed known-answer vectors before operating; halts and
  shows the failing check on the OLED if the lx106 silently corrupts a result. Plus the OLED
  npub display and the FLASH-button sign-approval gate.

Toolchain wins along the way: the right runtime is `xtensa-lx-rt 0.12` (patched
`naked_asm!` + `.ifndef` guard, vendored via `[patch]`); release-only (opt-0 fails register
alloc); link via Espressif's `xtensa-lx106-elf` (x86_64/Rosetta, at `~/.local`); k256
arithmetic+ecdh compiles at opt-z (SIGSEGV only at opt-3); common's deps forced
`default-features=false`.

**KNOWN GAPS — untested on hardware** (compiling+linking ≠ correct):
- Keys live in a **flash key store** now (`storage.rs`, sector at 0x3F0000) — provision the
  seed + bridge secret with `provision.py` (`PROVISION` 0x01 / `SET_BRIDGE_SECRET` 0x23).
  `PROVISION` (the seed write) is **gated on a button hold** too, so a compromised host can't
  silently overwrite the key. Remaining: the seed is host-supplied (no on-device
  GENERATE_IDENTITY without an OLED to show the phrase).
- **Sign approval** — `sign_event` shows the request on the **OLED** (kind + content
  preview) and requires a physical button hold (`button.rs`: GPIO0/FLASH, ~1.5 s, ~20 s
  timeout) before signing; the OLED then shows `signed`/`denied`. So the hold confirms a
  *seen* event. Still to come: a richer policy view (full tags/recipient).
- **RNG entropy — RESOLVED (no hardware RNG in the security path).** The lx106's
  `WDEV_RAND` is only well-seeded with RF active, so a radio-off signer can't trust it.
  Both nonce sources are now deterministic: BIP-340 signing uses `aux_rand = 0`
  (`crypto::sign`), and the NIP-44 nonce is synthesised as `HMAC-SHA256(seed; tag ||
  client_pk || plaintext)` (`sign_path::synthetic_nonce`) — unpredictable + unique per
  (peer, message), no RNG. The review also **caught + fixed a correctness bug**: `crypto::sign`
  used `try_sign`, which SHA-256s the message again, so it signed `sha256(event_id)` and every
  signature would have failed Nostr verification; now `sign_prehash_with_aux_rand` signs the id
  directly. Host-verified against real k256.
- The **k256 Xtensa-unaligned-access** risk (the original Phase-0 question) is still only
  verifiable by flashing a real ESP8266.

### Board bring-up (NodeMCU ESP8266 + 0.96" OLED, CH340G, ESP-12F, 4 MB / 64 KB)
Fixed by analysis for this board (still hardware-untested):
- **Baud (FIXED).** esp8266-hal's `serial()` sets no baud → UART0 stayed at the boot ROM's
  ~74880 while the daemon talks 115200 (they'd exchange garbage). `main` now writes
  `UART0_CLKDIV` (0x6000_0014) = 80 MHz / 115200 = 694 directly (the HAL has no baud API).
- **Watchdog (FIXED).** The signer blocks on `serial.read()` while idle and runs ~1 s of
  EC math per sign; an active WDT would reset it. `main` disables it
  (`dp.WDT.watchdog().disable()`).
- **CH340G** wires USB↔UART0 (GPIO1/GPIO3) — matches the firmware. The daemon takes a
  manual serial-port path (no Espressif-VID filter), so a CH340G port works fine.
- **OLED** (SSD1306, I²C GPIO12/14) is unused — no pin conflict; no on-device approval or
  display UI yet.
- **4 MB flash** fits the ~172 KB image; **64 KB SRAM** holds the 24 KB heap + stack.

First-flash setup: set the daemon's `bridge.secret` to 32 bytes of `0x42` (matches the
firmware placeholder); the device's npub (from the placeholder seed) is the signer
identity, discovered via `PROVISION_LIST`. Flash with `esptool.py --chip esp8266 elf2image`
+ `write_flash`.

Still hardware-only: the k256 unaligned-access fault risk and the patched exception-vector
correctness. (The NIP-44 nonce RNG entropy concern is resolved — nonces are now synthetic,
see the KNOWN GAPS above.)

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
