# Multi-board support: colour ST7789 boards + an ESP8266 spike

**Date:** 2026-06-24
**Status:** Design — for review before implementation
**Author:** Heartwood firmware

## Locked decisions (from kick-off)

1. **T-Display first.** The TENSTAR/LilyGO T-Display (classic ESP32 + ST7789) is the first new target — it is the smallest jump from today's Heltec/ESP32-S3 build.
2. **ESP8266 is a spike only.** The NodeMCU ESP-12F board gets a separate, time-boxed feasibility spike — *not* a port off the current firmware. It may prove infeasible; we decide go/no-go from the spike.
3. **Design before code.** This document is that design.

---

## 1. Motivation

Today the firmware runs on exactly one board family: the **Heltec WiFi LoRa 32 V3/V4**, both **ESP32-S3** with a **monochrome SSD1306 128×64 OLED**. We want Heartwood to run on three cheap, widely-available display boards:

| Ref | Board | Chip | Arch | Display | Host link | Buttons | Flash |
|----|-------|------|------|---------|-----------|---------|-------|
| — | **Heltec V3/V4** (baseline) | ESP32-S3 | Xtensa LX7 | SSD1306 **mono** 128×64 (I²C) | V4 native USB-JTAG / V3 CP2102 UART | 1 (PRG, GPIO0) | 8 MB |
| #2 | **TENSTAR / LilyGO T-Display** | **ESP32-D0WD** (original ESP32) | Xtensa LX6 | **ST7789 colour 240×135** (SPI) | CH9102 UART bridge | **2** (GPIO0 + GPIO35) | **4 MB** |
| #1 | **Waveshare ESP32-C6-LCD-1.47** | **ESP32-C6** | **RISC-V** (rv32imac) | **ST7789 colour 172×320** (SPI) | native USB-JTAG | 1 user (BOOT) | **4 MB** |
| #3 | **NodeMCU ESP-12F + OLED** | **ESP8266** | Xtensa LX106 | SSD1306 **mono** 128×64 (I²C) | CH340G UART bridge | 1 (FLASH) | ~4 MB |

Two things change at once for the two viable boards (#1, #2): the **display** (mono OLED → colour TFT) and the **chip/board** (new pins, new transport, and for the C6 a new CPU architecture). #3 is a different story (see §7).

Vendor reference captures for #2: [T-Display pin diagram](t-display-pin-diagram.png) (IPS ST7789V pinout — MOSI 19, SCLK 18, CS 5, DC 16, RST 23, BL 4) and [power/WiFi specifications](t-display-power-wifi-specs.png).

---

## 2. The gap — three seams that hard-code "Heltec S3 + SSD1306"

The current codebase has no board-abstraction layer; board identity is a compile-time cargo feature (`heltec-v3` / `heltec-v4`) and three concerns are wired directly to the Heltec hardware.

### 2.1 Display (`firmware/src/oled.rs`)
- A single concrete type alias drives everything (`oled.rs:28`):
  ```rust
  pub type Display<'a> = Ssd1306<I2CInterface<I2cDriver<'a>>, DisplaySize128x64, BufferedGraphicsMode<…>>;
  ```
  Every screen function takes `&mut Display<'_>`.
- **Good news:** all *drawing* goes through `embedded-graphics 0.8` (`Text`, `Rectangle`, `Line`, `Pixel`). The SSD1306-specific surface is tiny and confined to `oled.rs`: the type alias, `init`, `clear_buffer`, `flush`, and `set_display_on` (sleep/wake). ~14 touchpoints, one file.
- **Bad news:** the colour model is `BinaryColor` (mono), and **all 28 screens hard-code 128×64 landscape coordinates** — widths of `128`, height bounds of `64`, centring as `(128 - glyphs*10)/2`, bar widths `100`/`124`, `CHARS_PER_LINE = 18`. None of it is derived from the display size.
- The boot animation is a custom 56×56 1-bit cat sprite (`cat_sprites.rs`, `u64`-per-row bitmaps) drawn pixel-by-pixel — trivially re-colourable.

### 2.2 Board identity / pins / transport
- Pins are **hard-coded inline in `main.rs`** (no pin module): LED GPIO35, Vext GPIO36, I²C SDA/SCL GPIO17/18, OLED RST GPIO21, button GPIO0, plus the transport pins.
- Transport is a `#[cfg]`-branched struct `SerialPort` (`serial.rs:27`): V4 = `UsbSerialDriver` (native USB-JTAG), V3 = `UartDriver` (UART0). It already exposes a clean two-method contract — `read(buf, timeout_ms)` / `write(buf)` — that the whole codebase uses board-agnostically. **This is the pattern to extend.**
- `BOARD: &str` and the mutually-exclusive-feature `compile_error!` guards live in `main.rs:21-96`.

### 2.3 Build & flash plumbing — four knobs that must move together
- `.cargo/config.toml`: a single `[build] target = "xtensa-esp32s3-espidf"`, plus `[env] MCU = "esp32s3"` and per-target `CC_*` / `CFLAGS_* = -mlongcalls`.
- `Cargo.toml`: `default = ["heltec-v4"]`, board features.
- `sdkconfig.defaults` (shared, pins `CONFIG_IDF_TARGET="esp32s3"`) + per-board `sdkconfig.defaults.heltec-v{3,4}` fragments, selected via `ESP_IDF_SDKCONFIG_DEFAULTS`.
- `partitions.csv`: two **2 MB** OTA slots ⇒ needs **≥8 MB** flash. **Both new boards are 4 MB** — this table does not fit them (see §4.5).

---

## 3. Design overview

Four pieces, in dependency order:

1. **`board.rs`** — a compile-time board module: typed pin constants, button count, transport constructor, display constructor. Replaces the inline pins + `BOARD` const.
2. **Display driver swap** — an ST7789 colour `DrawTarget` behind the existing `oled::Display` seam, white-on-black first (minimal change), colour theming later.
3. **Responsive layout** — replace hard-coded 128×64 coordinates with size-derived helpers so the same screen code renders on 240×135 (landscape) and 172×320 (portrait).
4. **Build/flash plumbing** — per-board target/MCU/sdkconfig + a 4 MB partition table.

### 3.1 `board.rs` — the board abstraction

A new `firmware/src/board.rs`, one `#[cfg(feature = …)]` block per board, exposing a uniform surface:

```rust
// Pins (typed; None where a board lacks the signal)
pub const PIN_BUTTON_A: u32;            // primary / approve
pub const PIN_BUTTON_B: Option<u32>;    // second button (T-Display) or None
pub const PIN_LED: Option<u32>;
pub const PIN_BACKLIGHT: Option<u32>;   // TFT boards
// Display wiring (I2C OLED *or* SPI TFT — see DisplayKind)
pub enum DisplayKind { OledI2c { sda, scl, rst, vext }, St7789Spi { mosi, sclk, cs, dc, rst, bl, w, h, rotation } }
pub const DISPLAY: DisplayKind;
pub const BOARD: &str;                  // reported in FIRMWARE_INFO

// Constructors that consume the peripheral token (kept cfg-gated, like today)
pub fn make_serial(p: &mut Peripherals) -> SerialPort<'_>;
pub fn make_display(p: &mut Peripherals) -> oled::Display<'_>;
```

This keeps the **smallest non-breaking refactor** the board-seam analysis recommends: lift the inline pins and the two `#[cfg]` serial blocks out of `main.rs` into `board.rs`, leaving the Heltec builds byte-for-byte equivalent. New boards are added by filling in one `#[cfg]` block — `main.rs`'s dispatch loop never changes.

### 3.2 Display: SSD1306 mono → ST7789 colour

**Driver:** the [`mipidsi`](https://crates.io/crates/mipidsi) crate (maintained, ST7789 support, implements `DrawTarget<Color = Rgb565>`) over `esp-idf-hal` SPI (`SpiDeviceDriver`) with a `display-interface-spi` `SPIInterface` + DC/RST GPIOs.

**The seam** stays exactly where it is — the `oled::Display` type alias and five methods. We make `Display` an enum (or a small trait object) over the two backends and preserve the existing method names so **no screen function changes signature**:

| Existing call | SSD1306 (mono) | ST7789 (colour) |
|---|---|---|
| `clear_buffer()` | buffer memset | fill framebuffer with `Rgb565::BLACK` |
| `.draw(display)` (embedded-graphics) | `DrawTarget<BinaryColor>` | `DrawTarget<Rgb565>` |
| `flush()` | I²C buffer→panel | blit framebuffer over SPI (or no-op if direct-draw) |
| `set_display_on(b)` | SSD1306 command | toggle backlight pin (simplest, saves more power) |

**Colour model.** Drawing code uses `BinaryColor::On`. Stage the colour work:
- **Phase A (bring-up):** map `On → Rgb565::WHITE`, `Off/clear → BLACK`. The display looks like today's mono UI on a colour panel. Minimal diff, fast to get booting. A single theme constant `const FG: Rgb565` swapped in at every `MonoTextStyleBuilder` and in `draw_sprite_hd`.
- **Phase B (polish):** semantic colour — green APPROVED, red DENIED, amber countdown, a coloured cat. Pure additive change once Phase A works.

**Framebuffer vs direct-draw (RAM).** The existing `clear_buffer → draw → flush` model is double-buffered; to keep it flicker-free on a TFT we draw into an in-RAM `Rgb565` framebuffer (`embedded-graphics-framebuf`) and blit on `flush()`:

| Board | Framebuffer (W·H·2 bytes) | Usable SRAM | + secp ctx (~130 KB) | Verdict |
|---|---|---|---|---|
| T-Display (240×135) | **64.8 KB** | ~300 KB (ESP32 DRAM) | ~195 KB | comfortable |
| C6 (172×320) | **110 KB** | ~400 KB (C6 HP SRAM) | ~240 KB | workable; watch WiFi-standalone |

**Decision:** use a full `Rgb565` framebuffer on T-Display (preserves flush semantics, kills flicker, RAM is fine). Re-evaluate for the C6 — if 110 KB framebuffer + WiFi buffers + secp context gets tight in WiFi-standalone mode, fall back to direct-draw or a partial (banded) framebuffer there. (This is **Open decision A**.)

### 3.3 Responsive layout — the biggest single chunk of work

All 28 screens hard-code 128×64. The two new panels differ not just in size but in **orientation**: T-Display is **landscape 240×135** (close to today's 128×64 aspect, ~2× scale), C6 is **portrait 172×320** (taller — needs vertical re-flow). One hard-coded coordinate set cannot serve both.

Plan: introduce a `layout` module providing size-derived helpers, and rewrite each screen against it instead of literals:
```rust
pub struct Layout { pub w: i32, pub h: i32 }   // from board::DISPLAY
impl Layout {
    fn center_x(&self, text_w: i32) -> i32 { (self.w - text_w) / 2 }
    fn rule_y(&self) -> i32 { … }              // header underline
    fn line(&self, n: i32) -> i32 { … }        // nth body line for this height/font
    fn bar(&self) -> Rectangle { … }           // countdown/progress bar full-width
    fn font_scale(&self) -> u32 { … }          // 1× on OLED, 2× on TFT
}
```
- **Phase A** can ship with a coarse approach: keep landscape layouts, scale coordinates by the width/height ratio, and pick a larger font on the bigger panels (e.g. FONT_10X20 where FONT_5X8 was). Good enough to read on hardware.
- **Phase B** refines portrait screens on the C6 (more vertical room → stack more lines, bigger npub, taller cat).

This is ~28 screens to convert from literals to `Layout` calls — mechanical but not zero. It is the dominant cost and is shared across both new boards (and improves the OLED build too).

### 3.4 Buttons — 1 vs 2, and a pin collision

- **C6** has one user button (BOOT, **GPIO9** — verify) → behaves like today's single PRG button. No change to gesture logic.
- **T-Display** has **two** buttons (GPIO0 + GPIO35). GPIO35 is **also the Heltec LED pin** — fine, because pins are per-board in `board.rs`; there is no LED on T-Display to collide with at runtime.
- Today every handler takes a single `&PinDriver<Input>`. Rather than thread a second pin through `provision.rs`/`relay.rs`/`approval.rs`/etc. (wide blast radius), introduce a `Buttons` struct that owns one or two pins and exposes the *existing* gesture vocabulary, plus a natural two-button mapping where present:
  - 1-button board: tap / double-tap / hold (unchanged — today's logic).
  - 2-button board: **A = approve/select, B = cancel/back**, which is a clearer UX than hold-to-confirm. The seed-restore picker can map B to "back" instead of the long-hold.
- `Buttons` is constructed in `board.rs`; handlers take `&Buttons`. The gesture API stays source-compatible so the migration is a type swap, not a rewrite. (Two-button UX mapping is **Open decision B**.)

### 3.5 Build, target & flash plumbing

Per-board knobs (the build script already layers sdkconfig fragments; extend it):

| Knob | Heltec (S3) | T-Display (orig ESP32) | C6 (RISC-V) |
|---|---|---|---|
| Rust target | `xtensa-esp32s3-espidf` | `xtensa-esp32-espidf` | `riscv32imac-esp-espidf` |
| `MCU` | `esp32s3` | `esp32` | `esp32c6` |
| C cross-compiler | `xtensa-esp32s3-elf-gcc` | `xtensa-esp32-elf-gcc` | riscv32 gcc (IDF-provided) |
| `CFLAGS … -mlongcalls` | yes | **yes** | **no** (RISC-V) |
| `CONFIG_IDF_TARGET` | `esp32s3` | `esp32` | `esp32c6` |
| Console suppression | V3 only | **yes** (UART bridge) | no (native USB) |

Two structural notes:
1. **`.cargo/config.toml` has a single `[build] target` and an unconditional `MCU = esp32s3`.** Multi-target builds must pass `--target` explicitly and export `MCU` per board (the `[env]` entries are `force = false`, so a shell export wins). `scripts/build-firmware.sh` becomes the single source of truth: `build-firmware.sh tdisplay` sets target + MCU + sdkconfig together. Keep a sensible default for IDE/`cargo run`.
2. **4 MB partition table.** `partitions.csv` (2×2 MB OTA) needs 8 MB. Both new boards are 4 MB. Options:
   - **Single-OTA 4 MB** (`factory` + one `ota_0`, or one OTA slot + larger NVS): simplest, but **loses A/B rollback** — a bad OTA needs a USB re-flash.
   - **Dual-OTA 4 MB** at ~1.7 MB/slot: keeps rollback but is tight (app must stay < ~1.7 MB; today it targets < 2 MB with `opt-level="z"`).
   - Per-board `CONFIG_PARTITION_TABLE_CUSTOM_FILENAME` lets 8 MB and 4 MB boards coexist.
   (4 MB OTA strategy is **Open decision C**.)

---

## 4. Bring-up plan — T-Display (first target)

Pin map (LilyGO TTGO T-Display, classic ESP32; verify against the TENSTAR clone):

| Signal | GPIO |
|---|---|
| ST7789 MOSI | 19 |
| ST7789 SCLK | 18 |
| ST7789 CS | 5 |
| ST7789 DC | 16 |
| ST7789 RST | 23 |
| ST7789 backlight | 4 |
| Button A | 0 |
| Button B | 35 |
| Battery ADC | 34 |
| USB↔UART | via CH9102 on UART0 (TX0/RX0) |

Milestones:

- **M0 — toolchain + blink.** Install `xtensa-esp32-espidf` target; build a minimal binary; confirm flashing over the CH9102 bridge and serial-frame round-trip on UART0 (reuse the V3 UART path).
- **M1 — ST7789 hello.** Stand up `mipidsi` over esp-idf SPI; draw "HEARTWOOD" + a filled rect. Proves SPI pins, init sequence, orientation, backlight.
- **M2 — `board.rs` refactor.** Extract Heltec pins/transport into `board.rs` with the Heltec builds unchanged (CI still green). Add the T-Display block.
- **M3 — display seam.** Make `oled::Display` back onto either SSD1306 or ST7789; implement `clear/flush/set_display_on` for the framebuffer path; Phase-A white-on-black mapping.
- **M4 — responsive layout.** Land the `layout` module; convert the screens (start with boot, idle/npub, sign-approval, PIN, restore — the must-haves) to size-derived coordinates.
- **M5 — full firmware boot.** Provision a master, pair, **sign an event end-to-end** with physical approval via Button A; restore flow via the two-button picker.
- **M6 — fit & finish.** 4 MB partition table + OTA decision; FIRMWARE_INFO reports `tdisplay`; release asset wiring; hardware-test-checklist pass.

Top risks: ST7789 init/rotation quirks on the clone (low, well-trodden); UART-console bleed into the frame protocol (mitigated by `CONFIG_ESP_CONSOLE_NONE`, as on V3); 4 MB OTA tradeoff (decision, not a risk).

---

## 5. Second target — ESP32-C6

Reuses everything from §4 except the chip layer. What differs:
- **RISC-V target** `riscv32imac-esp-espidf`, `MCU=esp32c6`, **no `-mlongcalls`**. Confirm the esp Rust toolchain channel builds it (it's a `-Zbuild-std` espidf target; IDF 5.3 supports C6).
- **k256 alignment caveat is Xtensa-specific** — on RISC-V the pure-Rust path *might* work, but we stay on the `secp256k1` C-FFI backend for parity; it is portable C and builds for RISC-V.
- **Native USB-JTAG** transport (reuse the V4 `UsbSerialDriver` path) — no UART bridge.
- **Display** ST7789 **172×320 portrait** (MOSI6/SCLK7/CS14/DC15/RST21/BL22), WS2812 RGB LED on GPIO8 (a nice "approved/denied" colour cue), single BOOT button.
- Portrait re-flow (Phase B of §3.3) matters more here than on the landscape T-Display.

Effort is small *after* T-Display, because the display layer, layout module, board abstraction and partition work are already done — C6 is "new `board.rs` block + RISC-V build profile + portrait layout pass".

### Status (2026-06-25): code-complete, blocked on one RISC-V linker assert

The full C6 profile is implemented and **the firmware compiles**: `board.rs` bring-up (ST7789 172×320 portrait on SPI2 — MOSI6/SCLK7/CS14/DC15/RST21/BL22; native USB-Serial-JTAG on GPIO12/13; BOOT button GPIO9), the `riscv32imac-esp-espidf` target + the `riscv32-esp-elf` GCC (installed via `espup install -r -t esp32c6`; `~/export-esp.sh` now carries both Xtensa and RISC-V), `sdkconfig.defaults.c6`, the 4 MB partition table, and the `c6` build profile. Build: `scripts/build-firmware.sh c6 --release`.

**The one blocker is the final link, not the firmware:**

```
ld: The gap between .flash.rodata and .eh_frame_hdr must not exist to produce the final bin image.
```

esp-idf's `esp_system/ld/esp32c6/sections.ld` asserts `.flash.rodata → .eh_frame_hdr → .eh_frame` are contiguous (`ASSERT_SECTIONS_GAP`). The stray `.eh_frame` is the **RISC-V `libgcc`** (24 objects — the 64-bit-math / soft-float helpers the crypto pulls in; Rust, `core`/`std` and `secp256k1-sys` are all verified clean via `llvm-objdump`). The Xtensa boards have no such assert, so they link.

Fixes attempted and ruled out, with evidence:
- `-C force-unwind-tables=no` (Rust) + `-fno-*-unwind-tables` (C) — keep Rust/secp256k1 out of `.eh_frame` (verified clean objects), but libgcc's remains.
- `CONFIG_ESP_SYSTEM_USE_EH_FRAME=y` (force-applied via `cargo clean -p esp-idf-sys`) — collects `.eh_frame` into a placed section, but the assert still fails (a forward-`ALIGNOF` gap in esp-idf's own script).
- A `/DISCARD/ : { *(.eh_frame) *(.eh_frame_hdr) }` fragment via `-C link-arg=-Wl,-T,…` — correct in concept, but **`ldproxy` (esp-idf's linker wrapper) does not forward the extra `-T` to `ld`**, so it never applies. Confirmed: the arg reaches the rustc→ldproxy command but the gap persists with `USE_EH_FRAME` off and no competing `KEEP`.

Remaining paths (deferred — both must reach past `ldproxy`): patch esp-idf's `sections.ld.in` to relax/remove the `.eh_frame` asserts, or add a custom esp-idf component carrying a `linker.lf` discard fragment. The board also needs hardware to finish regardless — the panel offsets (34,0), colour inversion and SPI clock are bench-guesses, as on the T-Display.

> **Gotcha for the next session:** esp-idf-sys keeps a *sticky* generated `sdkconfig` — editing `sdkconfig.defaults.c6` does **not** regenerate it; force it with `cargo clean -p esp-idf-sys --release --target riscv32imac-esp-espidf`.

---

## 6. ESP8266 — feasibility spike (RESOLVED 2026-06-25: GO for a tethered signer, with caveats)

The ESP8266 cannot run this firmware (no ESP-IDF-v5 std; frozen RTOS/NONOS SDK). It is a **separate minimal `no_std` crate**, not a firmware feature — see [`esp8266-spike/`](../esp8266-spike/), which compiles and sizes the full signer for `xtensa-esp8266-none-elf`.

**The spike ran, and it flips this section's original assumption.** The make-or-break was thought to be RAM (a feared ~130 KB signing context). It is not: a *sign-only* secp256k1 context never allocates the large `ecmult` verify table — Schnorr signing touches only the small generator (`ecmult_gen`) table, which precomputation places in flash. Measured, pure-Rust `k256` building the full *seed → HMAC-SHA256 child → BIP-340 sign* chain:

| Metric | Result |
|---|---|
| Compiles (rustc 1.87 esp fork, `no_std`) | ✅ |
| Allocator | none (built `build-std=["core"]`) |
| Flash, reachable code (LTO) | **~145 KB** (fits 4 MB with vast margin) |
| Static RAM (`data`+`bss`) | **0 bytes** |
| Runtime RAM, one sign | **<5 KB stack** |

The one snag was the toolchain, not the crypto: `-Zbuild-std` choked on the rustc-1.87 f16/f128 soft-float intrinsics in `compiler_builtins` (the weakly-maintained LX106 backend "cannot scavenge register"), fixed with `build-std-features = ["compiler-builtins-no-f16-f128", "compiler-builtins-mem"]`.

**Residual gates — platform, not crypto; need hardware to close:**
1. **Runtime alignment.** Xtensa traps unaligned access and `k256`/`crypto-bigint` have historically faulted on it; compiling ≠ running, so confirm on-device or QEMU. The C `libsecp256k1` path avoids this but needs `xtensa-lx106-gcc`.
2. **Side channels.** `k256` is variable-time-multiplication-sensitive; the LX106 gives no constant-time guarantee. Weigh before production for a key-holding signer.
3. **Unmaintained glue.** `esp8266-hal` / `xtensa-lx106-rt` archived (embedded-hal 0.2); `espflash` 3.x dropped the 8266 (use `esptool.py`). The crypto is fine; the bare-metal platform is the cost.
4. **No Wi-Fi, ever.** Closed ROM blob, no `esp-wifi`. Fine for a USB-tethered signer; it can never join the WiFi-standalone relay path.

**Verdict:** feasible for a **USB-tethered signer**, on a frozen platform. The pragmatic substitute is the **ESP32-C3** — pin-compatible with the ESP8266, same price, fully-supported *stable* Rust, RISC-V (no Xtensa alignment risk), embedded-hal 1.0 — which clears gates 1–3 and reuses the §5 RISC-V / `board.rs` work. Open call for the user: pursue the tethered ESP8266 as-is, pivot the "cheap third board" to the ESP32-C3, or stop at the ESP32-S3 / ESP32 / C6 set already supported.

---

## 7. Sequencing, effort & shared work

```
board.rs refactor ──┐
                    ├─► display seam (mipidsi) ──► layout module ──► T-Display boot+sign ──► 4MB OTA + release
ST7789 hello ───────┘                                   │
                                                        └─► C6 (RISC-V profile + portrait pass)   [fast follow]

ESP8266 spike ───────────────────────────────────────── (independent; go/no-go gate)
```

- **Biggest cost:** the 28-screen responsive-layout conversion (§3.3) — shared by both new boards and benefits the OLED build.
- **Genuinely new per board:** a `board.rs` block, a build profile, a layout/orientation pass.
- **Reused as-is:** the entire NIP-46/crypto/storage/policy/OTA stack, the frame protocol, the transport contract, the gesture logic.
- T-Display and C6 share ~80% of the work; do T-Display end-to-end first to prove the seams, then C6 is a fast follow.

## 8. Open decisions (need your call)

- **A. Framebuffer strategy** — full `Rgb565` framebuffer (recommended for T-Display; flicker-free, RAM fine) vs direct-draw. Re-decide for C6 if WiFi-standalone RAM is tight.
- **B. Two-button UX (T-Display)** — keep the 1-button tap/double/hold vocabulary on both, or adopt **A=approve / B=cancel** where a second button exists (clearer, but a second UX path to maintain).
- **C. 4 MB OTA layout** — single-OTA (simple, no rollback) vs dual-OTA at ~1.7 MB/slot (keeps rollback, tight). Affects every 4 MB board.
- **D. Colour staging** — confirm Phase A (white-on-black, fast) before Phase B (semantic colour). Recommended.

---

*Appendix: source maps for this design — display rendering inventory (28 screens, all 128×64-hardcoded; SSD1306 coupling isolated to `oled.rs`), board-variation seam (`serial.rs` transport contract, inline pins in `main.rs`, build plumbing), and the ESP8266 RAM/toolchain feasibility brief — are summarised inline above and were produced from a full read of `firmware/src` on 2026-06-24.*
