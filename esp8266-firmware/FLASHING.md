# Flashing the Heartwood ESP8266 signer

Step-by-step for the **NodeMCU ESP8266 + 0.96" OLED** board (CH340G USB‑serial,
ESP‑12F module, 4 MB flash). Everything here is for a Mac (Apple Silicon); Linux
notes are inline.

> ⚠️ **Untested on hardware.** This firmware compiles, links, and produces a valid
> flashable image, and the board‑specific bugs (baud, watchdog) are fixed by
> analysis — but it has never run on real silicon. Flash a spare board first, and
> use a throwaway key until you've watched it sign correctly. See `NOTES.md` for
> the known gaps (hardcoded keys, auto‑approve, RNG entropy, the k256/lx106
> alignment question).

---

## 0. One‑time setup

**Build toolchain** (already installed in this workspace):
- The `esp` Rust toolchain (espup) — `source ~/export-esp.sh` puts it on PATH.
- The ESP8266 GNU linker at `~/.local/xtensa-lx106-elf/` (Espressif prebuilt; x86_64
  via Rosetta). If it's missing:
  ```sh
  curl -L https://dl.espressif.com/dl/xtensa-lx106-elf-gcc8_4_0-esp-2020r3-macos.tar.gz \
    | tar -xz -C ~/.local
  ```

**Flasher** — esptool (Espressif's universal flash tool, supports the ESP8266):
```sh
pip install esptool          # → `esptool.py` on PATH
# or use the one bundled with esp-idf:
#   ~/.espressif/python_env/idf5.2_py3.14_env/bin/esptool.py
```

**USB driver** — the board uses a **CH340G** (WCH vendor `0x1a86`). Recent macOS has
the driver built in; if the port doesn't appear, install WCH's `CH34xVCPDriver`.
(The board is *not* an Espressif‑VID device, which is fine — the daemon takes a
manual port path, it doesn't filter by VID.)

---

## 1. Build the firmware

```sh
cd heartwood-esp32        # the wip/esp8266-firmware branch
git checkout wip/esp8266-firmware
source ~/export-esp.sh
export PATH="$HOME/.local/xtensa-lx106-elf/bin:$PATH"   # the lx106 linker
cd esp8266-firmware
cargo build --release     # MUST be --release: opt-0 fails on the lx106 backend
```
Output ELF: `target/xtensa-esp8266-none-elf/release/heartwood-esp8266`.

## 2. Make the flashable image

```sh
ELF=target/xtensa-esp8266-none-elf/release/heartwood-esp8266
esptool.py --chip esp8266 elf2image \
  --version 2 --flash_mode dio --flash_freq 40m --flash_size 4MB \
  -o heartwood-esp8266.bin "$ELF"
# → "Successfully created esp8266 image." (single .bin, flashes at 0x0)
```
`dio`/`40m` are the universally‑safe ESP‑12F settings. Sanity‑check it:
```sh
esptool.py --chip esp8266 image_info heartwood-esp8266.bin   # expect "Checksum: … (valid)"
```

## 3. Find the serial port

Plug the board in via USB‑C, then:
```sh
ls /dev/cu.wchusbserial*     # macOS, CH340G  →  e.g. /dev/cu.wchusbserial1420
# Linux:  ls /dev/ttyUSB*    →  e.g. /dev/ttyUSB0
```

## 4. Flash

```sh
PORT=/dev/cu.wchusbserial1420            # from step 3
esptool.py --chip esp8266 --port "$PORT" --baud 460800 erase_flash
esptool.py --chip esp8266 --port "$PORT" --baud 460800 \
  write_flash 0x0 heartwood-esp8266.bin
```
The NodeMCU auto‑resets into the bootloader via DTR/RTS, so no buttons needed. If
esptool can't sync, hold **FLASH** (GPIO0) while tapping **RST**, then retry.

## 5. Verify the chip boots

The firmware itself prints **nothing** human‑readable — it only speaks the binary
frame protocol. But the **boot ROM** logs at 74880 baud, which confirms the flash
is good:
```sh
esptool.py --chip esp8266 --port "$PORT" --baud 74880 read_flash 0x0 0x10 /dev/null  # or:
python3 -m serial.tools.miniterm "$PORT" 74880   # watch the ROM boot banner, then Ctrl-]
```
A clean boot banner (no rst‑cause loop) = the image loads and runs. The firmware
then switches UART0 to 115200 and waits for the daemon.

## 6. Point the daemon at it

On the host running `heartwood-bridge`, configure an **HSM‑mode** instance
(`HEARTWOOD_DATA_DIR`, e.g. `/var/lib/heartwood/esp8266`):

| File | Contents |
|------|----------|
| `master.payload` | `hsm:/dev/cu.wchusbserial1420` (the port from step 3) |
| `bridge.secret` | 32 bytes of `0x42` — matches the firmware placeholder: `printf '\x42%.0s' {1..32} > bridge.secret` |
| `config.json` | `{"relays":["wss://relay.damus.io","wss://nos.lol"]}` |

Then run the bridge (`heartwood-bridge`, `RUST_LOG=info`). Staged check — each step
exercises more of the device:

1. **`bridge authenticated`** in the log → serial + **baud are correct** (this is
   the bug we fixed; if it hangs here, double‑check the port/baud).
2. **`device masters: npub1…`** → `PROVISION_LIST` worked, which means **k256
   pubkey derivation ran on the lx106** — the big alignment question is answered.
3. Point a NIP‑46 client (Amber, nostr‑tools, Bark) at that npub and ask it to
   sign → the bridge couriers `0x10`→`0x35`, the device does the full NIP‑44 +
   sign, and a signed event hits the relays. **End‑to‑end.**

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| esptool "Failed to connect" | Wrong port, or not in bootloader — hold FLASH + tap RST. |
| Boots, but bridge never authenticates | Baud/comms — confirm the firmware set 115200 (it should) and the port is right. |
| Authenticates, but no `device masters` | `PROVISION_LIST` failed → k256 fault on the lx106 (the alignment risk) — capture any exception output. |
| Resets mid‑sign | Watchdog (should be disabled) — or out‑of‑memory (shrink the 24 KB heap in `heap.rs`). |
| Signatures rejected by relays | NIP‑44 nonce/RNG or event‑id mismatch — verify the signed event against a known‑good signer. |

## Before using real keys
The placeholders make this a *demo*, not a vault: the master seed and bridge
secret are **hardcoded**, every request is **auto‑approved** (no button), and the
nonce RNG needs an entropy review. Don't put a real nsec on it until those land
(flash key storage + the OLED/button approval tier).
