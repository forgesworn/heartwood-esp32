# Bench: message-size sweep

Date: 2026-08-06
Board: `heltec-v4` (ESP32-S3R2, 2 MB PSRAM present but disabled)
Firmware: v0.13.9
Host: macOS, Apple Silicon, native USB-Serial-JTAG at `/dev/cu.usbmodem*`
Path under test: plaintext USB NIP-46 (frame 0x02)

Companion to `docs/plans/2026-08-06-message-size-limits.md`, which predicted a
relay-path ceiling of 20480 bytes from `MAX_WS_FRAME`. That prediction is NOT
what this bench measures. This bench is the USB path, which carries no NIP-44
and no base64, so its only structural limit is `MAX_PAYLOAD_SIZE` (32768).

## Result summary

| Stage | Ceiling found | Reboots |
|-------|---------------|---------|
| Receive + CRC + outer JSON parse | 32063 B frame (32054 B payload) | none |
| ... through `sign_event` dispatch to the approval prompt | 32206 B frame (32197 B payload) | none |
| ... post-approval sign, response build, response write | **not measured** | unknown |

**The plaintext USB path receives, parses and dispatches a ~32 KB signing
request without crashing.** Neither the USB transfer nor the JSON parse is the
limit on this board. Uptime rose monotonically across both sweeps
(390 s to 762 s through the sign sweep) with no reset.

The post-approval leg is unmeasured because every `sign_event` opens a 30 s
physical approval prompt and no press was made during the runs.

## Method

Two probes, both in `scripts/frame-size-probe.mjs`.

**Probe A, receive and parse only.** Sends `get_public_key` with the payload
padded out through `params`, which the method ignores. The device must take the
whole frame off the wire, CRC it and run it through serde, then answers from a
path that allocates almost nothing. No approval prompt, so it runs unattended.

**Probe B, `--sign`.** Sends a real `sign_event`. `handle_sign_event` runs
`parse_unsigned_event` (a second parse, duplicating the content) and builds the
OLED preview *before* opening the approval prompt, so a memory failure in that
window reboots the device with no press involved. This also runs unattended:
an approval timeout is the pass signal, a reboot is the failure signal.

Both read `uptime_s` from `FIRMWARE_INFO` (0x59) before and after every step.
**Uptime going backwards is the reboot detector.** That is the key measurement
choice here: the first attempt at this bench inferred crashes from missing
replies and got it wrong (see below).

Writes use Sapwood's measured pacing (64-byte chunks, 24 ms for the first
3072 bytes then 6 ms). Bursting whole frames overruns the V4's USB-Serial-JTAG
ring, which is what the v0.13.9 OTA pacing fix addressed; an unpaced probe
would measure the host's write pattern rather than the device.

## Raw results

Probe A, receive + parse, all `ok`, no reboot:

| Frame B | 575 | 1087 | 2111 | 4159 | 8255 | 12351 | 16447 | 20543 | 24639 | 28735 | 32063 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Uptime after (s) | 283 | 285 | 287 | 289 | 293 | 296 | 301 | 305 | 311 | 316 | 322 |

Probe B, `sign_event` to the prompt, all `approval_timeout`, no reboot:

| Frame B | 1230 | 2254 | 4302 | 8398 | 12494 | 16590 | 20686 | 24782 | 28878 | 32206 |
|---|---|---|---|---|---|---|---|---|---|---|
| Uptime after (s) | 423 | 459 | 496 | 533 | 570 | 607 | 646 | 683 | 722 | 762 |

## Discarded first attempt, and why

The first run used `scripts/size-sweep.mjs`, driving `sign-test` once per size.
It reported 1024 B signing and everything from 4096 B up failing, which reads
as a 4 KB ceiling. **That result is invalid.** The operator approved one prompt
and the device rebooted at some point during the run; every later step then
sent into a device that nobody was pressing, and the harness recorded the
silence as a size failure.

Three things made it unable to tell those apart, all fixed in the probe:

1. **It inferred crashes from missing replies.** A device that is rebooting, a
   device waiting on a button nobody presses, and a device that dropped an
   oversize response all look identical from the host. Reading `uptime_s` each
   step distinguishes them directly.
2. **It required a human for every step**, so an unattended run silently
   degrades into measuring operator attention.
3. **It re-opened the serial port per invocation**, adding a confound. Ruled
   out separately: four consecutive open/close cycles via the Sapwood CLI left
   uptime climbing monotonically (118, 125, 132, 139 s), so opening the port
   does not reset this board.

`size-sweep.mjs` is kept for the attended end-to-end run, now with an abort on
an unanswered prompt so it cannot record a missing human as a size ceiling.

## Status of the defects below

All five are fixed in the working tree. Items 1 to 3 are firmware changes and
are **built but not yet flashed to hardware**, so they are unverified on a real
device; items 4 and 5 are host-side and are verified (`cargo test` green,
including four new tests for the id-recovery helper). The re-run of this bench
against the new firmware is still outstanding.

## Defects found

**1. Oversize responses are discarded in silence.** `write_owned_frame`
(`firmware/src/protocol.rs:305`) drops any response over `MAX_PAYLOAD_SIZE`
with a bare `log::warn!` and returns. On every board that log goes nowhere:
`CONSOLE_NONE` on v3/tdisplay/c6, and unwired UART0 on the v4. So for content
between roughly 32348 and 32540 bytes the device prompts the user, takes their
button press, signs the event, and throws the signature away without telling
anyone. The host sees only a timeout. Narrow window, but it spends a physical
approval and produces nothing.

**2. Heap telemetry is unreachable over USB.** `[relay] heap: free ...
largest ...` is emitted only from the relay loop, and `EspLogger` writes to a
console that is unrouted on every board. So this bench can report pass/fail
thresholds but not the free-heap and largest-block curve the plan asked for.
`firmware_info_json()` (`main.rs:116`) already reports uptime and last_reset;
adding `free_heap` and `largest_block` there would make this and every future
sweep quantitative for about four lines.

**3. `last_reset` reports "unknown" on this board.** `reset_reason_str()`
(`main.rs:157`) does not map ESP-IDF 5.x's `ESP_RST_USB` or `ESP_RST_JTAG`, so
they fall through to "unknown". A USB-peripheral reset is exactly the kind of
event this field exists to distinguish, and on a native-USB board it is a
likely one. Worth adding both arms.

**4. `sign-test` could not build on Apple Silicon.** `sign-test/.cargo/config.toml`
pinned `target = "x86_64-apple-darwin"`, failing with "can't find crate for
`core`". The comment justified it as overriding a parent xtensa config, but
that config lives in `firmware/`, a sibling of `sign-test/` rather than a
parent, so cargo never inherited it. Pin removed; the `build-std` reset is what
actually does the neutralising if such a parent is ever added.

**5. `sign-test`'s oversize-request message is stale.** It prints "max 4096
bytes" when `MAX_PAYLOAD_SIZE` has been 32768 for some time.

## What is still unmeasured

- **The post-approval leg on USB** (sign, `build_sign_response`,
  `write_owned_frame`). Needs an attended run. Predicted silent-drop threshold
  is content of about 32348 B, where the response first exceeds 32768.
- **The relay path**, which is the one the plan's 20480 figure describes and
  the one that binds in the product. It needs a paired auto-signing app so it
  can be swept without a press per step, and it is the path that exercises
  `response_transportable` and NIP-44 base64 expansion. This is the sweep that
  should actually set `max_sign_bytes`.
- **The fragmented-heap condition.** Both sweeps above ran on a device with
  under 15 minutes of uptime and no relay sessions. The plan calls for a second
  run after a client has bulk-decrypted a message history, which is the state
  the field crashes were blamed on. That number, not the fresh-boot one, is the
  one that belongs in a header.
- **Every other board.** `tdisplay`, `esp32c6` and `heltec-v3` are untested.
