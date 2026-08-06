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
| ... through `sign_event` dispatch to the approval prompt | 31206 B frame, and 32206 in an earlier run | none |
| ... post-approval sign, response build, response write | **28672 B content signed; 32000 B panics** | one |

**The post-approval leg is the real ceiling, and it panics rather than
degrading.** Six sizes signed end to end with a button press (content 8192,
12288, 16384, 20480, 24576, 28672). Content of 32000 bytes crashed the device
outright: `last_reset: "panic"`, breadcrumb `crashed_during: "relay reading"`.
The true threshold is somewhere in 28672..32000; narrowing it further needs
more attended runs.

That crash is above the advertised `max_sign_bytes` of 20480, so a client that
respects the advertised limit never reached it. But nothing stopped a request
of that size arriving over USB, and `MAX_PAYLOAD_SIZE` (32768) permitted it.

### Fixed: the advertised ceiling is now enforced

`response_transportable` covers the encrypted path (`transport.rs`) and the
relay path, but **nothing guarded the plaintext USB path**. It ran straight
from `handle_request` into signing and response-building, and the panic
happened inside that window, before any guard could have run.

`handle_request` now rejects a `sign_event` whose serialised event exceeds
`board::MAX_SIGN_BYTES + SIGN_RESPONSE_OVERHEAD`, immediately after parsing and
before anything allocates at signing size. Parsing is already proven safe well
past that bound, so measuring the actual event is both accurate and cheap.

Re-flashed and verified on the same V4:

| Content | Frame | Before | After |
|---------|-------|--------|-------|
| 20480 | 20686 | signed | reaches approval prompt |
| 20992 | 21198 | signed | `event is too large for this signer` |
| 21504 | 21710 | signed | `event is too large for this signer` |
| 28672 | 28878 | signed | `event is too large for this signer` |
| 32000 | 32206 | **panic** | `event is too large for this signer` |

The boundary is exact: the device now accepts precisely what it advertises and
refuses everything above, with no reboot at any size.

This is deliberately stricter than before. The device previously signed up to
about 28672 bytes and then fell off a cliff. Refusing predictably at the
advertised number is worth losing that undocumented headroom, which existed
only in the run-up to a crash. Raising the number is a separate decision that
belongs with PSRAM (see the plan).

**Heap does not move with request size.** Free heap sat at 213 KB and the
largest contiguous block at 148 KB across every size from 575 B to 32 KB, on
both the parse sweep and the signing sweep, returning to the same figures after
each request. So on a freshly booted V4 with no relay sessions, large requests
neither leak nor fragment: whatever kills it at 32000 bytes is a transient peak
inside one operation, not accumulated pressure. Note how far these are above
the `DIAL_MIN_LARGEST_BLOCK = 24_000` the relay guards expect, which is the
*post-TLS-session* state; the fragmented condition remains untested.

**The plaintext USB path receives, parses and dispatches a ~32 KB signing
request without crashing.** Neither the USB transfer nor the JSON parse is the
limit on this board. Uptime rose monotonically across both sweeps
(390 s to 762 s through the sign sweep) with no reset.

The post-approval leg is unmeasured because every `sign_event` opens a 30 s
physical approval prompt and no press was made during the runs.

## The relay transport, measured

Run with `scripts/relay-size-sweep.mjs` as an ordinary NIP-46 client against a
throwaway connection slot with auto-sign on, so no button press per step.

**The derived ceiling of 20480 was wrong. The measured ceiling is 16384.**

| Content | Request on wire | Response | Outcome |
|---------|-----------------|----------|---------|
| 1024 | 2224 | 2140 | signed |
| 4096 | 7344 | 6916 | signed |
| 8192 | 14172 | 13744 | signed |
| 10240 | 16904 | 16476 | signed |
| **16384** | **27824** | **27396** | **signed** |
| 20480 | 33288 | -- | **PANIC** |
| 24576 | 38748 | -- | no reply |
| 32768 | 55132 | -- | no reply |

Two things the arithmetic missed.

**The request is bigger than the response.** The derivation worked backwards
from the response, but NIP-46 carries the event as a JSON *string inside* the
params array, so the event's own quotes are escaped a second time before the
request is padded, encrypted and base64'd. At 20480 bytes of content the
request reaches 33288 bytes on the wire, over the firmware's 32768-byte
`MAX_WS_FRAME`, while the response would have fitted.

**It panics rather than refusing.** 20480 did not produce the clean
"frame exceeds cap" drop that `relay.rs:4351` implies. The device crashed:
`last_reset: "panic"`, `crashed_during: "relay inbound event (heap 130k)"`.
Note the 130 KB of free heap at the time — this is not an out-of-memory
condition, so a heap threshold was never going to catch it and a size ceiling
is the reliable defence. Recovery is slow too: after the crash the relay
session took minutes to become usable again, so each oversize request costs far
more than the one request.

### The real fix: stop building a Value tree for every inbound event

**Correction to the section below.** It reported that the signer "stayed alive"
through the oversize sizes on the strength of it answering requests immediately
afterwards. That was wrong. Reading `last_reset` once the USB port was free
showed `panic`, `crashed_during: "relay inbound event (heap 131k)"`. It had
rebooted and come back, which from the relay looks identical to never having
died. Liveness after the fact does not prove survival; only `last_reset` does.

So the smaller ceiling did **not** fix the crash, and could not have: the guard
in `handle_parsed_request` runs after decryption, while the failure is upstream
in `handle_relay_msg`.

The cause was the parse strategy. Every inbound message was deserialised into a
`serde_json::Value` first, purely to read its first element and route on it.
For an EVENT that tree is a complete second copy of the message, including the
event's whole content string, alive at the same time as the raw bytes — and
`from_value::<SignedEvent>` then copied the content a third time. A NIP-46
request at the signing ceiling is ~28 KB on the wire, so the peak was roughly
84 KB of transient allocation to handle a 28 KB message, on a heap already
carrying a TLS session.

`nip46::relay_message_tag` now reads the leading tag straight out of the raw
bytes without parsing, and `nip46::RelayEventMessage` deserialises
`["EVENT", sub, event]` directly into its typed form. That removes the tree and
one full copy of the content. Non-EVENT branches were already working off
`raw` via `snippet`, so they were unaffected.

**Verified on hardware.** Across repeated 16384-byte signings and repeated
20480 and 32768 oversize requests, the signer reached 8m27s of uptime with
`last_reset: usb-peripheral-reset` — the deliberate reset from flashing, and no
panic since. The pre-fix firmware panicked on this traffic every time.

**Soak, 12m37s.** Re-run later with `heap-watch.mjs` sampling over USB every
30 s while the relay was driven with 16384-byte signings and 33288-byte oversize
requests. Uptime rose monotonically 1228 s → 1985 s, `last_reset` never changed,
and free heap and largest block sat dead flat at 209 KB / 136 KB (ratio 0.65)
for all 26 samples. No panic, no leak, no fragmentation drift. This is the soak
the previous revision listed as outstanding; the intermittent failure it
replaces did not recur.

One earlier conclusion also falls: 16384 now signs on the **tighter** relay,
which previously failed there. That failure was attributed to the relay
refusing to carry the larger response. It was the signer crashing.

### Post-fix re-run: 16384 confirmed

Repeated against the fixed firmware (`MAX_SIGN_CONTENT_RELAY` = 16384, guard in
`handle_parsed_request`) on the permissive relay:

| Content | Request | Response | Outcome |
|---------|---------|----------|---------|
| 8192 | 14172 | 13744 | signed |
| **16384** | **27824** | **27396** | **signed** |
| 20480 | 33288 | -- | no reply |
| 32768 | 55132 | -- | no reply |

16384 signs reliably — twice now, before and after the fix. That is the figure
the constant carries.

20480 no longer needs a guard to be safe: its request reaches 33288 bytes,
past the 32768 `MAX_WS_FRAME`, so the device discards it at the WebSocket layer
before it is ever decrypted or dispatched. **The device stayed alive through
both oversize requests in this run**, where the pre-fix sweep left
`crashed_during: "relay inbound event (heap 130k)"`.

What that discard *cost* is a separate matter, and was not looked at here: at
this point it also tore down the relay session. See "An oversize frame was a
remote off-switch" below.

One caveat applied when this was written: `last_reset` could not be read
afterwards to prove no panic occurred, because the USB port was held by a
browser tab, so the evidence for "survived" was only that the signer answered
requests immediately afterwards. That reasoning is exactly what proved wrong
once before (see the correction above), so it was re-confirmed over USB in the
12m37s soak — uptime monotonic, `last_reset` unchanged throughout.

Note also what this implies about the guard. A request at exactly
`MAX_SIGN_BYTES` produces a ~27.8 KB WebSocket message, and the pre-fix
firmware handled that same 27824-byte message successfully on one occasion and
fatally on another. The transient peak in `handle_relay_msg` — raw bytes, plus
the parsed `Value` tree, plus the `SignedEvent` copy — is therefore marginal at
the top of the range, and depends on heap state at the moment it lands. A
smaller ceiling buys margin; it does not remove the sharp edge.

**Correction (checked 2026-08-06).** This section previously called for bounding
the inbound message before `serde_json::from_slice`, and listed it as not done.
It was already done, structurally: `try_parse` refuses any frame declaring more
than `MAX_WS_FRAME` before a byte of body is handed on, so `raw` reaching
`handle_relay_msg` is bounded at 32768 by construction. There is no continuation
reassembly either — opcode 0x0 falls into `_ => WsMsg::Other` and the FIN bit is
never read on the inbound path — so a message cannot accumulate across frames.
A second length check would have been dead code. What that cap actually needed
fixing was its *consequence*, not its absence: see the next section.

### An oversize frame was a remote off-switch

Found while running the longer soak, and the most serious defect in this round.

`try_parse` returned `Err` for any frame over `MAX_WS_FRAME`. `session_step`
propagates that with `?`, and its contract is "an `Err` means the session is
dead and should be dropped". So one over-cap frame ended the relay session.

The trigger needs no authentication and no secret. The subscription is

    ["REQ","hw",{"kinds":[24133],"#p":[<our pubkeys>],"limit":0}, …]

and our pubkey is public — it is the host of every bunker URI we hand out. Any
party could publish an over-cap kind-24133 event p-tagged to us and knock us off
the relay, before a byte was decrypted or the sender was so much as looked at.
The kill lands at the WebSocket framing layer, upstream of every policy gate.

The cost is worse than one dropped connection:

- The **primary** session advances `relay_idx` and fails over to a *different*
  relay. Clients watching the old one just see silence.
- A **pinned** session takes `fails += 1` and backs off `15s · 2^fails`, to a
  600 s ceiling.
- The subscription is `limit:0` with **no `since`**, so requests published
  during the gap are never replayed. They are lost, not delayed.

Measured on the V4, one sweep on a single session:

| Content | Wire | Before | After |
|---------|------|--------|-------|
| 1024 | 2224 | signed | signed |
| 20480 | 33288 | **session dropped** | skipped, no reply |
| 1024 | 2224 | **no reply** | **signed** |
| 16384 | 27824 | **no reply** | **signed** |
| 20480 | 33288 | -- | skipped, no reply |
| 8192 | 14172 | **no reply** | **signed** |

Before the fix, everything after the first oversize request went unanswered and
the signer was found signing on *another* relay — alive the whole time, which is
why this reads as a crash from the client and is not one. Uptime was monotonic
across the entire episode.

The fix: an oversize frame is a **message**-level fault, not a
**connection**-level one. The stream is still correctly framed — the header says
exactly where the next frame begins — so the frame is now skipped and the
session kept, which is also what RFC 6455 intends by 1009 Message Too Big. A
`skip` counter on the session carries the remainder, because an over-cap body
can span several reads and its tail must not be parsed as a header.

One adjacent bug fixed in the same function: the 64-bit length path did
`u64 … as usize`, and `usize` is 32 bits on this chip, so a declared length above
`u32::MAX` truncated — `0x1_0000_0000` would read as a 0-byte frame and desync
the stream against a body still arriving. That path is reachable by an attacker,
since any frame over 65535 bytes uses it. A declared length that large now drops
the connection as a broken peer; merely-over-cap lengths take the skip path.

### Relay membership rotates, so "is it reachable" depends on when you ask

`MAX_SESSIONS` is 2, and the signer rotates its primary across the configured
set. Over one afternoon this device was reachable on one relay, then two
others, then back — while four were configured throughout. Several sweeps
that looked like a dead signer were simply aimed at a relay it was not
subscribed to at that moment.

Any relay measurement therefore has to confirm liveness on the specific relay
it is about to use, or it will mistake membership for failure. `ping.mjs`-style
liveness across every configured relay before a sweep is the cheap way to do
it.

### Relays differ, and the tighter one binds first

The same sweep against two relays gave different ceilings: one carried 16384
bytes of content, another stopped at 10240. So in the field the effective limit
is the *minimum* of the signer's ceiling and the tightest relay in the
configured set, and a signer that works on one relay fails on another at the
same size. Any future relay figure must name the relay it was measured against.
The 16384 above is the signer's own ceiling, measured on the more permissive
one.

The tighter relay's refusal is **silent to the client**. It accepted the
request (no `OK false`), and it is the signer's *response* — larger than the
request once re-encrypted — that the relay then would not carry. From the
client's side that is indistinguishable from a signer that crashed. The sweep
tool now surfaces `OK false` separately for exactly this reason, but a relay
that drops the response without complaint cannot be detected from the client at
all; only the signer's own liveness afterwards distinguishes the two.

## Heap under a live relay session

Sampled with `scripts/heap-watch.mjs` while the signer was WiFi-connected with
a live relay session (`relay_connected: true`), across two runs:

| Uptime | Free | Largest block | Ratio |
|--------|------|---------------|-------|
| 303 s | 209 KB | 136 KB | 0.65 |
| 348 s | 211 KB | 136 KB | 0.64 |
| 393 s | 211 KB | 136 KB | 0.64 |
| 438 s | 211 KB | 136 KB | 0.65 |
| 1570 s | 213 KB | 144 KB | 0.68 |

**Flat, and nowhere near the fragmented regime.** The relay guards are written
for a heap whose largest block has fallen to `DIAL_MIN_LARGEST_BLOCK` (24000)
or `RELAY_HEALTH_MIN_BLOCK` (16384); Sapwood's UI flags fragmentation below a
0.4 ratio. Observed here: 136-144 KB and a ratio of ~0.65, an order of
magnitude clear of the thresholds, holding steady over ~26 minutes of uptime
with the radio up and a relay session established.

So the fragmented condition **was not reproduced**, and this is not evidence
that it cannot happen. These samples cover an idle-with-relay signer. The state
the field crashes were blamed on is a client bulk-decrypting a message history,
which fires dozens of `nip44_decrypt` in a burst, and nothing here generated
that load. Reproducing it needs a client driving sustained decrypt traffic,
which is the natural next use of `relay-size-sweep.mjs`.

What these figures do settle is that the size ceilings above were measured on a
healthy heap. The 20480 relay panic happened with 130 KB free, so it was not
memory pressure, and a smaller ceiling — not a heap threshold — is the right
defence.

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

All five are fixed, and items 1 to 3 are **flashed and confirmed on hardware**.
Confirmations from the post-flash device read:

- `max_sign_bytes: 20480`, `free_heap: 218208`, `largest_block: 151552` are
  reported, so a sweep can now record the heap curve and a client can
  pre-flight against the ceiling.
- `last_reset: "usb-peripheral-reset"`, where the same device previously said
  `"unknown"`. This retroactively settles the first sweep: those reboots were
  host-triggered USB resets, not firmware crashes.

### Flashing note: the device's partition table is NOT this repo's

`espflash flash --partition-table partitions.csv` panics inside esp-idf-part
0.6.0 on the `config, data, 0x40` row (numeric subtype). That panic was
fortunate. Reading the live table back off the device gives the ESP-IDF
**default** layout, not the repo's:

    nvs,      data, nvs,     0x9000,  0x6000
    phy_init, data, phy,     0xf000,  0x1000
    factory,  app,  factory, 0x10000, 0xfa0000

Single `factory` app, no OTA slots, and NVS spanning 0x9000-0xF000. Writing the
repo's table would have placed `otadata` at 0xD000-0xF000, directly on top of
live NVS data, and taken the identities with it.

The safe procedure, used here, writes only the app and never the table:

    espflash save-image --chip esp32s3 --flash-size 16mb <elf> app.bin
    espflash write-bin 0x10000 app.bin
    espflash reset

Identities, persona and app pairings all survived, as the offsets predict.
This also means **OTA firmware update cannot work on this device**: the
bootloader rollback and `esp_ota_*` path need `otadata` plus `ota_0`/`ota_1`,
and this device has none of them.

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

- **The exact point the old firmware panicked**, known only to lie in
  28672..32000 bytes of content. Now academic: the ceiling is enforced at
  16384 and the crash is unreachable. Worth pinning down only if
  `MAX_SIGN_BYTES` is ever raised, since it marks where the real headroom ends.
- **The fragmented-heap condition.** Still not reproduced. The 12-minute soak
  below held a live relay session throughout and the heap did not budge, so it
  did not generate the state the field crashes were blamed on. The plan calls
  for a run after a client has bulk-decrypted a message history. That number,
  not the fresh-boot one, is the one that belongs in a header.
- **Every other board, on hardware.** Only the V4 was physically present.
  `heltec-v3`, `tdisplay` and `esp32c6` are **build-verified but not
  run-verified**: all four board features compile clean at v0.14.0, across all
  three architectures (Xtensa S3, classic Xtensa LX6, RISC-V rv32imac). That
  matters more than it sounds for this change set, because
  `esp_reset_reason_t_ESP_RST_USB` / `_JTAG` and
  `heap_caps_get_largest_free_block` are chip-specific bindings, and a build on
  the S3 alone would not have proven they exist elsewhere. What remains
  unverified per board is the runtime behaviour: actual heap figures, and
  therefore whether `MAX_SIGN_BYTES` of 16384 is right for a board with less
  memory than the V4. The classic-ESP32 T-Display is the one to watch.

  Building the non-S3 boards on a fresh macOS machine hits two snags worth
  recording. The esp-idf tool installer fails with
  `CERTIFICATE_VERIFY_FAILED` because the embedded Python has no CA bundle, and
  once the toolchains do install, `xtensa-esp32-elf-gcc` and
  `riscv32-esp-elf-gcc` are not on `PATH` for the cc-rs build of
  `secp256k1-sys`. Both are fixed by exporting, before
  `scripts/build-firmware.sh`:

      export SSL_CERT_FILE=<idf python env>/site-packages/certifi/cacert.pem
      export REQUESTS_CA_BUNDLE="$SSL_CERT_FILE"
      export PATH="<embuild>/tools/xtensa-esp-elf/<ver>/xtensa-esp-elf/bin:\
      <embuild>/tools/riscv32-esp-elf/<ver>/riscv32-esp-elf/bin:$PATH"
