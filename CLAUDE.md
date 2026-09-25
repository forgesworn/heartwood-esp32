# Heartwood ESP32

Hardware signing device for Nostr on a Heltec WiFi LoRa 32 (ESP32-S3). Both the V3 (CP2102 UART bridge) and V4 (native USB-Serial-JTAG) boards are supported from the same codebase via the `heltec-v3` / `heltec-v4` cargo features. See `firmware/src/serial.rs` for the transport abstraction. The operating mode is selected at runtime from the NVS network config (`NetConfig.mode`), not a build flag:

- **USB-bridged mode** (default) — USB-attached to a Pi, holds master secrets, all radios disabled; the Pi handles networking.
- **WiFi-standalone mode** (opt-in) — the ESP32 joins WiFi and talks to Nostr relays directly, running the full NIP-46 signing loop on-chip with no Pi. Enabled only when provisioned with an SSID + relay list; the USB cable stays fully live in parallel. See `firmware/src/relay.rs`.
- **Portable mode** (roadmap, not built) — battery-powered, holds a child key, BLE for phone signing.

## Security model

- **Physical approval required** — OLED shows the request, button press to sign. No silent signing. Applies in every mode, including WiFi-standalone.
- **USB-bridged mode (high-assurance default):** all radios disabled, USB serial only. Pi compromise is survivable — keys live on the ESP32, and in device-decrypts mode the Pi only ever sees ciphertext.
- **WiFi-standalone mode (opt-in convenience tier):** WiFi *is* enabled and the device reaches relays directly — a deliberately larger attack surface, accepted in exchange for dropping the Pi. Keys still never leave the chip, NIP-44 is still decrypted on-device, and every signature is still button-gated. Relay-side device management (kind 24134) is authenticated to a provisioned operator pubkey and replay-protected. Don't enable this tier where the USB high-assurance model is required.
- **Portable mode** (roadmap, not built) — would enable only BLE (short range) and hold a child key, never the master.
- **JTAG remains enabled** — disabling it requires eFuse burning, which permanently locks the chip and is deliberately rejected (see `docs/memory/feedback_no_efuse.md`); physical security is the protection model, including against debug-port key extraction.

## Feature flags & mode selection

Operating mode (USB-bridged vs WiFi-standalone) is selected **at runtime** from `NetConfig.mode` in NVS (`common/src/net_config.rs`: `"usb"` default, `"wifi"` opt-in) — it is **not** a cargo feature. Cargo features select the board (`heltec-v3` / `heltec-v4`) and the crypto backend (`k256-backend` for host tools/tests, `secp256k1-backend` for firmware — see Known issues below). The future `portable` (BLE) tier is not built.

## Current state

Phase 5 (flash-once production) complete (2026-04-03). Seven crates: `common/` (shared crypto + frame protocol + NIP-46 types + NIP-44/NIP-04 encryption + policy types), `firmware/` (ESP32), `provision/` (host CLI), `sign-test/` (signing test harness), `heartwoodd/` (Pi-side daemon -- Soft and Hard modes), `ota/` (Pi-side serial OTA tool), `sapwood/` (web management UI, separate repo). Multi-master NVS storage (up to 8 masters, three provisioning modes: bunker/tree-mnemonic/tree-nsec). On-device NIP-44 transport encryption -- the Pi is zero-trust in Hard mode, only sees ciphertext (including sign_event responses). Connection slot policies (NVS-persisted on ESP32, Argon2id keyfile on Pi). Full NIP-46 method set (16 methods: 8 standard + 8 heartwood extensions; proof methods stubbed, `heartwood_capabilities` advertises the served set per signer). Connect secret validation per NIP-46 spec. Serial OTA with SHA-256 verification and automatic rollback. Factory reset with button confirmation. Firmware uses libsecp256k1 (C FFI) for all signing.

Heartwood Soft mode: `heartwoodd` runs standalone on a Pi with no ESP32. Keys encrypted at rest with Argon2id + XChaCha20-Poly1305, unlocked via Sapwood. Policy-based auto-approve with Sapwood approval queue for out-of-policy requests. Same management API, same Sapwood UI, same NIP-46 signing -- just software-backed instead of hardware-backed.

Encrypted backup/restore of connection slots and policies via Sapwood -- MANUAL export/import only (there is no auto-snapshot: `runExport` is a button in Backup.svelte, and nothing captures slots on change; a board wiped without a prior manual export loses every pairing, since `create_client` always mints a fresh secret on-device and no raw NVS dump can restore a slot), Argon2id + XChaCha20-Poly1305 encrypted backup file, physical button confirmation on restore. Dedicated backup passphrase (default "heartwood", changeable via Sapwood). Works in both Hard and Soft modes.

Encrypted at rest on-device (opt-in): either a human PIN (P5, wipes after 5 failures) or a host-held 32-byte vault key (VAULT_SET 0x62 / VAULT_UNLOCK 0x63) that heartwoodd or Sapwood delivers — unattended reboot with ciphertext on flash. WiFi-standalone locked devices announce a per-boot ephemeral unlock pubkey (kind 24135) and receive the vault key live from the operator (kind 24136). Spec: docs/specs/2026-08-08-encrypted-at-rest-unlock-design.md. FIRMWARE_INFO and get_status report the at-rest state directly (`at_rest`: `none`/`pin`/`vault`/`encrypted`, plus `unlock_phone_count`), so a manager stops inferring the mode from side effects it happened to witness — resolved in one place, `heartwood_common::at_rest_status::resolve` (pure, host-tested, including the size-damage cases), behind a single firmware read, `firmware/src/pin.rs::at_rest_status`, that all three call sites (FIRMWARE_INFO, get_status's full and low-heap-fallback replies) share instead of each composing it themselves. FIRMWARE_INFO answers this while locked (any USB host, any mode), get_status only once unlocked and only to the device operator, never a per-identity delegate (including its low-heap `minimal_status_json` fallback) — both delegate reply shapes are keyed off `at_rest_status::DELEGATE_STATUS_KEYS`/`DELEGATE_STATUS_FALLBACK_KEYS`, host-tested so the fallback can never carry a data key the normal reply does not. Since the wrapped data key does not itself record which secret wrapped it, distinguishing PIN from vault needed a marker (`at_rest_kind` in `common/src/data_key.rs`, over `BlobStore` so the existing power-cut model tests cover it): kind byte plus the first 8 bytes of SHA-256(dk_sec), so a marker that no longer matches the wrapper on flash — a cut between the wrap write and the marker write, a failed write, a secret changed on firmware without this marker, any re-wrap it missed — reports `encrypted` (kind unknown) rather than a guess. `encrypted`, not a `pin` fallback: only a PIN_UNLOCK guess counts towards the 5-failure wipe, so mislabelling a vault board as PIN-protected would invite typed guesses into a counter it was never meant to arm. A board's own next successful unlock (PIN_UNLOCK, VAULT_UNLOCK, or the relay's 24136 operator vault delivery — all three run through `pin::try_unlock`) self-repairs a missing or wrong marker from the secret's length (4-8 digits or 32 bytes settles it) via `data_key::repair_secret_kind`, which takes the `Unlocked` proof a real unlock produces so it cannot run ahead of one; a phone-slot unlock never sees the secret and never touches the marker. `try_unlock` clears the PIN wipe counter immediately once the secret is proven correct, before migration or the marker repair — the two optional writes that follow — so a power cut during either can never catch the counter mid-way stale. `unlock_phone_count` is `null`, not `0`, over a damaged phone blob (never mistake damage for no phones), except once `at_rest` is `none`, which always reports `0` — removing the last identity leaves `dk_ph` behind (`provision.rs`, `masters.rs`), and a mode of "none" makes any leftover blob moot. The count itself walks and validates the blob (`PhoneSet::count`) rather than allocating a full `PhoneSet::decode`, sized from the NVS blob's actual length rather than a fixed 2,166-byte buffer, since this runs in the same low-heap path `minimal_status_json` exists for. Phone unlock (common/src/phone_unlock.rs) adds per-phone 24135s (one-time author, `["h", hint]` only, sealed content with `t` = `locked`) answered by a throwaway-key 24136; a relay-list change is told to the phones on their old relays as the same message with `t` = `relays` (common/src/phone_relays.rs: NVS `ph_relays` records what they were told and how many update rounds have gone out; locked boots repeat the announcement there, one old relay per announce interval straight after the live announcement, with per-relay backoff; unlocked boots post six randomly delayed update rounds over about a day, each on a publish-only connection that never carries the signer's subscription and never makes a third TLS session, resuming after a restart, then record the live list).

A phone can be added over the relay (2026-09-25, checklist section 29, not bench-run; Sapwood and Cambium support are PENDING follow-ups): `enrol_unlock_phone {enrol_pubkey, label?}` on the kind-24134 management channel, the cable's frame-0x64 enrolment moved onto the #64 deferred card queue (relay.rs `queue_phone_enrol` / `resolve_phone_enrol_card`) so the loop keeps serving while the owner walks to the board. Device operator only (a per-identity delegate is refused before anything else is looked at; a NIP-46 client has no route to management), behind the one-time mutation challenge, which is spent before the card goes up, so a request raises at most one card, before or after a restart. Then, in the host-tested order of `phone_unlock::admit_relay_enrol`: one enrolment waiting at a time, the request, the board, room in the queue, and last the claim on the enrolment key (used once per boot). The card (cable and relay alike, `oled::show_enrol_approval`, layout from `phone_unlock::enrol_card`) leads with the request code: FIVE words of spoken-token's en-v1 list (`common/src/spoken_words.txt`, compiled in and read by the Node bench library), `deriveToken(P, 'heartwood-unlock:enrol-request', 0, {format:'words', count:5})`, 55 bits, a page at a time (`phone_unlock::enrol_page`: words 1-2, 3-4, 5, each page `ENROL_PAGE_SECS` = 4 s and round again, no press needed), one word a line with its place number, as large as the span allows (`Layout::enrol_geometry`: FONT_6X10 at 2x on the Heltec, after the 2026-09-25 bench found the old two-a-line 6 px words unreadable in time), under a small top line `ADD "<label>"?`, with the hint "on phone? hold PRG" (`phone_unlock::enrol_hint`) and a countdown, everything inside the span clear of the button tags either way up (`Layout::text_span`; ui-preview mirrors the card and PHONE ADDED and checks no piece meets a tag or another piece on every panel, orientation and page). The enrol card's window is `phone_unlock::ENROL_CARD_SECS` = 60 s, cable and relay (relay.rs `card_window`); every other card keeps 30 s. The owner compares the BOARD with the PHONE, which made P; a browser's copy proves nothing, since whoever holds the operator key or the browser could swap in a key of their own, and a compromised browser can grind a matching key for as long as the owner waits (55 bits is weeks on one GPU, hours on a large rack; 44 was half an hour). Labels are printable ASCII only, quoted, and never share a line with a word. At the press the configured sessions heard from within PING_INTERVAL plus 10 s are noted once (`phone_unlock::heard_recently`), and that one snapshot both gates the enrolment and counts the delivery; the board is read again (phone set decoded once) and decided by `relay_enrol_completion` (still the device operator, a live relay, unlocked, a data key, relays, fewer than 16 phones); the hand-off is sealed in RAM and the record written only if the answer fits the heap (`response_transportable`), so nothing is written before the press and a card declined, expired (60 s on screen, 90 s queue TTL) or lost to a restart leaves no record. The answer is the cable's (`id`, `ephemeral_pubkey`, `sealed`), offered to every configured session; `phone_unlock::enrol_result` picks the screen: PHONE ADDED with the check code and "else revoke N" (if the phone never shows that code, revoke that record; the check code confirms delivery and catches mix-ups, but the hand-off comes from an unauthenticated one-off key, so it cannot prove the board sent it: the five words are the only defence against a swap, and an authenticated hand-off, the board signing (E, P) with its paired identity, is a parked follow-up), or "Not sent / revoke id N" when no live session took it (the answer is not held in the #82 outbox), or "No phone added". PHONE ADDED shows the check code at the card words' size. A cable enrolment waits for the approving press to be released before returning, so that press never dismisses PHONE ADDED. Every pressed result, and a cable enrolment's in either mode, holds the display until a fresh press (`phone_unlock::ResultHold`, `RESULT_HOLD_MAX_MS` = 5 min at most, the panel kept lit); nothing waiting for the screen waits longer than the old 20 s hold (`RESULT_HOLD_MS`): a queued relay card, or a cable command that would be refused "approval on screen" (relay.rs `cable_card_refused`), takes over once the result has stood 20 s, and an auto-approved confirmation drawn over it hands back to it after its own 5 s. The hold is stepped at the top of every relay loop pass and from `service_button`'s WiFi-down waits, so an outage cannot keep it standing or deaf to a press. In the USB-bridged loop (main.rs `held_result`) nothing is refused: frames are served as ever and PHONE ADDED is drawn again after each, instead of the "SIGNER READY" screen that used to replace it at once. ROLLOUT: ship this firmware only together with the Cambium release that shows the five words and keeps labels to printable ASCII, and the Sapwood release that tells the owner to compare with the phone; older Cambium labels outside printable ASCII are refused. Capability `phone_enrol_relay_v1`; bench client `scripts/phone-unlock.mjs enrol|enrol-for --over-relay`.

Field-test feedback landed 2026-08-14 (see docs/plans/2026-08-14-field-test-feedback-triage.md): approval loop hardened (B button = explicit cancel on two-button boards with on-screen hints, debounce, terminal "request expired" card so a stale countdown can never wedge the screen, 45 s browser-driven windows), wake-on-press (a serial bridge pinning GPIO 0 after a web flash no longer makes the device look dead), paged idle carousel (identity / network / device pages on short press), multiple prioritised WiFi networks (`NetConfig.networks` fallback list, per-SSID password `keep`, join-loop rotation incl. the locked vault-unlock phase, which previously never associated the station), and a `demo-game` bin (`scripts/build-firmware.sh demo`) — a branded board-check jump-and-duck game for pre-flashing handed-out T-Displays, deliberately not the signer. Sapwood gained the network-list editor, an app-only quick USB update for factory-layout boards, an update banner, and post-flash DTR/RTS release.

Family-bunker Phase 1 landed 2026-08-14 (signet-plans design doc §11.2): the persona registry moved to packed NVS chunks (`pc{c}` + `pcnt`, codec + power-cut models host-tested in `common/src/persona_pack.rs`) with a journalled one-time boot migration from the `p{n}_*` keys; per-board caps (Heltec 8/32, T-Display 8/64); NVS entry stats in FIRMWARE_INFO and get_status for the Sapwood storage gauge; derive refuses cleanly ("identity storage full") with policy headroom reserved; and `heartwood_remove_persona` / `heartwood_rename_persona` NIP-46 extensions (journalled removal, registry-only). Checklist section 9 ran and CP1 signed off 2026-08-14. C4 escalation + C5 audit rail landed 2026-08-15 as v0.17.0 (checklist section 11; button-free half benched); CP2 joint gate closed 2026-08-15 (checklist section 10 records the ack, Path A findings tracked as #64–#66). `get_status.capabilities` advertises `client_policy_flags_v1` for the C3 compiler push and `pairing_identity_v1` for the D2 persona-addressed pairing mint (`params.identity` on `create_client_v2` / `nostrconnect_v2` / `client_uri`; hardware verify is checklist §11b item 11 — needs the bench operator install, one button press, see scripts/set-operator.mjs).

CP2's Path A findings are closed on our side: #65 (idle watchdog reboot on an unprovisioned board) and #67 (derive answering success while the registry write failed) landed 2026-08-16, as did #66 (the first-boot setup screen now accepts a staged `SET_NET_CONFIG` before the first identity, and NACKs everything else with a reason). #64 followed the same day: in WiFi-standalone mode an interactive ask no longer blocks the relay loop. `nip46_handler::dispatch` takes an `ApprovalDecision` and hands a `Deferred` caller the ask back instead of putting the card up itself; relay.rs holds it the way a C4 park is held, the button sampler thread measures the hold so a loop running at ~1 Hz can judge one, and same-client asks for the same identity collapse onto one card whose single hold answers the batch (caps and admission rule host-tested in `common/src/approval_queue.rs`). Replies are stamped via `common/src/reply_clock.rs` for when they are sent rather than when the ask arrived. The USB tier deliberately keeps the blocking loop — the host is waiting on the reply frame. None of it is bench-run: checklist section 12.

Bearer-note locker landed 2026-08-18 (all five phases device-side; design and
per-phase record in docs/plans/2026-08-18-note-locker-goal.md): heartwood
custodies LUD-25 (LNURLcash) bearer notes as a sidecar to signing — the
browser wallet (a dni/lnurl-wallet fork, branch heartwood-transport) does all
mint HTTP, the device generates replacement secrets and discloses only their
SHA-256 until the mint confirms, and every plaintext export needs the button.
Lifecycle model + wire protocol host-tested in common/src/{note_store,
note_cmd}.rs (power-cut torture pins persist-before-disclose); USB surface is
one frame pair (NOTE_CMD 0x70 / NOTE_RESP 0x71, lnurl-vault's JSON command
set verbatim, bench driver scripts/note-cmd.mjs); notes are sealed at rest
under a random note key wrapped by the same PIN/vault secret as the seeds
(common/src/note_seal.rs, nk blob in the hw_notes namespace, one extra PBKDF2
at unlock, notes::sync_sealed converges every torn state and never deletes
what it cannot read). The locker self-tidies: MAX_SPENT (4) caps spent records
at the spend transition, and every creation path (both mint calls, receive,
import and claim) makes room out of the oldest spent record first, so the
locker cannot fill with dead records and no one has to prune by hand (#96,
#111). Live notes are never evicted for any reason: a full locker of
CONFIRMED notes still refuses. Relay path: heartwood_note_* NIP-46 extensions
(advertised note_locker_v1), gated methods pinned ButtonRequired ahead of the
generic extension gate so no slot policy can silence a disclosure, riding the
#64 deferred machinery. heartwood_note_rename joined that set (#96, checklist
section 18): it touches a LIVE note and no amount of pruning corrects a label
typed wrong, so a tier with no cable needs it; heartwood_note_delete
deliberately did not, because MAX_SPENT retires the record it would remove. Note SECRETS are deliberately NOT in backups and never
will be (restore onto two boards = double-spend), so a dead board's money is
still gone: the locker is a TILL, not a vault - collect promptly. What a
backup DOES carry since #86 is a non-spendable INVENTORY: an optional
top-level `note_inventory` array (common/src/backup.rs NoteInventoryEntry, at
most 16, built by build_note_inventory from NoteStore::commitments) holding,
per readable note, `id`, `commitment`, `state`, `amount_msat`, `host`,
`key_index`, `created_at`, `updated_at` and nothing else. `commitment` is the
public identifier the issuing mint already files the note under
(note_store::note_commitment_hex - sha256(k1) for a Part 1 note, the note's
own x-only pubkey for a Part 2 key note, since that is what the mint recovers
from a ck1; key_index non-null tells them apart). It is NOT called
`secret_hash`: for a key note it is not a hash of anything. A second optional
top-level `note_inventory_unreadable` (u32, omitted when zero) counts notes
the exporting board held but could not read - sealed at rest, or an unloadable
index - because otherwise an export from a locked board is byte-identical to
one from an empty locker, which is the false completeness the feature exists
to remove; the export card shows it as `<u> UNREAD`. It restores NOTHING -
BACKUP_IMPORT shape-checks via inspect_imported_inventory, logs and drops, and
no code path from the import reaches the locker. The inventory is also
LENIENT on read (backup::NoteInventory is an untagged Entries-or-Unreadable
enum): a record of money already gone must never block the restore of
identities and slots, so any shape that does not parse becomes
`unreadable_field` and the masters/slots stay exactly as strict as they were.
Pre-#86 backups still import (serde default), and a new backup still imports
on pre-#86 firmware (no deny_unknown_fields, pinned by a test). Sapwood's
parser (src/lib/backup.ts) is the matching reader (SECURITY-MODEL.md); destructive commands (mark_spent/discard/rename/
delete) are button-gated like lnurl-vault gates them, with ONE runtime
exception (#129): an approved export_secret leaves a single-use, RAM-only
grant (note_cmd::SpendGrant, 120 s, same note, same client) so the mark_spent
that completes a collect costs no second hold. The method policy pin is
unchanged - heartwood_note_spent still answers always_requires_button(). Notes also travel as
NIP-59 gift wraps (common/src/note_wrap.rs, kind-2525 rumor = LUD-25 URL):
a 1059 to a master npub raises a RECEIVE card (relay.rs handle_note_wrap,
stored CONFIRMED with Peer::From, MAX_RECEIVED cap, never re-sent);
heartwood_note_send seals on-device via nip59::gift_wrap (Peer::To recorded
before the wrap leaves, so once only). Advertised note_wrap_v1. WiFi tier NACKs the USB
note frames (use the relay methods) and refuses at-rest changes while notes
are held. Nothing bench-run: checklist section 13.

The spend grant starts at the handover (#137, 2026-09-12, checklist section
20): #129 minted the grant inside the dispatch, where the secret is generated,
so a reply lost or held in transit left a live card-free write-off for a note
whose ck1 the caller never received, and mark_spent takes a note out of
exportable state for good. The export arm now only records what a DELIVERED
reply would earn (note_cmd::SpendGrant::earn, one pending slot, nothing can be
spent against it); the surface that publishes arms it (SpendGrant::arm), and
the 120 s window runs from there, so a reply held across a reconnect does not
spend most of its window in RAM. A dropped, refused, expired or too-large
reply arms nothing, and a held reply carries the note id so its delivery is
what grants. The cable arms after write_frame, which is the same instant it
always was. Failure direction: anything that forgets to arm costs a card,
never a silent write-off. Nothing bench-run.

An approved reply outlives its session (#82, 2026-09-12, checklist section 19):
a NIP-46 reply is addressed to a client pubkey, not to a socket, so a reconnect
between the owner's hold and the publish no longer throws the answer away. A
card's approved reply is sealed once and offered to every live session; if none
takes it, it waits in a RAM-only outbox (`common/src/held_reply.rs`: 4 entries,
4 KB, 60 s, two publication attempts, delivered once and only to the pubkey it
was sealed to, dropped if that client's slot has since gone) for the next
session. A card that resolves with no session at all now dispatches and holds
instead of being abandoned, EXCEPT for a dependant persona, whose C5 audit rail
needs a live socket. Denials, expiries and `busy` refusals are never held. The
same hold catches a failed park completion; the guardian's `applied` value is
unchanged. Nothing bench-run.

A guardian verdict answers a note card too (#160, 2026-09-17, checklist section
24): on an `escalate` slot the approved park completed through the INTERACTIVE
handler, so a bearer-note method, pinned ButtonRequired whatever the slot
policy says, put its 30 s card up on a board nobody was standing at, blocked
the relay loop for the whole window and then refused. The verdict is an
approval of that one request (the park id IS the request event's id), so the
completion now dispatches `ButtonApproved` carrying what the notice showed, and
the handler's existing `Resume` check refuses fast if the request has since
changed identity or needs a different card. It widens nothing else: the
transient allow on its own still cannot silence a pinned method, so a second
note ask inside the verdict's window parks again rather than riding it, and a
pinned method on an escalate slot now parks even where the slot policy lifted
its tier instead of falling through to a card no one will press.

Two limits keep that narrow. A verdict answers the own card of the
bearer-note set only (`ApprovalDecision::VerdictApproved` refuses any other
card instead of pressing it by proxy), and the methods whose card only a press
can answer (`Nip46Method::device_press_only`: `heartwood_provision_rendezvous`,
which hands over a derived scalar, and `heartwood_pair_wallet`, which mints a
slot secret) are refused outright on an escalate slot rather than parked, so
the loop is never held for them either. And the approver has to see what they
release: the notice carries the device card itself (`card` and `detail` tags,
`nip59::ApprovalCard`, the same text `notes::relay_card` draws), and a request
whose preview cannot be built is not parked at all, it keeps its card. Pure
halves are `common::escalate::{route_request, park_completion,
park_verdict_matches}` and `nip46::Nip46Method::{pinned_physical,
device_press_only, verdict_may_answer_card}`, host-tested. Nothing bench-run.

A second configured relay (#92, 2026-09-11, checklist section 16): besides
the primary, the relay loop keeps one more configured relay live when the
second session slot is free and the heap can spare it (SECONDARY_MIN_* in
relay.rs), is promoted when the primary drops, gives its slot to a pinned
relay or a pairing, and is shed when the largest block falls below 32 KB.
net-config reports runtime.secondary_index.

LUD-25 Part 2 key notes (2026-09-11, checklist section 15, receive/scan/spend bench-run on real sats): a
lightning address owned by a master npub can be paid to keys the device
derives from that identity key (common/src/cash_key.rs: seed =
HMAC-SHA256(identity key, "LNURLcash/nostr-seed"), then lnurl-wallet's
m/139'/1'/d1..d4 and LUD-25's tweak, graded against lnurlcash-kit's
part2.json and tests/fixtures/lud25-nostr-seed.json on both curve backends). The
mint holds only the cx1 (heartwood_note_address, no hold); a key-note wrap
carries p/i/sig and no secret, and is opened only if the key is ours
(note_wrap::open_note_rumor). A key note stores its key as the secret plus
KeyNote {index, pubkey} (a v3 blob, written only for key notes), exports a
ck1 (never the key), cannot be sent, and a scan claim (heartwood_note_claim)
derives the key itself. Recoverable signing is the one new curve op:
secp256k1's `recovery` module on the firmware, k256 `ecdsa` on the host.

Next: bench the note locker (checklist section 13) and the remaining hardware verification of the encrypted-at-rest flows (USB auto-unlock and Hard-mode signing passed on real hardware 2026-08-13; see docs/HARDWARE-TEST-CHECKLIST.md section 7), the 2026-08-14 fixes and features (checklist section 8, not yet bench-run), and the Soft-mode approval path (fixed 2026-08-08: approvals were re-queued and the signed envelope dropped). Task watchdog landed 2026-08-08 (60 s, panic → crash crumb, fed by every blocking loop). JTAG disable is deliberately excluded — it requires eFuse burning, which permanently locks the chip (see docs/memory/feedback_no_efuse.md); physical security is the model. Sapwood tier badge/unlock/approvals/backup UI is in the sapwood repo.

## Build & flash

Five crates — build each from its own directory:

```bash
# common's tests assume the `cash` feature: note_store's test call sites pass
# new_secret's cfg-gated `cash` argument unconditionally, so without it the test
# target does not compile (35 arity errors). Use the two invocations CI uses:
cargo test --manifest-path common/Cargo.toml --no-default-features --features mnemonic-gen,cash
cargo test --manifest-path common/Cargo.toml --features nip44,nip46,nip04,ota-sign,seed-encrypt,cash
cd ui-preview && cargo test                # screen geometry + the show_error clipping guard
cd provision && cargo build                # host CLI tool
cd sign-test && cargo build                # signing test harness
cd heartwoodd && cargo build               # Pi-side daemon (Soft or Hard mode)
cd ota && cargo build                      # Pi-side serial OTA tool
cd firmware && cargo build                 # ESP32 firmware (needs ESP toolchain)
cd firmware && espflash flash target/xtensa-esp32s3-espidf/debug/heartwood-esp32
```

Requires the ESP Rust toolchain for firmware: `espup install`, then `source ~/export-esp.sh`.

## Conventions

- British English in all prose and comments
- No secrets in logs, serial output, or display — npub only
- Zeroize all private key material after use
- Git commits: `type: description` (feat:, fix:, docs:, refactor:, test:, chore:)
- No `Co-Authored-By` lines in commits
- Private docs (plans, session memory) live in gitignored directories

## Frozen protocol

The nsec-tree derivation MUST match heartwood-core byte-for-byte. The test vector in `common/src/derive.rs` asserts this. The mnemonic derivation path (`m/44'/1237'/727'/0'/0'`) is tested in `provision/src/main.rs`. If derivation logic changes, update both repos.

## GPIO pin assignments (Heltec V3 and V4)

Common to both boards:

| Function | GPIO | Verified |
|----------|------|----------|
| OLED SDA | 17 | Yes -- Heltec factory test, Meshtastic |
| OLED SCL | 18 | Yes -- Heltec factory test, Meshtastic |
| OLED RST | 21 | Yes -- must stay HIGH after init or display blanks |
| Vext (OLED power) | 36 | Yes -- active LOW, must be set before I2C init |
| White LED | 35 | Yes -- active HIGH |
| PRG button | 0 | Active LOW, internal pull-up |
| LoRa NSS | 8 | Not yet used |
| LoRa RST | 12 | Not yet used |
| LoRa DIO1 | 14 | Not yet used |

Board-specific (host transport):

| Board | Mechanism | GPIO |
|-------|-----------|------|
| V4 | Native USB-Serial-JTAG | 19 (D-), 20 (D+) |
| V3 | UART0 via CP2102 bridge | 43 (TX), 44 (RX) |

V4-only (not present on V3):

| Function | GPIO | Verified |
|----------|------|----------|
| GNSS TX | 34 | Not yet used |
| GNSS RX | 33 | Not yet used |

**PSRAM uses GPIO 26-32 on the V4 (S3R2).** V3 (S3FN8) has no PSRAM. Never drive those pins on V4.

## Known issues

### k256 LoadStoreAlignment on Xtensa (RESOLVED)

k256's field arithmetic does unaligned memory accesses that hang on Xtensa LX7.
No amount of thread/alignment tricks fixes it reliably — `SigningKey::from_bytes()`
hangs deterministically, with one-off successes depending on exact binary layout.

**Resolution:** Firmware now uses the `secp256k1` crate (C FFI wrapping Bitcoin
Core's libsecp256k1) which is alignment-safe on all architectures. The `common`
crate has a feature flag: `k256-backend` (default, for host tools/tests) and
`secp256k1-backend` (for firmware). Both backends produce identical outputs —
verified by the frozen test vector in `common/src/derive.rs`.

## Dependencies

All crypto crates are no_std-compatible but we use the ESP-IDF std framework:

| Crate | Why |
|-------|-----|
| secp256k1 | libsecp256k1 C FFI — BIP-340 Schnorr (firmware) |
| k256 | secp256k1 pure Rust — BIP-340 Schnorr (host tools/tests) |
| hmac + sha2 | HMAC-SHA256 child key derivation |
| zeroize | Deterministic secret cleanup |
| bech32 | npub encoding |
| bip39 + bip32 | Mnemonic derivation (provision CLI only) |
| crc32fast | Serial protocol integrity |
| esp-idf-svc + esp-idf-hal | ESP-IDF std framework (I2C, GPIO, NVS, logging) |
| ssd1306 + embedded-graphics | OLED driver and text rendering |
