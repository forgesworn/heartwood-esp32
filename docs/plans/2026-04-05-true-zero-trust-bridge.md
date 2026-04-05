# True zero-trust bridge — design note

**Status:** Design, not yet implemented. Grant-reserved (see placement section).
**Author:** 2026-04-05 session.
**Supersedes:** nothing. Complements the "device-decrypts mode" work already in the bridge.
**Related:** `prometheus/grants/plans/heartwood-hard-tier-future-grant.md`.

## The bug

The current bridge in `device-decrypts` mode has an architectural invariant that is not actually enforced by the code and not true of any realistic deployment:

> For ECDH to line up between Bark and the ESP32, `bunker_secret` on the Pi must equal one of the master secrets loaded on the device.

Concretely: Bark encrypts NIP-46 requests using `ECDH(bark_priv, bunker_pub)`. For the device to decrypt the same ciphertext it computes `ECDH(master.secret, bark_pub)`. These are only equal when `master.secret` corresponds to `bunker_pub`, i.e. when `master_secret == bunker_secret`. In `setup-hsm.py` as currently shipped the `BUNKER_SECRET` is a hardcoded random hex unrelated to any master nsec, so the requirement is silently violated on every fresh deployment and Bark gets instant NACKs back from the device. Our 2026-04-05 session rediscovered this the hard way.

The hack that makes it "work" is to set `--bunker-secret` on the bridge equal to a real master nsec, which puts a signing-capable private key on the Pi. That defeats the entire "Pi is zero-trust" framing in the CLAUDE.md. It is not acceptable as a permanent answer.

## Why fixing the bunker_secret is not enough

Even if `setup-hsm.py` were rewritten to prompt for a master nsec and use it as `bunker_secret`, the fundamental issue remains: the bridge needs a signing-capable key on the Pi because it signs two things:

1. **The NIP-44 layer** — needs the conversation key, which requires the private half of `bunker_pub` for ECDH.
2. **The NIP-46 envelope layer** — the outer `kind:24133` event that carries the encrypted response needs to be Schnorr-signed by `bunker_priv` before being published to relays. See `bridge/src/main.rs:792` where `bunker_keys.secret_key()` is passed to `EventBuilder::sign()`.

Both operations need a real private key on the Pi. Moving (1) to the device (which "device-decrypts mode" was supposed to achieve) is not enough as long as (2) still happens on the Pi. Any nsec we put in `bunker_secret` is immediately usable by a Pi attacker to sign arbitrary Nostr events as that identity.

The correct fix moves **both** operations to the device. The Pi keeps no signing-capable key of any kind.

## Target architecture

```
┌──────┐   NIP-44 ciphertext    ┌──────────┐   frame 0x10    ┌──────────┐
│ Bark │  (kind 24133 envelope  │   Pi     │  ENCRYPTED_REQ  │  ESP32   │
└──────┘   signed by Bark)      │  bridge  │ ───────────────→│ firmware │
   │                            └──────────┘                 └──────────┘
   │                                 │                             │
   │                                 │                             │ decrypts NIP-44 with
   │                                 │                             │ transport_secret
   │                                 │                             │ (on-device)
   │                                 │                             │
   │                                 │                             │ dispatches to NIP-46
   │                                 │                             │ handler (uses master
   │                                 │                             │ keys internally)
   │                                 │                             │
   │                                 │                             │ re-encrypts response
   │                                 │                             │ with transport_secret
   │                                 │                             │
   │                                 │  frame 0x11 (new variant)   │
   │                                 │ ←─────────────────────────── │ [signed envelope event]
   │                                 │                             │
   │                                 │ publishes verbatim          │
   │                                 │ (no signing on Pi)          │
   │                                 │                             │
   │ ←───── kind:24133 relay event ──│                             │
   │        signed by transport_pub  │                             │
```

Key differences from the current device-decrypts mode:

1. **Dedicated on-device transport key.** A secp256k1 key pair stored in NVS, provisioned at first boot or via a button-gated `SET_TRANSPORT_KEY` frame. Distinct from master keys. Its public half is what clients (Bark, etc.) pair with. Its private half never leaves the ESP32.

2. **Device signs the envelope event.** A new frame type `BUILD_SIGNED_ENVELOPE` (proposed 0x14, TBC): bridge sends `(client_pubkey, response_ciphertext, created_at)`, device builds the `kind:24133` event structure, computes the event ID, Schnorr-signs with `transport_secret`, returns the complete serialised signed event. Bridge publishes verbatim.

3. **Bridge uses only an optional ephemeral relay-auth key.** For NIP-42 relay auth (if any relay requires it), the bridge can use a random ephemeral secp256k1 key generated at startup, with zero authority for anything except the relay handshake. That key has no `user_metadata`, no `kind:0` profile, no stored presence on any relay's filters, and is thrown away at next restart. If an attacker compromises the Pi, the ephemeral relay-auth key lets them log in to relays as a fresh unknown identity and publish nothing of value.

4. **Pi holds nothing that can sign user events.** Any attacker with root on the Pi sees: ciphertext passing through, metadata (which bunker pubkey is active, which relays are subscribed, timing of requests), and the ephemeral relay-auth key. They cannot: produce a valid signature for the transport pubkey, decrypt Bark's requests, or forge NIP-46 responses. They can DoS the bridge (stop the daemon, block the ports), which is inherent to the role and not a key-security concern.

## Firmware changes

### New frame types

| Name | Value | Direction | Payload |
|---|---|---|---|
| `GET_TRANSPORT_PUBKEY` | 0x2D (TBC) | bridge → device | empty |
| `TRANSPORT_PUBKEY_RESPONSE` | 0x2E (TBC) | device → bridge | 32 bytes transport pubkey |
| `SET_TRANSPORT_KEY` | 0x24 (TBC) | bridge → device | 32 bytes secret OR 0 bytes to request on-device generation |
| `BUILD_SIGNED_ENVELOPE` | 0x14 (TBC) | bridge → device | `[client_pubkey_32][created_at_8][response_ciphertext_bytes...]` |
| `SIGNED_ENVELOPE_RESPONSE` | 0x15 (TBC) | device → bridge | Full JSON-serialised signed `kind:24133` event |

Frame byte values to be finalised; these conflict with existing NACK usage in some designs and will need renumbering during implementation. Not blocking for the design.

### NVS storage

Add a new NVS entry: `transport_secret` (32 bytes). Provisioned at one of:

- **First boot after firmware update.** Device generates a random key, stores it, logs the pubkey to the OLED ("Transport: npub1...") so the admin can copy it. No button required (no key material being accepted from outside).
- **Explicit `SET_TRANSPORT_KEY` frame with button approval.** Follows the same pattern as `SET_BRIDGE_SECRET` — 30 second approval window, 2 second button hold, NACK on deny. Allows operators to import a pre-generated transport key if they want deterministic pairing URIs.
- **Regeneration via `SET_TRANSPORT_KEY` with empty payload and button approval.** For rotation.

### `handle_build_signed_envelope`

New firmware handler in `firmware/src/transport.rs` or a new `firmware/src/envelope.rs`:

```rust
pub fn handle_build_signed_envelope(
    usb: &mut UsbSerialDriver<'_>,
    frame: &Frame,
    transport_secret: &[u8; 32],
    secp: &Arc<Secp256k1<SignOnly>>,
) {
    if frame.payload.len() < 40 {
        protocol::write_frame(usb, FRAME_TYPE_NACK, &[]);
        return;
    }
    let client_pubkey: [u8; 32] = frame.payload[..32].try_into().unwrap();
    let created_at = u64::from_be_bytes(frame.payload[32..40].try_into().unwrap());
    let ciphertext = &frame.payload[40..];

    // Build the kind:24133 event:
    //   pubkey = transport_pubkey (derived from transport_secret)
    //   created_at = given
    //   kind = 24133
    //   tags = [["p", hex(client_pubkey)]]
    //   content = base64(ciphertext)
    //
    // Serialise canonically, sha256, Schnorr sign, emit JSON.

    let event_json = build_and_sign_kind_24133(
        transport_secret,
        &client_pubkey,
        created_at,
        ciphertext,
        secp,
    );

    protocol::write_frame(usb, FRAME_TYPE_SIGNED_ENVELOPE_RESPONSE, event_json.as_bytes());
}
```

Implementation reuses `common/src/nip46.rs`'s existing event ID computation and Schnorr signing (frozen test vectors in `common/src/derive.rs` cover the signing path already).

### NIP-44 conversation key

The existing `handle_encrypted_request` in `firmware/src/transport.rs` currently uses `master.secret` for the conversation key. In the new architecture it uses `transport_secret` instead. The `master_pubkey` field in the `ENCRYPTED_REQUEST` frame becomes an internal routing hint for which master to dispatch the NIP-46 method to, rather than the ECDH peer. The device's internal dispatch already supports `heartwood_switch` for selecting a master per-request, so this is mostly a rename of an existing field.

Critical: the `ENCRYPTED_REQUEST` frame payload layout changes. The first 32 bytes become `[target_master_pubkey_32]` (same semantics as now, but clarified as routing hint). Since no existing clients speak this protocol outside our own codebase, the frame layout change is safe.

## Bridge changes

### Drop `bunker_secret` for crypto

- Remove `bunker_secret` from `CliArgs` (keep temporarily as deprecated env fallback for migration).
- Add `transport_pubkey` that the bridge queries from the device at startup via `GET_TRANSPORT_PUBKEY`.
- `bunker_uri` is built from `transport_pubkey`, not `bunker_keys.public_key()`.

### Generate ephemeral relay-auth key

- At startup, generate a random secp256k1 key in memory: `let relay_auth_keys = Keys::generate();`.
- Use only for relay `Client::new()` and NIP-42 auth if challenged.
- Never persisted to disk.

### Replace `EventBuilder::sign()` call

In `bridge/src/main.rs` around line 792, the current code:

```rust
let response_event = EventBuilder::new(Kind::NostrConnect, response_content)
    .tag(Tag::public_key(client_pubkey))
    .sign_with_keys(&bunker_keys)?;
client.send_event(&response_event).await?;
```

becomes:

```rust
// Forward to device for envelope signing.
let signed_event_json = {
    let mut port = port.lock().unwrap();
    forward_build_envelope(&mut port, &client_pubkey_bytes, created_at, &response_ciphertext)?
};
let signed_event: Event = serde_json::from_str(&signed_event_json)?;
client.send_event(&signed_event).await?;
```

The `client` here is still `Client::new(relay_auth_keys)` for transport layer, but the event being sent is signed by `transport_secret` on the device.

## OTA path

The firmware change ships via the existing OTA mechanism (`heartwood-esp32/ota`). Button-gated rollout:

1. Cross-build new firmware targeting `xtensa-esp32s3-espidf`.
2. Generate SHA-256 of new `.bin`.
3. From Sapwood's OTA tab (or CLI `ota` crate), POST new firmware + SHA.
4. Device flashes into B partition, reboots into B, sends a `READY` heartbeat, waits for manual confirmation via button.
5. Bridge side: once the new firmware boots, send `GET_TRANSPORT_PUBKEY` — if the device responds, the bridge knows the new architecture is live and switches modes automatically.
6. On boot, device generates a new `transport_secret` if none exists (first-run after firmware update), or loads the existing one if it was set previously.

**Pre-existing deployments need a re-pair:** the transport pubkey is new, so every previously-paired Bark instance (and any other NIP-46 client) needs to drop its old bunker URI and pair against the new one. Sapwood should display the new bunker URI prominently post-update and warn: "Clients paired against the old bridge must re-pair."

## Test plan

Coverage before claiming the refactor complete:

1. **Firmware unit tests** (`common/src/nip46.rs`-style, frozen test vectors):
   - `transport_key → transport_pubkey` deterministic derivation
   - `build_and_sign_kind_24133` produces an event whose ID and signature validate against a known-good reference (nostr-tools or similar)
   - NIP-44 decrypt with `transport_secret` and `client_pubkey` matches the plaintext Bark sent
2. **Firmware integration tests** on real hardware:
   - `GET_TRANSPORT_PUBKEY` returns the same pubkey that derives from NVS `transport_secret`
   - `BUILD_SIGNED_ENVELOPE` round-trip with a fixed ciphertext produces a valid serialised event
   - `SET_TRANSPORT_KEY` with button press writes new NVS entry, rejects without button
3. **Bridge tests** (mocked serial):
   - Startup sequence: `GET_TRANSPORT_PUBKEY` → builds bunker URI → subscribes to filter
   - On NIP-46 inbound: forwards encrypted request, receives encrypted response, forwards to device for envelope signing, receives signed event, publishes
   - Ephemeral relay-auth key does not appear in any filter, any response event, or any log
4. **End-to-end with Bark**:
   - Pair Bark against the new bunker URI
   - Request `get_public_key` — device prompts for button, user approves, Bark receives the pubkey of a selected master
   - Request `sign_event` — device prompts for button with event details, user approves, Bark receives a signed event
   - Pi compromise test: `kill -9` the bridge process, inspect `/proc/<pid>/environ`, `/proc/<pid>/maps`, memory dump. Verify no `transport_secret` or any master secret is present. Only the ephemeral relay-auth key and ciphertext/metadata.
5. **Migration test**: old firmware + old bridge, upgrade firmware via OTA, swap bridge binary, verify old Bark pairing breaks cleanly (401 or NIP-46 unauthorised error) and new pairing works.

## Estimated effort

| Component | Hours |
|---|---|
| Firmware: new frame types, NVS transport key, handle_build_signed_envelope | 12-15 |
| Firmware: OLED prompts, button gates, logging | 3-4 |
| Firmware: tests + frozen vectors | 4-6 |
| Bridge: drop bunker_secret crypto, add GET_TRANSPORT_PUBKEY, ephemeral relay key | 6-8 |
| Bridge: replace envelope signing with device round-trip | 3-4 |
| Bridge: tests | 2-3 |
| OTA rollout + Sapwood re-pair messaging | 2-3 |
| End-to-end testing with Bark on real hardware | 4-6 |
| **Total** | **36-49 hours** |

At G23's $77/hour rate that is $2,772 - $3,773.

## Placement in the grant roadmap

**Not safe to build before 7 April 2026.** Implementing this before G23 submission means the work becomes "pre-existing" and cannot be claimed against any G23 milestone. Git timestamps matter.

**Candidate homes** after submission:

1. **G23 M7 "Ongoing maintenance"** — 50h budget, currently framed as "bug fixes, security patches, community support, NIP revision cycles". The refactor fits naturally as "security patch discovered in architecture review" and consumes roughly 36-49 of the 50 hours, which is a plausible distribution. **Safest framing.** Requires no budget change. Add a sentence to M7 in the draft describing this fix explicitly.

   Note: at the time of writing (2026-04-05) a draft edit to this effect was made and then reverted because the broader G23 draft was simultaneously reframed as "Heartwood is signing software, not hardware" with ESP32 HSM as an optional mode. Under that reframe the refactor is not universally applicable — it only applies to ESP32-HSM deployments — and claiming it as a universal M7 deliverable misrepresents the grant scope. See `prometheus/grants/plans/heartwood-hard-tier-future-grant.md`.

2. **A dedicated "Heartwood Hard tier" grant** — pitched alongside or after G23, framed around the ESP32 variant specifically. The "host holds no signing-capable key" architecture becomes the central differentiation claim. This is the cleanest alignment because the grant scope matches the refactor scope exactly.

3. **GitHub Secure Open Source Fund** ($10K rolling, per `prometheus/grants/TRACKER.md` G30-G32 entries). A targeted security review of `heartwood-esp32` that surfaces the refactor as both the finding and the fix. Must be cross-checked against Heartwood Phase 2's reserved "external security audit" scope to avoid double-claiming.

4. **Heartwood Phase 2** (future NLnet or continuation grant). Phase 2 is explicitly reserved for "external security audit", "FROST threshold signing", "migration proof protocol", and "iOS signer" per the memory notes. The refactor is plausibly an M1 hardening item in a Phase 2 application.

## What not to do

- **Do not implement piecemeal in unfunded sessions.** The full refactor spans firmware + bridge + OTA + test, and partial implementations (e.g. just the firmware frame types without the bridge integration) leave the system in a broken intermediate state and are not claimable as a milestone.
- **Do not rush it pre-submission.** Two days is not enough time for the firmware test pass, and reviewers will notice.
- **Do not mix it with other M4 hardening items** (relay failover, watchdog, Shamir) in commits. Keep the refactor as its own commit series so it can be pointed to cleanly in a grant deliverable.
- **Do not reuse frame values 0x14 / 0x15 / 0x24 / 0x2D / 0x2E without verifying against `common/src/types.rs`.** The numbers in this doc are proposed, not allocated.

## Open questions

- **How does this interact with multi-master?** In the new architecture `transport_pubkey` is the only identity that appears on relays. Master switching is internal to the device via `heartwood_switch`. This is arguably a better UX (one bunker URI per device, not per master) but may need NIP-46 extension updates to expose "which master signed" in responses.
- **Deterministic vs random transport key?** Deterministic (derived from master nsec-tree via a fixed path) means the same device always has the same transport pubkey across factory resets. Random means better unlinkability but worse recoverability. Leaning random with optional deterministic mode via `SET_TRANSPORT_KEY` frame.
- **NIP-42 relay auth policy.** Most Nostr relays do not require NIP-42 auth for publishing `kind:24133` events; for those that do, the ephemeral relay-auth key approach works. For relays that require persistent identity (rare), the bridge would need to either hold a persistent non-signing identity or skip those relays.
- **Backward compat with the existing bridge-decrypts mode?** The current code has two modes: `bridge-decrypts` (Pi holds master secret and does all NIP-44 and signing) and `device-decrypts` (the mode we are refactoring). Post-refactor there is only one mode. `bridge-decrypts` should be deleted, not maintained. It never had a legitimate use case — it was a development shortcut.

## Open actions

- [ ] Verify frame byte allocations against `common/src/types.rs`
- [ ] Verify there is no conflict with existing OTA partition layout (B partition must have enough space for the larger firmware after new handler + event building code)
- [ ] Update `prometheus/grants/plans/heartwood-hard-tier-future-grant.md` with a link back to this doc once published
- [ ] Decide placement (P1-P4 above) after G23 submission outcome is known
