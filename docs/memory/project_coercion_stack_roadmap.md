---
name: Coercion-resistance stack as post-grant roadmap
description: How canary-kit + spoken-token + ring-sig + button+biometric compose into a duress-resistant signing stack for heartwood -- deferred until grants land
type: project
---

Designed in the 2026-04-05 deep dive after reframing heartwood as a tier ladder. Each primitive sits at a different point in the signing flow and defends a different threat. The stack is architecturally correct but MUST NOT be built in unfunded sessions -- see `project_heartwood_grant_timing.md` for why.

## The composition (roadmap, not current work)

| Layer | Primitive | What it provides |
|---|---|---|
| Input channel | spoken-token | Hands-free authorisation via HMAC-SHA256-derived words; natural carrier for duress safewords; discrete in hostile contexts |
| Local presence | Button (ESP32) + biometric (phone) | "I'm here, not remote" -- air-gapped, unspoofable |
| Cryptographic object | ring-sig (SAG/LSAG) | Deniability -- signature ambiguous over a set of keys. Kills "a coerced sig is indistinguishable from a genuine one" |
| Observable state | canary-kit | Publishable, time-bound, verifiable liveness/duress flag counterparties can check |

The critical insight: canary is NOT redundant with the others. Every other layer fails the same way -- a coerced signature, once produced, looks identical to a genuine one. Canary is the only layer that makes duress a **publishable assertion** observers can act on.

## Coercion scenario (how they compose)

1. Attacker forces a high-value sign
2. User speaks the duress word during the spoken-token challenge (sounds normal to bystander)
3. Phone produces a ring signature over `[real_key, decoy_1, decoy_2, …]` -- attacker can't prove which key signed
4. Duress word triggers delayed canary flip (secondary device, dead-man's timer -- not instant to avoid tipping off attacker)
5. Counterparty pulls canary stream for the event's time window, sees duress flag, rejects
6. User publicly repudiates later: canary shows duress AND ring signature provides cryptographic ambiguity

Attacker has to simultaneously: compel a voice challenge without tipping the victim off, compromise canary across multiple relays for the exact duress window, break ring-sig deniability, AND get counterparties to ignore all of it. Substantially harder than "make them press a button".

## What the research found (2026-04-05)

**canary-kit (TypeScript, v2.7.0, production):**
- Duress tokens with per-member collision avoidance and silent detection -- SHIPPED
- Group management, liveness tokens, Nostr kinds 30078/20078, NIP-17 gift wrap -- SHIPPED
- `deriveLivenessToken(seed, context, identity, counter)` -- SHIPPED
- Event-hash-to-counter binding: exists in spoken-token as `counterFromEventId()` (4-byte SHA-256 truncation → uint32), not directly exposed in canary-kit but trivially composable
- Rust/WASM port: **NOT SHIPPED -- reserved for G01 M3**
- Meshtastic transport: spec'd only

**spoken-token (TypeScript, v2.0.3, production):**
- Stateless HMAC-SHA256 → 2048-word lookup (en-v1)
- Event-bound counters via `counterFromEventId()` -- SHIPPED
- Directional pairs (two-party without echo), tolerance windows, identity-bound variants -- SHIPPED
- **Does zero voice processing** -- pure crypto primitive. STT is the application's job (can be local Whisper.cpp)
- Duress is NOT in spoken-token -- it's canary-kit's extension via different context suffix
- Rust port: **NOT SHIPPED -- reserved for G01 M3** (same milestone as canary-kit)

**ring-sig (TypeScript, v2.0.0, production):**
- SAG (Spontaneous Anonymous Group) and LSAG (Linkable SAG), Schnorr-based
- **secp256k1 with BIP-340 x-only pubkeys** -- directly Nostr-compatible, no curve blocker
- Signature sizes linear: ring-of-10 ≈ 1.4 KB, ring-of-100 ≈ 13.5 KB -- fits Nostr events
- 62 passing tests, constant-time comparisons, proper domain separation, side-channel hardened
- Max ring size 1000 (enforced)
- Rust/WASM: NOT SHIPPED. G12 NLnet Privacy is unsubmitted (Jun deadline) -- cross-impl test vectors is one of its milestones

**heartwood's current extension hooks:**
- `heartwood_create_proof` / `heartwood_verify_proof` are defined NIP-46 methods, currently stubbed -- pre-reserved hook points for exactly this integration
- Policy engine is per-client, per-method, per-kind with three tiers (AutoApprove / OledNotify / ButtonRequired)
- Device-decrypts mode makes bridge genuinely zero-trust -- duress metadata rides inside NIP-44 ciphertext
- Per-master policies allow tier-specific rules without firmware changes
- Signature output is a hex string in a JSON field -- ring sigs would serialise cleanly

## Policy tiering (so it's not all maximalism)

The button press should be rare, not constant. Friction matches stakes:

| Event class | Canary | Spoken | Ring sig | Button |
|---|---|---|---|---|
| kind 1 notes, reposts, likes | Heartbeat only | No | No | No |
| DMs, kind 4/14 | Heartbeat only | No | No | No (biometric) |
| Zaps < threshold | Heartbeat only | Optional safeword | No | No |
| Zaps ≥ threshold | Bound to event | Yes, challenge-bound | Yes, small ring | Yes |
| Kind 0 profile change, key rotation | Bound to event | Yes | Yes, full ring | Yes, on ESP32 |
| Root operations | All | Yes | Yes | Yes + second operator |

## Honest caveats (don't forget these)

1. **Counterparty canary verification is an unproven coordination loop.** Nobody runs the check today. Building the infrastructure for "verifiers" is a multi-year ecosystem problem, not a heartwood feature. Canary is valuable primarily for the user's *own* phone checking *their own* canary before signing.
2. **Liveness challenge per high-value sign is a UX disaster** if applied too broadly. Reserve for ~5 ceremonial operations per user per year.
3. **Ring-sig deniability as legal-compulsion defence is weak** in practice -- courts weigh circumstantial evidence. Don't oversell.
4. **Ring signatures have no counterparty market on Nostr today.** No client supports them, no relay filters on them. Building v1 is building an island.

**Why:** Designed in the 2026-04-05 conversation as the natural elaboration of the tier ladder. The composition is architecturally sound; the problem is it spans multiple unfunded grant milestones (G01 M3, G12 ring-sig work, Heartwood Phase 2 proof methods) and re-invents features that already ship in canary-kit.

**How to apply:** Treat this as the post-grant-funding roadmap, not current work. The right sequence is: G01 lands → funds the Rust port of canary-kit + spoken-token → G12 lands → funds ring-sig cross-impl + security review → Heartwood Phase 2 drafts → funds the integration. Until then, heartwood-pocket (if built) uses canary-kit as a TypeScript library consumer in the app layer, NOT as a Rust integration inside common/ or firmware/.
