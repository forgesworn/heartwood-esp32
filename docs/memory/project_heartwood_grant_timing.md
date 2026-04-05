---
name: Grant milestones reserved in/around heartwood-esp32
description: Which future heartwood-adjacent work is reserved for which grant, what their status is, and what must NOT be built in unfunded sessions -- as of 2026-04-05
type: project
---

Discovered in the 2026-04-05 research pass that the coercion-resistance stack I'd been designing for heartwood spanned several reserved grant milestones. Captured here so future sessions don't re-derive this and don't accidentally burn deliverables. Authoritative source is always `prometheus/grants/TRACKER.md` + `GUARDRAILS.md` -- verify before acting. Dates and statuses are snapshots from 2026-04-05.

## Reserved for grants NOT YET APPROVED

| Work | Grant | Status | Amount |
|---|---|---|---|
| Rust/WASM port of spoken-token core (CANARY-DERIVE + CANARY-DURESS in Rust) | **G01 NLnet CANARY M3** | SUBMITTED 24 Mar, decision late Apr/May | €5,250 of €28,500 |
| Formal IETF-style protocol spec for CANARY | G01 M1 | Submitted | €4,125 |
| Security analysis of duress mechanism (formal proof) | G01 M2 | Submitted | €3,750 |
| Canonical test vectors (100+) | G01 M4 | Submitted | €2,625 |
| EUDI Wallet feasibility study | G01 M5 | Submitted | €3,750 |
| NIP submission -- group event kinds | G01 M7 | Submitted | €3,000 |
| ring-sig formal security review | G12 NLnet Privacy | **NOT SUBMITTED** -- Jun deadline | €3,000 of €22,000 |
| ring-sig cross-implementation test vectors | G12 | Not submitted | €3,000 |
| ring-sig browser/mobile performance | G12 | Not submitted | €4,500 |
| ring-sig security review with GitHub Security Lab | G30 GitHub Secure OSS | To draft, rolling | $10,000 |
| `identity-migrate` flow with `heartwoodUri` | **RESERVED: Heartwood Phase 2 (future NLnet)** | Not drafted | TBD |
| Migration proof protocol (server-side) | **RESERVED: Heartwood Phase 2** | Not drafted | TBD |
| FROST threshold signing (Heartwood as share-holder in t-of-n Schnorr scheme, Frostr/Bifrost ecosystem) | **RESERVED: Heartwood Phase 2** (per G23 draft Future Direction section) | Not drafted -- waiting for FROST coordinator protocol to stabilise | TBD |
| External security audit of crypto implementation + key storage | **RESERVED: Heartwood Phase 2** (per G23 draft) | Not drafted | TBD |

## Safe to build (Heartwood Phase 1 milestones, assuming G23 submits on time 7 Apr)

**G23 OpenSats Heartwood -- $19,000, draft ready, target submission 7 Apr 2026:**

| Milestone | Hours | Amount |
|---|---|---|
| M1: nsec-tree NIP + multi-identity signing extensions NIP | 50h | $3,850 |
| M2: Start9 + Umbrel packaging | 20h | $1,540 |
| M3: Pi Zero 2 W flashable image | 20h | $1,540 |
| M4: Hardening -- relay failover, watchdog, Shamir | 20h | $1,540 |
| M5: Bark Firefox port, Chrome + Firefox store submissions, store listing assets | 45h | $3,465 |
| M6: Documentation and adoption | 12h | $924 |
| M7: Ongoing maintenance | 50h | $3,850 |

**G23 M5 scope note (important):** Per-site signing policies and auto-reconnect in Bark are **FOUNDATION (already shipped)**, not M5 deliverables. The M5 hours are strictly Firefox port + cross-browser testing + Chrome Web Store submission + Firefox Add-ons submission + store listing assets (screenshots, privacy policy, copy). This scope was tightened in the 4 Apr draft update -- do not accidentally re-claim already-shipped Bark features as grant work.

The tier-ladder reframe (Soft/Hard/Portable naming, Sapwood badges, upgrade flows, `.deb` packaging, Pi image) is EXACTLY G23 M2/M3 territory. It strengthens the G23 narrative and should feed into the draft before submission.

**G23 competitor landscape (from 4 Apr draft):** Amber (Android, gold standard for mobile, but phone attack surface), nsecBunker/nsec.app (server-side software, shared infra), LNbits NSD (ESP32 hardware signer -- closest competitor, but single key, BLE/WiFi only, no remote, no multi-identity), Frostr (FROST threshold signing, alpha stage). Heartwood's differentiation: dedicated hardware with multi-identity derivation, accessible remotely over Tor, Bark makes it invisible to web apps.

## Possible overlap to watch

**G29 OpenSats Bark iOS** ($15-20K, to draft) includes the line item "Heartwood integration -- remote bunker signing via NIP-46 (30h, $2,250)". If "Heartwood Pocket" (the phone tier) is built as a separate app, it may overlap with G29's iOS client work. Needs a strategy decision: is Pocket a separate future grant, folded into G29, or foundation work Darren builds independently? Don't build it until this is decided.

## The timing rule

`GUARDRAILS.md`: *"Building this before approval means you can't claim it as a deliverable."*

Translation: reviewers check git timestamps. Work done before submission date becomes "pre-existing" and cannot be claimed against milestones. Work done after submission but before approval decision is in limbo -- if the grant is rejected, no harm; if accepted, the milestone was completed before funding which reviewers may challenge.

## The sequence (if all grants land)

1. **Now → 7 Apr**: G23 submission. Tier ladder reframe feeds into the draft. Only foundation work on the actual repo.
2. **Late Apr / May**: G01 CANARY decision lands. If accepted, M3 Rust/WASM port becomes a funded deliverable -- that's when canary-kit/spoken-token get Rust bindings suitable for heartwood.
3. **May**: G23 Heartwood decision lands. If accepted, Phase 1 hardening + packaging work starts.
4. **1 Jun**: G12 NLnet Privacy submission (ring-sig, range-proof, shamir-words). Deadline-bound.
5. **Later 2026**: G12 decision. If accepted, ring-sig Rust work is funded.
6. **After G01 + G12 + G23 all land**: draft Heartwood Phase 2 application for the coercion-stack integration -- funded across the already-landed primitive grants + a new Phase 2 grant for the integration itself.

## What must NOT be built in unfunded sessions (explicit DO-NOT list)

- Rust port of canary-kit primitives (CANARY-DERIVE, CANARY-DURESS, wordlist lookup) -- G01 M3
- Formal security analysis of the CANARY duress mechanism -- G01 M2
- New canonical test vectors for canary-kit or spoken-token -- G01 M4
- Rust port of ring-sig (SAG or LSAG) -- G12
- ring-sig formal security review content -- G12 / G30
- Implementing `heartwood_create_proof` / `heartwood_verify_proof` beyond the current stubs -- Heartwood Phase 2
- `identity-migrate` flow -- Heartwood Phase 2 (explicit rule in GUARDRAILS.md)
- Migration proof protocol -- Heartwood Phase 2

**Why:** Discovered on 2026-04-05 when deep-diving the coercion-resistance stack design. Three of the four primitives I proposed sat directly on reserved milestones, potentially burning €8-10K+ of deliverable value if built now. The guardrails rule is explicit: work before approval can't be claimed.

**How to apply:** Before any implementation in canary-kit, spoken-token, ring-sig, or heartwood's proof/migration areas, read `prometheus/grants/TRACKER.md` + `GUARDRAILS.md` and check current status. Invoke the `prometheus:grant-guardrails` skill. If the work is on a reserved list and the grant isn't approved, tell the user clearly and suggest foundation alternatives.
