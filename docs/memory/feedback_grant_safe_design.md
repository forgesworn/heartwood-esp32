---
name: Check existing libraries and grant reservations before designing cross-repo crypto integration
description: Before proposing a new integration spanning grant-funded repos, read what the target libraries already ship AND check TRACKER.md for reserved milestones -- don't re-invent or front-run
type: feedback
---

Before designing any cryptographic integration between heartwood and other Citadel ecosystem repos (canary-kit, spoken-token, ring-sig, range-proof, shamir-words, nsec-tree, nostr-attestations), do two things first:

1. **Read what the target library already ships.** Dispatch Explore agents in parallel on each repo and get a full inventory of shipped vs planned primitives before writing any design. Don't assume a feature is "future work" just because it wasn't mentioned -- check the code.
2. **Read `prometheus/grants/TRACKER.md` and `GUARDRAILS.md`.** Invoke the `prometheus:grant-guardrails` skill. Identify which grants cover the target repos, their submission/approval status, and which milestones are reserved.

Only after both are done, begin sketching integration designs. Otherwise two things go wrong:

- You waste the user's time re-speccing features that already ship and work.
- You front-run grant milestones, making them unclaimable against reviewer git-history checks.

**Why:** On 2026-04-05, when reframing heartwood as a tier ladder (Soft/Hard/Portable/Pocket), I designed a four-primitive coercion-resistance stack (canary + spoken-token + ring-sig + button) across several messages without checking either of the above. When I finally did the research pass the user asked for, I discovered:

- **canary-kit v2.7.0 already ships** duress tokens, group management, liveness tokens, Nostr kinds 30078/20078, NIP-17 gift wrap -- roughly 80% of what I was describing as "what canary would provide". I was re-inventing shipping code from imagination.
- **spoken-token already has** `counterFromEventId()` for event-hash-to-counter binding -- the primitive I was pitching as the "challenge-bound signing" novelty was an existing export.
- **ring-sig v2.0.0 already ships** production SAG and LSAG over secp256k1 with BIP-340 x-only pubkeys -- directly Nostr-compatible, 62 passing tests, hardened against side channels. Not a research prototype.
- **G01 NLnet CANARY M3 is literally "Rust/WASM port of spoken-token core" (€5,250)** -- the first integration step I proposed. Submitted 24 Mar, not yet approved.
- **G12 NLnet Privacy** (not yet submitted, Jun deadline) reserves ring-sig cross-implementation test vectors and browser/mobile performance work (€7,500 combined).
- **`heartwood_create_proof` / `heartwood_verify_proof`** stubs in heartwood are reserved for **Heartwood Phase 2** (future NLnet), explicitly listed in `GUARDRAILS.md` as do-not-build.

The user had to interrupt and explicitly ask "is this right, have we over-engineered, does this affect grant work?" before I did the verification step that should have preceded the design. The correct sequence would have been: user says "what if we add canary to the duress story" → I dispatch parallel Explore agents on canary-kit + invoke grant-guardrails → *then* design.

**How to apply:**

- Trigger: any time the user proposes adding cryptographic primitives from another Citadel repo into heartwood, OR extending heartwood's NIP-46 methods in ways that might touch duress/identity-migration/proof territory, OR discussing new signing ceremonies that cross repo boundaries.
- Action: dispatch parallel Explore agents on every repo involved for a full primitive inventory + read `TRACKER.md` and `GUARDRAILS.md` + invoke `prometheus:grant-guardrails`. Do these in parallel, not sequentially.
- Output before any design: a table of "what exists today vs what's planned vs what's reserved for which grant". Only then start sketching integration.
- If any piece of the proposed integration maps to a reserved milestone in a not-yet-approved grant: say so clearly, propose foundation alternatives, and let the user decide whether to proceed or hold.
- Don't be shy about walking back speculative designs. Over-engineering is especially costly in grant-funded repos because it doesn't just waste time -- it destroys deliverables.
