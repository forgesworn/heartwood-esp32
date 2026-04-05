---
name: Grant applications only claim what is shipped and verifiable
description: Never add narrative claims to grant drafts that describe capabilities not currently implemented -- reviewers check repos and integrity damage dwarfs narrative lift
type: feedback
---

Grant applications must only claim capabilities that are actually shipped and verifiable in the current codebase. Aspirational or roadmap work belongs in clearly-labelled "Future direction" / "Phase 2" sections, never in competitive positioning, milestone descriptions, or "what nobody else has" framing.

When suggesting narrative additions to a grant draft, verify each claim against current code before proposing it. If a feature is partially built, not yet built, or depends on unresolved upstream protocols, either omit it or move it to the future direction section with honest language ("will", "is planned", "waiting for X to stabilise").

Late-draft edits near submission deadlines are risk-asymmetric: narrative lift is small, integrity damage is large. Favour caution. If a reframe would genuinely strengthen the pitch but requires claims the code doesn't yet back, either (a) build it first and resubmit next cycle, or (b) keep it out of this application and fold into Phase 2 / follow-on grants.

**Why:** Darren ruled this explicitly on 2026-04-05 when I suggested adding the Heartwood tier-ladder reframe (Soft/Hard/Portable/Pocket) to the G23 OpenSats Heartwood draft two days before 7 Apr submission. The reframe would have strengthened the product story, but Heartwood Soft (Pi standalone, no ESP32) isn't actually built yet -- the daemon currently requires an attached ESP32 to sign. Claiming otherwise would have been a lie reviewers could catch by grepping the repo. His words: *"let's not risk doing something it's impossible to deliver and we certainly don't want to lie!"*

**How to apply:**

- Before proposing narrative additions to any grant draft, read the target repo's current code state and verify every capability claim.
- Aspirational capabilities go in "Future direction" / "Phase 2" sections only, with honest hedging language.
- Near submission deadlines (within ~1 week), refuse narrative changes that touch unbuilt capabilities, even if they'd strengthen the pitch. The risk asymmetry isn't worth it.
- If a reframe genuinely belongs in the pitch but isn't deliverable today, flag it as "build first, then claim" for a later cycle -- not "claim now, build later".
- Reviewers check git history and grep repos. Aspirational claims discovered in review are reputation damage that affects future applications to the same funder, not just this one.
- The same rule applies to CLAUDE.md, README, and public docs -- never describe capabilities as shipped when they're not.
