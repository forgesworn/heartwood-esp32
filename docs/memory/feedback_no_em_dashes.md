---
name: No em dashes
description: Avoid em dashes and Unicode arrows in commits, comments, and prose - use plain ASCII
type: feedback
---

Don't use em dashes, Unicode arrows (->), or fancy Unicode in commit messages, comments, or OLED text. Stick to plain ASCII: `--` not `—`, `->` not `→`.

**Why:** User pointed it out twice. Consistency with ASCII-only OLED display and plain text tooling.

**How to apply:** In commit messages, comments, docs, and any generated text. Use `->` for arrows, `--` for dashes.
