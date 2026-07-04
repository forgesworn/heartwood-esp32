# Goal

Set 2026-07-04. Tracked across `sapwood` and `heartwood-esp32`.

## 1. Sapwood vs. other device flashers

Compare Sapwood's flashing/setup flow against other hardware signer and
hardware wallet flashers (e.g. Trezor Suite, Ledger Live, ColdCard, SeedSigner,
Krux, Jade, Foundation Passport, and similar guided web/desktop flashers).

Questions to answer:

- Are there features those flashers have that Sapwood is missing?
- Are there UI/UX changes that would make Sapwood's flow as simple and
  friendly to follow as the best of that field, for a non-technical user
  going through it for the first time?

## 2. Heartwood key restore UX (LilyGo firmware)

Heartwood firmware work is currently focused on the LilyGo board. That board
gives us two usable physical buttons (a main button plus a separate reset
button), where earlier Heltec-based work only had one.

Design the simplest possible restore-key interaction using this button
budget:

- Use click / double-click / long-press as the input vocabulary, mapped to
  distinct restore-related actions.
- Be careful with timing thresholds (double-click window, long-press
  duration) so the device doesn't misread deliberate input as noise, or
  noise as deliberate input.
- The device display must always make it obvious, in the moment, what the
  user needs to press and why, so nobody has to guess or consult a manual
  mid-restore.

## Deliverable

A concrete comparison (Sapwood vs. field) with a prioritised gap list, plus a
button-interaction design for restore (mapping, timings, on-screen prompts)
that's ready to implement in the LilyGo firmware.
