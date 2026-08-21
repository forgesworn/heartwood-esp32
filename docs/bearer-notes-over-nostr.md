# Bearer notes over Nostr

`draft` `optional`

How an LNURLcash bearer note ([LUD-25](https://github.com/lnurl/luds/pull/301))
travels from one Nostr identity to another: sealed in a
[NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md) gift wrap,
left on the recipient's [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md)
inbox relays, opened by whoever holds the recipient's key.

This is the contract heartwood-esp32 and notecase implement today. It is
written down here so the two stay in step and so it can be submitted as a
NIP once LUD-25 is merged. Until then the kind number is provisional.

## Why not just a DM

A LUD-25 note is a URL whose `k1` is the money. Anyone who reads it can
spend it. A plain text DM would carry it, and a receiver that accepts one
is part of this spec. But a sender that can say *this is money, not prose*
lets the receiver draw a card that says so, refuse anything else without
parsing it, and never mistake a pasted link in conversation for a payment.

[NIP-61](https://github.com/nostr-protocol/nips/blob/master/61.md) nutzaps
are the closest prior art. They are Cashu-specific and published in the
open, because a Cashu P2PK proof is locked to the recipient. A LUD-25 note
is a bearer secret and must never be published bare, so NIP-61's shape does
not fit.

## The note rumor

Kind `2525`, unsigned, as a NIP-59 rumor. Never published on its own.

```json
{
  "kind": 2525,
  "pubkey": "<sender>",
  "created_at": 1755000000,
  "tags": [
    ["p", "<recipient>"],
    ["amount", "21000"],
    ["u", "mint.example/w"]
  ],
  "content": "lnurlw://mint.example/w?k1=<64 hex>&amount=21000"
}
```

- `content` is the note, in the `lnurlw://` form LUD-25 and LUD-17
  define. It is authoritative.
- `amount` (msat) and `u` (the withdraw endpoint without scheme) repeat
  what the URL says, so a constrained receiver can draw a card without a
  URL parser, and so a URL that lacks `amount` still has one.
- `p` is the recipient, as NIP-59 requires of every rumor.

## Sealing and delivery

Exactly NIP-59: the rumor is NIP-44 encrypted into a kind `13` seal signed
by the sender, the seal is NIP-44 encrypted into a kind `1059` wrap signed
by a throwaway key, and both `created_at` values are jittered up to two
days into the past. The wrap's single `p` tag is the recipient.

The wrap goes to the recipient's kind `10050` inbox relays, as NIP-17
defines them. A sender that finds no `10050` SHOULD say so to its user
rather than guess. A hardware receiver that serves one relay at a time
MUST list every relay it might serve in its `10050`, because a sender
writes to all of them and the receiver reads whichever it is on.

The sender SHOULD treat the note as gone the moment the wrap is
published. It MAY reclaim it (rotate it onto a fresh secret) if the
recipient never does.

## Receiving

A receiver subscribes to kind `1059` with `#p` its own pubkey(s), opens
what it can, and looks at the rumor.

**Kinds.** A receiver MUST accept kind `2525`. It SHOULD also accept a
kind `14` (a NIP-17 direct message), because that is what a person on an
ordinary Nostr client can send today, and the money is the same money.

**Forms.** In either kind the note may appear in any form LUD-25 names:
`lnurlw://...`, `https://...`, or the URL bech32-encoded as an ordinary
`LNURL1...`, each with or without a `lightning:` prefix. A receiver MUST
treat these as the same note.

**Where to look.** A `2525` rumor's `content` is the note, whole; a
receiver MUST NOT search inside it. A `14` rumor is text: a receiver
SHOULD split it on whitespace, try each token, and accept the message as
a note only if exactly one token is one. Zero is prose. Two is ambiguous
and MUST be refused, because a parser that picks one is a parser that can
be led. A `14` carries no `amount` tag, so its URL MUST carry the amount.

**What to refuse.** Anything without a 32-byte hex `k1`, a host, and a
positive amount. A rumor whose `pubkey` is not the seal's signer (the
NIP-59 rule). The receiver's own card shows the amount and host from the
note, and those are the sender's word until a mint is asked.

**Stored wraps.** A kind `1059` is a regular event: relays keep it. A
receiver that is not always online MUST ask for stored wraps when it
connects, not only stream live ones, or a note sent while it was off is
never requested by anyone. Because of the two-day jitter, a `since` bound
MUST reach two days behind whatever it is anchored to. A receiver SHOULD
remember which wraps its owner has decided on so they are not offered
twice, and SHOULD remember nothing about a wrap it merely could not deal
with yet, so that one comes back.

## Claiming

Receiving the rumor is not receiving the money. The sender still knows
`k1`, and so does any relay operator who could read the plaintext (none,
under NIP-44, but the point stands). The recipient owns the note only once
it has been rotated at the mint onto a secret of the recipient's own. A
receiver that cannot speak to mints (an offline signer) SHOULD hand the
note to a wallet that can, and say on its card that it has done no more
than store it.

## Security considerations

- The wrap hides the sender, the recipient's relay list does not. A
  receiver's `10050` is public by design.
- Anyone can address a wrap to a public npub. A receiver with bounded
  storage MUST cap what it keeps for unclaimed notes, MUST NOT let an
  unsolicited wrap consume a resource its owner needs for anything else,
  and SHOULD write nothing durable for a wrap its owner has not decided
  on, so a flood cannot wear its storage.
- A wrap's `created_at` is the sender's to choose. A receiver that
  anchors a catch-up window on it MUST NOT let a forged-future value push
  the window ahead of notes it has not seen; anchoring on the lower of the
  last decision and its own clock does that.
- Two notes that are the same secret are one note. A receiver MUST be
  idempotent on `k1`.

## Kind number

`2525` sits in the regular-event range and was unused by any NIP when
chosen. It is never published bare, so a clash costs nothing on the wire.
Treat it as unallocated until this document is a NIP; the number may
move, and an implementation SHOULD make it a single constant.

## Implementations

- [heartwood-esp32](https://github.com/forgesworn/heartwood-esp32):
  receiver (RECEIVE card, persisted decisions, catch-up on connect) and
  sender (`heartwood_note_send`, sealed on-device); `common/src/note_wrap.rs`,
  `common/src/wrap_ledger.rs`, `common/src/nip59.rs`.
- [notecase](https://github.com/forgesworn/notecase): sender and
  receiver (`send --to <npub|nip05>`, `inbox`), and the wallet that claims
  what a heartwood received (`heartwood collect`); `src/nostr.ts`.
