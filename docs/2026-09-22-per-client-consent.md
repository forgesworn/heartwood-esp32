# Persistent consent for shared app pairings

A pairing keeps its credential and method/event-kind policy across app updates.
Persona consent belongs to each authenticated client public key within that
pairing. Returning clients keep their own approvals when another client becomes
current. Adding a new device does not give it another device's personas.

The client fingerprint is the authority identifier. App names and profile labels
are display hints. Bark, Cambium and My Signet still need their own downstream
origin/package checks: Heartwood sees the intermediary's credential.

## Consent and limits

Each pairing holds at most eight client credentials and sixteen explicit
client/persona grants. Adding a ninth client fails without evicting an existing
one. When explicit persona consent is full, the device offers an **ONCE AS**
card; a **REMEMBER AS** card records consent only after persistence verifies.
Method/kind ceilings and sensitive-operation confirmation remain separate gates.

Legacy migration snapshots the existing members and their previous identity
scope. Inherited identity tags retain their historical eight-byte matching
semantics; new explicit grants contain full public keys. New members do not
inherit those tags or an old bound-identity approval. Changing an identity
binding clears existing consent; selecting an identity does not approve it.

Sapwood lists persona consent by device fingerprint. Withdrawal may target one
persona for one device, all personas for one device, or every device in a
pairing. It preserves the pairing credential and capability limits. Withdrawn
consent requires a new approval before automatic use resumes. Pending device
cards and guardian verdicts are invalidated when authority changes; rollback
never makes an old pending approval current again. Guardian approve-once
windows remain RAM-only.

## Storage, migration and recovery

The existing `connslots_N` key stores a restrictive legacy projection plus a
versioned `g4` extension containing the actual policy and compact consent
snapshot. Known duplicate fields, malformed extensions, inconsistent membership
and unknown versions are rejected. A hash binds the extension to its projection;
it detects an old writer leaving a stale extension, and is not authentication or
an anti-rollback mechanism.

Migration verifies a complete table before serving it. A present but unreadable
table never falls back to an old connection secret. Writes require an exact
read-back before a durable success response. If a write cannot be verified,
callers restore and verify their previous snapshot. A failed compensation disables
that master's pairings for the boot rather than serving uncertain authority.
A physically approved USB backup restore can recover a quarantined table: it
first writes and verifies an empty table, then loads the sanitised backup. If a
later restore step fails, that empty baseline remains; the corrupt table is not
reinstated and an older connection secret cannot reappear through fallback.

The 64 KiB parser cap is an allocation bound, not a storage promise. Actual
capacity depends on the board's NVS partition and other stored data. Storage
exhaustion fails explicitly; it cannot silently approve or evict a device.
Migration can need additional NVS space, so test retained-state upgrades on the
actual board. NVS is assumed atomic for one key; multi-master backup replacement
is not a power-loss-atomic transaction.

Backup import preserves pairings but deliberately strips signing permission and
all persona consent, including inherited bound consent. The owner must renew
those permissions after restoring. An old backup cannot reinstate a previously
withdrawn persona grant merely by being imported.

## Downgrade

Old firmware sees no automatic methods, kinds or persona consent in a new-format
slot. Its typed writer drops the extension. Re-upgrading from that projection
keeps the restrictive state and requires renewed consent; it never reconstructs
new authority from a display label. The format does not protect against restoring
historical firmware together with historical flash contents.

## Release evidence

Host tests cover shared A/B/C pairing isolation, A → B → A, persistence, targeted
and pairing-wide withdrawal, full capacity, malformed state, migration failures,
write/read-back faults, compensation and pending-approval epochs. The host
storage harness compiles the actual firmware policy module and mocks NVS I/O.
It does not simulate ESP-IDF power-loss behaviour or prove hardware acceptance.

Sapwood has transport, component and browser tests for scoped withdrawal,
versioned USB acknowledgements, stale connection context and mobile layout.
Physical acceptance still needs the named board, installed revision, watched
prompt outcomes, signer reboot and reconnect, and the real app routes. Keep
payment/settlement acceptance and any unconfigured My Signet hardware route
separate from those results.
