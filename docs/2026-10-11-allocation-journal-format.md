# Allocation journal v1: private format and read-only inventory

This change freezes and implements the private byte formats, at-rest protection,
and read-only inventory checks. It does **not** implement journal writes,
enrolment, fresh witness reconciliation, signing, allocation entropy/KDF, or child release.
Local inspection now derives and checks the descriptor writer and verifies every
stored witness signature with the shared strict receipt codec. Inventory has no
runtime caller; boot exercises the crypto backend. A local inventory still requires a fresh,
strictly verified witness read before any authority decision. Production MLS stays
disabled. These boundaries are part of this construction, not optional follow-up.

## Namespace and authority

One normalized root owns one global allocation history. The subject and writer
are derived by the already reviewed allocation-writer namespace contract; master
slot, PIN, device, browser, expiry and witness choice never create another history.
The future single physical owner must retain `HeldAllocationRoot` and recheck it
before and after each authority decision. Separately opened NVS handles are not
excluded by that borrow. No browser/relay argument may select the signer root.

NVS namespace is `a` followed by lowercase hex of the first seven bytes of
HMAC-SHA256(root, `"HW allocation local namespace v1\0"`) (15 ASCII characters).
It does not disclose a witness subject prefix. The full encrypted authenticated
subject and genesis issuer in the anchor must match the held root-derived subject
and actual issuer; a prefix collision is HOLD, never replacement. Keys are `anchor`, `snap0`,
`snap1`, and `m01` through `m32`. The scanner must inspect all 32 positions and
reject unknown keys in this namespace; the read-only NVS adapter enumerates
all keys, distinguishes absence from read failure, and preserves exact widths.

Missing anchor or both snapshots is HOLD, including a restored root. A lone
valid snapshot is a distinct reconciliation-only report, never an acceptance. There is no
constructor that initializes absent storage. First enrolment will require an
explicit physical ceremony plus authenticated keeper enrolment of this subject,
per-subject installation, writer and exact genesis digest, independently pinned
witness and canonical route, and an authenticated **external** recovery anchor.
The ceremony/backup implementation is not supplied here; until it is reviewed,
new enrolment is unavailable. Total local loss cannot be repaired from local
metadata or by trusting a reset witness. A different witness or root-mode alias
with a different actual issuer requires a separate witnessed physical recovery
procedure; v1 refuses it and never resets the history. Retirement cannot re-enrol.

The canonical witness route for this format is the version-1 authenticated Link
node route: byte `1` followed by the pinned witness Ed25519 node key (33 bytes).
The service and read/advance paths are the fixed allocation-witness routes, not
an arbitrary URL. Route hash is SHA-256(`"HW allocation route v1\0" || route`).

## Canonical bytes

All integers are unsigned big-endian. All layouts have exact fixed widths, no
optional fields, trailing bytes, strings, or host-width integers. `||` means
concatenation. Every domain below includes the displayed final NUL. All hashes
are SHA-256. Key derivation uses HMAC-SHA256. All three stored object kinds are
AEAD sealed, with constant-time tag verification by the pinned cipher crate.

Descriptor (229 bytes): `"HWAD"(4) || version=1(1) || subject32 || writer32 ||
genesis_actual_issuer32 || installation32 || witness_key32 || route_hash32 ||
schema_hash32`. Each identity/hash is nonzero.
The derived writer seed must be nonzero before key construction, and the writer
must differ from the witness. A valid self-signature cannot satisfy that boundary.
The schema hash is SHA-256(`"HW allocation journal schema v1\0"`). The route hash must recompute.
`pins_hash = SHA-256("HW allocation pins v1\0" || descriptor)`.

Anchor plaintext (431 bytes): `descriptor229 || genesis_digest32 || genesis_receipt170`. The genesis digest must equal the empty state digest defined below. The
receipt is stored in the existing strict VMLS 170-byte wire format. This codec
uses the pinned public no_std VMLS strict verifier to check its historical
signature and exact bindings. It cannot establish challenge freshness or
independent enrolment authority. Neither an anchor nor a snapshot is an authority
token. The future owner must also use that shared strict verifier for fresh
receipts; `ed25519-compact` is not eligible for either check.

Manifest plaintext (278 bytes): `"HWAM"4 || version=1 || ordinal:u8 ||
actual_issuer32 || salt32 || R32 || target_device32 || browser_installation32 ||
bootstrap_operation32 || bootstrap_challenge32 || schema_hash32 ||
requested_at:u64 || deadline:u64`. Ordinals are 1..32; all 32-byte fields are
nonzero; schema must match; requested_at < deadline. Times are immutable and
expiry never removes or reuses a record. The codec checks shape only, not physical
entropy quality, curve validity, KDF correctness or device authorisation.
`allocation_id = SHA-256("HW allocation manifest v1\0" || pins_hash || plaintext)`.

Sealed manifest (356 bytes): `"HWAE"4 || version=1 || ordinal:u8 ||
allocation_id32 || nonce24 || ciphertext278 || tag16`. Use full-round
XChaCha20Poly1305 from exactly `chacha20poly1305=0.10.1`, default features off,
in-place detached tag. Key is HMAC-SHA256(normalized root,
`"HW allocation manifest key v1\0" || pins_hash`). AAD is
`"HW allocation manifest aad v1\0" || pins_hash || header62`, where header62 is
everything before ciphertext. A future writer must supply a fresh independent
192-bit nonce for each newly sealed plaintext, reject zero, and keep the exact
sealed bytes for retry. This codec consumes no entropy and does not bless a
caller-provided nonce as fresh. Decryption rechecks canonical plaintext,
ordinal/schema and allocation_id before returning any plaintext. Every manifest
actual issuer must equal the descriptor genesis issuer in v1. Sealing with
deterministic injected nonces exists only under cfg(test); production is read-only.

Anchor and snapshot AEAD keys are separately derived as HMAC-SHA256(root,
`"HW allocation anchor key v1\0"`) and HMAC-SHA256(root,
`"HW allocation snapshot key v1\0" || pins_hash`). Sealed anchor (476 bytes) is
`"HWAC"4 || version=1 || nonce24 || ciphertext431 || tag16`. Its AAD is
`"HW allocation anchor aad v1\0" || held_subject32 || held_actual_issuer32 || header29`.
Sealed snapshot (498 bytes) is `"HWSC"4 || version=1 || physical_slot:u8 || nonce24 ||
ciphertext452 || tag16`. Its AAD is
`"HW allocation snapshot aad v1\0" || pins_hash32 || header30`. Slot is 0 or 1,
checked against the actual key position before decryption. Each stored object
requires a fresh nonce, with test-only deterministic sealing. Keys/owned plaintext
buffers are Zeroizing; no Clone/Debug/export on secret-bearing objects. Normal
Drop is not a reset/power-loss wipe claim or proof of wiping cipher internals.

The namespace's opaque local pseudonym, key positions, number of retained
records, fixed object lengths, nonces and sealed manifest allocation IDs remain
readable on unencrypted flash. Stable local pseudonyms permit correlation between
physical copies. Anchor/snapshot identities, witness pins, receipts, digests and
lifecycle are encrypted, as are all full manifest fields. Witness traffic still
reveals the previously documented stable writer/subject, sequence, commitment,
challenge, timing and volume to the witness/courier. No plaintext fields are logged.
This encryption depends on root secrecy. Legacy plaintext master storage exposes
the key needed to open this journal to a physical flash reader. Before a future
writer can create/store real allocations, it must require the existing strict
all-slots data-key-encrypted master invariant; plaintext legacy roots remain
ineligible for that writer. Read-only fixture/inventory code does not establish
physical flash confidentiality or enable a writer for such a root.

State is `count:u8 || record_set_hash32 || lifecycle32`. Lifecycle per ordinal is
0=unused, 1=live, 2=abandoned, 3=retired; entries below count must be 1..3 and all
others zero. The record-set hash is SHA-256(`"HW allocation record set v1\0" ||
pins_hash || count || (ordinal:u8 || allocation_id32)*count`) in ordinal order.
The witnessed digest is SHA-256(`"HW allocation state v1\0" || pins_hash || state`).
Every full manifest remains, including abandoned/retired/expired/uncertain ones.

Snapshot plaintext (452 bytes): `"HWAS"4 || version=1 || phase:u8 || generation:u64 ||
predecessor_hash32 || pins_hash32 || active_seq:u64 || active_digest32 ||
active_receipt170 || active_state65 || candidate_state65 || pending_kind:u8 ||
pending_ordinal:u8 || candidate_digest32`. Generation starts at 1,
never wraps, predecessor is zero only for generation 1. Sequence is at most
VMLS MAX_SAFE_INTEGER. Phase 0 is committed: candidate_state/kind/ordinal/digest
all zero; active_digest recomputes. Phase 1 is pending: seq below the maximum,
candidate digest recomputes. Kind 1 appends exactly the next live ordinal;
kind 2 abandons exactly one live ordinal; kind 3 retires exactly one live ordinal.
Kinds 2/3 keep the same count and immutable set hash and change no other lifecycle
byte. Terminal entries cannot return live or be erased. Generation's predecessor
is SHA-256(`"HW allocation snapshot v1\0" || previous_physical_slot:u8 ||
previous_complete_sealed_snapshot498`). Generation 1 must be committed genesis: sequence0, exact empty state/digest,
active receipt byte-equal to the anchor genesis receipt, and zero candidate/pending
fields. Active sequence must be at least active count; empty state requires seq0.
For the anchor AND every snapshot, stored receipt structural rules are exact:
length170, version1, status Current=0, subject == descriptor.subject, seq ==
that object's active_seq (anchor/genesis 0), digest == that object's expected
active digest (anchor/genesis empty digest), nonzero challenge and signature.
The shared `vmls-core` codec additionally verifies each signature strictly under
the witness key in the authenticated local descriptor. The descriptor's writer
must equal the Ed25519 public key derived from the held root's writer seed.
These historical checks establish neither a fresh challenge nor independent
physical enrolment/pin authority. They never authorize allocation or release.

## Read-only inventory and crash ordering

Any read error, bad width/AEAD/schema, missing referenced manifest, duplicate
salt, R, bootstrap operation or bootstrap challenge, unknown key, invalid transition or inconsistent generations/chaining
is HOLD. There is no fallback around a present invalid snapshot. With two valid
snapshots require consecutive generations and exact predecessor, then validate
their transition: committed-to-pending retains the exact active state,
sequence, digest and receipt, introducing only the permitted candidate operation;
pending-to-committed sets active state/digest to the prior candidate, sequence to
prior active_seq+1, carries a structurally matching new receipt, and clears all
candidate/pending fields. In both directions generation must increase exactly by
one and the predecessor must equal the hash of the exact previous sealed frame.
No other adjacent phase transition is accepted. A lone valid slot
can only be described for fresh-witness reconciliation; it cannot release a child.
There must be at least one valid snapshot. Reports are
`PairedNeedsWitness`, `LoneNeedsWitness`, `OrphanNeedsWitness`, or HOLD; no report
is called valid, ready or authorised. All report variants explicitly leave the
fresh witness authority false, while identifying the derived writer and stored
signatures as checked. Both slots and the anchor must agree
on pins. The only production inventory entry is through `HeldAllocationRoot`,
with custody recheck before and after inspection and exact subject/issuer binding.
Before any future anchor creation/enrolment/request/receipt authority, strict
Dalek must derive the writer from the held root and match the descriptor exactly. The scanner opens and retains all contiguous immutable records (count <=32), not
merely the newest snapshot's references. At most one orphan is allowed, exactly
at active_state.count+1 after a committed snapshot; it is explicitly surfaced as an
orphan requiring exact-operation recovery. Conflicting/multiple orphans HOLD.
Pending snapshots require exactly their referenced records, with no extra orphan.

Future write ordering is mandatory: exact immutable manifest write/readback;
inactive pending snapshot write/readback; sign/forward the exact witness CAS;
strict fresh receipt; inactive committed snapshot write/readback; only then
encrypt/release child. Never overwrite the current authoritative snapshot or use
a mutable head key. The existing SDK set_blob wrapper erases before set; cuts after erase,
set/commit, and readback must be injected separately. Orphan recovery requires a
fresh witness read and the same operation/salt/R; it cannot generate a replacement.
Witness at exact active state allows exact retry; at exact candidate allows
promotion. Witness/local ahead, behind, unknown/retired, refusal, digest conflict,
unrecoverable record or ambiguous slots HOLD. Unexpected witness state never
authorizes deleting a manifest or silently selecting an older snapshot.

Two snapshots share one NVS partition/GC failure domain and do not prevent
rollback. The independent witness provides the fence; simultaneous signer and
witness rollback is outside this guarantee. Hardware cut acceptance is required
in addition to host tests before runtime use.

## Storage budget and runtime gate

The standard Heltec partition is 16 KiB (four 4096-byte pages); T-Display/legacy
layouts are 24 KiB. Neither layout changes here. ESP-IDF 5.3.2 pages have 126
32-byte entries, and a blob needs a blob index plus chunk metadata and payload
entries. These formats' **minimum**, single-chunk costs are anchor 17 entries,
each snapshot 18 entries, each record 14 entries, plus namespace 1: 54 fixed
entries + 14 per record. Keeping one whole GC page leaves at most 378 usable
entries on the 16 KiB partition. Thus 32 records need at least 502 entries,
exceeding the 378 entries available after preserving a GC page. The 32 ordinal limit is a
logical ceiling, never a fit promise. Even the arithmetic upper bound of 23
records ignores existing provisioned keys and fragmentation.

This implementation provides a lower-bound sizing diagnostic only. It is NOT a
capacity preflight and never permits entropy/signing based on NVS aggregate
stats. Before a runtime writer is added, measure the actual provisioned partition
and fragmented chunk/GC behavior on each board. Reserve enough space for the
new record plus pending and committed writes, including after witness success;
fail before fresh allocation entropy where possible. If a write fails after
witness success, keep pending HOLD and never release a child. Existing credentials
cannot be evicted, records cannot be truncated, and partition relocation cannot
be slipped into an OTA. The adapter/physical capacity proof is a separate gate,
not claimed complete by these formats or host tests.

Primary references: [RustCrypto 0.10.1 in-place AEAD and nonce requirements](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/),
[ESP-IDF 5.3.2 NVS](https://docs.espressif.com/projects/esp-idf/en/v5.3.2/esp32s3/api-reference/storage/nvs_flash.html),
and the locked esp-idf-svc 0.52.1 `set_blob` erase/set/commit implementation.
