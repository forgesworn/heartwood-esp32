# Physical allocation owner: construction and acceptance contract

Status: design prerequisites for a later private owner. This document adds no
runtime caller, command, enrolment endpoint, storage format or authority producer.
The dormant writer at Heartwood main
`b807e1995fe0ad2201e91f5833f55966ddd319c4` is independently reviewed and its
candidate and main CI passed all 14 jobs. Its synthetic pins, capacity and
manifest fixtures do not establish the authorities described here.

The [journal writer](2026-10-11-allocation-journal-writer.md),
[journal format](2026-10-11-allocation-journal-format.md) and
[root custody](2026-10-11-allocation-root-custody.md) remain binding. New intent,
recovery, capacity and time bytes require separate construction review and
independent vectors before code can mint their nominal inputs. This contract
specifies ownership, order, refusals and acceptance, not final bytes or an
approved installation, time or recovery service.

## Actual owner and selected master

One firmware command coordinator owns the ceremony. The device physically
selects the actual unlocked master; a host slot number, browser account or relay
request cannot select it. Display the actual served issuer and proposed operation
on the device and require deliberate physical approval. Root normalization,
persisted slot/mode/version/issuer and the all-slots authenticated encrypted
master invariant are checked through the existing private custody boundary.
Ambiguous legacy metadata or plaintext master storage holds.

The approval binds an immutable operation, selected issuer and root namespace,
target device, browser installation, bootstrap operation/challenge and requested
lifetime. Each binding's authority and exact encoding still need review. A host
can propose a target, but cannot certify device ownership, first use, witness
identity or authenticated time. Cancellation, master replacement/removal,
logout, lock, shutdown, changed request or elapsed approval invalidates the
volatile approval. Resumption requires a new physical approval of the same
persisted operation; it cannot silently make a replacement allocation.

Root-mode aliases share the deterministic writer/subject and local namespace.
They do not make existing history portable to another actual issuer. In v1 the
anchor's AEAD associated data contains the exact issuer and each manifest must
match the genesis issuer. A same-root alias with another issuer holds. Never
reset the namespace, weaken issuer checks, switch witness or re-enrol to bypass
this refusal. Cross-issuer use needs a separately reviewed versioned physical
migration retaining all permanent records and pending operations.

Keep a root/data-key/SDK handle only during synchronous validation, persistence,
request preparation or response acceptance. Both courier-token fetch and signed
transport happen after consuming/detaching that held owner. Detach retains only
the reviewed nonsecret guard and exact opaque bindings. Network waits pump the
watchdog and have a bounded cancellation/deadline path. Reacquire the same
physical selection and recheck custody, external pins, capacity, complete
inventory and exact operation before either signing or accepting. No borrowed
master or data-key guard spans transport. The existing 64-exchange bound remains;
reopening is fresh reconciliation, not renewal of physical approval.

## First enrolment and external continuity

A deterministic subject identifies a history; it does not prove that history
never existed. Missing local storage, an empty/refused witness, a restore, a new
PIN, a new installation or a reset witness cannot establish first use. Existing
forwarding read/advance routes do not enrol subjects. A Link pairing capability
or an authenticated courier is not keeper authority for an allocation writer.

An independently authenticated keeper/continuity authority must atomically
reserve one exact full enrolment candidate for the subject. This is a permanent
one-candidate CAS, not an initial “first use” boolean or approval naming only
subject/issuer. The candidate binds the root-derived subject/writer, actual
issuer, pinned witness/route, installation, schema, genesis digest and immutable
physically approved operation. Its canonical digest excludes the later
reservation receipt; the local intent contains both the exact candidate and the
authenticated receipt bound to that digest. Final bytes remain a separate review.

The external authority keeps recoverable exact candidate bytes, not only an
unrecoverable hash, and permits only absent -> exact pending -> exact completed
or retired. An exact retry returns the same candidate/proof; another candidate
for a reserved/used/retired subject is refused. The pending reservation is
permanent: no expiry, eviction, cancellation or reset releases it. Receipt/proof
binds the exact candidate, authority identity and reviewed continuity state and
must be authenticated in both the local intent and independent recovery copy.
These transitions require durable atomicity, authenticated queries and their own
crash/concurrency tests before runtime.

The authority's used/retired records and provenance of genuine absence must
survive signer loss and witness-store reset. An empty newly created continuity
store is not evidence of absence either. Neither a new witness signature nor
two empty stores supplies first-use authority. This source/service and its
anti-rollback/restore protocol are currently unselected; absence means HOLD.
Restore is a distinct recovery procedure and cannot call the first-enrolment
creator. If a reserved candidate cannot be recovered exactly, that subject
permanently holds rather than receiving another decision or installation.

The ceremony must freeze the root-derived subject/writer, actual genesis issuer,
canonical pinned Link witness node/route, journal schema, a unique per-subject
installation, descriptor and computed empty-state digest. Installation generation
and its authenticated keeper hand-off need their own reviewed specification.
If signer-generated, use the verified strong entropy path, reject failure/zero,
persist once, and never regenerate on retry. Store installation uniqueness is an
additional check, not proof of first use. No browser supplies replacement pins.

The new immutable intent is root-bound and authenticated, retains exact bytes,
and cannot be reconstructed from mutable display labels or host assertions. It
must be written/read back before any keeper enrolment dispatch. Its separate
storage layout, entropy/nonce rules, capacity budget and cut behavior remain
unimplemented. Do not add an intent key to the current allocation namespace:
the frozen scanner accepts only anchor, snapshots and permanent manifests.

Before keeper enrolment dispatch, establish an independently authenticated
recovery copy of the exact intent/pins and exact-candidate reservation proof. A local second
namespace, another file on the same signer, a browser-local cache or a live witness
alone is not this recovery copy. Select and review its custody, confidentiality,
anti-rollback/continuity and physical confirmation procedure. Transfer only
necessary recovery data; never export a root, writer seed or child scalar.

| Durable situation | Only permitted next action |
| --- | --- |
| No local intent and no authenticated exact-candidate reservation | Query the independent continuity authority; no keeper enrolment or inferred first use |
| Candidate prepared, external reservation not dispatched | Revalidate physical approval and continuity; reserve only the exact approved candidate or cancel before dispatch |
| External reservation dispatched/unknown, local intent absent | Authenticated query by the deterministic subject; recover and physically approve the exact reserved bytes/proof before writing; if unavailable HOLD, never submit another candidate |
| Exact reservation confirmed, cut before local intent readback | Recover its exact candidate/proof; resume only its reviewed no-erase local intent write, with full inventory/custody checks |
| Valid exact intent, recovery not confirmed | Establish the same external recovery copy and reservation proof; no keeper enrolment dispatch |
| Intent and recovery confirmed, enrolment reply lost or unknown | Reconcile/repeat only that exact keeper enrolment under the original exact-candidate reservation, then perform a fresh pinned witness read |
| Witness Current at sequence 0 and exact intent genesis | A separately reviewed creator may finish only that intent's local genesis |
| Witness ahead with missing local history | HOLD for recovery of the exact retained manifests/snapshots; a digest cannot reconstruct them |
| Changed installation, issuer, writer, witness, schema, conflicting or retired subject | HOLD; no replacement intent, reset or new genesis |
| Corrupt present intent/anchor/snapshot or uncertain write | HOLD; no skip, erase, older-state fallback or automatic repair |

Bothy `WitnessStore::enrol` repeats the same installation, active writer and
genesis even after the subject advances. Its returned state is not necessarily
sequence zero and is not a fresh signed read. Retrying keeper enrolment must
never restore a missing subject in an empty/reset store: independent continuity
must still prove the same permanent reserved candidate is the permitted
interrupted first operation; an empty/reset continuity authority holds. This
requires a separately reviewed keeper control path; do not expose a generic
courier enrol endpoint or treat a CLI acknowledgement as receipt authority.

The local first-creation order is:

1. Hold the physically approved root; freeze the exact candidate. Detach before
   querying/reserving it with the independent continuity authority. No keeper
   enrolment can be dispatched yet. If an exact reservation already exists,
   recover those bytes/proof and require physical approval of that same operation.
   A conflicting proposal cannot replace the reserved candidate.
2. Reacquire/recheck the exact root, issuer, proposal and authenticated reservation
   proof; persist/read back the root-bound intent and durable capacity reservation.
   A cut after external reservation but before local write recovers exactly that
   candidate/proof, or permanently holds if it cannot be recovered.
3. Establish and confirm the independent recovery copy of that exact intent and
   reservation proof. A cut here resumes only the same copy; no keeper enrolment
   is sent before confirmation. If a cut occurred before any external reservation
   dispatch, no first-use authority was created; revalidate approval/continuity
   before reserving a candidate. Unknown dispatch always requires a query.
4. Drop root/data-key/SDK handles; perform the authorised exact keeper enrolment
   and fresh witness query with newly generated token/challenge as applicable.
   A lost reply retains the intent/reservation and reconciles only that operation.
5. Reacquire the exact root/issuer and intent; strictly verify the pinned
   witness's HTTP 200 Current receipt, fresh one-use challenge, subject,
   sequence 0 and exact genesis digest. A late or conflicting reply holds.
6. Through a separately reviewed no-erase creator, persist/read back the exact
   anchor, then one committed generation-1 genesis snapshot. Full scans and
   custody rechecks surround every step. Retain frozen ciphertext for retry.
7. Confirm the exact local history and update the independently recoverable
   completion record and exact external reservation through their reviewed
   crash-safe protocols. Completion does not authorize child release or browser
   counter zero. No cut can return the subject to absent or admit another candidate.

The initial snapshot has sequence zero, generation one, zero predecessor and
empty state; its receipt bytes equal the anchor genesis receipt. The existing
codec classifies one snapshot as `LoneNeedsWitness`. Do not manufacture two
identical genesis slots or a committed-to-committed generation transition: the
v1 chain permits only committed-to-pending and pending-to-committed. The first
ordinary append follows a fresh exact-active read and the writer's normal chain.
A creator needs a narrowly reviewed exact-intent resume rule for anchor-only or
snapshot-only partial creation. Present mismatched/corrupt bytes always hold;
never borrow a general repair permission from this table.

Cancellation retains any durable intent and used installation, including an
unknown dispatch result. It does not delete tombstones or authorize another
first operation. Root restoration, total local loss, factory reset, PIN-wipe and
witness replacement are separate recovery/destruction boundaries. A wiped
signer must not enrol the same root as new. If independent history is absent,
continue HOLD; a fresh witness receipt cannot recreate lost manifest contents.

## Capacity before locked boot and after witness success

At the inspected main, default NVS opens before notes initialization, persisted
RNG proof, master/persona recovery and configuration writes; these precede the
PIN/vault gate. Multiple notes handles use the same default partition. A volatile
journal mutex excludes only controller instances and disappears on reboot. It
cannot reserve the space needed to promote a witness-advanced candidate after
locked startup has consumed capacity.

Choose and review one of these storage constructions before any runtime owner:

| Construction | Required guarantee |
| --- | --- |
| Existing default partition | A durable boot-visible reservation/floor is validated and enforced before every competing mutation, namespace creation, migration or recovery write, including locked-phase writes and all independent handles |
| Dedicated allocation partition | A reviewed on-device partition layout and migration preserves current partitions/history, supplies measured exclusive capacity, and is enforced by every allocator/creator/reader adapter |

Neither construction is selected or implemented here. The current writer checks
`partition == "nvs"`; a dedicated partition cannot be enabled by changing a
configuration string. It requires separate source review and migration evidence.
No automatic relocation, repartition, namespace deletion, credential eviction,
bearer-note removal or erasing NVS to make room is permitted.

A reservation must bind the actual partition identity/layout, provisioned history,
intent and operation, account for metadata/namespace and fragmented blob/GC
costs, and retain enough space for uncertain set outcomes and both orphan
reconstruction/promotion writes after witness success. It survives reset,
locked boot and other commands. It is not released after a transport timeout,
cancellation or an unanswered CAS. Recovery must account for physically missing
or corrupt targets without silently spending the promotion reserve elsewhere.

Boot can validate an authenticated reservation under its separately reviewed
boot-accessible protection, or conservatively hold all competing mutation until
unlock permits validation. Missing/invalid protection is not permission to
ignore an existing reservation. The exact reserve bytes, authentication/rollback
rules and PIN-attempt/destructive-wipe interactions require construction review;
do not disable PIN security or permit writes on the strength of an opaque hint.

`minimum_entries(n) = 54 + 14*n` is a lower bound, not a reservation. At 32
records it is 502 entries; the standard 16 KiB partition has at most 378 usable
entries before existing keys. The format's logical ceiling is not a fleet
capacity promise. Select a measured per-board record limit and reject exhausted
capacity before allocation salt/R entropy or any witness advance. Preserve all
terminal and expired records. Lifecycle operations also need their own complete
write budget; no permanent record can be reclaimed to extend the limit.

## Time and fresh allocation entropy

Choose a pinned authenticated time source and rollback policy before minting
immutable requested_at/deadline or a consumable result. Define key provenance,
canonical signed response, signer-owned challenge, issuer/operation binding,
bounded uncertainty/latency, units/ranges, clock rollback/restart and expiry
boundary. The current witness receipt contains no wall time. Boot-monotonic
30-second exchange deadlines protect volatile replies only. Browser timestamps,
host clock, uptime and unauthenticated network time cannot provide this authority.
When fresh current time is unavailable, reconciliation may retain/promote exact
history but cannot release a child. Expiry never erases or reuses an allocation.

The fresh-R/salt KDF is a separate versioned construction requiring independent
vectors and review: strong signer entropy, nonzero/valid scalar mapping, domain
separation, target/purpose binding, zeroizing ownership and exact recovery. Its
mathematical specification can proceed independently of physical-owner code.
The existing fixed-purpose indexed derivation cannot certify a fresh R.

Integrate the eventual manifest builder inside the held controller after its
fresh exact-active one-use Current grant. Only then generate new salt/R entropy,
validate authenticated time and freeze the full permanent manifest. A callable
external `AuthorisedManifest` constructor that generates salt/R before this grant
would violate the reviewed writer ordering. It must not be introduced by simply
making today's synthetic fixtures public. Authorised lifecycle decisions also
need the physical owner's exact ordinal and terminal-state approval.

## Release gates and evidence

Before runtime activation, require independent review of the exact source tree,
intent/recovery/capacity/time byte contracts and their authority producers;
independent canonical/hostile vectors; host cut/error tests of the actual owner
and creator; both curve suites; and actual per-board linked image/stack/watchdog
budgets. Current dormant image fit does not certify activation headroom.

Physical acceptance must identify the actual board/layout and approved issuer,
prove button selection/cancel/lock behavior, all enrolled/partial-creation cuts,
full/fragmented/GC and locked-reboot competition, retained promotion capacity
with witness ahead, lost enrolment/CAS replies, reset/refused/retired witness,
restored-root aliases, independent recovery and time rollback/expiry. Record
physical evidence separately from host/browser tests. Do not infer board identity
from a serial-port name.

After these gates, child delivery still requires purpose-only custody and a
separate witnessed browser transaction installing the legitimate child and
zero-counter ledger together. Existing-R global high water, keeper/private
admission authority, two-account ceremony, membership/recovery/P7 and production
acceptance remain separate. No Introduction or admission signature may use a
child before browser promotion. Production MLS stays disabled until its own
release gates pass.

Witness/courier exchanges expose stable writer/subject, commitments, sequence,
challenges, timing and volume. External continuity/recovery introduces its own
metadata and custody boundaries needing review. Never put full manifests, salt,
R, child, root, enrolment capabilities or recovery secrets into routine logs,
URLs, diagnostics or CI evidence. This contract makes no zero-metadata claim.
