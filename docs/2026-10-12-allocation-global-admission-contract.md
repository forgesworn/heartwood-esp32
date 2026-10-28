# Permanent global admission: owner and crash contract

Status: construction requirements for a later private allocator, extending the
[physical-owner contract](2026-10-12-allocation-physical-owner-contract.md).
This document selects the atomic ownership and operation order. It selects no
service, keys, protocol bytes, authority producer, migration or runtime caller.
Canonical scope, candidate, intent, proof, mirror, recovery and record-reservation
formats still require their own construction review and independent vectors.

The [actual SDK lifecycle/fullness campaign](2026-10-12-allocation-cold-lifecycle.md)
demonstrates that SDK no-space refusal can change flash metadata. Therefore an
SDK attempt followed by a capacity error cannot establish refusal before
mutation. Its journal-only eight-subject fixtures exclude the new catalog,
intent and recovery reserves and are not measurements of this construction.

## One owner for admission and the exact candidate

An independently authenticated external continuity allocator owns both the
global permanent subject budget and the exact full enrolment candidate in one
atomic decision. The local catalog is an authenticated mirror of those decisions;
it cannot admit a subject. A separate per-subject CAS followed by a local budget
check is forbidden: two restored signers could permanently reserve different
external candidates while only one local last slot succeeds.

The proposed policy is at most eight permanent distinct historical subjects per
allocation scope and at most 32 permanently charged allocation ordinals per
subject. These are logical ceilings, not measured flash capacity. A deployment
cannot raise them, silently lower an existing subject's retained requirements,
or reset its scope. Any changed profile requires a separate reviewed migration
that preserves every prior claim, manifest and uncertain operation.

One successful subject admission atomically:

1. Verifies authenticated scope provenance and the allocator's current,
   non-rollback continuity; verifies the physically authorized exact candidate.
2. Looks up the subject's permanent claim, including claims in other scopes.
   An exact existing claim is reconciled; another scope, issuer, installation,
   writer, candidate or retired/conflicting binding cannot be substituted.
3. If genuinely unclaimed, checks the scope's permanent count and uniqueness
   constraints, then permanently charges one slot and retains the recoverable
   exact candidate and its proof in the same durable transaction.
4. Makes that same exact claim queryable after a lost reply or restart. It never
   leaves a successful candidate reservation uncharged or a charge without its
   recoverable candidate. A definite exhausted/conflicting refusal changes no
   permanent claims, candidates or reservation records.

An existing exact retry does not consume a second slot, even when the scope is
full. Prepared, pending, interrupted genesis, completed and retired claims all
count. There is no release, expiry, eviction, cancellation, new-installation,
removed-master or reset transition back to unclaimed. The subject-wide permanent
claim prevents restoring the same root into a new scope to obtain first use.
Same-root aliases share it; another actual issuer holds under the existing v1
journal binding. Cross-scope/device migration is a separate procedure, not a
second admission or a changed field in an otherwise identical retry.

## Scope provenance, protection and continuity

A scope denotes one provisioned allocation history, not a host-selected string,
current master slot, browser installation or freshly generated identifier.
Its authority must bind the actual device lineage, exact installed partition
identity/layout and schema, fixed policy and pinned allocator identity. The
physical provisioning procedure and its recoverable evidence need separate
review. Software identifiers, MAC addresses or an SDK geometry read alone do
not attest that provenance. A cloned/restored signer must recover the same scope
and budget; a replacement device must use the reviewed recovery/migration path.
A fresh local installation or allocator database cannot create another budget.

The global allocator must authenticate every claim in the scope without using
another root's secrets or asking the browser to certify its history. It retains
recoverable exact candidate bytes and authenticates responses, queries, committed
scope revision and state commitment. A subject query must also bind the queried
subject and scope; a signed empty answer from a newly created/reset store is not
authenticated historical absence.

Allocator signing-key possession, a local database MAC, a sequence counter in
the same database, a backup of that database, and a fresh request challenge do
not establish anti-rollback continuity. A rolled-back store can sign fresh
answers. The construction must select a genuinely independent durable
continuity source and its restore protocol. Startup and every admission/query
must establish that the returned complete state is consistent with that source,
including commits whose replies/checkpoint acknowledgements were lost. The
source must not be reset or jointly restored with the allocator or signer.
Missing, behind, conflicting, unrecoverable or unverified continuity is HOLD,
not absence, a new epoch or an opportunity to retry under another key.

The construction must specify the actual commit/checkpoint order and failure
states; a boolean `healthy` supplied by a caller cannot replace this protocol.
If independent continuity knows a later committed claim but exact candidate
bytes are missing, hold rather than infer or regenerate them. If a complete
candidate was prepared but its commitment outcome is unknown, retain and
reconcile those exact bytes. A definite refusal must be distinguishable from
an unavailable/unknown outcome before any rollback or replacement is considered.
This service/source and protection protocol are currently unselected.

Pin/claim/mirror protection must survive reboot, PIN changes, factory reset,
master replacement and restoration without disabling existing PIN security.
Before unlocking, hold the allocation pool's competing mutations whenever the
required authentication is unavailable. Use a genuinely boot-readable protected
binding or wait for authenticated unlock; do not trust an opaque catalog hint.
Ordinary default-NVS boot activity is separate from this exclusive pool, cannot
consume its reserve and is not covered by a claim of allocation-operation
zero-mutation refusal. All adapters must enforce that separation.

## Exact operation order and cut states

This refines the physical-owner contract's external-before-local steps 1-2.
The external reservation is now the single atomic budget/candidate admission;
the later local capacity record is its mirror plus a separately measured
physical reserve. It is not another independent admission decision.

The device physically selects and freezes the same immutable operation,
root-derived subject/writer and issuer through existing held custody. Neither
root/data-key/SDK handles nor physical-approval authority span network waits.
Detach and reacquire/recheck the same selected master, approval and exact
operation as specified by the physical-owner contract. A new challenge or token
does not make a changed operation an exact retry.

| Durable/observed state | Only permitted next action |
| --- | --- |
| Scope/provenance or independent continuity unavailable | HOLD before allocation SDK acquisition or any new claim/intent/recovery mutation |
| Exact candidate frozen, no admission dispatch | Authenticated query, then conditional atomic admission of only that candidate under the fixed scope |
| Admission dispatched, result lost or unknown | Query that same subject/scope/candidate; do not classify it as refused, refund a slot, or submit replacement bytes |
| Definite exhausted/conflicting admission | Refuse with unchanged external permanent state and no allocation entropy, SDK acquisition/RW write, local intent/reserve, recovery-copy, keeper enrolment or witness advance |
| Exact external claim exists; local mirror/intent missing | Recover exact candidate/proof; reacquire physical approval of that operation; assess the independent physical reserve and perform only the reviewed no-erase local persistence |
| Local persistence is uncertain or mismatched | HOLD; retain the external charge; reconcile/read back exact records, with no external refund or new candidate |
| Exact claim, mirror, intent and physical reserve confirmed; recovery absent | Establish and confirm the independent recovery copy of the same intent and claim proof; no keeper enrolment yet |
| Recovery confirmed; keeper enrolment reply unknown | Repeat/reconcile only exact enrolment under that claim; require a fresh pinned witness read |
| Exact witness genesis and authorized local creation | Only the separately reviewed exact-intent creator may write anchor then generation-1 genesis; no inference from empty or anchor-only storage |
| Completed or retired history; master removed/replaced or local state lost | Preserve the claim and ordinals; recover that same history or HOLD; never free a slot or enrol the same root as new |

Queries and a conditional atomic admission request are allowed before local
mutation. On a race for the last slot, at most one distinct subject succeeds;
the losing transaction changes no permanent allocator state. A transport timeout
is an unknown outcome, not a successful refusal test. Definite refusal includes
the complete allocator state, not just the subject table. Retried existing
operations may reconcile already retained state and are not new slot admissions.

Do not acquire the present `hwalloc` owner to discover that admission is full:
its initialization can recover/write SDK metadata before it reads NVS. Obtain
the authenticated external decision first. An NVS-only catalog requiring SDK
initialization cannot implement this preflight. A different local preflight
needs separate review of a truly non-mutating raw/boot read and its protection.

## Permanent ordinal and physical reserves

Record admission must bind one exact physically authorized operation and its
subject/ordinal permanently before fresh allocation salt/scalar entropy and
journal mutation. Its protocol and bytes require their own construction review.
An orphan manifest or unknown append consumes that ordinal even when the latest
active snapshot has not advanced. Neither active ordinal alone, missing local
keys nor retirement can determine unused ordinals or authorize a replacement.
An exact reserved retry must recover its exact manifest/prepared randomness
through reviewed durable intent/recovery; it must not generate fresh R or salt.
If those bytes were never safely prepared/recoverable, HOLD that charged ordinal
instead of granting a replacement. Charging an operation is not authority to
derive or release a child.

The ordinal32 ceiling refuses a new ordinal33; it cannot prevent reconciliation
or retirement of the existing records. Those operations need a separately
protected lifecycle/promotion budget. Unknown witness advance, pending snapshots
and orphan reconstruction retain that budget until exact recovery. No unbounded
replacement attempts, transient-error retries or SDK free-entry statistic can
stand in for this physical budget.

Before local persistence, the exclusive pool must be measured with all catalog,
intent, recovery metadata, namespace/anchor/genesis, eight permanent histories,
both snapshot slots, fragmented blob/GC costs and uncertain write outcomes.
Account for every pool writer and boot path. The default-partition dormant
writer cannot become a dedicated writer by changing `partition == "nvs"` to
a different string. Fixed-identity creator/reader/writer adapters, reset policy,
installed-layout migration and physical measurements require separate review.
Never insert a catalog/intent key into the strict journal namespace or erase
another credential/history to fund a new operation.

## Privacy and trust boundary

Atomic global admission necessarily lets its selected authority associate the
scope's permanent claims. It must see enough authenticated claim information to
enforce the global budget and exact retries. It never receives a root, root data
key, writer seed, allocation scalar, child scalar or unrelated account content.
Recoverable candidate storage needs reviewed confidentiality and access control;
an opaque hash alone cannot support the required exact recovery.

Scope/device/subject linkage, issuer/writer and witness bindings, operation
timing and volume, routing destinations and denial behavior remain metadata.
Transport encryption or an own node does not remove this disclosure. The owner
must select the keeper/allocator, route, minimal retained fields and logging
policy deliberately; no telemetry, broad discovery or raw identity/request
logging is enabled by this contract. Proofs expose only the bindings needed by
the actual signer/recovery owner, not other subjects' private candidate bytes.
A global state commitment/count is not permission to enumerate peer identities.

## Acceptance before authority producers

1. Review canonical scope/candidate/proof/intent/mirror/ordinal/recovery bytes,
   signing/authentication, continuity checkpoint protocol and privacy policy.
   Prove fresh response challenges cannot conceal state rollback, that complete
   candidate bytes are recoverable, and that resets/clone restores cannot
   manufacture absence or another scope. Independent vectors precede producers.
2. Implement the actual allocator's atomic store/continuity integration. Test
   all eight permanent claims; concurrent last-slot contenders; exact/conflicting
   retry; prepared/committed/lost-reply/checkpoint cuts; boot/restore/rollback;
   subject claims across scopes; issuer aliases; removed/retired history; charged
   orphan/unknown ordinals and ordinal33. Preserve full pre/post state evidence.
3. Integrate the actual private signer controller. Definite ninth-subject and
   ordinal33 refusal must show zero allocation entropy requests, zero allocation
   SDK initialization/RW/set/commit/erase, zero new local mirror/intent/reserve or
   independent recovery-copy mutations, zero keeper enrolment/advance dispatches,
   unchanged external permanent reservations and byte-identical retained pool.
   Authenticated queries/conditional requests are permitted; helper-only or
   caller-side limit tests cannot close this actual-controller gate.
4. Measure the complete pool with the pinned actual SDK under full/fragmented/
   GC/write/reboot cuts, then with an identified physical device and verified
   installed geometry, independent backups, migration and recovery procedure.
   Confirm program/erase behavior, RAM/timing/watchdog and reset retention.
   Synthetic fixtures, signatures, logical ceilings and build success do not
   establish any of those physical guarantees.

The authenticated time source, fresh-R entropy/KDF integration, purpose-only
child delivery, browser witnessed custody, live admission, membership/retirement
and P7 production/physical gates remain separate. This contract grants no
first-use, capacity, witness freshness, child-release or production authority.
