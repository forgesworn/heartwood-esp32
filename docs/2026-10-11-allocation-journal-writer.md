# Allocation journal writer construction

This construction implements the existing frozen journal format's durable
mutation and fresh-reconciliation component inside the held-root boundary.
It is not a first-enrolment ceremony, physical selected-master owner, capacity
certificate producer, R/KDF construction, child release, or browser genesis.
Those remain required before runtime activation. Missing storage never becomes
first use. No production caller or physical flash is introduced by this work.

## Inputs and ownership

A private synchronous controller owns the held root by value while inspecting,
staging, signing or accepting a response. It retains a nonblocking global
single-writer guard, the root's data-key guard and exact selected master/issuer. It refuses plaintext legacy master storage: all counted
seeds must authenticate under the held data key, with no plaintext shadows.
Custody is rechecked before and after every storage or witness decision.
There is no await/callback or network I/O while the root is held, and no
raw-seed constructor, generic byte signer, generic key/blob writer or public root
export. The controller is consumed to detach a private nominal context or
prepared attempt. Its held root and every SDK handle are dropped before returning.
The detached value contains no root, seed, plaintext manifest, salt or R. It
retains only the nonsecret global journal guard, independent enrolled pins and
capacity input, exact inventory fingerprint/generation/operation binding, and
bounded one-use exchange expectation/envelope when a request has been prepared.
It is not Clone, Debug, serializable or reconstructible from caller bytes.

The eventual physical owner fetches a courier token and performs transport only
while holding that detached value. Transport pumps the watchdog and bounds its
wait; cancellation, logout, lock, shutdown or timeout drops/invalidate the attempt.
Unrelated commands can run with no data-key/NVS/master borrow held. Another
journal controller receives Busy while the nonsecret global guard is retained.
Before signing or accepting, reacquire the physically selected master as a new
HeldAllocationRoot and revalidate encrypted custody, root namespace, actual
issuer, enrolled descriptor/genesis, complete inventory fingerprint, exact latest
sealed predecessor/generation and immutable operation, and monotonic deadline.
A changed selection, local mutation or late reply cannot be accepted. Reboot
loses every detached value and expectation; recovery always starts a fresh read.
The nonsecret journal guard is transferred back to the synchronous controller,
not reacquired recursively. No root/data-key lock spans network transport.

Opening requires independently enrolled pins and measured storage capacity.
These are private nominal inputs, not browser booleans or values recovered from
the local descriptor alone. Their runtime producers do not exist yet. No
production constructor from an unauthenticated caller is added. Synthetic test
constructors prove component behavior only and cannot satisfy physical gates.
The controller matches the external enrolled descriptor/genesis anchor against
the root-bound, strictly verified local anchor before opening a writable handle.
It never writes an anchor or creates a replacement history.

It reads all existing keys through the fallible SDK adapter twice and compares
complete bytes, then applies the strict codec to the entire inventory. No
unknown key, bad present frame, missing referenced record, manifest gap,
duplicate burned value or invalid chain is ignored. Before each mutation or
forwarded operation, it re-reads and requires byte equality with the held
inventory. Independent handles, partition erasure and ABA cannot be excluded
by that comparison: the eventual physical owner must serialize every competing
partition writer. A global journal guard only excludes this controller's own
concurrent instances. Fresh witness CAS fences competing restored signers.

SDK read-write open may create an empty namespace if an outside partition
writer removes it between the read-only check and open. The controller rechecks
the inventory on the writable handle and holds before writing any history. It
does not erase that empty namespace as cleanup. Runtime exclusion of that race
is a physical-owner gate; no atomic-open-existing claim is made.

## Storage behavior

Use raw `nvs_set_blob`, checked `nvs_commit`, exact-width readback and complete
inventory revalidation. Do not use esp-idf-svc's erase-before-set wrapper and do
not explicitly erase any journal key. ESP-IDF 5.3.2 writes in set_blob; commit
is currently a valid-handle no-op. The fault model therefore applies successful
sets immediately, including when the subsequent commit/readback fails. It must
also represent uncertain failed writes as old, new, missing or corrupt target
bytes; no successful commit is invented as a transaction boundary.

Every write failure poisons this controller instance: no follow-on signing,
write, repair or child release. Reopen performs a new full scan and fresh
witness read; it never chooses an older slot around a present invalid frame.
A missing slot is distinct and reconciliation-only. The current snapshot,
anchor and all previous manifests remain untouched by each attempted mutation.

A new append or lifecycle mutation requires a fresh Current read matching the
exact held active sequence/digest before any new mutation entropy or persistence.
That one-use grant is bound to the exact inventory and monotonic deadline; it
cannot be copied, reused for a second mutation or extended by accepting a reply.
A typed authorised manifest must come from the separately reviewed physical
owner/R-KDF/time boundary; no raw caller-plaintext constructor is introduced.

An append freezes that typed full manifest into one exact AEAD frame, checks all
permanent burned fields, writes the next absent ordinal and reads it back,
then writes the inactive pending snapshot and reads it back. If that ordinal
already exists, only the exact same sealed bytes may be used for recovery;
there is no manifest overwrite. The pending frame retains the active state,
sequence, digest and historical receipt exactly and binds its predecessor to
the latest complete sealed snapshot. Generation/sequence overflow holds.
Abandon/retire stages preserve every record and change one live lifecycle only.

Snapshots are constructed from the held validated state, never accepted as
caller-supplied replacement frames. Only the inactive slot is written. The
candidate and all immutable bytes are revalidated before an advance request can
be formed. There is no mutable head key, deletion, terminal reclaim or expiry
reuse. Observed orphan recovery uses the same exact full manifest and operation;
it cannot mint new salt, R or target/browser/bootstrap bindings. With committed
local state and exactly one validated orphan, compute the exact append candidate
from that same permanent manifest and full current record set. Fresh Current at
exact active state permits reconstructing/readback of its exact inactive pending
snapshot, followed by the ordinary exact CAS flow. Fresh Current at exactly
active_seq+1/exact orphan candidate digest permits reconstructing/readback of
that exact pending predecessor first, then writing/readback of the committed
snapshot using the fresh Current receipt. It sends no new CAS in that case.
Every other ahead/digest state holds. Reconstruction consumes fresh storage
nonces only; it does not regenerate allocation salt, R or operation bindings.

The boot-monotonic timer bounds only in-memory exchanges and grants, never
immutable requested_at/deadline or durable expiry. Manifest times are bound
fields with provenance from a future nominal authenticated owner/time source;
there is no such producer yet, and uptime is not substituted for it. No future
one-use allocation result can be consumed unless requested_at/deadline validity
and a fresh authenticated current time are established and it has not expired.
Historical already-advanced state may still be promoted solely to reconcile,
then held or explicitly abandoned; expiry never releases a child, erases a
manifest or authorises a replacement allocation.

Nonce and witness-challenge generation uses the firmware's verified strong
entropy path inside the controller; production accepts no injected nonce or
challenge. Failure, zero output or observed reuse holds. Exact sealed bytes are
retained for uncertain-write/retry recovery. Existing ciphertext nonces and
issued challenges are checked for observed collisions. Tests inject hardware
entropy/time only through cfg(test), not a production callback. This does not
prove physical entropy quality or absence of every historical nonce collision.
R/salt generation and KDF correctness remain a separate owner gate: the writer
cannot turn a shape-valid manifest into proof of authorised child derivation.

The measured capacity input must bind this provisioned partition and operation
budget, preserving GC space and enough room for manifest, pending and committed
writes even after witness success. Aggregate NVS statistics or the format's
minimum-entry arithmetic never create that input. No credentials are evicted,
records truncated, partition relocated or capacity guessed. The runtime capacity
producer and fragmented/full-partition physical proof remain unavailable.

## Fresh witness reconciliation

Each read/advance request owns a new nonzero challenge and bounded monotonic
lifetime. Starting another request invalidates the old in-flight expectation;
responses are one-use and late, repeated or mismatched responses hold. The
controller signs only its exact typed read or held pending CAS under the
root-derived writer, using the shared canonical forwarding envelope, a new
courier token, and the externally pinned witness domain. Live challenge/token
history is capped at 64 exchanges before further entropy or signing; observed
tokens are retained only as domain-separated hashes. No manifest, salt,
R or child bytes leave in that envelope. A token authenticates no witness.

Only a strict shared-codec receipt under the externally enrolled witness key,
with exact request challenge, subject, status and allowed sequence/digest can
change controller state. A read returning Current at the exact active state
permits exact retry/staging as appropriate. For pending state, or the exact
reconstructible orphan case above, a read returning Current at exact
active_seq+1/candidate_digest permits promotion with the specified durable
pending predecessor. Every other state holds: ahead, behind, other digest, unknown, retired or refused. An
unmarked courier failure invalidates the exchange and retains pending state;
it cannot become an authoritative store reset or refusal. No unsigned response
provides state authority.

An advance succeeds only with a Current receipt at exact candidate position.
A Conflict receipt, even when it describes the candidate, cannot be stored in
a format requiring Current; retain pending and obtain a fresh read instead.
Lost reply retries use a new courier token, fresh receipt challenge and new
signature while retaining the same persisted operation, salt and R. There is
no replacement allocation or replay of an old signed envelope.

Promotion creates the inactive committed snapshot from the exact pending
candidate and fresh Current receipt, increments sequence/generation exactly,
binds the exact pending sealed predecessor, writes and reads back, and validates
the entire resulting inventory. Only then can a later reviewed owner consume a
bounded one-use result. This component exposes no child, public release token
or admission authority. The owner must also recheck root and freshness and
complete the separate witnessed browser child/counter promotion before MLS use.

## Evidence and gates

Host tests execute the real firmware controller and raw SDK adapter with
synthetic preinstalled history, external pins and capacity fixtures. Cover all
adjacent operations, lone/orphan recovery, exact lost-reply retry, every raw
storage error, uncertain post-set bytes, receipt challenge/status/key/position
transposition, expiry/one-use, encrypted eligibility and custody drift.

Required remaining acceptance: independent source review; standard full host
and both curve suites; actual per-board firmware build/image budgets; physical
SDK cut/GC/capacity and boot timing/stack checks; actual selected-master owner;
physical enrolment/external recovery anchor; fresh R/KDF/child and browser
counter genesis; live keeper/admission/recovery/P7/production acceptance.

Primary SDK source: [ESP-IDF 5.3.2 blob and commit API](https://github.com/espressif/esp-idf/blob/v5.3.2/components/nvs_flash/src/nvs_api.cpp),
[handle implementation](https://github.com/espressif/esp-idf/blob/v5.3.2/components/nvs_flash/src/nvs_handle_simple.cpp).
