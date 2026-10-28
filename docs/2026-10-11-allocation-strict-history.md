# Strict stored-history verification

The held-root journal path now derives the descriptor writer's Ed25519 public
key from the frozen HMAC writer-seed domain and rejects a different writer.
It refuses an all-zero writer seed before key construction and rejects a writer
equal to its witness, including cryptographically valid self-signed history.
It parses every anchor/snapshot witness receipt with the shared `vmls-core`
codec and strictly verifies its signature under the witness key in the
authenticated local descriptor. Status Current, exact subject/sequence/digest,
and nonzero challenge/signature remain mandatory. There is no fallback around
an invalid present receipt, snapshot or anchor.

The shared public core is pinned to reviewed commit
`e6985dd9583207853ffa9f5224b33e05d5094010`, with default features disabled.
The signing-key backend is `ed25519-dalek = 2.2.0`, with only its `zeroize`
feature requested. Its key/expanded-secret Drop handlers and the owned HMAC seed
buffer clear secret material. Temporary owned receipt fields are also cleared
on success and error. This does not promise erasure of every library stack copy.
The compact Ed25519 backend used elsewhere for OTA is not used for this path.
The source audit allows only this first-party Git source; both manifests and
locks pin the exact revision.

## Boot and error behavior

Boot performs a fixed known-answer check after board/display bring-up and before
NVS initialization, seed/persona loading, command processing or radio startup.
It checks RFC8032 writer-key derivation, an independently generated valid witness
receipt, challenge mismatch, a canonical order-two witness key and identity-R
signature refusal. Inputs are public synthetic constants; it reads no operational
root or journal and consumes no entropy. The actual shared verifier is linked
and exercised by normal firmware builds, so their image-size checks include it.
Compiler black boxes keep the known inputs from eliminating that path.

The result is cached for the boot. Failure displays `CRYPTO HOLD`,
`Preserve device`, `Recovery needed`; the shared boot-hold loop feeds the watchdog
every 100 ms. It performs no NVS initialization, automatic recovery, wipe, retry,
command processing or fallback verifier selection. Held-root inventory also
refuses a failed backend before opening journal storage.

`allocation-crypto-selfcheck-fail` is an opt-in bench-only fault feature in the
firmware and host harness. It deliberately produces the same permanent hold;
never enable it for a usable release. The host fault test executes the actual
held-root path and verifies no journal open or storage write occurs.

## Historical signatures are not fresh authority

The receipt's stored challenge is used only to authenticate its historical
signed bytes. It is not a fresh caller challenge. A local report explicitly says
`derived_writer_verified: true`, `stored_witness_signatures_verified: true`, and
`fresh_witness_authority: false`; it has no release/ready/authorised token.
Independent physical enrolment and external installation/witness pins are still
required: a locally sealed descriptor alone cannot establish those pins.
Read-only inspection remains dormant, and no real witness request is made.

Future allocation/recovery must use a newly generated challenge, the enrolled
witness pin, and exact subject/status/sequence/digest checks through the same
strict codec. It must reconcile permanent manifests and pending/committed state
before a child is released. Signer or witness reset, absent state and a root-mode
alias must never become permission to start a replacement history.

Host tests cover independent known answers, every receipt bit and truncation,
authenticated seals containing bad signatures, wrong writer binding, a forgery
accepted by the compact verifier but rejected by the actual anchor path, and
cryptographically valid receipts on invalid transitions. Full board builds,
image budgets, crypto-hold panel geometry and source review are required.
The local linked V4 app image is 2,071,424 bytes against its 2,097,152-byte slot,
leaving 25,728 bytes; the preceding main image was 1,999,664 bytes. This is a
measured local build, pending independent review and per-board hosted CI.
Physical boot timing, stack/IRAM behavior, fault-feature hold, journal capacity
and power-cut acceptance remain open. Linked image size does not establish those
physical properties or the future writer's complete footprint.

No journal writes, physical master-selection owner, enrolment, fresh allocation
entropy, child release, production MLS activation, signed release or board flash
is introduced by this source change.
