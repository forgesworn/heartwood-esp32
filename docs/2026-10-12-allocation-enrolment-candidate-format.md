# Exact enrolment candidate: canonical framing proposal

Status: independently reviewed canonical framing only. This freezes only the exact enrolment candidate, not the allocator/continuity protocol, signed proof, scope certificate, encrypted intent, physical capacity token, recovery container or any authority producer. The private parser checks this syntax independently of selecting a live service. It does not close any actual-controller or physical gate.

The proposed state owner/order is the contract in Heartwood PR244, exact tree bd2001493f8667013af9383d006b80574377d82e. The extension is merged; its separate actual-main release verification remains recorded in the release evidence. Subject admission must atomically charge the immutable global scope and retain this complete candidate. Its digest excludes the later admission proof, witness receipt and mutable completion state. An exact retry compares complete bytes; digest equality alone does not permit reconstructing absent bytes.

## Bytes

Exactly 435 bytes, no optional fields, padding, text labels or extensions. Integer lifetime is unsigned 64-bit big-endian seconds. Unknown versions, prefixes, purpose values, wrong lengths or trailing bytes are refused. A changed format requires a new version and reviewed migration; parsers cannot reinterpret v1.

| Offsets, end exclusive | Width | Value |
| --- | --- | --- |
| 0..5 | 5 | ASCII HWEN followed by byte01 |
| 5..37 | 32 | scope_binding_digest |
| 37..266 | 229 | exact existing HWAD01 journal descriptor |
| 266..298 | 32 | computed empty-state genesis digest |
| 298..299 | 1 | purpose01: witnessed browser-bootstrap child only |
| 299..331 | 32 | target_device |
| 331..363 | 32 | browser_installation |
| 363..395 | 32 | bootstrap_operation |
| 395..427 | 32 | bootstrap_challenge |
| 427..435 | 8 | requested_lifetime_seconds |

Candidate digest = SHA256(ASCII "HW allocation enrolment candidate v1" || byte00 || complete candidate bytes). It is a commitment, not a signature or authorization. Every field and its position is covered. The candidate retains the full approved operation bindings rather than an unrecoverable operation hash. The genesis digest, requested lifetime and purpose are included; no allocation salt/R/scalar, root, key or child is present.

The descriptor is byte-identical to existing journal v1:
HWAD01 || subject32 || writer32 || actual_issuer32 || subject_installation32 || witness_key32 || route_hash32 || journal_schema_hash32.
Its subject-installation is distinct in role from the browser installation. The current journal route is SHA256("HW allocation route v1" || byte00 || byte01 || witness_key). The schema is SHA256("HW allocation journal schema v1" || byte00). Standalone syntax checks are field-specific:

- Descriptor prefix must be HWAD01. schema and route must equal the formulas above. Recompute pins = SHA256("HW allocation pins v1" || byte00 || descriptor); empty = byte00 || SHA256("HW allocation record set v1" || byte00 || pins || byte00) || 32 zero bytes; genesis = SHA256("HW allocation state v1" || byte00 || pins || empty). The included genesis digest must equal that exact result.
- actual_issuer and target_device must be valid nonzero secp256k1 x-only points (lift_x succeeds), not arbitrary opaque bytes. Their ownership is not proved by point validity.
- writer and witness_key must decode as valid Ed25519 verification keys, have canonical compressed-point encoding and not be weak/small-order points. They must differ. Parsing these keys is not verification of a witness receipt or a writer signature.
- subject, subject_installation, browser_installation, scope_binding_digest, bootstrap_operation and bootstrap_challenge are nonzero opaque 32-byte bindings, not public keys. Schema, route and genesis are hash values constrained by recomputation, not points.

This is the standalone candidate syntax rule, not a claim that the full private journal decoder ran. The future held-root producer still verifies root-derived subject/writer, actual issuer and descriptor bindings. It must strictly verify the fresh pinned witness receipt through the existing codec before local genesis. This candidate contains no receipt; it cannot supply that verification.

scope_binding_digest is a digest of the separately reviewed immutable scope binding certificate body. That body's format/provenance is not chosen here: it must bind actual device lineage, installed partition identity/layout and policy, pinned allocator/independent continuity identities and fixed global history scope. It cannot be a host-supplied random replacement scope or a hash of a local installation ID. The complete certificate and its authenticated proof must be recoverable separately with the candidate; a digest alone supplies neither scope provenance nor recovery authority. Certificate signature/revision framing and the digest domain require their own review before this field can be produced outside public fixtures.

The candidate descriptor/target/browser/operation/challenge/digest fields are nonzero. requested_lifetime_seconds must be nonzero. The parser validates bounded syntax only. A physically authorized producer must additionally enforce its reviewed lifetime policy and checked conversion to authenticated requested_at/deadline later, through the selected time authority. A relative interval is not current time and never authorizes release. Absolute time/time-statement bytes remain a separate construction; this proposal introduces none.

## Producer and recovery boundary

An unverified parsed candidate may be retained by a public synthetic test. Real candidate bytes expose stable scope/subject/writer/issuer/witness, target/browser and operation/challenge/lifetime bindings. Carriage or recovery transfer is permitted only inside a separately reviewed confidential authenticated envelope, with recipient/route/access authority and no raw logs, public tags, routine cache or plaintext courier storage. Parser validity never permits disclosure. It cannot construct EnrolmentPins, MeasuredCapacity, AuthorisedManifest or a physical approval. There is no generic signing API or replacement enrollment route. A future producer must obtain the actual held root/issuer, independently authenticated scope/certificate, pinned witness and exact physical operation; recompute subject/writer, schema, route, empty state and genesis through the actual private journal construction. Host target/installation values are proposals, not ownership certificates. Their independent authority and physical display/approval must be checked before admission.

Freeze this exact candidate once. Subject-installation generation/protection, scope provisioning and target ownership remain separately reviewed producers. Requested lifetime is what the device approved, not an unauthenticated absolute deadline. After authoritative admission, obtain the separately authenticated absolute requested_at/deadline and time statement for this same candidate digest once. Bind the full exact result (not merely its hash) to the candidate/operation, protect it and establish its durable recoverability before fresh allocation salt/R, journal-frame entropy, witness advance or child effects. A time request with unknown outcome must reconcile that exact time decision or HOLD; it cannot resample current time to extend the same charged candidate. Exact retry reuses the same immutable result. Expiry or missing/corrupt/conflicting time evidence holds the operation without refund, replacement candidate or regenerated time; fresh current time may confirm expiration but cannot extend it. The time authority's atomic issuance/query, request challenge, continuity, encoding, checked arithmetic and cut order are separate required construction/vector gates. A raw live time sample or caller-supplied deadline cannot implement this once-bound result. A grant timeout or changed selection requires fresh physical approval of the same candidate for recovery; no recovered bytes automatically preserve a volatile approval. No root/data-key/SDK guard spans network exchange.

On external dispatch with unknown outcome, query the same immutable scope/subject/candidate, recover complete exact bytes plus the admission/continuity proof and scope binding, then physically approve that exact operation. Another issuer, witness, scope, target, installation, challenge, operation, purpose or lifetime is a different candidate and cannot replace a charged one. If any required exact bytes/proof are unavailable or disagree, HOLD. Never infer first use from absence/reset or rebuild the candidate from mutable host fields. Cancellation, retirement and removed masters keep its permanent claim.

The exact candidate must be stored recoverably by the atomic admission owner and, after authenticated admission, included in the protected local intent and independently authenticated recovery copy with the exact reservation proof. Protection/encryption, capacity budget, nonce ownership and rollback continuity for those containers are not implemented here. They must not put a new key into the strict journal namespace or export a root/writer seed/child.

## Independent vectors and implementation acceptance

Use only public fixture material. Include the existing 229-byte descriptor and computed genesis digest, clearly synthetic scope-binding digest and target/browser/operation/challenge values, lifetime1/3600/u64MAX syntax cases, complete candidate bytes and domain-separated digest. These fixtures create no scope certificate or authority. An independent generator and actual codec must agree byte-for-byte.

Test each field's complete bytes, all lengths and version/purpose values; wrong schema/route, zero fields, invalid public keys/issuer syntax; endian and lifetime-zero mistakes; every single-byte mutation's digest change; and full-byte exact retry versus every changed operation binding. A mathematically valid changed candidate can remain syntactically valid, but must never be an exact retry. Tests must distinguish framing validity from authentication and physical authorization.

The private firmware parser implements only this approved framing; it has no runtime caller, signing method, raw-byte export or nominal-authority conversion. Scope/proof/intent/continuity/time/physical producers remain blocked by their separate construction/vector gates. Signature validation or decoding a candidate cannot supply authenticated first use, anti-rollback, capacity, witness freshness or child release.

Reproduce the public fixtures with `python3 common/tests/fixtures/generate_allocation_enrolment_candidate.py --check`. Actual firmware parser tests run under `allocation_root::enrolment_candidate` on both curve backends. They are framing/retry checks, not capacity, physical, authenticated-time or transport acceptance.
