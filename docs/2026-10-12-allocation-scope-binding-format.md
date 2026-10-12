# Immutable scope binding body: non-authoritative framing proposal

Status: independently reviewed non-authoritative syntax and public vectors only. This selects
no service, signing algorithm, provisioner, independent non-rollback source,
physical migration, binding-component producer or authority constructor. A valid
body is not an authenticated certificate. Its digest is intended to occupy the
scope_binding_digest field of the already reviewed 435-byte candidate only after
this framing and all actual provisioning/protection proofs are separately reviewed.

## Exact bytes

Exactly 263 bytes; no padding, optional fields or trailing bytes. Offsets below
are end-exclusive. No signatures or mutable state are in this body.

| Offsets | Width | Field |
| --- | --- | --- |
| 0..5 | 5 | ASCII HWSB followed by byte01 |
| 5..37 | 32 | permanent_history_scope |
| 37..69 | 32 | device_lineage_binding_digest |
| 69..101 | 32 | installed_layout_binding_digest |
| 101..133 | 32 | allocation_pool_binding_digest |
| 133..165 | 32 | reset_migration_policy_binding_digest |
| 165..197 | 32 | allocator_identity_binding_digest |
| 197..229 | 32 | independent_continuity_identity_binding_digest |
| 229..261 | 32 | journal_schema_hash |
| 261..262 | 1 | permanent distinct-subject ceiling: byte08 |
| 262..263 | 1 | permanently charged per-subject ordinal ceiling: byte20 |

Body digest = SHA256(ASCII "HW allocation scope binding v1" || byte00 ||
complete 263-byte body). journal_schema_hash is exactly the already approved
SHA256("HW allocation journal schema v1" || byte00). All seven preceding
32-byte bindings are nonzero opaque bindings, not public keys or signatures.
Allocator and continuity identity bindings must differ. Their different bytes
prove neither actual key independence nor independent durable storage.

permanent_history_scope is a stable opaque identifier, not a digest. Its later
producer must specify generation, collision handling and authenticated immutable
provenance. Syntax accepts arbitrary nonzero identifiers and therefore supplies
none of those guarantees. The reviewed provenance/continuity producer must
forbid minting/selecting a replacement scope to regain budget or first use. Every other
opaque digest commits a separately reviewed complete immutable component body.
Those component formats, digest domains, exact key/protocol identities and
physical provenance are explicitly unselected. Real producers cannot substitute
arbitrary host bytes, MAC/serial strings, local installation IDs, signing-key
hashes or a healthy boolean for those components. Full exact component bodies,
certificate authentication/proof and provisioning evidence must be recoverable
with the body; seven opaque binding values alone are not a recoverable certificate.

The device-lineage component must bind the actual device lineage. Layout/pool
components must bind the actual installed table, partition name/type/subtype,
offset/size, storage schema and physical ownership, including any relevant
firmware/layout provenance required by reviewed migration. Reset/migration
policy must retain all prior scope claims and charged ordinals. Identity
components must pin actual allocator and independent continuity identities,
protocol/key choices and their reviewed restore relationship. These are required
component meanings, not approvals of any component encoding or producer.

The byte08/byte20 values are the proposed permanent logical policy already in
PR244, not physical capacity measurements. Other values and unknown versions
are refused. A changed body is a different commitment and cannot silently
replace an existing provisioned scope/candidate. Recovery/migration and key or
layout changes require their own reviewed retention procedure; matching a new
body's syntax does not grant that procedure. Same-root restoration still uses
the external subject-wide permanent index across scopes.

## Privacy, parser and authority boundary

This body links history/device/layout/pool/policy/allocator/continuity bindings.
It is not for public tags, raw logs, routine caches or plaintext couriers. Actual
transfer/protection requires a separately reviewed confidential authenticated
envelope and access route. A parser, hash or body equality grants no disclosure.

A future private parser may own zeroizing fixed bytes and provide only bounded
syntax, digest and complete-byte equality. No raw getter, generic signer,
Debug/Clone/Serialize, scope provisioner, live service selection, nominal
authority conversion or runtime caller is proposed. Complete-byte equality is
required for exact body retry; equal digest alone cannot recover absent bytes.
Parsing proves no installed geometry, lineage, scope provenance, prior absence,
anti-rollback continuity, permanent reservation or physical capacity.

## Public independent vectors and acceptance

Use clearly synthetic seven opaque public byte patterns, the independently
computed existing journal schema and fixed policy bytes. Include all complete
263 bytes and domain-separated digest. Independent generator and actual parser
must agree. Test every shorter length/trailing bytes, all prefix/version bytes,
every field's zero case, wrong schema/policy, equal allocator/continuity digests,
all 67,065 single-byte substitutions' digest changes and complete-byte retry
behavior (at each of 263 offsets, replace the byte with each of the 255 unequal
uint8 values).
A changed opaque binding can remain syntactically valid; it is not an exact
retry and does not establish independent provenance. The reproducible independent stdlib generator is
`python3 common/tests/fixtures/generate_allocation_scope_binding.py --check`; it asserts all 67,065
substitutions change the body commitment. No component is produced
or authenticated by these fixtures; no candidate is submitted to any service.

Scope/certificate component encoding, signatures, provisioning/recovery, exact
admission/ordinal/continuity proof semantics, protected intent/mirror/recovery,
actual allocator transactions and private controller/device gates stay open.

The private parser now implements only this syntax, digest and full-byte equality. It has no runtime caller or authority conversion. Host tests exercise the actual firmware source on both crypto backends; they do not verify scope provenance, continuity, installed capacity or physical acceptance.
