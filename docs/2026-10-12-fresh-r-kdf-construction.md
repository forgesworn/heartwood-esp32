# Fresh rendezvous allocation KDF v1: proposed construction

Status: proposed mathematical/input contract for independent review. No callable
firmware producer, allocation command, child delivery or browser genesis is added.
The existing permanent allocation journal, physical owner, first-enrolment
continuity/recovery, measured capacity and authenticated time requirements remain
binding. Production MLS remains disabled. This proposal does not prove physical
entropy, first use, safe delivery or counter-ledger genesis.

## Inputs and exact bytes

Use the actual held normalized master root, not the raw Bunker secret, an npub,
account signature key, derived child, slot label or browser-provided secret. Its
strict persisted mode/version/issuer and encrypted master custody have already
been validated. The actual issuer remains a separate exact manifest binding;
root-mode aliases do not bypass the current v1 journal issuer refusal.

The signer obtains one fresh unpredictable 32-byte salt from its verified strong
entropy path **inside the held controller after a fresh exact-active one-use
Current grant**. Reject entropy failure and all-zero output. Check permanent
retained manifests, including abandoned/retired/expired/uncertain operations,
for used salt and resulting public R; reject observed reuse. Salt is stored in
the exact immutable encrypted manifest. Neither a target browser nonce nor a
caller-selected salt is this entropy authority. Do not repeat entropy or change
context to rescue a failed KDF within this attempt.

The fresh signer-generated salt is independent of the normalized root and is
not attacker-chosen, as required by RFC5869 section3.4. Its physical independence
and quality remain acceptance gates. The KDF context is only the fixed version/purpose domain and frozen journal-v1
schema_hash32, which is nonzero and fixed by the format. HKDF info contains no
root-derived subject/writer/pins_hash or actual issuer, and no target key that
might itself derive from the same master. This keeps info independent of the
secret IKM value as required by RFC5869 section3.2. The minimal context is also
a deliberate protocol choice; safe target binding rests on the full authenticated
manifest, physical owner and encrypted delivery described below.

The physically approved manifest independently authenticates the exact actual
issuer, target browser-device key, browser installation, bootstrap operation and
bootstrap challenge. Their provenance and cryptographic validation are owner
requirements. Changing those bindings is not permission to retain/reuse salt or
R, retarget delivery or treat the same R as another counter namespace. The future
encrypted child-delivery transcript must authenticate that full frozen tuple.
Target binding is enforced by manifest/owner/delivery, not by modifying the KDF.

Slot, label, wall clock, receipt challenge, courier token, retry count, witness,
adder and room are not KDF inputs. They must not alter a recovered R. Witness
replacement and issuer migration remain separate HOLD boundaries, never
permission to rederive/change history. The same root/salt/schema derives the
same R; namespace-wide permanent salt/R refusal is consequently essential.

All concatenation below is raw bytes; the UTF-8 domain includes the final NUL.
There is no text hex, JSON, length prefix, optional field or implicit padding.
HKDF is RFC5869 with HMAC-SHA256, output length exactly32:

```
IKM = normalized_root32
salt = signer_random_salt32
info = UTF8("VMLS/1 fresh rendezvous allocation scalar\0") || schema_hash32
PRK = HMAC-SHA256(salt, IKM)
candidate32 = HMAC-SHA256(PRK, info || byte(1))
```

The candidate is one 256-bit big-endian integer d. Accept only 1 <= d < n,
where secp256k1 group order n is
`FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`. <!-- pragma: allow-secret: public secp256k1 group order -->
Zero or out-of-range is HOLD for the attempt. Do not reduce modulo n, mask bits,
add one, increment a counter, switch domains, substitute a legacy child index,
use another caller context or silently regenerate a salt. This exact refusal
mapping preserves uniformity over valid scalars conditioned on acceptance.
The order is a public mathematical constant, not a key.

Compute point d*G with the production secp256k1 backend and R = its 32-byte
x-only public key using the existing VMLS/BIP340 representation. Validate the
resulting nonzero public key. The private scalar is the original valid d bytes;
do not silently replace d with n-d as another stored derivation. The ECDH used
by VMLS consumes only the shared x coordinate, so both public-key parities must
have independently verified agreement vectors. Detect d and n-d's identical
public R as public-R reuse if observed in the retained history.

The KDF domain is separate from existing fixed-purpose/indexed rendezvous
children and the allocation writer/subject/AEAD domains. It does not change
existing VMLS Introduction mailbox/record derivation or sender-R-global counter
semantics. R freshness is probabilistic, subject to verified salt entropy and
negligible cryptographic collisions; a KDF does not prove absence of prior use.
The permanent allocation witness/recovery protocol establishes the permissible
allocation history. Old R retirement/high-water and exact old intents remain a
separate gate, even if this construction creates another public R.

## Secret ownership and recovery

Root, PRK, candidate and child scalar buffers require reviewed Zeroizing owners,
no Clone/Debug/serialization or generic raw-byte constructor/signing API. Avoid
unwiped intermediate copies in HKDF/curve adapters. Document unavoidable library
stack/internal-copy limits; normal Drop is not proof of erasure on reset or flash.
The public R and salt/context must not be logged or sent in witness-forwarding
requests. Salt is not required to be secret for HKDF security, but is protected
in this manifest to minimise correlation/recovery metadata.

New derivation runs only within the fresh-granted, physically approved controller
and stages the full frozen manifest before any witness advance. Expired or
uncertain writes/grants hold; lost replies retain the exact salt/context/R and
operation, never allocate a new key. The controller still owns the strict
capacity and authenticated-time inputs. No external public AuthorisedManifest
constructor may perform pre-grant salt/R generation.

An attempt before the first durable manifest set has only volatile candidate
state. If scalar rejection or a cut occurs before any candidate write was
attempted and before any witness advance/child effect, no durable allocation
exists. It burns no retained record, but ends the approval/grant; only a newly
physically approved operation with a fresh exact-active grant may draw new salt.
A reboot cannot prove that pre-write boundary by itself: reopening requires the
complete inventory scan and fresh witness reconciliation under independent pins.
If any write was attempted, its effect is uncertain until that inspection. A
present manifest/orphan/pending operation always retains its exact saved salt/R;
missing/corrupt/inconsistent state holds according to the strict journal rules.
No failure or cut grants permission to replace a possibly persisted allocation.

Recovery derives only from a fully authenticated retained manifest under the
same held root, exact issuer, schema and externally enrolled history. Recompute
R and require byte equality with its stored R. A mismatch holds; do not rewrite
R, accept caller salts or turn this into a recovery oracle. Fresh reconciliation
and current authenticated time remain necessary for any bounded one-use delivery;
reconciliation alone may preserve expired history but cannot release a child.

The recovered scalar can reach only the reviewed purpose-only child delivery
boundary. Browser custody and its witnessed zero-counter ledger must be installed
in one recoverable transaction before any Introduction or admission use. A
mathematically valid d/R, fresh witness receipt or owner confirmation cannot
substitute for that browser promotion. No ordinary account/event signing API may
use this child; account proofs remain in the corresponding held persona scope.

## Required independent evidence before implementation

Freeze exact domain, field order and scalar refusal mapping after review.
Generate synthetic public fixtures independently in Python HMAC/curve code and
check with Node HKDF/secp256k1 plus both firmware curve backends. Include root
mode aliases and normalized-vs-raw Bunker distinction; changed salt/schema; unchanged mathematical R across target/installation/
operation/challenge proposals coupled with mandatory owner refusal of retargeting
any frozen manifest; omitted NUL/domain/version/truncation; zero root/salt/schema; big-endian
boundaries 0,1,n-1,n,n+1,2^256-1; both point parities; d vs n-d x-only collision;
exact recovery and changed stored R; and symmetry/equality of actual VMLS ECDH x
and resulting Introduction mailbox/record derivations. Synthetic mapping failures
are test inputs only, not an injectable production KDF or entropy callback.

Then review the exact private owner/controller integration and test entropy
failure/reuse, fresh-grant ordering, all custody and write cuts, exact lost-reply
recovery, zeroizing lifetime, budget/stack/watchdog, purpose-only encrypted delivery
and witnessed browser promotion. Physical entropy and full allocation/browser
acceptance remain required separately.

Primary specifications: [RFC5869](https://www.rfc-editor.org/rfc/rfc5869.html)
sections2.2-2.3 and3.2, [BIP340](https://bips.dev/340/) for secp256k1 order and
x-only public-key representation. Actual VMLS derives Introduction from ECDH x,
recipient R and u64 counter in `vmls-core/src/derive.rs::introduction` at Vennel
main `a2667c3ed558069a660688c8cae72ad2bc84b137`; the KDF must not reset that
counter namespace for an existing R.
