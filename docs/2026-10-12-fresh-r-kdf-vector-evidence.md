# Fresh-R v1 mathematical vector evidence

The companion construction contract has independent mathematical approval. Its
mathematical contract is published in `2026-10-12-fresh-r-kdf-construction.md`,
with a public-constant annotation for the repository secret scanner.
This change publishes synthetic evidence and host tests only. It adds no
production KDF, caller-salt API, entropy injection, allocation owner, partition,
manifest constructor, recovery method or child delivery. Production MLS remains
disabled. A mathematical scalar and public R establish no allocation authority.

## Reproduce

From the repository root:

```sh
python3 common/tests/fixtures/generate_fresh_r_kdf.py --check
node common/tests/fixtures/check_fresh_r_kdf.mjs
CARGO_TARGET_DIR="$PWD/out/host-target" cargo +stable test --locked --manifest-path common/Cargo.toml --features nip44,cash fresh_r_vectors
CARGO_TARGET_DIR="$PWD/out/host-target" cargo +stable test --locked --manifest-path common/Cargo.toml --no-default-features --features firmware fresh_r_vectors
```

The Python generator requires `cryptography`; it uses stdlib HMAC SHA256 and
OpenSSL secp256k1. The Node checker uses built-in OpenSSL HKDF and ECDH with no
npm packages. Their curve implementation is related; agreement with both Rust
backends supplies additional independent curve evidence. No device files,
network or runtime entropy are read. The JSON contains deliberately public
synthetic root/scalar/PRK/shared-secret values; never use them as real keys.

Six eligible mathematical input fixtures include changed root/salt, Bunker
normalization and TreeNsec/Bip39 representations of the same normalized root.
The raw Bunker alternative is intentionally wrong custody input even though it
is a valid scalar and has mathematical HKDF output. Ten additional negative or
perturbed inputs cover that raw input, zero root/salt/schema, different schema,
omitted domain NUL, changed version and truncated root/salt/schema. Their
`contractInputEligible` metadata describes the approved contract; it does not
assert any implemented input gate. Fixtures deliberately preserve mathematical
HKDF output for invalid protocol inputs so future refusal tests can distinguish
protocol refusal from a merely valid derived scalar.

Six direct scalar fixtures cover 0, 1, n-1, n, n+1 and maximum u256. Actual
Heartwood public/compressed-key adapters reject invalid scalars without
reduction. Both eligible point parities occur. Every valid derived scalar is
checked against its independently computed original compressed point and n-d;
the latter has the same x-only R and must trigger future public-R reuse refusal.
No stored-secret parity normalization is added.

Thirty-six Introduction fixtures cover six allocations, both recipients and
counters 0, 1 and u64::MAX. Host tests call the actual private NIP-44 ECDH-x
adapter on k256 and secp256k1, require symmetry and n-d equality, then call the
pinned `vmls-core` Introduction implementation. They compare exact mailbox and
record-secret bytes with independent fixtures. This is compatibility evidence,
not an allocation integration call site or permission to reset a counter.

## Remaining acceptance

The permanent retained salt/R reuse checks, manifest target/installation/
operation/challenge binding, authenticated saved-manifest recovery and changed
stored-R refusal are still implementation gates. Those fields are intentionally
absent from KDF info; this math evidence cannot authorize retargeting and does
not pretend to test a nonexistent owner. Strict held-root/issuer custody remains
covered separately by allocation root/journal tests.

Fresh one-use grant ordering, signer entropy quality/failure/reuse, durable
capacity, first-enrolment continuity, authenticated time, every uncertain write
and recovery cut, zeroizing lifetime and internal-copy limits, firmware
activation budgets, purpose-only encrypted delivery, witnessed browser custody
and zero-counter promotion, old-R retirement/high-water, physical acceptance and
live production rollout remain open. Synthetic backend tests are not board or
entropy acceptance. No firmware was flashed or released by this change.
