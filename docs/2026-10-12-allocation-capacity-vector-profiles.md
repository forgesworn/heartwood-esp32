# Public maximum-history profiles for SDK capacity and crash tests

The dedicated 256 KiB partition proposal needs valid authenticated journal data
at its proposed eight permanent historical subjects and 32 records per subject.
Exact-width arbitrary blobs can measure steady occupancy, but cannot classify
journal crash states or prove that the final pending promotion remains feasible.
These independent public fixtures supply the valid maximum-history inputs for
that next SDK-backed measurement harness. They do not measure capacity themselves.

Generate eight distinct normalized roots consisting of public byte values 1..8
repeated 32 times. Python HMAC/SHA derives the existing exact subject/writer/namespace
and AEAD keys; OpenSSL supplies actual issuer public keys; libsodium independently
seals frames; Python Ed25519 supplies synthetic stored witness receipts. No real
root, salt, owner, device state or issuer enrolment is accessed. The same public
witness seed is a fixture input, not an available production witness authority.

Each profile contains one 476-byte anchor, 32 immutable 356-byte manifests and
129 chronological 498-byte snapshots. Generation 1 is exact genesis. Each append
has a pending snapshot followed by its committed successor, through generations
64/65 for record 32. Then each of the 32 active records retires exactly once,
again with pending/committed successors, ending at generations 128/129. All 32
records remain permanently retained after retirement. The two physical snapshot
slots alternate; the full fixture history is input for sequencing/cut tests, not
129 simultaneously stored NVS values.

The existing small journal fixture remains byte-identical. Its builder gains
optional public fixture-only root/full-history inputs; its default command and
output are unchanged. The new generator has a byte-identical `--check` mode.
Fixtures use deterministic public test nonces only. No entropy injection or
constructor is added to firmware, and no frame, selected root or replacement
snapshot can be supplied to a production allocation controller.

Four test groups execute the actual firmware journal codec. They compare actual
curve-backend issuer and root-derived namespaces, authenticate every adjacent
append and retirement transition for all eight profiles, and classify final
record 31, record-32 orphan, pending and committed states. Maximum-history tests
reject missing manifests, corrupt newer snapshots, a wrong held-root binding
and a 33rd record. A missing newer slot yields only a local lone pending history;
a present corrupt slot never falls back to the older valid slot. Every valid
report remains witness-gated and grants no first-use or child-release authority.

These tests construct public normalized roots inside test code only. They do
not provide actual master custody, physical selection, enrolment, fresh witness
or authenticated-time authority. The profiles do not certify the proposed
subject ceiling, durable reservation, free-entry headroom or safe NVS GC.

The next harness must use the pinned actual ESP-IDF public C APIs and emulator,
measure subject-major and interleaved write sequences, prove the worst final
manifest/pending/promotion sequence and pending recovery margin, observe actual
GC, and cold-reconstruct after every logical and primitive write/erase cut with
no orderly cleanup hiding crash effects. Classify with this actual codec as
exact old, exact new or HOLD, including errors that nevertheless persisted bytes.
Byte-verify all retained anchors/snapshots/manifests after refusal and each cut;
record flash hashes/traces. Emulator results remain separate from installed
layout, physical partial programming/wear/cuts, timing/watchdog/RAM, migration,
authenticated permanent reservation, reset policy and production acceptance.
No partition table, device, runtime owner/controller or firmware release changes.
