# Public offline lifecycle and artificial fullness

These host-only campaigns extend the pinned actual-SDK harness. They use the
unchanged worker, official unmodified NVS implementations, public authenticated
fixtures, ASan/UBSan, separate fresh processes and fsynced direct abrupt captures.
They are not runtime writers, namespace/genesis authorization, fresh witnesses,
capacity reservations, installed-layout migration or physical acceptance.

Build the worker with the [original builder](2026-10-12-allocation-sdk-cold-harness.md).
All scratch paths must be explicitly owned under `~/WebstormProjects/.worktrees`.
Use new evidence paths; campaigns refuse existing output. Example:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/allocation-nvs-cold/lifecycle.py \
  --worker "$HOME/WebstormProjects/.worktrees/heartwood-nvs-cold/build/allocation-nvs-cold" \
  --fixtures common/tests/fixtures/allocation-capacity-profiles-v1.json \
  --scratch "$HOME/WebstormProjects/.worktrees/heartwood-nvs-cold/lifecycle" \
  --evidence "$HOME/vennel-evidence/new-lifecycle"
PYTHONDONTWRITEBYTECODE=1 python3 scripts/allocation-nvs-cold/fullness.py \
  --worker "$HOME/WebstormProjects/.worktrees/heartwood-nvs-cold/build/allocation-nvs-cold" \
  --fixtures common/tests/fixtures/allocation-capacity-profiles-v1.json \
  --scratch "$HOME/WebstormProjects/.worktrees/heartwood-nvs-cold/fullness" \
  --evidence "$HOME/vennel-evidence/new-fullness" \
  --baselines "$HOME/vennel-evidence/new-lifecycle"
```

Complete lifecycle first: fullness loads and verifies its two exact pre-final
retirement baselines. Preserve builder/source pins and all public evidence before
removing owned worktrees, SDK and scratch build directories.

## Fixed lifecycle tables

Seven subjects begin with all32 terminal manifests permanently retained. The
eighth begins absent, in subject-major and interleaved population orders. Real SDK
read-write open while attempting the fixed anchor supplies namespace-only cut
evidence. No namespace constructor is added to firmware or runtime code.

| Local state | Snapshots | Records | Actual codec report | Result |
| --- | --- | --- | --- | --- |
| absent namespace | none | none | exact target open/enumeration NOT_FOUND, zero entries | HOLD |
| empty namespace | none | none | Missing | HOLD |
| anchor-only | none | zero | authenticated anchor, Missing | HOLD |
| local genesis | g1 | zero | LoneNeedsWitness, nonpending | exact-local-genesis |
| first orphan | g1 | one | OrphanNeedsWitness, orphan1, nonpending | exact-orphan-first |
| first pending | g1/g2 | one | PairedNeedsWitness, pending | exact-first-pending |
| first promotion | g2/g3 | one | PairedNeedsWitness, nonpending | exact-first-promoted |
| pre-final retirement | g126/g127 | 32 | PairedNeedsWitness, nonpending | exact-pre-final-retirement |
| final retirement pending | g127/g128 | 32 | PairedNeedsWitness, pending | exact-final-retirement-pending |
| final retirement promotion | g128/g129 | 32 | PairedNeedsWitness, nonpending | exact-final-retirement-promoted |

Every named state additionally matches exact fixed fixture bytes, slot count,
retained count, pending flag and orphan ordinal. g126 is retirement31 pending;
g127 is its promotion. g128 is retirement32 pending; g129 is its promotion.
All32 manifests stay present forever. Missing/empty/anchor states always remain
HOLD and never authorize genesis. Retirement never permits reclamation.

Expected target absence has one exact SDK shape and is distinct from generic
SDK failure. All seven existing histories still have to match fully. Any error
in an existing history, contradictory target status or partial report produces
total HOLD; valid partial namespaces are never treated as successful decoding.
Every complete readable observation submits all eight namespace captures to the
actual private authenticated codec on both backends, including the seven fixed
terminal histories. An absent target is still submitted as an explicit HOLD.

For anchor/g1/m01/g2/g3 and final g128/g129 writes, cut every completed word/erase,
successful init/open/set/commit/readback/close boundary and official transient
fault. Every exact prior non-target key stays byte-identical. Early states may
legitimately have zero/one slots; paired states preserve the other live slot.
Missing replacement slots and off-phase valid bytes HOLD; corrupt present newer
frames cannot fall back. Every output has `authority:false`, even exact genesis
or promotion. The optional batch additionally asserts its expected local state.

## Separate artificial fullness

The fixed `hostfull` namespace and `f0001..f2048` keys are raw test filler outside
the proposed production subject ceiling and outside the journal codec. Each
512-byte value is SHA256 of a fixed public domain, key and version repeated16.
Seed16 keys, replace them for32 rounds, then append keys until the actual SDK
returns NVS_NOT_ENOUGH_SPACE. Record the exact status and observed sector erases;
deliberate churn must actually exercise GC before that claim is accepted.
No free-entry statistic becomes usable space, a reserve or an application limit.

The unchanged worker always queries eight namespaces. One fresh cold view
captures all eight journals. A second fresh cold view captures seven journals
plus filler. Both full flash images must be byte-identical; seven shared
inventories must match. This binds all eight journal and filler inventories to
the same flash state without modifying SDK or worker source. After every change
or refusal, every pre-existing filler key/value except the exact attempted key
must remain present and exact, alongside all eight permanent histories.

The second experiment attempts the valid final-retirement pending journal write
at artificial fullness, from g126/g127 to g127/g128. Record its own SDK outcome,
primitive trace and flash equality separately from filler refusal; reopen and
classify exact old/new/HOLD through the codec while all filler values and every
non-target journal key remain exact. Cut its observed primitives, successful
write/init boundaries and transient errors. No SDK result proves a reservation
or zero-mutation refusal by the application controller.

Recognized SDK reconstruction failures serialize total HOLD, complete native
captures/hashes/traces and `retentionVerified:false`. A fullness reconstruction
HOLD stops that campaign with distinct exit92 and a receipt declaring
`campaignComplete:false`; it is neither harness success nor a crash. Timeouts,
sanitizer failures, signals, unknown errors, malformed protocol or missing evidence
fail the harness. No successful partial inventory is passed to Rust after error.

Run `sdk_capacity_inventory_batch` on both backends for each campaign's
`lifecycle-codec-input.jsonl`. Full outputs must be byte-identical, all expected
class/local-state/report fields must match and every authority flag must be false.
Ordinary CI tests all fixed states and refuses contradictory absence, partial
errors, off-phase data, corrupt newer slots and missing permanent manifests.

These are bounded lifecycle/fullness cases, not exhaustive repeated recovery,
physical subword programming/erase, wear, timing/RAM/watchdog or board acceptance.
The previous finite recovery graph still leaves483 subject-major images queued.
The ninth-subject/33rd-record pre-mutation gates remain open until a real
authorized global permanent-history controller exists. No caller-supplied fake
gate, raw SDK namespace acceptance or no-space error can close those requirements.
