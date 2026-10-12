# Offline record32 reconciliation and repeated cold recovery

This extends the first bounded actual-SDK host campaign. It exercises public
authenticated fixtures and cold SDK writes only. There is no witness ceremony,
authorized writer/controller, fresh grant, migration, physical device or release.
An exact promoted local inventory still needs a fresh witness and grants no
child-release, capacity or runtime authority.

Build the unchanged worker with the pinned builder described in the
[original harness](2026-10-12-allocation-sdk-cold-harness.md). Run:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/allocation-nvs-cold/recovery.py \
  --worker "$HOME/WebstormProjects/.worktrees/heartwood-nvs-cold/build/allocation-nvs-cold" \
  --fixtures common/tests/fixtures/allocation-capacity-profiles-v1.json \
  --scratch "$HOME/WebstormProjects/.worktrees/heartwood-nvs-cold/reconciliation" \
  --evidence "$HOME/vennel-evidence/new-reconciliation-campaign" \
  --max-depth 2 --max-edges 2048
```

Both scratch and evidence paths must be new. The fixed public fixture hash and
eight public roots are checked. All native operations retain the first harness's
SDK pins, full fsynced flash/trace capture and abrupt exit without cleanup.
Each process has a 60-second timeout; crashes, sanitizers, unknown status values,
impossible exits, malformed output or missing evidence fail the harness. They
cannot be classified as a successful test or HOLD.

## Reconciliation states

For each subject-major and interleaved population, all seven other subjects have
32 permanently retained terminal records. The eighth is populated through
record31, then m32 is written and separately cold reconstructed. Instrumented
and ordinary successful population must produce byte-identical flash images.

The strict test-only classifier binds statuses, namespace, every key, type,
width and complete bytes before calling the actual private firmware decoder.
The recipe allows only fixed canonical states appropriate to that phase:

| Class | Snapshot generations | Records | Codec layout | Pending | Orphan |
| --- | --- | --- | --- | --- | --- |
| exact-orphan | 62, 63 | 32 | OrphanNeedsWitness | false | 32 |
| exact-pending | 63, 64 | 32 | PairedNeedsWitness | true | none |
| exact-promoted | 64, 65 | 32 | PairedNeedsWitness | false | none |

Each exact state additionally requires two snapshot slots and the codec's
retained count32. Valid bytes outside the intended phase are HOLD. Lone slots,
missing replacement slots and present corrupt newer frames cannot fall back to
an older slot. Reports expose the actual layout/pending/retained/orphan fields;
every outcome emits `authority:false`.

The orphan-to-pending and pending-to-promoted writes start from separate cold
processes. Every completed native word/sector primitive, successful init/write/
commit/readback/close API boundary, and official transient-error boundary is
tested. Read-only inventory API cuts were covered in the first campaign; this
slice cuts recovery and write calls. All seven other histories and every eighth
subject key except the exact replacement slot must remain present and byte-exact
on every successful reconstruction. The replaced slot may be exact old, exact
new, or absent with HOLD; unexpected present bytes fail retention checks.

Recognized SDK init/open/enumeration/read/status failures yield a total HOLD
with hashes, traces and their complete native error capture. No partial inventory
is passed to Rust as valid reconstruction. Such an edge records
`retentionVerified:false`; inability to read is not evidence of retained data.

## Finite repeated recovery graph

Seeds are deterministic: the midpoint primitive and each observed sector erase's
immediate predecessor, erase and successor for both writes and population orders.
Full seed images and hashes are retained. Seed selection does not depend on
classification success. A node is the full 256KiB flash hash plus intended phase;
equal inventories do not collapse distinct flash metadata images.

For each node a fresh uncut process reconstructs its inventory and records all
cold-init mutations. Every completed cold-init word/sector primitive and the
successful init API boundary generates a separate abrupt-cut child. Each child
is cold reopened, retention-checked and submitted to the actual codec. Novel
image/phase pairs enter the queue; duplicates/cycles retain their edges without
being expanded twice. Node/edge traces record parent/child hashes and depths.

Expansion stops at the declared depth or per-order edge budget. Summary counts
explicitly identify depth-limited and queued unexpanded images and budget stops.
`transitiveClosureProved` is always false: even an empty explored queue is not a
claim that this selected seed set closes the lifecycle or all possible recovery.
Complete native inventories for all eight subjects are archived, alongside
ordered traces, hashes, graph records, baseline/seed images and codec batch inputs.
Other per-process images are removed only after capture verification.

Run `sdk_capacity_inventory_batch` on both curve backends with the documented
input/output environment variables. The full outputs must match byte-for-byte,
every expected class must pass and every authority flag must remain false.
Ordinary CI always tests all three typed states and refuses off-phase, lone,
corrupt-newer and partial/error captures without external campaign inputs.

This remains a bounded host slice. Blank initialization/enrolment/first append,
terminal retirement cuts, exhaustive repeated recovery, fragmented/physical full
refusal, ninth-subject/33rd-record controller refusal and permanent global
reservations remain separate gates. Raw SDK free-entry stats cannot issue a
capacity token. No reset/absence/retirement permits genesis or reclamation.
Production geometry, partial programming/erase, wear, timing/RAM/watchdog,
installed-layout migration and physical custody/witness acceptance remain open.

The next [lifecycle/fullness campaign](2026-10-12-allocation-cold-lifecycle.md)
adds separate creation/first-append/final-retirement tables and raw SDK fullness
experiments. Those bounded cases do not close the physical/controller gates.
