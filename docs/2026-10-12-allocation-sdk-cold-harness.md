# Offline actual-SDK cold reconstruction harness

This is host test tooling, outside every firmware/runtime manifest and call graph.
It provides a reproducible first bounded crash campaign and a strict test-only
bridge to the existing authenticated journal codec. It is not a capacity token,
production writer/controller, migration, release, or physical acceptance.

## Build and run

Use a fresh explicitly owned scratch path under `~/WebstormProjects/.worktrees`.
The builder clones ESP-IDF v5.3.2 and refuses any commit other than
`9d7f2d69f50d1288526d4f1027108e314e8c879f`, with the pinned mbedTLS submodule
`98fcfd6d2cea90d306e8fde8e5bffd6087c9cda8`. It preserves the SDK's actual
legacy host Makefile, emulator, public C API, page, storage and GC implementations.
The build proof hashes checked-out tracked files, worker, binary, command and
toolchain. ASan and UBSan are enabled. Native execution was validated on macOS;
Linux needs Clang, Make, Git and libbsd development files and remains a separate
host portability check.

```sh
python3 scripts/allocation-nvs-cold/build.py \
  --scratch "$HOME/WebstormProjects/.worktrees/heartwood-nvs-cold"
python3 scripts/allocation-nvs-cold/worst32.py \
  --worker "$HOME/WebstormProjects/.worktrees/heartwood-nvs-cold/build/allocation-nvs-cold" \
  --fixtures common/tests/fixtures/allocation-capacity-profiles-v1.json \
  --scratch "$HOME/WebstormProjects/.worktrees/heartwood-nvs-cold/campaign" \
  --evidence "$HOME/vennel-evidence/new-empty-cold-campaign"
```

Create the evidence directory first. Existing campaign output files cause
refusal. Preserve its proof, recipes/source revision and outputs before removing
the owned SDK/build/campaign scratch folder. Never use a real device or its flash
image: these inputs are the eight fixed public synthetic normalized roots only.

The worker creates exactly 64 sectors, then loads only an exact 262,144-byte
image. It never uses the emulator filename constructor that adds a spare sector.
SDK initialization uses the official internal host `init_custom` seam to inject
the test partition. It does not exercise production
`nvs_flash_init_partition_ptr`, board geometry or installed partition tables.
Blob open/set/commit/get/readback/enumeration/stats use the pinned public C API.

All three mutating virtual routes (`write`, `write_raw`, `erase_range`) are
instrumented beneath the unmodified driver. Four-byte word splitting supplies
adversarial cut points; it does not claim physical program atomicity. Erases
remain whole-sector operations. At a selected completed primitive or successful
API-call boundary, the worker writes and fsyncs an exclusive separate full flash
capture and trace, then calls `_Exit` directly. It performs no post-cut SDK close,
commit, deinit, destructor or test-framework unwinding. A separate transient
mode uses the official emulator's one-shot failure countdown and records SDK
errors, including any bytes that persisted despite an error.

Every reconstruction is a fresh process and manager. Public-C-API inventories
are collected again after initialization; SDK errors cannot become valid reports.
The Rust `cfg(test)` adapter refuses status, namespace, type, key, width, duplicate
and length inconsistencies, then runs the actual private authenticated codec.
It labels only byte-exact specified old/new inventories or HOLD. Even an exact
new orphan/pending/paired report grants no fresh witness or child-release authority.
For an offline JSONL batch, set `HW_ALLOCATION_SDK_CAPTURE_INPUT` and the fresh
`HW_ALLOCATION_SDK_CAPTURE_OUTPUT` paths, then run the common test
`sdk_capacity_inventory_batch` with the same full host features as CI.

## Bounded campaign and remaining evidence

`worst32.py` populates seven complete terminal histories and an eighth history
at record 31 in subject-major and interleaved orders. Instrumented and ordinary
successful population images must match byte-for-byte. For the final `m32`,
pending snapshot and committed promotion, it tests each successful API-call,
word-write and official transient-error boundary, then cold reconstructs. It
byte-verifies every other history and every already retained non-target key,
including the other live snapshot slot;
every visible target frame must be an exact old/new value. Missing replacement
slots produce HOLD. Separate old/new equality never excuses a codec failure.
Ordered traces, full input/output/recovery image hashes, complete inventory
hashes, baseline images and target codec inputs are retained; per-child scratch
images are removed after verification.

This bounded campaign does not exhaustively cut every earlier enrolment/append,
retirement, GC copy/erase or recovery initialization. It does not yet test
orphan/pending reconciliation writes, artificial physical fullness and its
refusal, or every logical ceiling refusal. Real GC during population alone does
not prove GC-cut recovery. SDK free-entry counts include spare/GC constraints and
cannot issue a reservation. Ninth-subject and 33rd-record limits must be refused
before writes by a future authorized owner, separately from artificial filler
space exhaustion. Permanent reservations, physical partial programming/erase,
wear, cuts, timing/watchdog/RAM, reset retention, migration, custody, fresh witness,
authenticated time and production activation remain open.

The later [bounded reconciliation/recovery campaign](2026-10-12-allocation-cold-reconciliation.md)
adds explicit record32 orphan/pending/promoted states and repeated cold-init cuts.
Its finite graph limits do not close the remaining matrix described above.
