# Dormant allocation journal NVS reader

The private `HeldAllocationRoot::inspect_persisted_journal` reads the existing
root-derived journal namespace and returns only a local inventory report. It
has no runtime caller, initializes nothing, writes nothing and grants no
allocation or fresh witness authority. It now checks the root-derived writer
and stored signatures; missing data is HOLD, never first use.
The encrypted formats and remaining runtime gates are defined in
[the journal format](2026-10-11-allocation-journal-format.md).

## Read boundary

The adapter borrows the selected master's existing default-partition NVS owner
for the lifetime of a separate raw `NVS_READONLY` handle. It never calls
`EspDefaultNvsPartition::take`, partition initialization, erase, set or commit.
Custody is rechecked before opening and after the read, including failed reads.
The post-read custody check takes precedence over any inventory result.

The raw SDK iterator is used because esp-idf-svc 0.52.1's convenience
`EspNvsKeys::next_key` discards the return value from `nvs_entry_next`. Only
`ESP_ERR_NVS_NOT_FOUND` with a NULL iterator ends a scan. Every other SDK error
and success/pointer contradiction returns `InventoryHold::Storage`. Iterator
ownership follows the SDK's updated pointer: the pre-next pointer is never
retained or freed separately. The current iterator and opened handle are
released on every exit.

Each scan enumerates every entry type. It accepts only the exact derived
namespace, blob type and unique `anchor`, `snap0`, `snap1`, `m01` through `m32`
keys. Unknown names, malformed C strings, wrong types or duplicates HOLD.
The 35-entry limit is a bounded inventory ceiling, not a capacity promise.
Each enumerated blob must query and read at its exact frozen width: 476 bytes
for the anchor, 498 for a snapshot and 356 for a manifest. Oversized lengths
are rejected before allocation; disappearing entries, read errors and short
successful reads never become missing-data recovery or a partial report.

Two complete scans must return the same sorted keys and ciphertext bytes.
Observed drift returns `InventoryHold::Changed`. Matching scans do not prove
an atomic snapshot, exclude an ABA change or prevent another independently
opened writer. A real single-owner runtime and witness reconciliation are
still required. The existing codec authenticates every present object and
refuses a corrupt snapshot even if the other physical slot is valid. Lone
snapshots and retained orphans remain local reconciliation information only.

## Validation and activation gates

Host tests compile the actual firmware adapter and custody code. Only the raw
NVS C boundary is replaced with a fault-injection mock; it deliberately exposes
no write, erase or initialization functions. Tests cover every call position,
including terminal iterator errors, pointer/status contradictions, exact widths,
resource cleanup, custody failures before and after reads, scan drift, present
corruption and permanently retained manifests/orphans. Production board CI
must also compile the actual SDK bindings; host tests alone do not prove ABI
compatibility, physical storage behavior or power-cut safety.

The subsequent [boot preservation change](2026-10-11-preserve-nvs-on-boot-error.md)
uses `take_with(false)` and remains in HOLD on initialization failure. It closes
the old implicit partition-erase policy; physical faulted-storage acceptance and
external recovery remain open. The strict crypto boot check also runs before
NVS initialization, and a failed backend refuses journal access before opening.

Further gates include fresh witness reconciliation and independent pin authority, crash-safe write and
lost-reply reconciliation, encrypted master eligibility, first physical
enrolment and external recovery anchors, fragmented capacity and promotion
reserves, fresh entropy and child release, and physical cut-point testing.
No partition layout, production MLS setting, signed release or board state is
changed by this reader.

SDK reference: [ESP-IDF 5.3.2 NVS declarations and iterator ownership contract](https://github.com/espressif/esp-idf/blob/v5.3.2/components/nvs_flash/include/nvs.h).
