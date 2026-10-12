# Dormant private allocation partition owner

The dedicated allocation partition needs an owner that cannot silently erase or
substitute storage. The existing `EspCustomNvsPartition::take` convenience path
can erase and reinitialize on full/new-version errors. This private foundation
uses the raw ESP-IDF v5.3.2 pointer initialization API instead. There is no boot,
command, serial, browser, relay or writer call site for the new owner.

## Identity before initialization

The production constructor selects the compiled board internally. Callers cannot
supply a label, layout, namespace, flash bytes or descriptor. It checks the actual
default chip's full raw 4096-byte sector at `0x8000`, hashing sixteen 256-byte reads.
Only the five exact successor fingerprints in the pinned official-generator
fixtures are accepted. Predecessors and unknown bytes hold before initialization.
The accepted profiles and fixed `hwalloc` entry come from the offline planner;
the default CSVs, firmware partition selection and installed device are unchanged.

Physical capacity comes from `esp_flash_get_physical_size`. Configured/addressable
capacity comes separately from `esp_flash_get_size`. Both must be one of 4, 8 or
16 MiB, with addressable capacity no larger than physical and every known old/new
range addressable. The board/profile must match physical capacity: V3/V4 standard
8 MiB; V4 standard and either legacy 16 MiB; T-Display/C6 single 4 MiB. V4 physical
16 MiB/header 8 MiB is accepted only with the exact corresponding profile and
all ranges fitting. A 4 MiB header cannot address the 8/16 MiB profiles' new range.
This SDK result is not independent physical device identification or provenance.

Exactly one SDK descriptor must match the fixed label, including its NUL tail,
data/NVS type/subtype, fixed offset, 256 KiB size, default chip, 4096-byte erase
size, encryption false and read-only false. A same-label duplicate or descriptor
mismatch holds. The iterator tracks the SDK's consumed/current pointer and releases
only that pointer, including every error path. No arbitrary pointer is accepted.

## Permanent boot lifecycle

A global atomic CAS changes `Virgin` to `Acquiring` before the first SDK operation.
Only the successful exact pre/post-init identity checks permit `Live`. Every
acquisition failure or observed owner drift leaves `Poisoned` until reset. A
competing acquire changes nothing and makes no SDK call. Dropping a live owner
leaves `Retired`; it does not deinitialize and cannot permit reacquisition that
boot. The private owner has no Clone, Debug, Send, Sync or raw-handle export.

Initialization happens at most once per boot using the exact verified SDK pointer.
Errors including no-free-pages, new-version and uncertain state hold without
an erase, reinitialization, convenience take, default fallback or retry. Raw NVS
initialization, even when successful, can write normal metadata or perform
recovery. This is **not zero-write, migration or measured-capacity evidence**.

## Nominal root-bound read boundary

The only read API takes a concrete `HeldAllocationRoot`. It rechecks actual root
custody and the crypto backend, derives its namespace internally, and opens fixed
`hwalloc` read-only. The handle borrows the owner and cannot escape. The existing
in-handle collector performs two matching complete scans, exact-width/key checks
and the authenticated journal codec. Owner geometry, table and descriptor are
rechecked before and after every SDK open/inventory operation. Status/pointer
contradictions and observed drift hold; owner drift permanently poisons it.

The current NVS iterator and handle close **before** both final root and owner
checks on success and error. Even a custody failure still executes the final
owner check. Missing namespace/history is HOLD; a report only describes local
authenticated stored bytes needing a fresh external witness. It creates no
anchor, manifest, child, first-use decision, high-water authority or browser ledger.

Default encrypted root custody, legacy inspection and the dormant default writer
retain their existing paths. The collector's optional owner-check hook is a no-op
for those existing adapters. There is no custom RW, generic namespace, write,
commit, erase, reset, deinitialization, entropy or authority-producing facade.

## Validation and remaining gates

Host tests execute the actual firmware owner and collector with only SDK I/O
mocked. They cover five-profile/board/header combinations; every altered sector
byte and predecessor refusal; all descriptor fields, duplicates and missing
partitions; every bounded acquisition-read cut; SDK init errors; pre/init drift;
competing acquisition/drop/no-retry; authenticated double inventory; read errors;
per-operation drift, pointer/status contradictions and cleanup before final checks.
The firmware backend gets an explicit locked hosted test step, alongside the full
existing suite and all four real firmware ABI/build/image-budget jobs.

No installed partition capture, device migration, flash/reset or signed release
was performed. Physical identity and capture provenance, unused-range/backup and
migration cut recovery, measured full/fragmented/GC/write-cut capacity and permanent
subject reservations, reset retention, physical selected-master/issuer ownership,
first-enrolment permanent CAS and independent recovery, authenticated time,
fresh-R entropy/KDF integration, child delivery/browser witnessed custody and
live production acceptance remain open. This owner must stay dormant until its
separate integration and acceptance gates are satisfied.
