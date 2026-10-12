# Offline allocation partition planner

Status: candidate profile evidence only. No partition table/build selection,
firmware owner, storage namespace, erase, flash, migration or capacity authority
is changed. This tool reads a capture and emits an unsigned candidate in JSON;
it always reports HOLD and all physical/migration/capacity approvals false.
Production MLS remains disabled.

The standard default NVS cannot credibly promise the journal's permanent space
alongside the independent default-partition writers. The proposed direction is
a dedicated `hwalloc` data/NVS partition, size 256 KiB, with a separate future
non-erasing owner. The proposed global lifetime ceiling is eight permanent
historical subjects, each with up to 32 retained records. This is not the number
of current master slots: replacement/removal/retirement never frees history.
These parameters remain unmeasured candidates, not a storage guarantee.

## Exact candidate profiles

The source registry is `common/tests/fixtures/allocation-partition-profiles-v1.json`.
It records the source CSV hash, exact expected full-sector predecessor and
successor hashes/bytes, explicit board choices and geometry for five cases:

| Profile | Board choices | Exact claimed flash | New offset |
| --- | --- | --- | --- |
| standard-8MiB | Heltec V3, V4 | 8 MiB | 0x420000 |
| standard-16MiB | Heltec V4 | 16 MiB | 0x420000 |
| single-4MiB | T-Display, C6 | 4 MiB | 0x320000 |
| legacy-v4-two-slot-16MiB | Heltec V4 | 16 MiB | 0x420000 |
| legacy-v4-bigapp-16MiB | Heltec V4 | 16 MiB | 0x420000 |

Board model and installed layout are separate. In particular, standard V4
16 MiB cannot be inferred from either legacy V4 profile. Source CSVs are not
installed state. No real device capture or device-reported geometry has yet
been confirmed: all registry sectors are synthetic expected fingerprints from
the official generator. An actual captured sector must match one exactly for
this planner to produce a candidate. An unknown table cannot be accepted by
changing a caller hash, guessing defaults or finding similar CSV entries.

The accepted input is exactly 4096 bytes from partition-table offset 0x8000,
with an independently recorded full-sector SHA256 supplied separately. Parse
the official 0xc00 table region, require one canonical MD5 record, verify its
digest and require every byte after it through byte 4095 to be 0xff. Refuse
missing/duplicate MD5, early end markers, trailing entries/signatures/data,
malformed labels, duplicates, overlaps and misalignment. Known profiles have
flags zero. Encrypted/read-only/unknown flags, encrypted captures and signed or
otherwise noncanonical sectors are outside this planner's acceptance.

Append one exact little-endian 32-byte entry: magic 0x50aa, type 0x01,
subtype 0x02, offset as listed, size 0x40000, NUL-padded ASCII `hwalloc`, flags
zero. Preserve every old raw entry byte and its order. Recompute the official
MD5 record and pad the remainder with 0xff. Compare the complete successor
with the independent official-generator fixture. This verifies the candidate
format and preservation, not authority to install it. MD5 is the IDF format's
checksum; it is not authentication or a replacement for capture provenance.

The 502 per-history and 4016 eight-history values are NVS entry-slot lower
bounds. The 7938 value is only a theoretical 63-page entry-slot upper limit
with one page excluded; none is byte capacity or measured usable space.
Fragmentation, GC, uncertain writes, intent/promotion reserves and the permanent
global inventory/reservation policy still require separate evidence.

## Reproduce and inspect

No tool download, network, serial access or output-file write happens inside
the planner. Obtain the exact upstream generator separately if regeneration
is needed. The generator checks its pinned SHA256 before invoking it:

```sh
python3 common/tests/fixtures/generate_allocation_partition_profiles.py --idf-tool /path/to/gen_esp32part.py --check
python3 scripts/test_allocation_partition_planner.py
python3 scripts/plan-allocation-partition.py --table /path/to/captured-sector.bin --recorded-sha256 RECORDED_FULL_SECTOR_SHA256 --profile standard-16MiB --board heltec-v4 --device-flash-bytes 0x1000000
```

The independent fixture generator uses [ESP-IDF v5.3.2's partition tool](https://github.com/espressif/esp-idf/blob/v5.3.2/components/partition_table/gen_esp32part.py)
with partition-table offset 0x8000 and explicit flash geometry. It appends the
candidate row to each original CSV, then fills the final 1 KiB with 0xff.
No existing source table or default firmware build is modified.

Seven host safety tests include all five profiles and listed boards, exact
geometry/layout mismatches, every changed capture byte with its recomputed
SHA256, MD5/trailing-byte cuts and corruption, duplicate/overlapping/unaligned
entries, labels/flags/order mutations with valid checksums, and CLI success/
refusal without device access. These are synthetic checks, not physical tests.

## Remaining gates

A claimed board or geometry parameter is not attested device evidence. Preserve
identified-device captures, geometry evidence and independent hashes before
migration planning. Back up/hash the original table and every existing region;
prove the proposed range is unused, safely erase/read back only that range,
and retain a loader/recovery procedure for a torn partition table. OTA alone
cannot perform or establish this migration. No erase/flash command is supplied.

Before firmware activation, implement/review a fixed-identity raw non-erasing
partition owner, inventory and permanent history reservation, and physically
measure full/fragmented/GC/write-cut/reboot behavior. Select and explain the
reset retention/destruction policy separately; ordinary reset must not silently
make retained history look like first use. First enrolment/recovery, authenticated
time, fresh granted signer entropy/KDF, child delivery, browser witnessed custody
and zero-counter promotion, live admission/production and full physical acceptance
remain open. This planner cannot approve any of them.
