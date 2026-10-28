# Select the default NVS explicitly during destructive reset

PIN-threshold and physical factory-reset paths call `persistent_wipe::erase_all`.
The adapter erases and verifies the `config` partition first, then the mandatory
default NVS. Previously the NVS lookup selected the first data/NVS partition,
with no label. That depends on table order: a secondary NVS partition placed
first could be erased while the real default `nvs` retained the master keys.
Likewise a missing default could incorrectly report successful erasure of some
other NVS partition.

Select data/NVS with the exact `nvs` label. Other NVS partitions are not a
substitute. Missing default or wrong type/subtype remains a wipe error; no caller
may report success or reboot through that error. Preserve the existing config
before default-NVS order, optional absent-config behavior, complete raw readback,
nonblank refusal and retry behavior. This changes no supported partition table,
creates no new partition, and does not initiate any reset or flash operation.

Host tests execute the actual firmware erase/readback adapter. Only raw SDK
partition discovery, erase and read calls are replaced. The mock puts a secondary
NVS before the default, records every touched range, and represents partial
failed erasure. Tests cover exact named selection, missing/wrong-type default,
legacy absent config, erase failure at each region, every readback failure,
nonblank final bytes and exact complete-order retry. The secondary partition
remains untouched in every case. Chunk checks include partial final reads.
These are adapter/fault tests, not physical flash-cut or SDK ABI acceptance;
actual board CI still has to compile the production SDK path.

A future dedicated allocation partition remains a separate construction. Its
fixed identity, non-erasing initializer, exact preserving table migration,
capacity/GC/reservation and reset/retirement semantics need review and physical
acceptance. Ordinary reset must never turn loss of allocation history into new
first-use authority. If that future construction retains allocation ciphertext
or tombstones across reset, the UI and reset documentation must explicitly state
what remains; current wording must not silently imply complete metadata erasure.
No such partition or reset-policy extension is enabled by this correction.

SDK source: [ESP-IDF 5.3.2 partition lookup](https://github.com/espressif/esp-idf/blob/v5.3.2/components/esp_partition/include/esp_partition.h).
