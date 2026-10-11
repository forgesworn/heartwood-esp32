# Preserve NVS on boot initialization failure

The firmware boot path now calls `EspDefaultNvsPartition::take_with(false)`.
In esp-idf-svc 0.52.1, `take()` calls `take_with(true)` and responds to
`ESP_ERR_NVS_NO_FREE_PAGES` or `ESP_ERR_NVS_NEW_VERSION_FOUND` by erasing and
reinitializing the default partition. These errors cannot establish that
stored keys, custody journals or witnessed history are disposable.

Any partition initialization or initial `heartwood` namespace-open error now
logs only its numeric SDK code and enters a permanent boot hold. The display
reads `STORAGE HOLD`, `Preserve device`, `Recovery needed`. This path stays
before note storage, entropy initialization, seed/persona loading, command
processing and radio startup. It feeds the already-armed watchdog and delays
100 ms per iteration. It never retries initialization, offers a wipe, starts
provisioning, handles commands or automatically restarts the device.

Successful initialization retains the existing boot order and namespace
creation behavior. This change does not provide an external recovery protocol,
prove that all SDK initialization is physically read-only, validate every NVS
value, or make absent allocation journals legitimate genesis. Explicit physical
enrolment, external recovery anchors and all durable-writer/witness gates remain
required. It closes only the automatic partition-erase policy described in the
[dormant journal reader](2026-10-11-allocation-journal-nvs-reader.md).

Validation requires source review of both failure branches and their ordering,
the existing host/UI checks, and every production board build and image-size
gate. Physical acceptance remains open: use a spare board with a retained raw
partition backup, reproduce both SDK initialization errors, and verify that
repeated resets preserve its partition and remain in hold. Do not manufacture
faults on a device holding the owner's only keys. Confirm the three display
lines on each panel and ensure no USB command processing or network activity
starts. This is a checklist, not evidence that those checks have occurred.

No partition layout, dependency, signed release, production MLS flag or physical
board is changed by this source patch.
