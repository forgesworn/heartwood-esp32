# Development device state recovery

Heartwood's normal portable backup deliberately excludes bearer notes and an
identity generated on-device never exports its seed. That remains the product
security model.

For our development Heltec only, `scripts/dev-state-backup.mjs` provides a
separate disaster-recovery image. It reads the complete NVS partition, so the
encrypted artifact contains all of the following:

- retained master seeds and derived Nostr identities;
- NIP-46 client pairings and their device-side state;
- network/operator state stored in NVS;
- every LUD-25 bearer-note record, including note secrets; and
- the raw partition table, config partition and OTA selection state.

This is a device clone, not an account-level export. Keep it encrypted, never
attach it to an issue or release, and restore it only while the original is
retired or unavailable. Duplicate note records are acceptable for this dev DR
copy while it is dormant; running both copies risks two devices attempting to
spend the same bearer value.

## Create and verify a backup

Install Espressif's current `esptool`, have two independent age recipients,
and keep at least one verification identity available locally. The tool stages
plaintext only on `/dev/shm` (Linux) or a temporary RAM disk (macOS), encrypts
to exactly two recipients, decrypts the finished artifact in memory to verify
it, and atomically renames the ciphertext into place.

```sh
node scripts/dev-state-backup.mjs \
  --port /dev/cu.usbmodem3401 \
  --firmware-version 0.18.0-beta.5 \
  --out /secure/heartwood-heltec-v4-dev-state-YYYYMMDDTHHMMSSZ.tar.gz.age \
  --recipient age1LOCAL... \
  --recipient age1OFFSITE... \
  --verify-identity /secure/local-age-identity.txt \
  --esptool /secure/tools/esptool \
  --leave-in-loader
```

Copy only the encrypted `.age` file off-site. Store the second identity
separately from both the signer and the first identity.

## Install a signed release without truncating legacy NVS

The named 16 MB Heltec V4 has a 24 KiB legacy NVS at `0x9000`. Never flash the
fleet Heltec table over it. Beta releases carry a separate
`partition-table-heltec-v4-legacy-nvs-bigapp.bin` and describe it under
`boards.heltec-v4.migration.legacyNvsBigApp` in `version.json`.

The migration refuses every write until it has verified the release hashes and
ed25519 signature, recognised one of the two committed legacy layouts, and
proved that the encrypted backup's partition-table and NVS hashes exactly
match the attached board. It then writes and reads back only the app,
bootloader, safe partition table and blank OTA selector. NVS and config are
never written.

```sh
cargo +stable build --release --manifest-path ota-sign/Cargo.toml
node scripts/migrate-legacy-v4.mjs \
  --port /dev/cu.usbmodem3401 \
  --release-dir /secure/heartwood-v0.18.0-beta.5 \
  --backup /secure/heartwood-heltec-v4-dev-state-....tar.gz.age \
  --backup-identity /secure/local-age-identity.txt \
  --esptool /secure/tools/esptool \
  --loader-session \
  --check-only
```

Run that exact command once with `--write` in place of `--check-only` only
after the read-only gate succeeds. Do not reset, unlock, power-cycle or run a
normal esptool command between backup, check-only and write: all three phases
share one flasher-stub session so firmware cannot rewrite NVS or boot from a
partially updated image between operations. The final verified readback is the
only command that hard-resets into the new firmware.

After migration, run `scripts/vault-unlock.mjs`, verify the master and note
counts, power-cycle and repeat the unlock, then complete a tiny-value
mint-confirm-export-melt-spent round trip before publishing the beta draft.
`scripts/net-mode.mjs` provides the physically confirmed, password-preserving
switch to USB mode needed for local note housekeeping, and the matching switch
back to WiFi relay mode afterwards.
