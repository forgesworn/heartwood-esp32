# Persistent state, reset, and master removal

Status: 2026-07-12.

Heartwood has two independently writable sources of durable configuration:

1. the raw flash-time `config` partition written by the web flasher; and
2. the complete ESP-IDF `nvs` partition, including every namespace.

A destructive reset is complete only after `config` is erased first and the
whole NVS partition is erased second. Each erase is followed by a full readback
verification that every byte is `0xff`. An older board with no `config`
partition is already incapable of re-seeding NVS and is treated as blank; a
missing NVS partition is an error.

Both physical factory reset and the five-wrong-PIN security wipe use this one
path. They acknowledge/display completion and reboot only after both regions
verify blank. An erase failure is displayed and NACKed where a USB request is
in flight; the firmware remains in a retry loop rather than returning to a
signing path with partially erased state.

## NVS inventory

All application-owned NVS state found in the firmware is in the `heartwood`
namespace:

| Keys | Contents / ownership |
|------|----------------------|
| `master_count` | Number of master slots |
| `master_N_secret` | Plaintext master seed when boot PIN protection is off |
| `mN_seed_enc` | PIN-encrypted master seed; compact name stays within ESP-IDF's 15-character key limit |
| `master_N_label`, `master_N_mode`, `master_N_pubkey` | Master metadata |
| `master_N_conn`, `policy_N` | Legacy client secret/policy migration state |
| `connslots_N` | Current client credentials and exact signing policy for master slot N |
| `persona_count`, `pE_ms`, `pE_ix`, `pE_pk`, `pE_pp`, `pE_nm` | Compact persona registry; `pE_ms` owns entry E to a master slot |
| `imanN`, `imavN` | Master-slot display name/avatar |
| `bridge_secret` | Authenticated USB bridge secret |
| `pin_attempts` | Durable wrong-PIN counter |
| `net_config`, `net_trial`, `net_rev`, `net_last`, `ncfg_crc` | Active/staged network configuration, outcome, and flash-seed marker |
| `pinned_rly` | Client-requested relay reachability cache, with master/client slot coordinates |
| `mgmt_nonce` | One-time remote-management mutation challenge, rotated and read back before dispatch |
| `mgmt_seen` | Legacy request-id cache left harmlessly in place but ignored; current duplicate suppression is RAM-only |
| `root_secret` | Legacy single-master seed key; not used by the current boot path |
| `rm_journal`, `rm_pinned` | Temporary power-loss journal and pinned-relay shadow during master removal |

The factory/PIN wipe erases the partition rather than enumerating this table,
so a future or unknown key cannot survive merely because a cleanup list was not
updated.

## Power-safe individual master removal

`PROVISION_REMOVE` remains available for any existing slot. Removal is a
journalled transaction completed before the firmware reloads or serves any
identity:

1. Persist the versioned, CRC-protected `rm_journal` and shadow the original
   `pinned_rly` cache.
2. For each higher master, copy source slot `i + 1` to destination `i`, including
   seed/plain-or-encrypted metadata, `connslots_N`, both legacy policy keys, and
   `imanN`/`imavN`. The source remains intact until all copies finish.
3. Compact personas: remove entries owned by the target and decrement owners
   above it. The original owner byte is journalled before an in-place rewrite,
   so retry cannot decrement it twice.
4. Clear the persona tail and terminal source-slot bundle.
5. Rebuild `pinned_rly` from its original shadow: target-owned entries are
   removed and higher master coordinates decrement. Malformed cache data is
   discarded because it is reachability state, not signing authority.
6. Remove the legacy global `root_secret`, commit and verify the new
   `master_count`, then delete the shadow and journal.
7. ACK and reboot so master, policy, persona, identity, and relay caches all
   reload from the completed transaction.

Every data mutation precedes its cursor advance and is safe to repeat. Boot
resumes a surviving journal before loading any secret or authority. If corrupt
authoritative state prevents recovery, signing stays blocked and the screen
offers a deliberate two-second PRG hold to perform the full persistent wipe;
the error never causes an automatic factory reset.
