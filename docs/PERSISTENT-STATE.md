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

### A wipe costs one power-cycle before new keys

The boot RNG self-test proves the hardware entropy source is live by comparing
this boot's draw against a hash of the previous boot's, held in NVS under
`rng_proof`. A wipe erases that proof along with everything else, so the boot
immediately afterwards has nothing to compare against — and that is precisely
the boot an owner provisions on. The device therefore seeds a fresh proof and
stays UNVERIFIED on a post-wipe boot: signing continues, but generating a seed
or minting a slot secret is refused until one more boot proves the draw
changed. The refusal says so ("power-cycle the signer once, then retry") and is
not a fault. Order of operations after a reset: **wipe, power-cycle, then
provision.**

## NVS inventory

All application-owned NVS state found in the firmware is in the `heartwood`
namespace:

| Keys | Contents / ownership |
|------|----------------------|
| `master_count` | Number of master slots |
| `master_N_secret` | Plaintext master seed when boot PIN protection is off |
| `mN_seed_enc` | Sealed master seed (PIN or vault key): an 82-byte `HWDK` blob under the data key from beta.17, or the older 92- or 101-byte `seed_cipher` record until the first unlock on beta.17 or later migrates it; beta.16 and older read only the older records. Compact name stays within ESP-IDF's 15-character key limit |
| `master_N_label`, `master_N_mode`, `master_N_pubkey` | Master metadata |
| `master_N_conn`, `policy_N` | Legacy client secret/policy migration state |
| `connslots_N` | Current client credentials and exact signing policy for master slot N |
| `persona_count`, `pE_ms`, `pE_ix`, `pE_pk`, `pE_pp`, `pE_nm` | Compact persona registry; `pE_ms` owns entry E to a master slot |
| `imanN`, `imavN` | Master-slot display name/avatar. `imavN` is `[0x00][0x01][w][h]` then `w*h` bytes of RGB332 (`identity_avatar::encode_stored`; an Rgb565 picture converted, an RGB332 one as it came; 2,308 B for 48x48); earlier firmware stored `[w][h]` then `w*h*2` bytes of Rgb565, which is still read and never rewritten. The first form cannot be mistaken for the second (a legacy blob with `w` = 0 has no pixels). Firmware up to 0.18.0-beta.38 reads the new form as no picture and shows no card for that identity, its name included, until Sapwood sends the picture again. A cached picture is dropped when a pairing table, network config, persona or phone write would otherwise be refused or, after its erase, lost, or could then go in place rather than erase first (an in-place-only rewrite of a stored key, which the bound refuses before ESP-IDF is asked, only when its room lets it land) (`nvs::make_room_to_replace`, `make_room_to_grow`); a picture is stored only with room left for a full-size network config rewrite (`nvs::avatar_allowed`) |
| `bridge_secret` | Authenticated USB bridge secret |
| `pin_fails` | Durable wrong-PIN counter (`u8`); `pin_attempts` is the one-byte blob earlier firmware used, read until the first guess or unlock moves it. A downgrade reads only the blob, so it shows 0 |
| `net_config`, `net_trial`, `net_rev`, `net_last`, `ncfg_crc` | Active/staged network configuration, outcome, and flash-seed marker |
| `pinned_rly` | Client-requested relay reachability cache, with master/client slot coordinates |
| `mgmt_nonce` | Legacy device-operator one-time remote-management mutation challenge, rotated and read back before dispatch |
| `mgmt_<operator-prefix>` | Per-delegated-operator one-time challenge record, bound to the full public key; a prefix collision fails closed rather than sharing a replay boundary |
| `mgmt_seen` | Legacy request-id cache left harmlessly in place but ignored; current duplicate suppression is RAM-only |
| `root_secret` | Legacy single-master seed key; not used by the current boot path |
| `rm_journal`, `rm_pinned` | Temporary power-loss journal and pinned-relay shadow during master removal |
| `dk_sec`, `dk_ph`, `lk_boots`, `ann_op`, `ph_relays` | Phone unlock: the data key's PIN/vault wrapper, the packed phone records, the locked-restart count, the operator-announcement switch, and `ph_relays`, the relays the phones were last told about with the count of relay-update rounds sent (written when first needed, when a change only dropped relays, after each of a relay change's six update rounds, the last of which records the new list, and replaced at the first enrolment after every phone has gone; never on a network-trial boot, never over a record this firmware cannot read; removed with the last phone) |
| `rng_proof` | SHA-256 of last boot's RNG self-test draw; a wipe clears it, costing one power-cycle before new key material (see above) |

Every blob in this table is written through `ReplaceBlob`
(`firmware/src/nvs.rs`), which calls ESP-IDF's `nvs_set_blob` with no erase
in front of it when there is room for the new copy beside the old one: a
power cut during the write then leaves the old value or the new one. With no
room, the secrets and the keys whose loss weakens the board (`dk_sec`,
`mN_seed_enc`, `master_N_secret`, `at_rest_kind`, `bridge_secret`,
`rzrec_N`, `net_config`, `net_trial`) are refused and keep their value, and
every other key is erased and then written, as all writes were before, so a
cut there loses that key. `pin_fails`, `net_rev` and `ncfg_crc`
are integer items, which ESP-IDF replaces new-before-old in a single entry.
No write spans two keys, which is what the journals below are for. See
"Power cuts and NVS writes" in SECURITY-MODEL.md for the per-key table.

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
