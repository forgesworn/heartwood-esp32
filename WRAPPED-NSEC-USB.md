# Wrapped accounts over USB, v1

Test-key preview. Independent security review and physical recovery acceptance
are separate gates. The format is the published nsec-tree
[WRAPPED-NSEC.md](https://github.com/forgesworn/nsec-tree/blob/main/WRAPPED-NSEC.md).
The shared public fixture is copied unchanged into
`common/tests/fixtures/wrapped-nsec-v1.json`.

An unrelated existing account B can be encrypted under A's tree root without
changing B's raw secret or npub. Recovery requires **the same root construction
and the encrypted file**. A alone cannot derive B. This is imported custody,
with no public linkage, derivation attestation or app authority inherited from A.

This remains local, owner-controlled software. The change adds no hosted
endpoint, telemetry, server-side key custody or new relay payload.

## Transport and authority

`FIRMWARE_INFO` advertises `wrapped_nsec_usb_v1`. This capability is deliberately
cable-only, including a cable attached to WiFi-standalone firmware. There is no
relay-management or NIP-46 recovery method and no generic decrypt fallback.

Authenticated bridge session required for every operation. New frame `0x68`
contains one UTF-8 JSON command, at most 768 bytes. `0x69` answers with a public
JSON receipt; failure is `NACK` with a bounded reason. Unknown fields and
operations are refused. Send each ceremony once. A lost restore reply requires
refreshing the identity list before another attempt.

Each root/target reference is `{slot, npub, mode}` and must match an unlocked,
currently loaded master exactly. Personas are not raw-key slots. Distinct root
and target slots are required. The device also derives each selected slot's
actual public key and compares it with that reference before root conversion;
cached identity metadata alone is insufficient. Commands:

```json
{"op":"wrap","root":{"slot":0,"npub":"<A npub>","mode":1},"target":{"slot":1,"npub":"<B npub>","mode":0}}
{"op":"check","root":{"slot":0,"npub":"<A npub>","mode":1},"record":"nstw1:...","expected_npub":"<B npub>"}
{"op":"restore","root":{"slot":0,"npub":"<A npub>","mode":1},"record":"nstw1:...","expected_npub":"<B npub>","destination":1,"label":"existing account"}
```

`wrap` returns `{op,npub,record}`. `check` returns `{op,npub}` only after
authenticating the record, validating its scalar, recomputing its public key and
matching the expected npub. `restore` additionally returns
`{slot,mode:0,derivation_version:0}`. No response includes a raw secret.

All three operations require physical approval. The existing three-page dwell
and button-release gate shows the complete root npub and mode, the complete
target npub, and the operation with restore destination. Each page must have
its full dwell before a fresh five-second hold can approve. B cancels on
two-button boards. Timeout or denial changes nothing.

## Root and storage semantics

Firmware tree modes 1 and 2 already store a tree-root secret: use it directly.
Bunker/raw mode 0 stores the original nsec: apply the existing
`nsec_to_tree_root` HMAC once. These are exactly the existing device derivation
semantics; the wrap code calls the same helper. Choosing another construction
does not recover the record.

Only mode-0 targets can be wrapped. Fresh salt and nonce come from the device's
strong RNG after its boot self-test; the host cannot supply either. RustCrypto
AES-256-GCM/HKDF implement the frozen format, with the existing secp256k1 backend
on the device. Owned key, payload and read-back buffers zeroise on drop.
AES, GHASH and POLYVAL erasure features are enabled explicitly: AES-GCM's
own `zeroize` feature does not enable all retained authenticator erasure.

Restore refuses existing master or persona npubs and accepts only the next
empty master slot. It clears that slot's complete stale bundle, including
connection slots, policies, delegate operator, encrypted-seed leftovers and
display/receipt state. It writes and reads back the raw secret and public
metadata before atomically publishing `master_count`. An interrupted restore
leaves the previous visible slot set or the complete new raw slot. A lost
commit acknowledgement may mean success: refresh/reboot, never overwrite.
Host tests inject pre-commit failures, commits that return errors, unreadable
protection state, failed authority cleanup and corrupted secret read-back.

As with existing device provisioning, adding a new identity while at-rest seed
encryption is active is refused. This preview has no retained unlock key with
which to seal the new slot. It never writes a plaintext slot beside encrypted
ones or disables the owner's PIN/vault configuration automatically. Wrapping
and checking unlocked slots do not change at-rest protection.

## Sapwood and other clients

Sapwood's Identity panel selects both real slots, downloads a generic
`imported-account.nstw`, then requires the user to select the saved file and
check it on the device before claiming verification. Restore requires that
same root/file/expected-npub check and a named, empty destination. No browser
decrypt, automatic activation, pairing migration or raw-key export is added.

Bark's fixed method allow-list and Cambium's typed NIP-55/Heartwood interface
remain unchanged. A restored identity needs its normal app pairing and physical
identity consent. Bray's already released owner CLI/SDK remains a separate
software custody path; no recovery MCP tool or signer extension is added.

## Physical acceptance still required

Use a disposable signer with verified independent recovery, not an owner's live
wallet. Record the exact firmware ELF, board, port and partition layout before
flashing. With public test keys, wrap B under A, cancel a ceremony, reject a
wrong root and corrupted file, check the saved file, remove only the disposable
B slot, restore to the empty slot, reboot and sign an event with B's exact
npub. Verify no app permission or delegate followed the slot. Exercise a power
cut before and after the count publication on a bench partition. Host tests,
rendered screens and an ELF size check do not establish this acceptance.
