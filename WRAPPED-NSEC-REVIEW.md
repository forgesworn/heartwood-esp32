# Wrapped-account source review, 16 November 2026

Implementation review and regression evidence, not independent security
approval. The format remains a test-key preview. Keep Heartwood #309 and
Sapwood #200 draft until physical acceptance is recorded. No live signer was
opened, flashed, reset or provisioned for this review.

## Scope and trust boundary

Reviewed Heartwood `66e239a` and Sapwood `9bf6dc4`, followed by the fixes in
these paired PRs. The PR heads and retained evidence manifest identify the
exact subsequent source revisions and builds. Compared the codec with
nsec-tree's frozen public wrapped-record fixture and `WRAPPED-NSEC.md`.
Existing derivation and Recovery Words vectors are unchanged.

The USB host supplies bounded commands and ciphertext. The existing bridge
session flag and fresh physical full-npub approval authorise each operation.
The signer selects unlocked slot/key/npub/mode tuples, performs the existing
mode-specific root conversion once, and returns ciphertext or public receipts.
No raw secret, relay recovery API, automatic activation, pairing grant or
derivation attestation is added. A compromised host can request a ceremony;
the physical review is still essential.

## Findings and corrections

| Finding | Evidence before correction | Correction / verification |
| --- | --- | --- |
| A committed restore could leave stale in-memory identity state after a failed count-write acknowledgement. | Actual firmware storage code under the host NVS harness reproduces count 2 with an error; the reload regression fails. Durable slot contents remain complete. | Storage errors distinguish pre-publication refusal from uncertain publication. The cable handler sends an uncertain-outcome NACK, flushes and reboots on the latter before serving again. Both pre-commit and committed-with-error publication faults require reload; a pre-publication secret-write fault does not. The physical reboot path remains a bench check. |
| An older file read could win a race against the latest selected file. | Two component regressions fail: a slow old file replaces the latest valid record, or revives an old record after the latest selection is rejected. | A selection generation invalidates all older reads and errors. The check request uses only the latest valid selection. |
| Wrapping used the pre-radio entropy helper even on a USB cable attached to Wi-Fi firmware. | `wrapped_nsec::execute` called `fill_random_strong`, which brackets the SAR-ADC source. `main::fill_random` already selects the appropriate source for the current radio state. | Reuse `fill_random`; keep the boot RNG gate and fresh 44-byte salt/nonce draw. Compile evidence does not establish physical entropy quality or RF behaviour. |
| Sapwood accepted undocumented fields in a successful receipt. | A check receipt with an extra field was accepted by the API regression. | Require the exact per-operation fields, bound payloads before decoding and reject malformed UTF-8. Valid firmware check/restore receipts remain accepted. |

The RNG correction follows Espressif's rule that the temporary bootloader
entropy source must be disabled before Wi-Fi/Bluetooth use. See the
[ESP32 RNG guidance](https://docs.espressif.com/projects/esp-idf/en/v5.4.2/esp32/api-reference/system/random.html).

## Checked invariants and limits

* The 181-character/131-byte canonical record, suite/kind rejection, authenticated
  header, scalar validation and recomputed public key match the frozen fixture.
  Wrong roots/expected npubs and each single-byte record mutation are rejected.
* Selected secrets must match displayed npubs before mode-specific root
  conversion. Raw targets remain mode 0. Restores refuse existing master and
  persona npubs, require the next empty slot and clear its complete stale bundle.
* At-rest protection inspection fails closed. A new raw slot is refused while
  any existing slot is sealed; PIN/vault protection is not disabled automatically.
* Restore writes and reads back all fields before publishing the count. Host
  faults cover stale-authority cleanup, protection reads and secret read-back.
* The browser sends the physical operation once. An overdue serial response
  closes the session and rejects queued work so a late reply cannot satisfy
  another operation. Saved-file checks bind the root, expected npub and record.
* Caller-owned Rust key/payload/read-back buffers use `Zeroizing`; AES, GHASH and
  POLYVAL erasure features are explicit. This does not establish erasure of all
  compiler copies, registers or internal HKDF/HMAC/SHA state. The pinned hkdf
  0.12.4/hmac 0.12.1 source retains keyed digest state without an explicit
  zeroising drop. No custom crypto or dependency replacement is introduced;
  assessment of that residual-memory threat belongs in independent review.

## Bench acceptance record to complete

Use a separate disposable board and public test keys only. Record the exact
firmware source, ELF/app hashes, board, partition table and Sapwood revision.
Do not use the owner's live signer. Independently retain A and B before testing.

| Test | Required observable result | Evidence |
| --- | --- | --- |
| Wrap and saved-file check in USB-only mode, then with Wi-Fi active | Complete root/target npubs and action; all three pages; fresh 5-second hold; generic encrypted file verifies as B | Pending physical |
| Cancel, timeout and pre-held button | No approval from a prior hold; no restored slot or record success claim | Pending physical |
| Wrong A, wrong expected npub and modified file | Refusal, no storage mutation | Pending physical |
| Independently remove only disposable B, then restore | Next empty raw slot; exact B npub; no automatic activation or copied app/delegate grant | Pending physical |
| Reboot and sign a disposable event with restored B | Same B npub and valid event signature after restart | Pending physical |
| Simulated failed final count acknowledgement | Uncertain-outcome NACK; signer reloads before serving; refresh shows either the old slot set or one complete B | Host fault passes; physical reboot pending |
| Bench power cut before and after count publication | Old slot set or one complete new B; original slots unchanged | Pending physical |
| PIN/vault-encrypted state | Restore refused without plaintext slot creation or protection changes | Host fault passes; physical pending |

The existing firmware-backend/common suites, Sapwood unit/component tests,
type/build checks and T-Display release build are required after these fixes.
Retain exact receipts and artifact hashes under
`/tmp/wrapped-review-20261116/`; this document is a review map, not a replacement
for that evidence or independent approval.
