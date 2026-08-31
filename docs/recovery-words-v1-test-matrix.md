# ForgeSworn Recovery Words v1 alpha release gate

Status at 2026-08-31 12:46 BST: **automated gates pass; physical gate blocked
because no Heartwood USB device is connected.** Recovery Words v1 is shipping
only as an explicitly untested alpha until the physical rows pass.

Never copy recovery words into this file, a terminal, a log, a photograph, or
source control. Record only public npubs, firmware/build identifiers, and the
result. Use a test-only signer whose existing contents have been inspected and
are safe to erase.

## Automated evidence

| Gate | Result | Evidence |
|---|---|---|
| TypeScript recovery vectors and all 19/22/25/28/31 counts | PASS | `nsec-tree`: 180 tests |
| Sapwood restore, firmware gating, and all mnemonic strengths | PASS | 850 tests; Svelte and CLI typechecks; web and CLI builds |
| Rust recovery vectors and all mnemonic strengths | PASS | `heartwood-common`: 360 unit + 6 integration tests |
| Heartwood host surfaces | PASS | provision CLI: 15 tests; heartwoodd: 49 tests |
| Firmware build | PASS | Board-aware 0.18.0-alpha.1 release builds: Heltec V3/V4, T-Display and ESP32-C6 |
| Typed Shamir v3 | PASS | 69 tests; mixed payload kinds and mixed split sets rejected |
| End-to-end 2-of-3 | PASS | 19 words -> 28 compact bytes -> 35 words/share -> expected frozen npub |
| Whitespace/diff gate | PASS | `git diff --check` in all four repositories |

The earlier dirty-worktree ELF hashes are deliberately not recorded as release
evidence. The tagged alpha release workflow rebuilds every board from the
merged commit; its signed `version.json` and release assets are the
authoritative artefact hashes.

## Physical matrix

| ID | Ceremony | Expected result | Status/evidence |
|---|---|---|---|
| P0 | Connect the designated test signer; read board, firmware and provision list before mutation | Exact device identified; no unverified identity is erased | BLOCKED: no `/dev/cu.usb*` device present |
| P1 | Flash the reviewed 0.18.0-alpha.1 build | Firmware query reports the reviewed version and board | NOT RUN |
| P2 | Generate a 19-word identity on-device; record words only on paper and record its npub here | Device shows 19 words; host receives only the npub | NOT RUN |
| P3 | Factory-reset the test signer, restore all 19 words on-device, and compare npub | Restored npub exactly equals P2 | NOT RUN |
| P4 | Repeat generation and restore with a 31-word identity | Restored npub exactly matches the generated npub | NOT RUN |
| P5 | Restore scalar-one typed raw-nsec and tree-nsec vectors through Sapwood/CLI | Raw and tree modes return their distinct frozen npubs; conflicting legacy mode is ignored | NOT RUN |
| P6 | Restore passphrase-required typed mnemonic through Sapwood paste/CLI | Missing/wrong passphrase fails; correct passphrase restores expected npub | NOT RUN |
| P7 | Restore explicit legacy 12- and 24-word BIP-39 phrases on firmware 0.18.0-alpha.1 | Existing derivation and npubs remain unchanged | NOT RUN |
| P8 | Attempt a typed non-12 count against pre-0.18 firmware through Sapwood | Sapwood refuses before starting device entry | NOT RUN (automated UI gate passes) |
| P9 | Damage one header word and one payload word in test copies | Both fail before provisioning; no identity is stored | NOT RUN |

## Completion record

Fill these fields without recording secrets:

- Test board and serial identifier:
- Reviewed firmware commit and artefact SHA-256:
- Firmware query after flash:
- P2 generated npub:
- P3 restored npub:
- P4 generated/restored npub:
- Raw-nsec npub:
- Tree-nsec npub:
- Passphrase-vector npub:
- Legacy 12-word npub:
- Legacy 24-word npub:
- Operator and date:
- Deviations or failures:

The four repositories may be merged and published only under explicit alpha
versions and warnings while these rows remain open. Only after P0-P9 pass may
`nsec-tree/RECOVERY.md` change from `alpha` to `stable`, the warning banners be
removed, and stable versions be published.
