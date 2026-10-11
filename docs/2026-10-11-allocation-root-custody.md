# Private allocation root custody prerequisite

The dormant `firmware/src/allocation_root.rs` validates the original NVS
metadata and exact persisted seed of one exclusively borrowed `LoadedMaster`.
There is no runtime caller, allocation request, generic signing API, key export,
child release or MLS activation. The future physical owner still has to route
its actually selected identity; this gate alone cannot establish that selection.

Mode, derivation version, issuer, master count and slot must have exact widths
and valid values. Missing legacy metadata holds instead of using `load_one`'s
fallback. A pending master-removal journal holds. The loaded seed must be
unlocked, a valid scalar, and have the exact stored actual x-only issuer before
mode normalization. The actual issuer remains separate from the normalized root.

A public-key comparison alone is insufficient: scalars k and n-k share an
x-only key but derive different allocation namespaces. For plaintext storage,
the gate compares the exact stored seed. For encrypted storage, it authenticates
and opens every counted data-key sealed seed, requires no plaintext shadows,
and compares the selected seed's exact bytes. A
missing/wrong held data key, malformed ciphertext, old directly PIN/vault sealed
format, plaintext shadow or mixed plaintext/encrypted board state holds. This
code performs no migration or storage repair.

The existing `LoadedMaster` definition and Drop move without semantic changes
to `master_identity.rs`; `masters` re-exports the same type. The existing
current/remember/forget data-key functions move unchanged to `held_data_key.rs`
and remain re-exported by `data_key_store`. The new private guard uses try_lock:
contention or mutex poison holds, while its lifetime excludes remember/forget.
Legacy calls recover poison as before; the new allocation gate does not.

The held root owns Zeroizing normalized bytes, an exclusive mutable borrow of
the loaded master and NVS handle, and the boot data-key guard. It exposes only
the actual public issuer and a strict recheck. It cannot be constructed from
raw bytes, cloned, printed or exported. A failed recheck holds without replacing
the root. No callback or await is accepted. Any future owner must recheck before
and after its authority decision and drop custody before calling the legacy
current/remember/forget APIs, which otherwise block on the same mutex.
Rust borrows exclude mutations through this handle; they do not establish
exclusive ownership against separately opened NVS handles, malicious firmware,
physical flash changes or simultaneous rollback.

Owned normalized buffers and authenticated decrypted-seed buffers wipe on
normal Drop. Existing curve, HMAC normalization and data-key primitives still
have internal/returned stack temporaries without a comprehensive wipe guarantee.
Panic abort, reset and power loss do not run Drop. This prerequisite does not
claim all stack copies wipe, alter existing master custody or approve a future
writer-key constructor. Dalek 2.2 with minimal zeroize features remains a reviewed
direction only; no new crypto dependency is added here.

Host tests include the actual firmware modules, with only ESP NVS I/O replaced
by the existing fault-injection mock. Five independent Vennel namespace vectors
exercise normalization and issuer separation. Tests cover original metadata
absence/width/version errors, locked/invalid/substituted seeds, x-only scalar
ambiguity, read failures, authenticated encrypted seeds, legacy-format refusal,
plaintext downgrade, durable drift and concurrent/nested guard refusal. CI runs
these on both curve backends. These are automated host results, not hardware
NVS, PIN-unlock, power-loss or physical approval acceptance.

Permanent allocation journal, physical witness/installation/genesis enrolment,
typed writer requests and strict receipts, fresh-R entropy/KDF, browser child
and counter-ledger promotion, and complete firmware/physical acceptance remain
required. No production allocation flow is enabled by this prerequisite.
