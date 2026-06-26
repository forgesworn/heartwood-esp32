# heartwood-provision — air-gapped signer setup

`heartwood-provision` puts a signing key onto a heartwood signer (ESP32 or
ESP8266) over USB serial. The key is derived/generated **on this host** and sent
to the device; it is never typed into a browser and never leaves the host except
to the device over the cable.

**Run it on an OFFLINE computer.** A signing key must never touch an
internet-connected machine. The recommended setup is a spare laptop or a Pi with
networking disabled, used only for provisioning. The tool reads secrets
interactively (never from the command line / shell history), and zeroises them
before opening the serial port.

The (internet-connected) **bridge** daemon that couriers Nostr traffic to the
signer never sees the key — it only holds the *bridge secret*, a session token.

---

## Restore an existing key

Plug the device into the offline computer, find its port (`ls /dev/tty*` /
`/dev/cu.*`), then:

```sh
# From a 12/24-word recovery phrase (BIP-39 → tree root):
heartwood-provision --port /dev/ttyUSB0 provision --mode tree-mnemonic

# From an nsec (HMAC → tree root):
heartwood-provision --port /dev/ttyUSB0 provision --mode tree-nsec

# Raw nsec, no tree derivation (vanilla bunker):
heartwood-provision --port /dev/ttyUSB0 provision --mode bunker
```

You'll be prompted for the phrase/nsec (hidden input). The tool shows the npub it
derived, asks you to confirm, then sends it. **Hold the device's button** to
approve when it prompts. It reads the npub back from the device to confirm.

## Generate a fresh key

```sh
heartwood-provision --port /dev/ttyUSB0 generate            # 12 words
heartwood-provision --port /dev/ttyUSB0 generate --words 24 # 24 words
```

The 12/24 words are shown **once** for you to write down — they are the only
backup, and are never written to disk. Type `yes` to confirm, then provision as
above.

## Pair the bridge secret in the same step

The signer answers Nostr only through a `heartwood-bridge` daemon, which shares a
32-byte *bridge secret* with the device. Set it during provisioning:

```sh
# Generate one (printed so you can copy it into the bridge's config):
heartwood-provision --port /dev/ttyUSB0 generate --gen-bridge-secret

# Or use a value you already have (e.g. shown by the Sapwood flasher):
heartwood-provision --port /dev/ttyUSB0 provision --mode tree-mnemonic \
  --bridge-secret <64-hex>
```

The bridge secret is **not** the signing key — it only authenticates the
daemon↔device session, so copying it to the (online) bridge host is fine.

---

## Then: move the device to the bridge host

1. Unplug the signer from the offline computer.
2. Plug it into the always-on computer that runs `heartwood-bridge` (e.g. a Pi).
3. Put the bridge's three files in its `HEARTWOOD_DATA_DIR` — the Sapwood flasher
   renders these for you, or write them by hand:
   - `master.payload` → `hsm:/dev/ttyUSB0` (the device's port on that host)
   - `bridge.secret` → the 32-byte secret you set above
   - `config.json` → `{"relays":["wss://…"]}`
4. Run `heartwood-bridge`. It couriers NIP-46 over your relays to the signer.

The signing key only ever existed on the offline computer and inside the device.
