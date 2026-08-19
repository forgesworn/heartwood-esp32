#!/usr/bin/env python3
"""
Heartwood HSM setup — provision the ESP32, set bridge secret, and start the bridge.

Run on the Pi with the ESP32 connected via USB serial.

Usage:
    HEARTWOOD_BRIDGE_SECRET=<64-hex> \
    HEARTWOOD_BUNKER_SECRET=<64-hex> \
    python3 setup-hsm.py

Secrets MUST be supplied via environment variables -- never commit them to
source. You will additionally be prompted for the master nsec at runtime
(input hidden, never persisted).

Generate fresh secrets with:

    python3 -c 'import secrets; print(secrets.token_hex(32))'
"""

import binascii
import getpass
import json
import os
import struct
import subprocess
import sys
import time
import zlib


# --- Config ---
SERIAL_PORT = os.environ.get("HEARTWOOD_SERIAL_PORT", "/dev/heartwood-hsm")
BAUD = int(os.environ.get("HEARTWOOD_BAUD", "115200"))
RELAYS = os.environ.get(
    "HEARTWOOD_RELAYS",
    "wss://relay.damus.io,wss://nos.lol,wss://relay.trotters.cc",
)
LABEL = os.environ.get("HEARTWOOD_LABEL", "Heartwood")


def _require_hex_env(name: str) -> str:
    value = os.environ.get(name, "")
    if len(value) != 64:
        sys.stderr.write(
            f"ERROR: environment variable {name} must be 64 hex characters "
            f"(got {len(value)}). See the usage block at the top of this script.\n"
        )
        sys.exit(2)
    try:
        binascii.unhexlify(value)
    except binascii.Error:
        sys.stderr.write(f"ERROR: {name} is not valid hex.\n")
        sys.exit(2)
    return value


BRIDGE_SECRET = _require_hex_env("HEARTWOOD_BRIDGE_SECRET")
BUNKER_SECRET = _require_hex_env("HEARTWOOD_BUNKER_SECRET")


def build_frame(frame_type, payload):
    """Build a heartwood serial frame."""
    length = len(payload)
    crc_data = bytes([frame_type]) + struct.pack(">H", length) + payload
    crc = zlib.crc32(crc_data) & 0xFFFFFFFF
    return b"\x48\x57" + bytes([frame_type]) + struct.pack(">H", length) + payload + struct.pack(">I", crc)


def read_response(port, timeout=35):
    """Read one frame; return (frame_type, payload), or (None, None) on timeout."""
    start = time.time()
    while time.time() - start < timeout:
        b = port.read(1)
        if not b or b[0] != 0x48:
            continue
        b2 = port.read(1)
        if not b2 or b2[0] != 0x57:
            continue
        header = port.read(3)
        if len(header) < 3:
            continue
        resp_type = header[0]
        resp_len = struct.unpack(">H", header[1:3])[0]
        body = port.read(resp_len + 4)  # payload + CRC
        return resp_type, body[:resp_len]
    return None, None


def wait_for_ack(port, timeout=35):
    """Wait for an ACK (0x06) or NACK (0x15) frame; return the frame type."""
    resp_type, _ = read_response(port, timeout)
    return resp_type


# --- bech32 (BIP-173) ---
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    """BIP-173 checksum primitive: hrp_expand(hrp) + data + checksum == 1."""
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i, g in enumerate(generators):
            if (top >> i) & 1:
                chk ^= g
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def decode_nsec(nsec_str):
    """Decode a bech32 nsec to 32 raw bytes, verifying the checksum."""
    nsec_str = nsec_str.strip().lower()
    if not nsec_str.startswith("nsec1"):
        # Might be raw hex
        if len(nsec_str) == 64:
            try:
                return binascii.unhexlify(nsec_str)
            except Exception:
                pass
        raise ValueError("Input must be an nsec (nsec1...) or 64-char hex")

    data_part = nsec_str[5:]
    values = []
    for c in data_part:
        idx = CHARSET.find(c)
        if idx < 0:
            raise ValueError(f"Invalid bech32 character: {c}")
        values.append(idx)
    # Verify the checksum BEFORE stripping it — a one-char typo must fail
    # loudly here rather than silently provision a different key.
    if _bech32_polymod(_bech32_hrp_expand("nsec") + values) != 1:
        raise ValueError("Bad bech32 checksum — check the nsec for typos")
    # Strip 6-char checksum
    values = values[:-6]
    # Convert 5-bit to 8-bit
    acc = 0
    bits = 0
    result = []
    for v in values:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            result.append((acc >> bits) & 0xFF)
    if len(result) != 32:
        raise ValueError(f"Decoded {len(result)} bytes, expected 32")
    return bytes(result)


def main():
    import serial

    print()
    print("=== Heartwood HSM Setup ===")
    print()

    # Step 1: Get nsec
    nsec_input = getpass.getpass("Enter your nsec (hidden): ")
    try:
        secret_bytes = decode_nsec(nsec_input)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    print("Secret decoded OK")

    # Open serial
    print(f"Opening {SERIAL_PORT}...")
    port = serial.Serial(SERIAL_PORT, BAUD, timeout=10)
    port.dtr = False
    port.rts = False
    time.sleep(1)
    port.reset_input_buffer()

    # Step 2: Provision
    print(f"Provisioning as '{LABEL}' (bunker mode)...")
    mode = 0x00  # bunker
    label = LABEL.encode()
    payload = bytes([mode, len(label)]) + label + secret_bytes
    port.write(build_frame(0x01, payload))
    port.flush()
    time.sleep(2)

    resp = wait_for_ack(port, timeout=10)
    if resp == 0x06:
        print("  Provisioned!")
    elif resp == 0x15:
        print("  NACK — provision failed (already provisioned?)")
        port.close()
        sys.exit(1)
    else:
        print("  No response — check device")
        port.close()
        sys.exit(1)

    # Step 3: Set bridge secret
    print()
    print("Setting bridge secret...")
    print(">>> Hold the button on the ESP32 for 2 seconds <<<")
    bridge_bytes = binascii.unhexlify(BRIDGE_SECRET)
    port.write(build_frame(0x23, bridge_bytes))
    port.flush()

    resp = wait_for_ack(port, timeout=35)
    if resp == 0x06:
        print("  Bridge secret set!")
    elif resp == 0x15:
        print("  NACK — denied or already set")
        port.close()
        sys.exit(1)
    else:
        print("  Timeout — did you hold the button?")
        port.close()
        sys.exit(1)

    # Step 4: Read the identity back so the operator can eyeball the npub
    # (same confirmation provision/ does). The checksum catches typos; this
    # confirms the device actually holds the intended key.
    print()
    port.write(build_frame(0x05, b""))  # PROVISION_LIST
    port.flush()
    rtype, rpayload = read_response(port, timeout=10)
    if rtype == 0x07:  # PROVISION_LIST_RESPONSE
        try:
            masters = json.loads(rpayload.decode("utf-8", "replace"))
            for m in masters:
                if not m.get("persona"):
                    print(
                        f"  Device identity: {m.get('npub', '?')} "
                        f"(slot {m.get('slot', '?')}, '{m.get('label', '?')}')"
                    )
        except ValueError:
            print(f"  Could not parse identity response: {rpayload[:64]!r}")
    else:
        print("  (no identity read-back — older firmware?)")

    port.close()
    print()

    # Step 5: Start bridge. Secrets go via the environment — never argv
    # (visible in ps / /proc/<pid>/cmdline for the daemon's whole lifetime)
    # and never echoed.
    print("Starting bridge in passthrough mode...")
    print()
    cmd = [
        "heartwood-bridge",
        "--port", SERIAL_PORT,
        "--relays", RELAYS,
    ]
    env = {
        **os.environ,
        "RUST_LOG": "info",
        "HEARTWOOD_BUNKER_SECRET": BUNKER_SECRET,
        "HEARTWOOD_BRIDGE_SECRET": BRIDGE_SECRET,
    }
    print(f"  {' '.join(cmd)}  (bunker + bridge secrets passed via environment)")
    print()
    print("Bridge output below (Ctrl+C to stop):")
    print("-" * 60)
    try:
        subprocess.run(cmd, env=env)
    except KeyboardInterrupt:
        print("\nBridge stopped.")


if __name__ == "__main__":
    main()
