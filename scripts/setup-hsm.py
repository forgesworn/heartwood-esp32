#!/usr/bin/env python3
"""
Heartwood HSM setup — provision the ESP32, set bridge secret, and start the bridge.

Run on the Pi with the ESP32 connected via USB serial.

Usage:
    python3 setup-hsm.py

You will be prompted for your nsec (input is hidden).
"""

import binascii
import getpass
import struct
import subprocess
import sys
import time
import zlib


# --- Config ---
SERIAL_PORT = "/dev/heartwood-hsm"
BAUD = 115200
BRIDGE_SECRET = "6db9d0876c4f390b589810fecdcc23e7cc82ae1ebf56cdb483355dc8ffd65d69"
BUNKER_SECRET = "3bd5c8427095d4a2b7bc292905962dbe257eedfa86223045caa300d6976d99a9"
RELAYS = "wss://relay.damus.io,wss://nos.lol,wss://relay.trotters.cc"
LABEL = "primary"


def build_frame(frame_type, payload):
    """Build a heartwood serial frame."""
    length = len(payload)
    crc_data = bytes([frame_type]) + struct.pack(">H", length) + payload
    crc = zlib.crc32(crc_data) & 0xFFFFFFFF
    return b"\x48\x57" + bytes([frame_type]) + struct.pack(">H", length) + payload + struct.pack(">I", crc)


def wait_for_ack(port, timeout=35):
    """Wait for an ACK (0x06) or NACK (0x15) frame."""
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
        port.read(resp_len + 4)  # payload + CRC
        return resp_type
    return None


def decode_nsec(nsec_str):
    """Decode a bech32 nsec to 32 raw bytes."""
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
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

    port.close()
    print()

    # Step 4: Start bridge
    print("Starting bridge in passthrough mode...")
    print()
    cmd = [
        "heartwood-bridge",
        "--port", SERIAL_PORT,
        "--bunker-secret", BUNKER_SECRET,
        "--bridge-secret", BRIDGE_SECRET,
        "--relays", RELAYS,
    ]
    print(f"  {' '.join(cmd)}")
    print()
    print("Bridge output below (Ctrl+C to stop):")
    print("-" * 60)
    try:
        subprocess.run(cmd, env={**__import__("os").environ, "RUST_LOG": "info"})
    except KeyboardInterrupt:
        print("\nBridge stopped.")


if __name__ == "__main__":
    main()
