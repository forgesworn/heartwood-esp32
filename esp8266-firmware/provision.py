#!/usr/bin/env python3
"""Provision the Heartwood ESP8266 signer over USB serial.

Writes the master seed + bridge-session secret into the device's flash key store
via the HW frame protocol (PROVISION 0x01 + SET_BRIDGE_SECRET 0x23), then reads
back the npub (PROVISION_LIST 0x05) to confirm. This is the local, one-time
provisioning step — separate from the relay-courier daemon, which never sees keys.

Wire format: [magic "HW"][type u8][len u16-be][payload][crc32-be]; the CRC covers
type+len+payload (NOT the magic), matching the firmware and heartwood-bridge.

Usage:
    pip install pyserial
    # generate a fresh seed on the host (or pass --seed <64 hex>):
    python3 provision.py --port /dev/cu.wchusbserial1420 --gen \
        --bridge-secret <64-hex-bridge-secret>      # e.g. "$(printf '42%.0s' {1..32})"

Then set the daemon's `bridge.secret` to the SAME 32 bytes.

NOTE: this sends the seed over USB. That's the trusted local provisioning phase
(the firm constraint is only that the seed never transits a *relay*). For a
hardware-generated seed that never leaves the device, the firmware needs a
GENERATE_IDENTITY path + an OLED to show the phrase — a later addition.
"""

import argparse
import os
import struct
import sys
import time
import zlib

try:
    import serial  # pyserial
except ImportError:
    sys.exit("pip install pyserial")

MAGIC = b"HW"
PROVISION = 0x01
ACK = 0x06
NACK = 0x15
PROVISION_LIST = 0x05
PROVISION_LIST_RESPONSE = 0x07
SET_BRIDGE_SECRET = 0x23


def build_frame(ftype: int, payload: bytes) -> bytes:
    header = MAGIC + bytes([ftype]) + struct.pack(">H", len(payload))
    crc = zlib.crc32(header[2:] + payload) & 0xFFFFFFFF  # type+len+payload, not magic
    return header + payload + struct.pack(">I", crc)


def read_frame(ser, timeout=30):  # long enough for the on-device button-hold approval
    deadline = time.time() + timeout
    buf = bytearray()
    while time.time() < deadline:
        b = ser.read(1)
        if not b:
            continue
        buf += b
        if len(buf) < 9:
            continue
        if buf[0:2] != MAGIC:        # resync on the preamble
            del buf[0]
            continue
        plen = struct.unpack(">H", buf[3:5])[0]
        total = 5 + plen + 4
        if len(buf) < total:
            continue
        return buf[2], bytes(buf[5:5 + plen])
    raise TimeoutError("no frame from device — wrong port/baud, or it didn't boot")


def txn(ser, ftype, payload):
    ser.write(build_frame(ftype, payload))
    return read_frame(ser)


def main():
    ap = argparse.ArgumentParser(description="Provision the Heartwood ESP8266 signer.")
    ap.add_argument("--port", required=True, help="e.g. /dev/cu.wchusbserial1420")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--seed", help="32-byte master seed as 64 hex chars")
    ap.add_argument("--gen", action="store_true", help="generate a random 32-byte seed")
    ap.add_argument("--bridge-secret", required=True, help="32-byte bridge secret, 64 hex chars")
    a = ap.parse_args()

    if a.gen:
        seed = os.urandom(32)
        print("generated seed:", seed.hex())
    elif a.seed:
        seed = bytes.fromhex(a.seed)
    else:
        sys.exit("provide --seed <64 hex> or --gen")
    secret = bytes.fromhex(a.bridge_secret)
    if len(seed) != 32 or len(secret) != 32:
        sys.exit("seed and bridge-secret must each be 32 bytes (64 hex chars)")

    ser = serial.Serial()
    ser.port = a.port
    ser.baudrate = a.baud
    ser.timeout = 1
    # Don't let opening the port pulse the auto-reset into the bootloader.
    ser.dtr = False
    ser.rts = False
    ser.open()
    time.sleep(1.5)  # let the device boot and switch UART0 to 115200
    ser.reset_input_buffer()

    print("PROVISION (master seed) … HOLD the FLASH button on the device to approve.")
    t, _ = txn(ser, PROVISION, seed)
    if t != ACK:
        sys.exit(f"seed rejected (got frame 0x{t:02x})")

    print("SET_BRIDGE_SECRET …")
    t, _ = txn(ser, SET_BRIDGE_SECRET, secret)
    if t != ACK:
        sys.exit(f"bridge secret rejected (got frame 0x{t:02x})")

    print("PROVISION_LIST (read back identity) …")
    t, p = txn(ser, PROVISION_LIST, b"")
    if t == PROVISION_LIST_RESPONSE:
        print("device identity:", p.decode("utf-8", "replace"))

    print("\nprovisioned ✔  — set the daemon's bridge.secret to:", secret.hex())


if __name__ == "__main__":
    main()
