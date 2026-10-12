#!/usr/bin/env python3
"""Public synthetic journal vectors: Python HMAC/SHA + independent libsodium.

Requires libsodium and cryptography. No device data, entropy or private files.
Run --check to prove the checked-in JSON is byte-identical. This is a fixture
generator, never production allocation/nonce/recovery code.
"""
import argparse
import ctypes
import ctypes.util
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = bytes([1]) * 32


def sha(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def hk(*parts):
    return hmac.digest(ROOT, b"".join(parts), "sha256")


def pub(seed):
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)


def u64(n):
    return n.to_bytes(8, "big")


def build(root=ROOT, records=3, complete=False):
    # Optional inputs are public fixture construction only, never firmware APIs.
    assert len(root) == 32 and 1 <= records <= 32
    assert complete or records == 3

    def hk(*parts):
        return hmac.digest(root, b"".join(parts), "sha256")

    library = ctypes.util.find_library("sodium")
    if library is None and Path("/opt/homebrew/lib/libsodium.dylib").exists():
        library = "/opt/homebrew/lib/libsodium.dylib"
    if library is None:
        raise FileNotFoundError("libsodium is required for independent fixtures")
    lib = ctypes.CDLL(library)
    assert lib.sodium_init() >= 0
    encrypt = lib.crypto_aead_xchacha20poly1305_ietf_encrypt
    encrypt.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong),
                        ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
                        ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_void_p,
                        ctypes.c_void_p]
    encrypt.restype = ctypes.c_int

    def seal(key, nonce, plaintext, associated):
        out = ctypes.create_string_buffer(len(plaintext) + 16)
        length = ctypes.c_ulonglong()
        assert encrypt(out, ctypes.byref(length), plaintext, len(plaintext),
                       associated, len(associated), None, nonce, key) == 0
        assert length.value == len(plaintext) + 16
        return out.raw[:length.value]

    subject = hk(b"VMLS/1 allocation subject\0")
    writer = pub(hk(b"VMLS/1 allocation writer seed\0"))
    issuer = ec.derive_private_key(int.from_bytes(root, "big"), ec.SECP256K1()).public_key().public_numbers().x.to_bytes(32, "big")
    witness_secret = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([9]) * 32)
    witness = pub(bytes([9]) * 32)
    schema = sha(b"HW allocation journal schema v1\0")
    descriptor = b"HWAD\x01" + subject + writer + issuer + bytes([4]) * 32 + witness + sha(b"HW allocation route v1\0", b"\x01", witness) + schema
    assert len(descriptor) == 229
    pins = sha(b"HW allocation pins v1\0", descriptor)

    def state(ids, lives):
        count = bytes([len(ids)])
        pairs = b"".join(bytes([i+1]) + value for i, value in enumerate(ids))
        return count + sha(b"HW allocation record set v1\0", pins, count, pairs) + bytes(lives) + bytes(32-len(lives))

    def digest(s):
        return sha(b"HW allocation state v1\0", pins, s)

    def receipt(seq, d):
        body = bytes([1, 0]) + subject + u64(seq) + d + bytes([20+seq]) * 32
        return body + witness_secret.sign(sha(b"VMLS/1 witness receipt", body))

    empty = state([], [])
    genesis_digest = digest(empty)
    genesis_receipt = receipt(0, genesis_digest)
    anchor_plain = descriptor + genesis_digest + genesis_receipt
    nonce = bytes([40]) * 24
    header = b"HWAC\x01" + nonce
    anchor = header + seal(hk(b"HW allocation anchor key v1\0"), nonce, anchor_plain,
                           b"HW allocation anchor aad v1\0" + subject + issuer + header)
    assert len(anchor) == 476

    manifests, ids = [], []
    for ordinal in range(1, records + 1):
        data = b"HWAM\x01" + bytes([ordinal]) + issuer
        for base in [50, 60, 70, 80, 90, 100]:
            data += bytes([base+ordinal]) * 32
        data += schema + u64(1000+ordinal) + u64(2000+ordinal)
        assert len(data) == 278
        allocation_id = sha(b"HW allocation manifest v1\0", pins, data)
        ids.append(allocation_id)
        nonce = bytes([110+ordinal]) * 24
        header = b"HWAE\x01" + bytes([ordinal]) + allocation_id + nonce
        sealed = header + seal(hk(b"HW allocation manifest key v1\0", pins), nonce, data,
                               b"HW allocation manifest aad v1\0" + pins + header)
        assert len(sealed) == 356
        manifests.append({"plaintext": data.hex(), "sealed": sealed.hex(), "id": allocation_id.hex()})

    snapshots = []
    predecessor = bytes(32)

    def snapshot(generation, seq, active, candidate=None, kind=0, ordinal=0):
        nonlocal predecessor
        phase = int(candidate is not None)
        d = digest(active)
        data = b"HWAS\x01" + bytes([phase]) + u64(generation) + predecessor + pins + u64(seq) + d + receipt(seq, d) + active
        data += candidate if candidate is not None else bytes(65)
        data += bytes([kind, ordinal]) + (digest(candidate) if candidate is not None else bytes(32))
        assert len(data) == 452
        slot = (generation-1) % 2
        nonce = bytes([120+generation]) * 24
        header = b"HWSC\x01" + bytes([slot]) + nonce
        sealed = header + seal(hk(b"HW allocation snapshot key v1\0", pins), nonce, data,
                               b"HW allocation snapshot aad v1\0" + pins + header)
        assert len(sealed) == 498
        predecessor = sha(b"HW allocation snapshot v1\0", bytes([slot]), sealed)
        snapshots.append({"slot": slot, "plaintext": data.hex(), "sealed": sealed.hex()})

    if complete:
        snapshot(1, 0, empty)
        for ordinal in range(1, records + 1):
            active = state(ids[:ordinal-1], [1] * (ordinal-1))
            candidate = state(ids[:ordinal], [1] * ordinal)
            snapshot(2*ordinal, ordinal-1, active, candidate, 1, ordinal)
            snapshot(2*ordinal+1, ordinal, candidate)
        lives = [1] * records
        for ordinal in range(1, records + 1):
            active = state(ids, lives)
            lives[ordinal-1] = 3
            candidate = state(ids, lives)
            seq = records + ordinal - 1
            snapshot(2*records+2*ordinal, seq, active, candidate, 3, ordinal)
            snapshot(2*records+2*ordinal+1, seq+1, candidate)
    else:
        one = state(ids[:1], [1])
        two = state(ids[:2], [1, 1])
        abandoned = state(ids[:2], [2, 1])
        retired = state(ids[:2], [2, 3])
        snapshot(1, 0, empty)
        snapshot(2, 0, empty, one, 1, 1)
        snapshot(3, 1, one)
        snapshot(4, 1, one, two, 1, 2)
        snapshot(5, 2, two)
        snapshot(6, 2, two, abandoned, 2, 1)
        snapshot(7, 3, abandoned)
        snapshot(8, 3, abandoned, retired, 3, 2)
        snapshot(9, 4, retired)

    return {"description": ("PUBLIC SYNTHETIC ONLY. ROOT [1;32]; nonce injection is test-only. Python HMAC/SHA and libsodium XChaCha20Poly1305; independent Ed25519 receipts." if root == ROOT else "PUBLIC SYNTHETIC ONLY. Root is the shown public fixture; nonce injection is test-only. Python HMAC/SHA, libsodium AEAD and Ed25519 receipts."),
            "root": root.hex(), "issuer": issuer.hex(), "subject": subject.hex(),
            "namespace": "a" + hk(b"HW allocation local namespace v1\0")[:7].hex(),
            "anchor_plaintext": anchor_plain.hex(), "anchor": anchor.hex(), "pins_hash": pins.hex(),
            "manifests": manifests, "snapshots": snapshots}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).with_name("allocation-journal-v1.json")
    result = json.dumps(build(), indent=2) + "\n"
    if args.check:
        assert path.read_text() == result, "fixture drift"
        print("Independent libsodium journal fixture: byte-identical")
    else:
        path.write_text(result)
