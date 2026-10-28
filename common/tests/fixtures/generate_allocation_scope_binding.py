#!/usr/bin/env python3
"""Public synthetic scope-body vectors; no provisioning, entropy or authority."""
import argparse
import hashlib
import json
from pathlib import Path

PREFIX = b"HWSB\x01"
DOMAIN = b"HW allocation scope binding v1\0"

def generate():
    schema = hashlib.sha256(b"HW allocation journal schema v1\0").digest()
    body = PREFIX + b"".join(bytes([i]) * 32 for i in range(1, 8)) + schema + bytes([8, 32])
    assert len(body) == 263
    digest = hashlib.sha256(DOMAIN + body).digest()
    count = 0
    for offset in range(len(body)):
        for replacement in range(256):
            if replacement == body[offset]:
                continue
            changed = bytearray(body)
            changed[offset] = replacement
            assert changed != body
            assert hashlib.sha256(DOMAIN + changed).digest() != digest
            count += 1
    assert count == 67065
    return {
        "format": "public-synthetic-allocation-scope-body-v1",
        "authority": False,
        "bodyBytes": len(body),
        "bodyHex": body.hex(),
        "digest": digest.hex(),
        "bindings": "seven synthetic byte patterns 01..07; no actual scope/component/provenance",
        "schemaHash": schema.hex(),
        "exhaustiveSingleByteSubstitutions": count,
        "substitutionDefinition": "each of 263 offsets replaced with each of its 255 unequal uint8 values",
    }

if __name__ == "__main__":
    args = argparse.ArgumentParser()
    args.add_argument("--check", action="store_true")
    check = args.parse_args().check
    target = Path(__file__).with_name("allocation-scope-binding-body-v1.json")
    result = json.dumps(generate(), indent=2) + "\n"
    if check:
        assert target.read_text() == result, "independent vectors differ"
    else:
        target.write_text(result)
    print("67065 exhaustive single-byte substitutions verified; fixture SHA256 " + hashlib.sha256(result.encode()).hexdigest())
