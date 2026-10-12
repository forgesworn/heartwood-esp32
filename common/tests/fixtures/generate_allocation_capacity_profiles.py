#!/usr/bin/env python3
"""PUBLIC SYNTHETIC ONLY: eight permanent 32-record journal histories.

Uses the independent Python HMAC/libsodium/Ed25519 fixture builder. All roots,
nonces and signing seeds are reproducible public test inputs. No physical NVS,
capacity reservation, writer authority or production constructor is involved.
"""
import argparse
import json
from pathlib import Path
from generate_allocation_journal import build


def profiles():
    return {
        "description": "PUBLIC SYNTHETIC ONLY. Eight root bytes [1..8] repeated32, 32 permanent manifests, generation1 genesis plus append and terminal retirement transitions. Not measured capacity or physical evidence.",
        "anchorFrameBytes": 476,
        "snapshotFrameBytes": 498,
        "manifestFrameBytes": 356,
        "subjects": [build(root=bytes([n]) * 32, records=32, complete=True)
                     for n in range(1, 9)],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).with_name("allocation-capacity-profiles-v1.json")
    result = json.dumps(profiles(), indent=2) + "\n"
    if args.check:
        assert path.read_text() == result, "capacity profile fixture drift"
        print("Eight independent maximum-history profiles: byte-identical")
    else:
        path.write_text(result)
