#!/usr/bin/env python3
"""Verify the recorded, self-contained QR runtime snapshot without another checkout."""
import base64
import hashlib
import json
from pathlib import Path
import tomllib

root = Path(__file__).resolve().parent.parent / 'firmware/vendor/forgesworn-qr-embedded'
manifest = tomllib.loads((root / 'Cargo.toml').read_text())
assert manifest['dependencies'] == {}, 'vendored runtime must have no dependencies'
assert 'dev-dependencies' not in manifest, 'repository-only test oracles must not be vendored'
record = json.loads((root / 'VENDORED.json').read_text())
for name, expected in record['files_sha256_base64'].items():
    actual = base64.b64encode(hashlib.sha256((root / name).read_bytes()).digest()).decode()
    if actual != expected:
        raise SystemExit(f'Vendored QR source differs from recorded snapshot: {name}')
print('QR runtime snapshot hashes and dependency boundary verified')
