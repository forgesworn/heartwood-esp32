#!/usr/bin/env python3
# scripts/nvs-dump-read.py
#
# Read a raw NVS partition dump (espflash read-flash 0x9000 <size>) with
# ESP-IDF's own parser, reassembling multi-page blobs, so a restore never
# depends on byte offsets that move whenever NVS rewrites a page.
#
#   --keys                   namespace, key, type and size of every live item.
#                            Prints no value: safe to paste.
#   --get <namespace> <key>  one item's bytes as hex on stdout, for piping
#                            into a restore step. Never write it to disk.
#
# Needs nvs_partition_tool from the ESP-IDF checkout the firmware builds
# against (NVS_TOOL_DIR, default: the firmware's .embuild copy).

import argparse
import os
import sys
from pathlib import Path

DEFAULT_TOOL = (
    Path(__file__).resolve().parent.parent
    / 'firmware/.embuild/espressif/esp-idf/v5.3.2/components/nvs_flash/nvs_partition_tool'
)
sys.path.insert(0, os.environ.get('NVS_TOOL_DIR', str(DEFAULT_TOOL)))
import nvs_parser  # noqa: E402


def items(path):
    part = nvs_parser.NVS_Partition(Path(path).name, bytearray(Path(path).read_bytes()))
    entries = []
    for page in part.pages:
        if page.is_empty:
            continue
        for e in page.entries:
            if e.state == 'Written' and e.key is not None and not e.is_empty:
                entries.append(e)
    namespaces = {e.data['value']: e.key for e in entries if e.metadata['namespace'] == 0}

    def payload(e):
        buf = bytearray()
        for child in e.children:
            buf += child.raw
        return bytes(buf[: e.data['size']])

    chunks = {}
    out = {}
    for e in entries:
        ns = e.metadata['namespace']
        if ns == 0:
            continue
        kind = e.metadata['type']
        if kind == 'blob_data':
            chunks[(ns, e.key, e.metadata['chunk_index'])] = payload(e)
        elif kind in ('string', 'blob'):
            out[(ns, e.key)] = (kind, payload(e))
        elif kind != 'blob_index':
            out[(ns, e.key)] = (kind, e.data['value'])
    for e in entries:
        if e.metadata['namespace'] != 0 and e.metadata['type'] == 'blob_index':
            ns, start, count = e.metadata['namespace'], e.data['chunk_start'], e.data['chunk_count']
            parts = [chunks.get((ns, e.key, start + i)) for i in range(count)]
            if any(p is None for p in parts):
                out[(ns, e.key)] = ('blob-incomplete', b'')
                continue
            data = b''.join(parts)
            if len(data) != e.data['size']:
                out[(ns, e.key)] = ('blob-incomplete', b'')
                continue
            out[(ns, e.key)] = ('blob', data)
    return {(namespaces.get(ns, f'#{ns}'), key): v for (ns, key), v in out.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dump')
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--keys', action='store_true')
    group.add_argument('--get', nargs=2, metavar=('NAMESPACE', 'KEY'))
    args = ap.parse_args()
    found = items(args.dump)
    if args.keys:
        for (ns, key), (kind, value) in sorted(found.items()):
            size = len(value) if isinstance(value, (bytes, bytearray)) else '-'
            print(f'{ns:12} {key:16} {kind:15} {size}')
        return
    hit = found.get(tuple(args.get))
    if hit is None:
        sys.exit(f'{args.get[0]}/{args.get[1]} not found')
    kind, value = hit
    if not isinstance(value, (bytes, bytearray)):
        print(value)
    else:
        print(value.hex())


if __name__ == '__main__':
    main()
