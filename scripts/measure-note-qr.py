#!/usr/bin/env python3
"""Record offline firmware size and individual Xtensa frame evidence; never opens USB."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    return base64.b64encode(hashlib.sha256(path.read_bytes()).digest()).decode()


def elf_sections(path):
    data = path.read_bytes()
    assert data[:6] == b'\x7fELF\x01\x01', 'expected little-endian ELF32'
    at = struct.unpack_from('<I', data, 32)[0]
    stride, count, strings = struct.unpack_from('<HHH', data, 46)
    headers = [struct.unpack_from('<10I', data, at + i * stride) for i in range(count)]
    names_at, names_len = headers[strings][4:6]
    names = data[names_at:names_at + names_len]
    sections = {}
    flash = ram = 0
    for name, kind, flags, address, offset, size, link, info, align, entry in headers:
        if not flags & 2:
            continue
        name = names[name:].split(b'\0', 1)[0].decode()
        sections[name] = size
        if kind != 8:
            flash += size
        if flags & 1:
            ram += size
    # Linker dummy/reservation sections are included; this is not live RAM use.
    return {'allocated_file_backed_bytes': flash,
            'allocated_writable_section_bytes_including_reservations': ram, 'sections': sections}


def frames(elf, objdump):
    result = subprocess.run([objdump, '-d', '-C', str(elf)], check=True, text=True, capture_output=True)
    found = {}
    name = None
    for line in result.stdout.splitlines():
        match = re.match(r'^[0-9a-f]+ <(.+)>:$', line)
        if match:
            name = match[1]
        elif name:
            # Some Xtensa ELF mapping symbols make objdump print an entry as
            # a raw 32-bit word. The low 24 bits still hold the first opcode.
            word = re.match(r'^\s*[0-9a-f]+:\s+([0-9a-f]{6,8})\b', line)
            if not word:
                continue
            if any(part in name for part in ['offline_qr::', 'note_qr::', 'qrcodegen_no_heap::',
                                              'forgesworn_qr_embedded_prototype::', 'forgesworn_qr_embedded::']):
                opcode = int(word[1], 16) & 0xffffff
                if opcode & 0xfff == 0x136:  # windowed ABI: entry a1, imm12 * 8
                    size = (opcode >> 12) * 8
                    decoded = re.search(r'\bentry\s+a1,\s*(0x[0-9a-f]+|[0-9]+)\b', line)
                    if decoded:
                        assert size == int(decoded[1], 0), 'entry opcode disagrees with objdump'
                    found[name] = size
            name = None
    return found


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('label')
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--chip', choices=['esp32', 'esp32s3', 'esp32c6'], required=True)
    parser.add_argument('--objdump', required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--frames-only', action='store_true', help='refresh frames of a hash-verified existing ELF without changing its source record')
    args = parser.parse_args()
    if args.frames_only:
        report = json.loads(args.report.read_text())
        entry = report['builds'][args.label]
        assert digest(args.elf) == entry['elf_sha256_base64'], 'ELF differs from recorded artefact'
        entry['individual_qr_frames_bytes'] = frames(args.elf, args.objdump)
        entry['frame_evidence'] = 'Xtensa entry instructions, including raw mapped words; individual frames only'
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(f'Refreshed {len(entry["individual_qr_frames_bytes"])} frames for {args.label}')
        raise SystemExit(0)
    image = args.elf.with_suffix('.bin')
    image.unlink(missing_ok=True)  # A failed converter must not reuse a stale image.
    # The local espflash panics parsing the custom config partition. Match CI's
    # image conversion without a table, then check the real app capacity here.
    subprocess.run(['espflash', 'save-image', '--skip-update-check', '--chip', args.chip,
                    str(args.elf), str(image)], check=True)
    assert image.is_file(), 'image conversion produced no application image'
    capacity = 0x200000 if args.chip == 'esp32s3' else 0x300000
    entry = elf_sections(args.elf)
    entry.update({'elf_sha256_base64': digest(args.elf), 'app_sha256_base64': digest(image),
                  'app_bytes': image.stat().st_size, 'app_capacity_bytes': capacity,
                  'fits_app_partition': image.stat().st_size <= capacity,
                  'individual_qr_frames_bytes': frames(args.elf, args.objdump) if args.chip != 'esp32c6' else {},
                  'frame_evidence': 'Not collected for RISC-V' if args.chip == 'esp32c6' else 'Xtensa entry instructions, including raw mapped words; individual frames only',
                  'source_base': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
                  'source_sha256_base64': {str(path.relative_to(ROOT)): digest(path) for path in
                      [ROOT / 'firmware/Cargo.toml', ROOT / 'firmware/Cargo.lock', ROOT / 'firmware/src/offline_qr.rs',
                       ROOT / 'firmware/.cargo/config.toml', ROOT / 'firmware/sdkconfig.defaults']}})
    for path in [ROOT / 'firmware/src/note_qr.rs', ROOT / 'firmware/vendor/forgesworn-qr-embedded/VENDORED.json']:
        if path.is_file() and not args.label.endswith('-baseline'):
            entry['source_sha256_base64'][str(path.relative_to(ROOT))] = digest(path)
    report = json.loads(args.report.read_text()) if args.report.exists() else {
        'schema': 1, 'rustc': subprocess.check_output(['rustc', '+esp', '--version'], text=True).strip(),
        'espflash': subprocess.check_output(['espflash', '--version'], text=True).strip(),
        'stack_method': 'Individual Xtensa entry-frame sizes from linked release disassembly; not a call-chain bound or FreeRTOS high-water mark',
        'physical_device_tested': False, 'builds': {}}
    report['builds'][args.label] = entry
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(f'{args.label}: app={entry["app_bytes"]}, capacity={capacity}, fits={entry["fits_app_partition"]}')
    print(f'Recorded {len(entry["individual_qr_frames_bytes"])} individual QR frames in {args.report}')
