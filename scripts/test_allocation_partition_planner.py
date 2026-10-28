#!/usr/bin/env python3
"""Synthetic safety checks for the offline planner. No devices, flash or writes."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('allocation_partition_planner',ROOT/'scripts/plan-allocation-partition.py')
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)
V=json.loads(M.REGISTRY.read_text());PROFILES=V['profiles']


def old(p):return base64.b64decode(p['predecessorBase64'])

def rehash(entries):
    prefix=b''.join(entries)
    data=prefix+M.MD5_MARKER+hashlib.md5(prefix).digest()
    return data+b'\xff'*(0x1000-len(data))


class PlannerTests(unittest.TestCase):
    def test_five_official_profiles_preserve_every_raw_entry_and_order(self):
        self.assertEqual(len(PROFILES),5)
        for p in PROFILES:
            for board in p['boards']:
                with self.subTest(profile=p['name'],board=board):
                    raw=old(p);before=M.parse_sector(raw)
                    r=M.plan(raw,p['predecessorSHA256'],p['name'],board,p['flashBytes'])
                    after=base64.b64decode(r['successorSectorBase64']);parsed=M.parse_sector(after)
                    self.assertEqual(after,base64.b64decode(p['successorBase64']))
                    self.assertEqual([e['raw'] for e in before],[e['raw'] for e in parsed[:-1]])
                    self.assertEqual(parsed[-1]['label'],'hwalloc')
                    self.assertEqual((parsed[-1]['type'],parsed[-1]['subtype'],parsed[-1]['size'],parsed[-1]['flags']),(1,2,0x40000,0))
                    self.assertEqual(parsed[-1]['offset'],p['newOffset'])
                    for flag in ['migrationApproved','capacityAuthority','defaultBuildChanged','physicalIdentityAndGeometryVerified']:
                        self.assertFalse(r[flag])
                    self.assertEqual(r['bounds']['unit'],'NVS entry slots')
                    self.assertFalse(r['bounds']['measuredUsableCapacity'])
                    self.assertTrue(r['status'].startswith('HOLD'))

    def test_exact_geometry_board_and_layout_are_separate(self):
        for p in PROFILES:
            for size in [0x400000,0x800000,0x1000000,0x2000000]:
                if size!=p['flashBytes']:
                    with self.assertRaises(M.Hold):M.plan(old(p),p['predecessorSHA256'],p['name'],p['boards'][0],size)
            for board in ['heltec-v3','heltec-v4','tdisplay','c6','unknown']:
                if board not in p['boards']:
                    with self.assertRaises(M.Hold):M.plan(old(p),p['predecessorSHA256'],p['name'],board,p['flashBytes'])
        for p in PROFILES[2:]:
            with self.assertRaises(M.Hold):M.plan(old(PROFILES[0]),PROFILES[0]['predecessorSHA256'],p['name'],p['boards'][0],p['flashBytes'])

    def test_every_changed_capture_byte_is_unknown_even_with_its_actual_hash(self):
        p=PROFILES[0];original=old(p)
        for at in range(4096):
            b=bytearray(original);b[at]^=1;raw=bytes(b)
            with self.assertRaises(M.Hold):M.plan(raw,hashlib.sha256(raw).hexdigest(),p['name'],'heltec-v4',p['flashBytes'])
        for recorded in ['',p['predecessorSHA256'].upper(),'0'*64,p['predecessorSHA256'][:-1]]:
            with self.assertRaises(M.Hold):M.plan(original,recorded,p['name'],'heltec-v4',p['flashBytes'])
        with self.assertRaises(M.Hold):M.plan(original,p['predecessorSHA256'],'unknown','heltec-v4',p['flashBytes'])

    def test_complete_capture_one_canonical_md5_and_all_trailing_bytes(self):
        raw=old(PROFILES[0]);count=len(M.parse_sector(raw));start=count*32
        for size in [0,1,31,32,0xbff,0xc00,0xfff,0x1001]:
            b=raw[:size] if size<=len(raw) else raw+b'\xff'
            with self.assertRaises(M.Hold):M.parse_sector(b)
        for at in range(start,4096):
            b=bytearray(raw);b[at]^=1
            with self.assertRaises(M.Hold):M.parse_sector(bytes(b))
        b=raw[:start]+raw[start+32:]+bytes(32)
        with self.assertRaises(M.Hold):M.parse_sector(b)
        b=raw[:start+32]+raw[start:start+32]+raw[start+64:]
        with self.assertRaises(M.Hold):M.parse_sector(b)
        # Replacing the end region with another valid entry is still ambiguous.
        b=raw[:start+32]+raw[:32]+raw[start+64:]
        with self.assertRaises(M.Hold):M.parse_sector(b)

    def test_valid_md5_cannot_hide_duplicate_overlap_or_bad_alignment(self):
        entries=[e['raw'] for e in M.parse_sector(old(PROFILES[0]))]
        duplicate=entries+[entries[0]]
        with self.assertRaises(M.Hold):M.parse_sector(rehash(duplicate))
        for name,offset,size in [('overlap',0x9000,0x4000),('bad-offset',0x420001,0x40000),('bad-size',0x420000,1),('zero-size',0x420000,0),('table-overlap',0x8000,0x1000)]:
            new=M.ENTRY.pack(b'\xaa\x50',1,2,offset,size,name.encode()+bytes(16-len(name)),0)
            with self.assertRaises(M.Hold):M.parse_sector(rehash(entries+[new]))
        bad=M.ENTRY.pack(b'\xaa\x50',0,0,0x421000,0x10000,b'bad-app'+bytes(9),0)
        with self.assertRaises(M.Hold):M.parse_sector(rehash(entries+[bad]))

    def test_equivalent_entries_with_unknown_flags_label_padding_or_order_hold(self):
        p=PROFILES[0];entries=[e['raw'] for e in M.parse_sector(old(p))]
        for at in [2,3,4,8,12,27,28,31]:
            b=bytearray(entries[0]);b[at]^=1
            raw=rehash([bytes(b)]+entries[1:])
            with self.assertRaises(M.Hold):M.plan(raw,hashlib.sha256(raw).hexdigest(),p['name'],'heltec-v4',p['flashBytes'])
        raw=rehash(list(reversed(entries)))
        with self.assertRaises(M.Hold):M.plan(raw,hashlib.sha256(raw).hexdigest(),p['name'],'heltec-v4',p['flashBytes'])
        # Nonzero label bytes following the first NUL must also fail the parser.
        b=bytearray(entries[0]);b[27]=1
        with self.assertRaises(M.Hold):M.parse_sector(rehash([bytes(b)]+entries[1:]))

    def test_cli_reads_only_stdin_emits_candidate_and_fails_without_output(self):
        p=PROFILES[0];args=[sys.executable,str(ROOT/'scripts/plan-allocation-partition.py'),'--table','/dev/stdin','--recorded-sha256',p['predecessorSHA256'],'--profile',p['name'],'--board','heltec-v4','--device-flash-bytes',str(p['flashBytes'])]
        run=subprocess.run(args,input=old(p),capture_output=True)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertFalse(json.loads(run.stdout)['migrationApproved'])
        run=subprocess.run(args,input=old(p)[:-1],capture_output=True)
        self.assertEqual(run.returncode,2);self.assertEqual(run.stdout,b'');self.assertTrue(run.stderr.startswith(b'HOLD:'))


if __name__=='__main__':unittest.main()
