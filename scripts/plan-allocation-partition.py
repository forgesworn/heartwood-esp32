#!/usr/bin/env python3
"""No-write offline allocation partition planner. Always produces HOLD evidence.

No device/serial/network access, erase, flash, file-write or firmware selection.
Captured bytes/recorded hash and claimed device geometry are inputs, never
attested physical authority. Only exact known unsecured, unencrypted sectors.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT/'common/tests/fixtures/allocation-partition-profiles-v1.json'
MD5_MARKER = b'\xeb\xeb'+b'\xff'*14
ENTRY = struct.Struct('<2sBBII16sI')


class Hold(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Hold(reason)


def parse_sector(raw):
    require(len(raw)==0x1000,'capture must be the complete 4096-byte sector at 0x8000')
    entries=[]
    for pos in range(0,0xc00,32):
        frame=raw[pos:pos+32]
        if frame[:2]==b'\xeb\xeb':
            require(frame[:16]==MD5_MARKER,'noncanonical MD5 marker')
            require(frame[16:]==hashlib.md5(raw[:pos]).digest(),'invalid IDF table MD5')
            require(bool(entries) and raw[pos+32:]==b'\xff'*(0x1000-pos-32),'bytes after MD5 or empty table')
            return entries
        require(frame[:2]==b'\xaa\x50','missing MD5, early end marker or invalid entry')
        magic,kind,subtype,offset,size,name,flags=ENTRY.unpack(frame)
        label,separator,tail=name.partition(b'\0')
        require(bool(separator) and bool(label) and tail==b'\0'*len(tail),'noncanonical partition label')
        try:label=label.decode('ascii')
        except UnicodeDecodeError:raise Hold('non-ASCII partition label') from None
        require(offset>=0x9000 and offset%0x1000==0 and size>0 and size%0x1000==0,'invalid range/alignment')
        require(kind!=0 or offset%0x10000==0,'app offset alignment')
        require(not any(e['label']==label for e in entries),'duplicate partition label')
        require(not any(offset<e['offset']+e['size'] and e['offset']<offset+size for e in entries),'overlapping partitions')
        entries.append(dict(label=label,type=kind,subtype=subtype,offset=offset,size=size,flags=flags,raw=frame))
    raise Hold('missing MD5 inside official 0xc00 table region')


def plan(raw, recorded_hash, profile_name, board, flash_bytes):
    require(isinstance(recorded_hash,str) and len(recorded_hash)==64 and all(c in '0123456789abcdef' for c in recorded_hash),'recorded SHA256 must be exact lowercase hex')
    require(hashlib.sha256(raw).hexdigest()==recorded_hash,'captured bytes differ from independently recorded full-sector SHA256')
    registry=json.loads(REGISTRY.read_text())
    matches=[p for p in registry['profiles'] if p['name']==profile_name]
    require(len(matches)==1,'unknown or ambiguous layout profile')
    p=matches[0]
    require(board in p['boards'],'board is not listed for this layout profile')
    require(flash_bytes==p['flashBytes'],'exact device-reported geometry does not match profile')
    require(hashlib.sha256((ROOT/p['sourcePath']).read_bytes()).hexdigest()==p['sourceSHA256'],'source CSV changed: profile must be independently regenerated/reviewed')
    require(recorded_hash==p['predecessorSHA256'],'unknown captured sector: source CSV similarity is insufficient')
    expected=base64.b64decode(p['predecessorBase64'],validate=True)
    require(raw==expected,'capture differs from exact accepted expected-profile bytes')
    entries=parse_sector(raw)
    require(all(e['flags']==0 for e in entries),'encrypted/read-only/unknown entry flags unsupported')
    require(not any(e['label']=='hwalloc' for e in entries),'allocation partition already present')
    offset=p['newOffset'];size=0x40000
    require(offset==(0x320000 if flash_bytes==0x400000 else 0x420000),'unknown candidate offset')
    require(offset%0x1000==0 and offset+size<=flash_bytes,'candidate range exceeds geometry')
    require(all(e['offset']+e['size']<=flash_bytes for e in entries),'old partition exceeds geometry')
    require(not any(offset<e['offset']+e['size'] and e['offset']<offset+size for e in entries),'candidate overlaps installed entry')
    old_entries=b''.join(e['raw'] for e in entries)
    new_entry=ENTRY.pack(b'\xaa\x50',1,2,offset,size,b'hwalloc'+bytes(9),0)
    prefix=old_entries+new_entry
    require(len(prefix)+32<0xc00,'no table space for new entry and MD5')
    successor=prefix+MD5_MARKER+hashlib.md5(prefix).digest()
    successor+=b'\xff'*(0x1000-len(successor))
    require(successor[:len(old_entries)]==raw[:len(old_entries)],'existing raw entries changed')
    require(hashlib.sha256(successor).hexdigest()==p['successorSHA256'] and successor==base64.b64decode(p['successorBase64'],validate=True),'successor differs from independently generated official-IDF profile')
    parsed=parse_sector(successor);require(len(parsed)==len(entries)+1,'successor entry count')
    return dict(status='HOLD: offline candidate only; no migration or runtime authority',profile=profile_name,claimedBoard=board,claimedDeviceFlashBytes=flash_bytes,
                physicalIdentityAndGeometryVerified=False,tableOffset=0x8000,predecessorSHA256=recorded_hash,successorSHA256=p['successorSHA256'],
                preservedRawEntryCount=len(entries),candidateEntry=dict(label='hwalloc',type=1,subtype=2,offset=offset,size=size,flags=0,rawHex=new_entry.hex()),
                successorSectorBase64=base64.b64encode(successor).decode(),
                proposedPermanentHistoricalSubjects=8,recordsPerSubjectLogicalCeiling=32,
                bounds=dict(unit='NVS entry slots',oneHistoryLowerBound=502,eightHistoriesLowerBound=4016,theoretical63PageUpperLimit=7938,measuredUsableCapacity=False),
                migrationApproved=False,capacityAuthority=False,defaultBuildChanged=False,
                remaining=['independent device identity/geometry and exact capture provenance','backups/hashes of table and all existing regions','proof new range is unused and safe erase/readback','retained-loader power-cut recovery for partition table replacement','global permanent history inventory/reservation and measured fragmentation/GC/full/cut behavior','separate destructive-reset retention policy','raw non-erasing partition owner','enrolment/recovery/time/entropy/child/browser/production acceptance'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--table',type=Path,required=True);p.add_argument('--recorded-sha256',required=True);p.add_argument('--profile',required=True);p.add_argument('--board',required=True);p.add_argument('--device-flash-bytes',type=lambda x:int(x,0),required=True);a=p.parse_args()
    try:
        with a.table.open('rb') as f:raw=f.read(0x1001)
        result=plan(raw,a.recorded_sha256,a.profile,a.board,a.device_flash_bytes)
    except (Hold,OSError,ValueError,KeyError,TypeError) as e:
        p.exit(2,'HOLD: '+str(e)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
