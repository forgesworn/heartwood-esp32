#!/usr/bin/env python3
"""Generate SYNTHETIC profile sectors with pinned official ESP-IDF v5.3.2.

Not an installed-device capture or migration/capacity acceptance. --check is
read-only. The tool path is explicit; no network, downloads or device access.
"""
import argparse
import base64
import hashlib
import json
import subprocess
from pathlib import Path

TOOL_SHA256 = 'fd5fb70f2da3a9775d98dcbf89336e4bb1dc130aabcc318059c8c9cf097a4078'
ROOT = Path(__file__).resolve().parents[3]
PROFILES = [
 ('standard-8MiB','firmware/partitions.csv',8,['heltec-v3','heltec-v4'],0x420000),
 ('standard-16MiB','firmware/partitions.csv',16,['heltec-v4'],0x420000),
 ('single-4MiB','firmware/partitions-4mb.csv',4,['tdisplay','c6'],0x320000),
 ('legacy-v4-two-slot-16MiB','firmware/partitions-v4-16mb-legacy-nvs.csv',16,['heltec-v4'],0x420000),
 ('legacy-v4-bigapp-16MiB','firmware/partitions-v4-16mb-legacy-nvs-bigapp.csv',16,['heltec-v4'],0x420000),
]
SOURCE_HASHES = {
 'firmware/partitions.csv':'f042759d0499238df33e62fdd3a5925ec30793283866143f445db8f8286c5a58',
 'firmware/partitions-4mb.csv':'79c35163d0f4da25e4f1d48f1d9f1259f155d3c218d8ac6f59e81f779aab16ed',
 'firmware/partitions-v4-16mb-legacy-nvs.csv':'dc84d4c4f37fdc9618829f687899c026984abd5e07b4e6b2b31f7de0546129bf',
 'firmware/partitions-v4-16mb-legacy-nvs-bigapp.csv':'520efd7ccea8c46a9aefbcb5e2b28a1d3041e13b877c995e77cc266437383476',
}


def build(tool):
 assert hashlib.sha256(tool.read_bytes()).hexdigest() == TOOL_SHA256, 'wrong official generator bytes'
 profiles=[]
 for name,path,mb,boards,offset in PROFILES:
  csv=(ROOT/path).read_bytes(); assert hashlib.sha256(csv).hexdigest()==SOURCE_HASHES[path], 'source layout drift'
  def generate(text):
   raw=subprocess.check_output(['python3',str(tool),'--quiet','--offset','0x8000','--flash-size',str(mb)+'MB','-'],input=text)
   assert len(raw)==0xc00
   return raw+bytes([255])*0x400
  old=generate(csv)
  new=generate(csv+f'hwalloc, data, nvs, 0x{offset:x}, 0x40000,\n'.encode())
  profiles.append(dict(name=name,sourcePath=path,sourceSHA256=SOURCE_HASHES[path],flashBytes=mb*1024*1024,boards=boards,newOffset=offset,
                       predecessorSHA256=hashlib.sha256(old).hexdigest(),successorSHA256=hashlib.sha256(new).hexdigest(),
                       predecessorBase64=base64.b64encode(old).decode(),successorBase64=base64.b64encode(new).decode()))
 return dict(description='SYNTHETIC expected profile sectors from official generator. No installed table/geometry/capacity/migration acceptance.',
             generatorVersion='ESP-IDF v5.3.2',generatorSHA256=TOOL_SHA256,tableOffset=0x8000,captureBytes=0x1000,
             candidatePartitionSizeBytes=0x40000,permanentHistorySubjectsProposed=8,profiles=profiles)


if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--idf-tool',type=Path,required=True);p.add_argument('--check',action='store_true');a=p.parse_args()
 output=json.dumps(build(a.idf_tool),indent=2)+'\n';dest=Path(__file__).with_name('allocation-partition-profiles-v1.json')
 if a.check:
  assert dest.read_text()==output,'profile fixture drift';print('Independent official-IDF partition profiles: byte-identical')
 else:dest.write_text(output)
