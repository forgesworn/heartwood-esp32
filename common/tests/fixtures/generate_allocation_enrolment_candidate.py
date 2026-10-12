"""PUBLIC SYNTHETIC PROPOSAL ONLY. No private/device files or authority."""
import argparse,hashlib,hmac,json,struct
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec,ed25519
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
P=Path(__file__).resolve().parent
def sha(*parts):return hashlib.sha256(b''.join(parts)).digest()
def pub(seed):return ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
root=bytes([1])*32
subject=hmac.digest(root,b'VMLS/1 allocation subject\0','sha256');writer=pub(hmac.digest(root,b'VMLS/1 allocation writer seed\0','sha256'))
issuer=ec.derive_private_key(int.from_bytes(root,'big'),ec.SECP256K1()).public_key().public_numbers().x.to_bytes(32,'big')
witness=pub(bytes([9])*32);schema=sha(b'HW allocation journal schema v1\0');route=sha(b'HW allocation route v1\0',b'\1',witness)
descriptor=b'HWAD\1'+subject+writer+issuer+bytes([4])*32+witness+route+schema
pins=sha(b'HW allocation pins v1\0',descriptor)
empty=b'\0'+sha(b'HW allocation record set v1\0',pins,b'\0')+bytes(32)
genesis=sha(b'HW allocation state v1\0',pins,empty)
assert len(descriptor)==229 and len(empty)==65
fixture=json.loads((P/'allocation-journal-v1.json').read_text())
anchor=bytes.fromhex(fixture['anchor_plaintext']);assert descriptor==anchor[:229] and genesis==anchor[229:261]
fields=dict(scope_binding_digest=sha(b'PUBLIC SYNTHETIC SCOPE BINDING ONLY'),descriptor=descriptor,genesis_digest=genesis,purpose=b'\1',target_device=ec.derive_private_key(int.from_bytes(bytes([2])*32,'big'),ec.SECP256K1()).public_key().public_numbers().x.to_bytes(32,'big'),browser_installation=bytes([41])*32,bootstrap_operation=bytes([42])*32,bootstrap_challenge=bytes([43])*32)
rows=[]
for lifetime in [1,3600,2**64-1]:
 packet=b'HWEN\1'+b''.join(fields.values())+struct.pack('>Q',lifetime)
 assert len(packet)==435
 digest=sha(b'HW allocation enrolment candidate v1\0',packet)
 for at in range(len(packet)):
  changed=bytearray(packet);changed[at]^=1
  assert sha(b'HW allocation enrolment candidate v1\0',changed)!=digest
 rows.append(dict(requested_lifetime_seconds=str(lifetime),candidate=packet.hex(),candidateSHA256=digest.hex()))
result=dict(description='PUBLIC SYNTHETIC PROPOSAL ONLY. Does not certify a scope, issuer ownership, physical approval, first use, capacity or release.',version=1,bytes=435,fields={k:v.hex() for k,v in fields.items()},vectors=rows,completeSingleByteCommitmentChanges=435*len(rows),sourceJournalFixtureSHA256=hashlib.sha256((P/'allocation-journal-v1.json').read_bytes()).hexdigest(),authorityProducer=False,physicalAcceptance=False)
out=P/'allocation-enrolment-candidate-v1.json'
encoded=json.dumps(result,indent=2)+'\n'
parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
if args.check:
 assert out.read_text()==encoded,'fixture differs; no files changed'
 print('PUBLIC ENROLMENT CANDIDATE VECTORS BYTE-EXACT')
else:
 out.write_text(encoded)
