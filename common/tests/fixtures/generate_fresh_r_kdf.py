#!/usr/bin/env python3
"""PUBLIC SYNTHETIC ONLY. Independent Python HMAC + OpenSSL curve fixtures.

Requires cryptography. --check is read-only. This is mathematical evidence,
never an entropy source, signer, recovery API or owner/retarget authorization.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ORDER = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)
DOMAIN = b'VMLS/1 fresh rendezvous allocation scalar\0'
SCHEMA = hashlib.sha256(b'HW allocation journal schema v1\0').digest()


def scalar(n):
    return n.to_bytes(32, 'big')


def mac(k, msg):
    return hmac.digest(k, msg, 'sha256')


def point(d):
    return ec.derive_private_key(int.from_bytes(d, 'big'), ec.SECP256K1()).public_key()


def compressed(d):
    return point(d).public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def shared(d, peer_x):
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b'\x02' + peer_x)
    return ec.derive_private_key(int.from_bytes(d, 'big'), ec.SECP256K1()).exchange(ec.ECDH(), peer)


def build():
    root, salt = bytes([1])*32, bytes(range(1, 33))
    raw = scalar(7)
    normalized = mac(raw, b'nsec-tree-root')
    inputs = [
        ('tree', root, salt, SCHEMA, DOMAIN),
        ('changed-salt', root, bytes(range(32, 0, -1)), SCHEMA, DOMAIN),
        ('changed-root', bytes([2])*32, salt, SCHEMA, DOMAIN),
        ('bunker-normalized', normalized, salt, SCHEMA, DOMAIN),
        ('tree-nsec-root-alias', normalized, salt, SCHEMA, DOMAIN),
        ('bip39-root-alias', normalized, salt, SCHEMA, DOMAIN),
        ('raw-bunker-is-wrong-IKM', raw, salt, SCHEMA, DOMAIN),
        ('zero-root', bytes(32), salt, SCHEMA, DOMAIN),
        ('zero-salt', root, bytes(32), SCHEMA, DOMAIN),
        ('zero-schema', root, salt, bytes(32), DOMAIN),
        ('changed-schema', root, salt, hashlib.sha256(b'changed schema').digest(), DOMAIN),
        ('omitted-NUL', root, salt, SCHEMA, DOMAIN[:-1]),
        ('changed-version', root, salt, SCHEMA, DOMAIN.replace(b'/1 ', b'/2 ')),
        ('truncated-root', root[:-1], salt, SCHEMA, DOMAIN),
        ('truncated-salt', root, salt[:-1], SCHEMA, DOMAIN),
        ('truncated-schema', root, salt, SCHEMA[:-1], DOMAIN),
    ]
    cases = []
    for name, ikm, s, schema, domain in inputs:
        info = domain + schema
        prk = mac(s, ikm)
        d = mac(prk, info + b'\x01')
        valid = 0 < int.from_bytes(d, 'big') < ORDER
        entry = dict(name=name, root=ikm.hex(), salt=s.hex(), schema=schema.hex(), domain=domain.hex(),
                     info=info.hex(), prk=prk.hex(), candidate=d.hex(), scalarValid=valid,
                     # Wrong raw Bunker input is scalar-valid but never eligible custody.
                     contractInputEligible=name in {x[0] for x in inputs[:6]})
        if valid:
            entry.update(compressed=compressed(d).hex(), R=compressed(d)[1:].hex(),
                         negatedScalar=scalar(ORDER-int.from_bytes(d, 'big')).hex())
        cases.append(entry)
    boundaries = []
    for name, n in [('zero',0), ('one',1), ('n-minus-one',ORDER-1), ('n',ORDER), ('n-plus-one',ORDER+1), ('max',2**256-1)]:
        d = scalar(n); valid = 0 < n < ORDER
        boundaries.append(dict(name=name, candidate=d.hex(), scalarValid=valid,
                               R=compressed(d)[1:].hex() if valid else None))
    ecdh = []
    peer = scalar(11); peer_R = compressed(peer)[1:]
    for case in cases[:6]:
        d = bytes.fromhex(case['candidate']); R = bytes.fromhex(case['R'])
        x = shared(d, peer_R)
        assert x == shared(peer, R) == shared(bytes.fromhex(case['negatedScalar']), peer_R)
        for recipient_name, recipient in [('peer', peer_R), ('allocation',R)]:
            prk = mac(b'VMLS/1 introduction', x)
            for counter in [0,1,2**64-1]:
                suffix = recipient + counter.to_bytes(8,'big')
                ecdh.append(dict(case=case['name'], peerScalar=peer.hex(), peerR=peer_R.hex(), sharedX=x.hex(),
                                 recipient=recipient_name, recipientR=recipient.hex(), counter=str(counter),
                                 mailbox=mac(prk,b'VMLS/1 introduction mailbox'+suffix+b'\x01').hex(),
                                 recordSecret=mac(prk,b'VMLS/1 introduction record'+suffix+b'\x01').hex()))
    assert {c['compressed'][:2] for c in cases[:6]} == {'02','03'}
    return dict(description='PUBLIC SYNTHETIC ONLY. Python HMAC SHA256 and cryptography/OpenSSL secp256k1. No runtime allocation, entropy, owner or browser authority.',
                order=scalar(ORDER).hex(), domain=DOMAIN.hex(), schema=SCHEMA.hex(),
                bunker=dict(raw=raw.hex(), normalizedRoot=normalized.hex(), rawIssuer=compressed(raw)[1:].hex(), normalizedIssuer=compressed(normalized)[1:].hex()),
                cases=cases, scalarBoundaries=boundaries, introduction=ecdh,
                ownerBindingCaveat='Target/installation/operation/challenge are excluded from this KDF. Equal R across those changes cannot authorize retargeting. Manifest/owner refusal remains unimplemented and untested here.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--check', action='store_true'); args = parser.parse_args()
    path = Path(__file__).with_name('fresh-r-kdf-v1.json')
    output = json.dumps(build(), indent=2)+'\n'
    if args.check:
        assert path.read_text() == output, 'fixture drift'
        print('Independent Python fresh-R fixtures: byte-identical')
    else:
        path.write_text(output)
