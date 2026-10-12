// PUBLIC SYNTHETIC ONLY. Independent Node/OpenSSL HKDF and ECDH checker.
// Never accepts device data or produces runtime signer/allocation authority.
import assert from 'node:assert/strict';
import { createHash, createHmac, createECDH, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
const v = JSON.parse(readFileSync(new URL('fresh-r-kdf-v1.json', import.meta.url)));
const bytes = h => Buffer.from(h, 'hex');
const hex = b => Buffer.from(b).toString('hex');
const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
assert.equal(BigInt(`0x${v.order}`),n);
const scalarValid = h => h.length === 64 && BigInt(`0x${h}`) > 0n && BigInt(`0x${h}`) < n;
const domain = Buffer.from('VMLS/1 fresh rendezvous allocation scalar\0');
assert.equal(hex(domain), v.domain);
assert.equal(createHash('sha256').update('HW allocation journal schema v1\0').digest('hex'),v.schema);
const curve = h => { const e = createECDH('secp256k1'); e.setPrivateKey(bytes(h)); return e; };
const pub = h => curve(h).getPublicKey(undefined,'compressed');
assert.equal(createHmac('sha256',bytes(v.bunker.raw)).update('nsec-tree-root').digest('hex'),v.bunker.normalizedRoot);
assert.equal(hex(pub(v.bunker.raw).subarray(1)),v.bunker.rawIssuer);
assert.equal(hex(pub(v.bunker.normalizedRoot).subarray(1)),v.bunker.normalizedIssuer);
assert.notEqual(v.bunker.rawIssuer,v.bunker.normalizedIssuer);
for (const c of v.cases) {
  assert.equal(c.info,c.domain+c.schema);
  assert.equal(createHmac('sha256',bytes(c.salt)).update(bytes(c.root)).digest('hex'),c.prk);
  assert.equal(hex(hkdfSync('sha256',bytes(c.root),bytes(c.salt),bytes(c.info),32)),c.candidate);
  assert.equal(scalarValid(c.candidate),c.scalarValid);
  if (c.scalarValid) {
    assert.equal(hex(pub(c.candidate)),c.compressed);
    assert.equal(hex(pub(c.negatedScalar).subarray(1)),c.R);
    assert.equal(BigInt(`0x${c.candidate}`)+BigInt(`0x${c.negatedScalar}`),n);
  }
}
assert.deepEqual(new Set(v.cases.slice(0,6).map(c=>c.compressed.slice(0,2))),new Set(['02','03']));
for (const b of v.scalarBoundaries) {
  assert.equal(scalarValid(b.candidate),b.scalarValid);
  if (b.scalarValid) assert.equal(hex(pub(b.candidate).subarray(1)),b.R);
  else assert.throws(()=>curve(b.candidate));
}
for (const e of v.introduction) {
  const c = v.cases.find(c=>c.name===e.case);
  assert.equal(hex(curve(c.candidate).computeSecret(bytes('02'+e.peerR))),e.sharedX);
  assert.equal(hex(curve(c.negatedScalar).computeSecret(bytes('02'+e.peerR))),e.sharedX);
  assert.equal(hex(curve(e.peerScalar).computeSecret(bytes('02'+c.R))),e.sharedX);
  const count = Buffer.alloc(8); count.writeBigUInt64BE(BigInt(e.counter));
  const suffix = Buffer.concat([bytes(e.recipientR),count]);
  for (const [tag,expected] of [['mailbox',e.mailbox],['record',e.recordSecret]]) {
    assert.equal(hex(hkdfSync('sha256',bytes(e.sharedX),Buffer.from('VMLS/1 introduction'),Buffer.concat([Buffer.from(`VMLS/1 introduction ${tag}`),suffix]),32)),expected);
  }
}
console.log(`Independent Node fresh-R fixtures: ${v.cases.length} HKDF, ${v.scalarBoundaries.length} scalar boundaries, ${v.introduction.length} ECDH/Introduction cases passed`);
