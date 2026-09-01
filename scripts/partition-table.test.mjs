import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { compileCsv, parseBinary, parseCsv, sameLayout } from './partition-table.mjs'

const csv = readFileSync(new URL('../firmware/partitions-v4-16mb-legacy-nvs-bigapp.csv', import.meta.url), 'utf8')

test('legacy V4 table compiles byte-for-byte to the bench-proven image', () => {
  const table = compileCsv(csv)
  assert.equal(table.length, 0xc00)
  assert.equal(
    createHash('sha256').update(table).digest('hex'),
    '0533c10e29f8988177754e8c299c59ba05f9823eea112af5547ff737b2f262c9', // # pragma: allow-secret -- public artifact SHA-256
  )
  assert.deepEqual(parseBinary(table), parseCsv(csv))
})

test('binary parser rejects a changed entry', () => {
  const table = compileCsv(csv)
  table[8] ^= 1
  assert.throws(() => parseBinary(table), /MD5 mismatch/)
})

test('layout comparison includes flags and offsets', () => {
  const entries = parseCsv(csv)
  assert.equal(sameLayout(entries, structuredClone(entries)), true)
  const changed = structuredClone(entries)
  changed[0].offset++
  assert.equal(sameLayout(entries, changed), false)
})
