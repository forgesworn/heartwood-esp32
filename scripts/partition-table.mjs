#!/usr/bin/env node
// Compile and inspect the small, explicit ESP-IDF partition tables Heartwood
// ships as recovery assets. This intentionally rejects implicit offsets and
// sizes: migration code must never guess where persistent state lives.

import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const TABLE_BYTES = 0xc00
const ENTRY_BYTES = 32
const ENTRY_MAGIC = 0x50aa
const MD5_MAGIC = Buffer.from([0xeb, 0xeb, 0xff, 0xff])

const TYPES = new Map([
  ['app', 0x00],
  ['data', 0x01],
])

const SUBTYPES = {
  app: new Map([
    ['factory', 0x00],
    ['test', 0x20],
    ...Array.from({ length: 16 }, (_, i) => [`ota_${i}`, 0x10 + i]),
  ]),
  data: new Map([
    ['ota', 0x00],
    ['phy', 0x01],
    ['nvs', 0x02],
    ['coredump', 0x03],
    ['nvs_keys', 0x04],
    ['efuse', 0x05],
    ['undefined', 0x06],
    ['esphttpd', 0x80],
    ['fat', 0x81],
    ['spiffs', 0x82],
    ['littlefs', 0x83],
  ]),
}

function number(value, what) {
  const text = value.trim()
  const match = /^(0x[0-9a-f]+|[0-9]+)([kKmM])?$/.exec(text)
  if (!match) throw new Error(`${what} must be an explicit integer, got ${JSON.stringify(value)}`)
  let result = Number(match[1])
  if (match[2]?.toLowerCase() === 'k') result *= 1024
  if (match[2]?.toLowerCase() === 'm') result *= 1024 * 1024
  if (!Number.isSafeInteger(result) || result < 0 || result > 0xffffffff) {
    throw new Error(`${what} is outside the uint32 range`)
  }
  return result
}

function enumValue(value, names, what) {
  const text = value.trim().toLowerCase()
  if (names.has(text)) return names.get(text)
  return number(text, what)
}

function flagsValue(value) {
  const text = value.trim().toLowerCase()
  if (!text) return 0
  if (text === 'encrypted') return 1
  return number(text, 'flags')
}

export function parseCsv(text) {
  const entries = []
  for (const [zeroIndex, raw] of text.split(/\r?\n/).entries()) {
    const lineNumber = zeroIndex + 1
    const line = raw.replace(/#.*$/, '').trim()
    if (!line) continue
    const fields = line.split(',').map((field) => field.trim())
    if (fields.length < 5 || fields.length > 6) {
      throw new Error(`line ${lineNumber}: expected 5 or 6 comma-separated fields`)
    }
    const [label, typeText, subtypeText, offsetText, sizeText, flagsText = ''] = fields
    if (!/^[\x20-\x7e]{1,16}$/.test(label)) {
      throw new Error(`line ${lineNumber}: label must be 1-16 printable ASCII bytes`)
    }
    const typeName = typeText.toLowerCase()
    const type = enumValue(typeName, TYPES, `line ${lineNumber} type`)
    const subtypeNames = SUBTYPES[typeName] ?? new Map()
    const subtype = enumValue(subtypeText, subtypeNames, `line ${lineNumber} subtype`)
    const offset = number(offsetText, `line ${lineNumber} offset`)
    const size = number(sizeText, `line ${lineNumber} size`)
    const flags = flagsValue(flagsText)
    if (type > 0xff || subtype > 0xff) throw new Error(`line ${lineNumber}: type/subtype must fit one byte`)
    if (size === 0) throw new Error(`line ${lineNumber}: partition size must be non-zero`)
    entries.push({ label, type, subtype, offset, size, flags })
  }
  if (entries.length === 0) throw new Error('partition CSV has no entries')
  if ((entries.length + 1) * ENTRY_BYTES > TABLE_BYTES) throw new Error('partition table is too large')
  const sorted = [...entries].sort((a, b) => a.offset - b.offset)
  for (let i = 1; i < sorted.length; i++) {
    const previousEnd = sorted[i - 1].offset + sorted[i - 1].size
    if (sorted[i].offset < previousEnd) {
      throw new Error(`${sorted[i].label} overlaps ${sorted[i - 1].label}`)
    }
  }
  return entries
}

export function compile(entries) {
  const encoded = Buffer.alloc(entries.length * ENTRY_BYTES)
  entries.forEach((entry, index) => {
    const out = encoded.subarray(index * ENTRY_BYTES, (index + 1) * ENTRY_BYTES)
    out.writeUInt16LE(ENTRY_MAGIC, 0)
    out[2] = entry.type
    out[3] = entry.subtype
    out.writeUInt32LE(entry.offset, 4)
    out.writeUInt32LE(entry.size, 8)
    out.write(entry.label, 12, 16, 'ascii')
    out.writeUInt32LE(entry.flags, 28)
  })

  const md5 = createHash('md5').update(encoded).digest()
  const checksumEntry = Buffer.alloc(ENTRY_BYTES, 0xff)
  MD5_MAGIC.copy(checksumEntry, 0)
  md5.copy(checksumEntry, 16)
  const table = Buffer.alloc(TABLE_BYTES, 0xff)
  Buffer.concat([encoded, checksumEntry]).copy(table)
  return table
}

export function compileCsv(text) {
  return compile(parseCsv(text))
}

export function parseBinary(table) {
  if (table.length !== TABLE_BYTES) {
    throw new Error(`partition table must be exactly ${TABLE_BYTES} bytes, got ${table.length}`)
  }
  const entries = []
  let checksumOffset = -1
  for (let offset = 0; offset < table.length; offset += ENTRY_BYTES) {
    const raw = table.subarray(offset, offset + ENTRY_BYTES)
    if (raw.subarray(0, 4).equals(MD5_MAGIC)) {
      checksumOffset = offset
      const expected = raw.subarray(16, 32)
      const actual = createHash('md5').update(table.subarray(0, offset)).digest()
      if (!actual.equals(expected)) throw new Error('partition table MD5 mismatch')
      break
    }
    if (raw.every((byte) => byte === 0xff)) break
    if (raw.readUInt16LE(0) !== ENTRY_MAGIC) {
      throw new Error(`invalid partition entry magic at 0x${offset.toString(16)}`)
    }
    const nul = raw.indexOf(0, 12)
    const labelEnd = nul >= 12 && nul < 28 ? nul : 28
    entries.push({
      label: raw.subarray(12, labelEnd).toString('ascii'),
      type: raw[2],
      subtype: raw[3],
      offset: raw.readUInt32LE(4),
      size: raw.readUInt32LE(8),
      flags: raw.readUInt32LE(28),
    })
  }
  if (checksumOffset === -1) throw new Error('partition table has no MD5 entry')
  if (!table.subarray(checksumOffset + ENTRY_BYTES).every((byte) => byte === 0xff)) {
    throw new Error('partition table has non-0xff data after its MD5 entry')
  }
  return entries
}

export function sameLayout(left, right) {
  return JSON.stringify(left) === JSON.stringify(right)
}

function usage() {
  console.error('usage: node scripts/partition-table.mjs compile <table.csv> <table.bin>')
  console.error('       node scripts/partition-table.mjs inspect <table.bin>')
  console.error('       node scripts/partition-table.mjs verify <table.bin> <table.csv>')
}

async function main(args) {
  const [command, first, second] = args
  if (command === 'compile' && first && second) {
    writeFileSync(second, compileCsv(readFileSync(first, 'utf8')), { mode: 0o644 })
    return
  }
  if (command === 'inspect' && first && !second) {
    console.log(JSON.stringify(parseBinary(readFileSync(first)), null, 2))
    return
  }
  if (command === 'verify' && first && second) {
    const actual = parseBinary(readFileSync(first))
    const expected = parseCsv(readFileSync(second, 'utf8'))
    if (!sameLayout(actual, expected)) throw new Error('partition table layout does not match CSV')
    return
  }
  usage()
  process.exitCode = 2
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message)
    process.exitCode = 1
  })
}
