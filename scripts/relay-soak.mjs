#!/usr/bin/env node
// scripts/relay-soak.mjs
//
// Long heap soak over the relay: run the operator's get_status every few
// minutes for hours and log the memory figures, so a board can be left alone
// and the run read afterwards. Each round is one scripts/mgmt-request.mjs call,
// so it needs the same operator key and master as that script.
//
// Logged per round (CSV, one row; a timed-out round is a row too):
//   free_heap, largest_free_block, min_free_heap, uptime_s, relay_connects,
//   last_reset, every stack_free mark, crash_detail.
// A fall in uptime_s is reported as a reboot, with last_reset and
// crash_detail, and the soak carries on.
//
// Usage:
//   node scripts/relay-soak.mjs --master <npub|hex> --relay wss://... \
//     [--every 300] [--hours 12] [--label beta.38] [--out soak.csv] \
//     [--key-file <path>] [--timeout 45000]
//
// Two boards side by side: start one soak per board with its own --master,
// --label and --out, then compare the two CSVs.

import { argv, exit } from 'node:process'
import { spawn } from 'node:child_process'
import { appendFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const arg = (n, d = null) => { const i = argv.indexOf(n); return i === -1 ? d : argv[i + 1] }
const MASTER = arg('--master', process.env.HEARTWOOD_MASTER)
const RELAY = arg('--relay')
const EVERY = Number(arg('--every', '300'))
const HOURS = Number(arg('--hours', '12'))
const LABEL = arg('--label', '')
const KEY_FILE = arg('--key-file')
const TIMEOUT = arg('--timeout', '45000')
const OUT = arg('--out', `soak-${LABEL || 'board'}-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, '')}.csv`)

if (!MASTER || !RELAY || !(EVERY >= 30) || !(HOURS > 0)) {
  console.error('usage: node scripts/relay-soak.mjs --master <npub|hex> --relay wss://... [--every 300 (>= 30)] [--hours 12] [--label x] [--out file.csv]')
  exit(2)
}

const MGMT = join(dirname(fileURLToPath(import.meta.url)), 'mgmt-request.mjs')
const STACKS = ['main', 'btn_latch', 'sys_evt', 'esp_timer', 'tcpip']
const COLS = ['time', 'label', 'ok', 'uptime_s', 'free_heap', 'largest_free_block', 'min_free_heap',
  'relay_connects', 'last_reset', ...STACKS.map((s) => `stack_${s}`), 'crash_detail', 'error']

/** First value found under `key` anywhere in the reply, depth first. */
function find(obj, key) {
  if (obj === null || typeof obj !== 'object') return undefined
  if (Object.hasOwn(obj, key)) return obj[key]
  for (const v of Object.values(obj)) {
    const r = find(v, key)
    if (r !== undefined) return r
  }
  return undefined
}

function getStatus() {
  const a = [MGMT, '--method', 'get_status', '--master', MASTER, '--relay', RELAY, '--timeout', TIMEOUT]
  if (KEY_FILE) a.push('--key-file', KEY_FILE)
  return new Promise((resolve) => {
    const p = spawn(process.execPath, a, { stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    let err = ''
    p.stdout.on('data', (d) => { out += d })
    p.stderr.on('data', (d) => { err += d })
    p.on('close', (code) => {
      if (code === 0) {
        try { resolve({ ok: true, status: JSON.parse(out) }) } catch (e) { resolve({ ok: false, error: `bad JSON: ${e.message}` }) }
      } else {
        resolve({ ok: false, error: (err.split('\n').find((l) => l.trim()) ?? `exit ${code}`).trim() })
      }
    })
  })
}

const csv = (v) => {
  if (v === undefined || v === null) return ''
  const s = typeof v === 'object' ? JSON.stringify(v) : String(v)
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

if (!existsSync(OUT)) appendFileSync(OUT, COLS.join(',') + '\n')
console.log(`soak ${LABEL || ''}: get_status every ${EVERY} s for ${HOURS} h -> ${OUT}`)

const end = Date.now() + HOURS * 3600_000
let lastUptime = null
let rounds = 0
let answered = 0
let lowFree = Infinity
let lowBlock = Infinity

while (Date.now() < end) {
  const started = Date.now()
  const r = await getStatus()
  const time = new Date().toISOString()
  rounds++
  const s = r.ok ? r.status : {}
  const g = (k) => (r.ok ? find(s, k) : undefined)
  const stacks = g('stack_free') ?? {}
  const row = {
    time, label: LABEL, ok: r.ok ? 1 : 0,
    uptime_s: g('uptime_s'), free_heap: g('free_heap'),
    largest_free_block: g('largest_free_block') ?? g('largest_block'),
    min_free_heap: g('min_free_heap'), relay_connects: g('relay_connects'),
    last_reset: g('last_reset'), crash_detail: g('crash_detail'), error: r.error,
  }
  for (const st of STACKS) row[`stack_${st}`] = stacks?.[st]
  appendFileSync(OUT, COLS.map((c) => csv(row[c])).join(',') + '\n')

  if (r.ok) {
    answered++
    if (typeof row.free_heap === 'number') lowFree = Math.min(lowFree, row.free_heap)
    if (typeof row.largest_free_block === 'number') lowBlock = Math.min(lowBlock, row.largest_free_block)
    if (lastUptime !== null && typeof row.uptime_s === 'number' && row.uptime_s < lastUptime) {
      console.log(`${time} REBOOT: uptime ${lastUptime} -> ${row.uptime_s}, last_reset ${row.last_reset}, crash_detail ${csv(row.crash_detail) || 'null'}`)
    }
    if (typeof row.uptime_s === 'number') lastUptime = row.uptime_s
    const marks = STACKS.map((st) => `${st}=${row[`stack_${st}`] ?? '-'}`).join(' ')
    console.log(`${time} up ${row.uptime_s}s free ${row.free_heap} block ${row.largest_free_block} min ${row.min_free_heap} | ${marks}`)
  } else {
    console.log(`${time} no answer: ${r.error}`)
  }

  const wait = EVERY * 1000 - (Date.now() - started)
  if (Date.now() + wait >= end) break
  if (wait > 0) await new Promise((res) => setTimeout(res, wait))
}

console.log(`done: ${answered}/${rounds} answered; lowest free_heap ${lowFree === Infinity ? '-' : lowFree}, lowest largest block ${lowBlock === Infinity ? '-' : lowBlock}; log ${OUT}`)
