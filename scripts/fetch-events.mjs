#!/usr/bin/env node
// scripts/fetch-events.mjs — dump relay events matching a filter.
//
// Without --live it collects the stored events and prints them as one JSON
// array at EOSE. With --live it stays open and prints each event as it
// arrives, one per line, which is the only way to see ephemeral kinds (the
// C4/C5 notices, the management channel) — relays do not store those, so a
// stored query returns nothing however long you wait.
//
// Deps resolve via scripts/relay-deps.mjs.
//
// Usage:
//   node scripts/fetch-events.mjs --filter '{"kinds":[1059],"#p":["<hex>"],"limit":5}'
//   node scripts/fetch-events.mjs --live --filter '{"kinds":[24133]}'
//   [--relay wss://...] [--timeout 10000]

import { argv, exit } from 'node:process'
import { WebSocket, arg, DEFAULT_RELAY } from './relay-deps.mjs'

const RELAY = arg(argv, '--relay', DEFAULT_RELAY)
const FILTER = JSON.parse(arg(argv, '--filter', '{}'))
const TIMEOUT = Number(arg(argv, '--timeout', '10000'))
const LIVE = argv.includes('--live')

const ws = new WebSocket(RELAY)
const events = []
setTimeout(() => {
  if (!LIVE) console.log(JSON.stringify(events))
  exit(0)
}, TIMEOUT)

ws.on('open', () => ws.send(JSON.stringify(['REQ', 'f', FILTER])))
ws.on('message', (data) => {
  let msg
  try {
    msg = JSON.parse(data.toString())
  } catch {
    return
  }
  if (msg[0] === 'EVENT' && msg[1] === 'f') {
    if (LIVE) console.log(JSON.stringify(msg[2]))
    else events.push(msg[2])
  }
  if (msg[0] === 'EOSE' && !LIVE) {
    console.log(JSON.stringify(events))
    ws.close()
    exit(0)
  }
})
ws.on('error', (e) => {
  console.error(String(e.message))
  exit(1)
})
