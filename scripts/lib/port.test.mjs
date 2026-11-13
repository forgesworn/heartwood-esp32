import assert from 'node:assert/strict'
import { test } from 'node:test'

import { checkSerialDevicePath, readPortArg } from './port.mjs'

// 2026-11-02: `argv[argv.indexOf('--port') + 1]` with no --port flag resolves
// to argv[0], and three bench drivers went on to open the node binary running
// them as the "port". These pins keep a bench driver's flag parse from ever
// choosing a path, and keep every chosen path under /dev/cu.* / /dev/tty.*.

test('real serial device names pass', () => {
  for (const p of [
    '/dev/cu.usbserial-5B310133351',
    '/dev/cu.usbmodem101',
    '/dev/cu.wchusbserial-1A2B',
    '/dev/cu.SLAB_USBtoUART',
    '/dev/tty.usbserial-5B310133351',
  ]) {
    assert.equal(checkSerialDevicePath(p), null, p)
  }
})

test('anything not a serial device is refused', () => {
  for (const p of [
    undefined,
    null,
    '--sizes',
    // argv[0], the node binary itself, the 2026-11-02 incident value
    '/Users/x/.nvm/versions/node/v24.21.0/bin/node',
    '/etc/hosts',
    '/dev/sda',
    '/dev/cu',
    '/dev/cu.',
    '/dev/cu..',
    '/dev/cu.foo/../../etc/hosts'.split('/').join('\\'),
    '/dev/cufoo',
    'relative/path',
  ]) {
    assert.ok(checkSerialDevicePath(p), `should refuse ${p}`)
  }
})

test('readPortArg returns a checked device path', () => {
  assert.equal(
    readPortArg(['node', 'tool', '--port', '/dev/cu.usbserial-X'], 'usage'),
    '/dev/cu.usbserial-X',
  )
})

test('readPortArg never returns argv[0] or a flag', () => {
  for (const argv of [
    ['node', 'tool'],
    ['node', 'tool', '--port'],
    ['node', 'tool', '--port', '--sizes', '1024'],
  ]) {
    assert.throws(() => readPortArg(argv, 'usage: test'), /usage: test|port must be/)
  }
})
