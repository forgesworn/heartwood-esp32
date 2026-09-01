#!/usr/bin/env node
// Opt-in disaster-recovery backup for development devices. Unlike Heartwood's
// normal portable backup, this captures the complete NVS partition, including
// seeds, pairings and bearer notes. Plaintext is staged only on a RAM-backed
// filesystem and the final artifact is encrypted to two independent age keys.

import { createHash } from 'node:crypto'
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { argv, platform } from 'node:process'
import { spawnSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

import { parseBinary } from './partition-table.mjs'

export function run(command, args, options = {}) {
  const encoding = Object.hasOwn(options, 'encoding') ? options.encoding : 'utf8'
  const result = spawnSync(command, args, {
    encoding,
    input: options.input,
    maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
    stdio: options.stdio,
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    const detail = typeof result.stderr === 'string' ? result.stderr.trim() : ''
    throw new Error(`${command} failed (${result.status})${detail ? `: ${detail}` : ''}`)
  }
  return result
}

export function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

export function withRamWorkspace(callback) {
  let root
  let ramDevice
  try {
    if (platform === 'linux' && existsSync('/dev/shm')) {
      root = mkdtempSync('/dev/shm/heartwood-dev-state-')
    } else if (platform === 'darwin') {
      const label = `HWRAM${process.pid}`
      const attached = run('hdiutil', ['attach', '-nomount', 'ram://65536']).stdout.trim()
      ramDevice = attached.split(/\s+/)[0]
      if (!/^\/dev\/disk\d+$/.test(ramDevice)) throw new Error(`unexpected RAM disk device ${ramDevice}`)
      run('diskutil', ['erasevolume', 'HFS+', label, ramDevice])
      root = `/Volumes/${label}`
      if (!existsSync(root)) throw new Error(`RAM volume did not mount at ${root}`)
      chmodSync(root, 0o700)
    } else {
      throw new Error('no supported RAM-backed staging filesystem (requires macOS or /dev/shm)')
    }
    return callback(root)
  } finally {
    if (root && existsSync(root)) {
      const safe = root.startsWith('/dev/shm/heartwood-dev-state-') || /^\/Volumes\/HWRAM\d+$/.test(root)
      if (!safe) throw new Error(`refusing to clean unexpected staging path ${root}`)
      if (ramDevice) {
        run('hdiutil', ['detach', ramDevice])
      } else {
        rmSync(root, { recursive: true, force: true })
      }
    }
  }
}

export function readFlash(esptool, chip, port, offset, size, output) {
  run(esptool, [
    '--chip', chip,
    '--port', port,
    'read-flash', `0x${offset.toString(16)}`, `0x${size.toString(16)}`, output,
  ], { stdio: 'inherit' })
}

export function decryptBackup(backup, identity) {
  const decrypted = run('age', ['--decrypt', '--identity', identity, backup], {
    encoding: null,
    maxBuffer: 64 * 1024 * 1024,
  }).stdout
  const listing = run('tar', ['-tzf', '-'], { input: decrypted }).stdout.trim().split(/\r?\n/)
  for (const required of ['manifest.json', 'partition-table.bin', 'nvs.bin']) {
    if (!listing.includes(required)) throw new Error(`backup archive is missing ${required}`)
  }
  const manifestText = run('tar', ['-xOzf', '-', 'manifest.json'], { input: decrypted }).stdout
  const manifest = JSON.parse(manifestText)
  for (const region of Object.values(manifest.regions ?? {})) {
    if (!/^[a-z0-9][a-z0-9-]*\.bin$/.test(region.file ?? '') || !listing.includes(region.file)) {
      throw new Error(`backup manifest names an invalid or missing region file: ${region.file}`)
    }
    const bytes = run('tar', ['-xOzf', '-', region.file], { input: decrypted, encoding: null }).stdout
    const digest = createHash('sha256').update(bytes).digest('hex')
    if (bytes.length !== region.size || digest !== region.sha256) {
      throw new Error(`backup region verification failed: ${region.file}`)
    }
  }
  return { manifest, listing, archiveHashesVerified: true }
}

function values(args, name) {
  const found = []
  for (let i = 0; i < args.length; i++) if (args[i] === name) found.push(args[i + 1])
  return found.filter(Boolean)
}

function value(args, name, fallback) {
  const found = values(args, name)
  return found.length ? found.at(-1) : fallback
}

function usage() {
  console.error('usage: node scripts/dev-state-backup.mjs --port <serial> --firmware-version <version> \\')
  console.error('  --out <backup.tar.gz.age> --recipient <age1...> --recipient <age1...> \\')
  console.error('  --verify-identity <age identity file> [--esptool <path>] [--board heltec-v4]')
}

function main(args) {
  if (args.includes('--help')) {
    usage()
    return
  }
  const port = value(args, '--port')
  const firmwareVersion = value(args, '--firmware-version')
  const output = value(args, '--out')
  const identity = value(args, '--verify-identity')
  const esptool = value(args, '--esptool', 'esptool')
  const board = value(args, '--board', 'heltec-v4')
  const chip = value(args, '--chip', 'esp32s3')
  const recipients = [...new Set(values(args, '--recipient'))]
  if (!port || !firmwareVersion || !output || !identity || recipients.length !== 2) {
    usage()
    throw new Error('exactly two independent recipients and all required arguments must be supplied')
  }
  if (!recipients.every((recipient) => /^age1[023456789acdefghjklmnpqrstuvwxyz]{50,}$/.test(recipient))) {
    throw new Error('each recipient must be an age X25519 public key')
  }
  const finalPath = resolve(output)
  const partialPath = `${finalPath}.part-${process.pid}`
  if (existsSync(finalPath) || existsSync(partialPath)) throw new Error('refusing to overwrite a backup artifact')
  if (!existsSync(dirname(finalPath))) throw new Error(`output directory does not exist: ${dirname(finalPath)}`)
  if (!existsSync(identity)) throw new Error(`verification identity does not exist: ${identity}`)

  try {
    withRamWorkspace((root) => {
      const tablePath = join(root, 'partition-table.bin')
      readFlash(esptool, chip, port, 0x8000, 0xc00, tablePath)
      const layout = parseBinary(readFileSync(tablePath))
      const named = new Map(layout.map((entry) => [entry.label, entry]))
      const nvs = named.get('nvs')
      if (!nvs) throw new Error('installed partition table has no NVS partition')

      const regions = [{ name: 'nvs', ...nvs }]
      for (const optional of ['config', 'otadata']) {
        const entry = named.get(optional)
        if (entry) regions.push({ name: optional, ...entry })
      }
      for (const region of regions) {
        readFlash(esptool, chip, port, region.offset, region.size, join(root, `${region.name}.bin`))
      }

      const files = [
        {
          file: 'partition-table.bin', offset: 0x8000, size: 0xc00,
          sha256: sha256File(tablePath),
        },
        ...regions.map((region) => ({
          file: `${region.name}.bin`, offset: region.offset, size: region.size,
          sha256: sha256File(join(root, `${region.name}.bin`)),
        })),
      ]
      const manifest = {
        format: 'heartwood-dev-state-v1',
        classification: 'SECRET DEVICE CLONE - DEVELOPMENT DISASTER RECOVERY ONLY',
        warning: 'Contains seeds, Nostr identities and pairings, network state, and LUD-25 bearer-note records. Restore only when the original device is retired or unavailable; never run two copies of this state.',
        createdAt: new Date().toISOString(),
        board,
        chip,
        firmwareVersion,
        includes: ['seeds', 'nostr identities', 'client pairings', 'network state', 'LUD-25 bearer-note records'],
        layout,
        regions: Object.fromEntries(files.map((file) => [file.file.replace(/\.bin$/, '').replace('-', '_'), file])),
      }
      writeFileSync(join(root, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 })
      const archive = join(root, 'dev-state.tar.gz')
      const archiveFiles = ['manifest.json', ...files.map((file) => file.file)]
      run('tar', ['-czf', archive, '-C', root, ...archiveFiles])

      const ageArgs = recipients.flatMap((recipient) => ['--recipient', recipient])
      run('age', [...ageArgs, '--output', partialPath, archive])
      chmodSync(partialPath, 0o600)
      const verified = decryptBackup(partialPath, identity)
      if (verified.manifest.format !== manifest.format || verified.manifest.regions.nvs.sha256 !== manifest.regions.nvs.sha256) {
        throw new Error('encrypted backup verification did not reproduce the manifest')
      }
      renameSync(partialPath, finalPath)
      console.log(JSON.stringify({
        backup: finalPath,
        sha256: sha256File(finalPath),
        board,
        firmwareVersion,
        regions: files.map(({ file, offset, size, sha256 }) => ({ file, offset, size, sha256 })),
        recipients: recipients.length,
        decryptVerified: true,
        archiveHashesVerified: verified.archiveHashesVerified,
      }, null, 2))
    })
  } catch (error) {
    // The partial contains ciphertext only, but it must never be mistaken for
    // an accepted backup when decrypt/list/manifest verification did not pass.
    if (existsSync(partialPath)) rmSync(partialPath)
    throw error
  }
}

if (argv[1] && import.meta.url === pathToFileURL(argv[1]).href) {
  try {
    main(argv.slice(2))
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
