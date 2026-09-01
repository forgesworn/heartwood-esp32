#!/usr/bin/env node
// Recoverably install a signed release on the one-off 16 MB Heltec V4 whose
// 24 KiB legacy NVS must not be truncated. The encrypted dev-state backup must
// match the current partition table and NVS bytes before any write is allowed.

import { existsSync, readFileSync } from 'node:fs'
import { basename, join, resolve } from 'node:path'
import { argv } from 'node:process'
import { pathToFileURL } from 'node:url'

import { decryptBackup, readFlash, run, sha256File, withRamWorkspace } from './dev-state-backup.mjs'
import { parseBinary, parseCsv, sameLayout } from './partition-table.mjs'

function value(args, name, fallback) {
  const index = args.lastIndexOf(name)
  return index === -1 ? fallback : args[index + 1]
}

function requireFile(path, what) {
  if (!path || !existsSync(path)) throw new Error(`${what} does not exist: ${path ?? '(missing)'}`)
}

function assertHash(path, expected, what) {
  const actual = sha256File(path)
  if (!/^[0-9a-f]{64}$/.test(expected ?? '') || actual !== expected) {
    throw new Error(`${what} SHA-256 mismatch: expected ${expected}, got ${actual}`)
  }
}

function writeFlash(esptool, port, offset, path) {
  run(esptool, [
    '--chip', 'esp32s3', '--port', port, '--before', 'no-reset', '--after', 'no-reset', 'write-flash',
    `0x${offset.toString(16)}`, path,
  ], { stdio: 'inherit' })
}

function usage() {
  console.error('usage: node scripts/migrate-legacy-v4.mjs --port <serial> --release-dir <dir> \\')
  console.error('  --backup <dev-state.tar.gz.age> --backup-identity <age identity> \\')
  console.error('  [--esptool <path>] [--ota-verifier <heartwood-ota-sign>] \\')
  console.error('  --loader-session (--check-only | --write)')
}

function main(args) {
  if (args.includes('--help')) {
    usage()
    return
  }
  const repo = resolve(new URL('..', import.meta.url).pathname)
  const port = value(args, '--port')
  const releaseDir = resolve(value(args, '--release-dir', ''))
  const backup = resolve(value(args, '--backup', ''))
  const identity = resolve(value(args, '--backup-identity', ''))
  const esptool = value(args, '--esptool', 'esptool')
  const verifier = resolve(value(args, '--ota-verifier', join(repo, 'ota-sign/target/release/heartwood-ota-sign')))
  const checkOnly = args.includes('--check-only')
  const allowWrite = args.includes('--write')
  const loaderSession = args.includes('--loader-session')
  if (!port || !value(args, '--release-dir') || !value(args, '--backup') || !value(args, '--backup-identity')) {
    usage()
    throw new Error('all required arguments must be supplied')
  }
  if (checkOnly === allowWrite) throw new Error('choose exactly one of --check-only or --write')
  if (!loaderSession) throw new Error('the verified backup must leave the board in one continuous loader session; pass --loader-session')
  requireFile(join(releaseDir, 'version.json'), 'release manifest')
  requireFile(backup, 'encrypted backup')
  requireFile(identity, 'backup identity')
  requireFile(verifier, 'OTA signature verifier (build ota-sign first)')

  const version = JSON.parse(readFileSync(join(releaseDir, 'version.json'), 'utf8'))
  const board = version.boards?.['heltec-v4']
  const migration = board?.migration?.legacyNvsBigApp
  if (!board || !migration) throw new Error('release does not declare the heltec-v4 legacyNvsBigApp migration')
  const app = join(releaseDir, board.app)
  const bootloader = join(releaseDir, board.bootloader)
  const table = join(releaseDir, migration.partitionTable)
  const signature = `${app}.sig`
  for (const [path, what] of [[app, 'app'], [bootloader, 'bootloader'], [table, 'migration partition table'], [signature, 'app signature']]) {
    requireFile(path, what)
  }
  assertHash(app, board.sha256, 'app')
  assertHash(bootloader, board.bootloaderSha256, 'bootloader')
  assertHash(table, migration.partitionTableSha256, 'migration partition table')
  if (readFileSync(app).length > migration.appBytes) throw new Error('app does not fit the declared migration slot')
  if (readFileSync(bootloader).length > 0x8000) throw new Error('bootloader overlaps the partition table')
  const signatureText = readFileSync(signature, 'utf8').trim()
  if (signatureText !== board.signature) throw new Error('detached app signature does not match version.json')
  run(verifier, [
    'verify', '--pubkey', join(repo, 'firmware/ota-release-pubkey.hex'),
    '--board', 'heltec-v4', '--image', app, '--sig', signature,
  ], { stdio: 'inherit' })

  const backupState = decryptBackup(backup, identity)
  if (backupState.manifest.format !== 'heartwood-dev-state-v1' || backupState.manifest.board !== 'heltec-v4') {
    throw new Error('backup is not a Heltec V4 heartwood-dev-state-v1 artifact')
  }

  const targetLayout = parseBinary(readFileSync(table))
  const targetCsv = parseCsv(readFileSync(join(repo, 'firmware/partitions-v4-16mb-legacy-nvs-bigapp.csv'), 'utf8'))
  if (!sameLayout(targetLayout, targetCsv)) throw new Error('release migration table is not the committed safe layout')
  const twoSlotCsv = parseCsv(readFileSync(join(repo, 'firmware/partitions-v4-16mb-legacy-nvs.csv'), 'utf8'))

  withRamWorkspace((root) => {
    const installedTable = join(root, 'installed-partition-table.bin')
    readFlash(esptool, 'esp32s3', port, 0x8000, 0xc00, installedTable, {
      before: 'no-reset', after: 'no-reset',
    })
    const installedLayout = parseBinary(readFileSync(installedTable))
    const alreadyMigrated = sameLayout(installedLayout, targetLayout)
    if (!alreadyMigrated && !sameLayout(installedLayout, twoSlotCsv)) {
      throw new Error('installed table is neither supported legacy V4 layout; refusing all writes')
    }
    const backupTable = backupState.manifest.regions?.partition_table
    const backupNvs = backupState.manifest.regions?.nvs
    if (!backupTable || !backupNvs) throw new Error('backup manifest lacks partition_table or nvs evidence')
    assertHash(installedTable, backupTable.sha256, 'installed table versus backup')

    const installedNvsEntry = installedLayout.find((entry) => entry.label === 'nvs')
    if (!installedNvsEntry || installedNvsEntry.offset !== backupNvs.offset || installedNvsEntry.size !== backupNvs.size) {
      throw new Error('installed NVS bounds do not match the backup manifest')
    }
    const currentNvs = join(root, 'current-nvs.bin')
    readFlash(esptool, 'esp32s3', port, installedNvsEntry.offset, installedNvsEntry.size, currentNvs, {
      before: 'no-reset', after: 'no-reset',
    })
    assertHash(currentNvs, backupNvs.sha256, 'current NVS versus encrypted backup')

    console.log(`Pre-write gate passed: signed ${version.version}; encrypted backup exactly matches current NVS.`)
    if (checkOnly) {
      console.log('Check-only complete; no flash region was written or erased. Device remains in the same loader session for --write.')
      return
    }
    writeFlash(esptool, port, 0x10000, app)
    const appReadback = join(root, basename(app))
    readFlash(esptool, 'esp32s3', port, 0x10000, readFileSync(app).length, appReadback, {
      before: 'no-reset', after: 'no-reset',
    })
    assertHash(appReadback, board.sha256, 'app readback')

    writeFlash(esptool, port, 0x0, bootloader)
    const bootloaderReadback = join(root, basename(bootloader))
    readFlash(esptool, 'esp32s3', port, 0x0, readFileSync(bootloader).length, bootloaderReadback, {
      before: 'no-reset', after: 'no-reset',
    })
    assertHash(bootloaderReadback, board.bootloaderSha256, 'bootloader readback')

    if (!alreadyMigrated) writeFlash(esptool, port, 0x8000, table)
    const tableReadback = join(root, 'partition-table-readback.bin')
    readFlash(esptool, 'esp32s3', port, 0x8000, 0xc00, tableReadback, {
      before: 'no-reset', after: 'no-reset',
    })
    assertHash(tableReadback, migration.partitionTableSha256, 'partition table readback')

    run(esptool, [
      '--chip', 'esp32s3', '--port', port, '--before', 'no-reset', '--after', 'no-reset',
      'erase-region', '0x414000', '0x2000',
    ], { stdio: 'inherit' })
    const otadata = join(root, 'otadata-readback.bin')
    readFlash(esptool, 'esp32s3', port, 0x414000, 0x2000, otadata, {
      before: 'no-reset', after: 'hard-reset',
    })
    if (!readFileSync(otadata).every((byte) => byte === 0xff)) throw new Error('otadata erase readback is not blank')

    console.log(JSON.stringify({
      installed: version.version,
      board: 'heltec-v4',
      backupMatchedCurrentNvs: true,
      appReadbackVerified: true,
      bootloaderReadbackVerified: true,
      partitionTableReadbackVerified: true,
      otadataBlankVerified: true,
      nvsWritten: false,
      configWritten: false,
    }, null, 2))
  })
}

if (argv[1] && import.meta.url === pathToFileURL(argv[1]).href) {
  try {
    main(argv.slice(2))
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
