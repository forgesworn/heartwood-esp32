#!/usr/bin/env node
// scripts/identity-meta-params.mjs
//
// Prints the params JSON for a relay `set_identity_meta` request with a test
// picture, for checklist section 41 (RGB332 identity picture). Sapwood sends
// RGB332 only over the cable, so the relay half of the bench needs this.
//
// The picture is four colour bands (red, green, blue, white) over a black
// border, so a wrong format or byte order is plain on the panel.
//
// Usage:
//   node scripts/mgmt-request.mjs --method set_identity_meta --challenge \
//     --params "$(node scripts/identity-meta-params.mjs --name bench)"
//   [--format rgb332|rgb565] [--size 64] [--bytes <n>]
//
// --bytes truncates or pads the pixel bytes to n, for the refusal step
// (4095 or 4097 at 64x64 RGB332).

import { argv, exit, stdout } from 'node:process'
import { pathToFileURL } from 'node:url'

function arg(name, fallback) {
  const i = argv.indexOf(name)
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : fallback
}

// RGB332 is RRRGGGBB; Rgb565 is big-endian RRRRRGGGGGGBBBBB, as the panel
// path reads it.
const BANDS = {
  rgb332: [0xe0, 0x1c, 0x03, 0xff],
  rgb565: [0xf800, 0x07e0, 0x001f, 0xffff],
}

export function picture(format, size) {
  const bands = BANDS[format]
  if (!bands) throw new Error(`format must be rgb332 or rgb565, not ${format}`)
  const bpp = format === 'rgb332' ? 1 : 2
  const out = new Uint8Array(size * size * bpp)
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const border = x < 2 || y < 2 || x >= size - 2 || y >= size - 2
      const v = border ? 0 : bands[Math.min(3, Math.floor((y * 4) / size))]
      const i = (y * size + x) * bpp
      if (bpp === 1) out[i] = v
      else {
        out[i] = v >> 8
        out[i + 1] = v & 0xff
      }
    }
  }
  return out
}

export function params({ name, format, size, bytes }) {
  let px = picture(format, size)
  if (bytes !== undefined) {
    const sized = new Uint8Array(bytes)
    sized.set(px.subarray(0, Math.min(bytes, px.length)))
    px = sized
  }
  return { name, w: size, h: size, avatar_b64: Buffer.from(px).toString('base64') }
}

if (import.meta.url === pathToFileURL(argv[1]).href) {
  const size = Number(arg('--size', '64'))
  const bytesArg = arg('--bytes')
  if (!Number.isInteger(size) || size < 1 || size > 255) {
    console.error('--size must be 1-255')
    exit(2)
  }
  try {
    const p = params({
      name: arg('--name', 'bench'),
      format: arg('--format', 'rgb332'),
      size,
      bytes: bytesArg === undefined ? undefined : Number(bytesArg),
    })
    stdout.write(JSON.stringify(p) + '\n')
  } catch (e) {
    console.error(e.message)
    exit(2)
  }
}
