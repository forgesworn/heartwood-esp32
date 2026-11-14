import { test } from 'node:test'
import assert from 'node:assert/strict'
import { picture, params } from './identity-meta-params.mjs'

test('a 64x64 RGB332 picture is w*h bytes, Rgb565 is w*h*2', () => {
  assert.equal(picture('rgb332', 64).length, 4096)
  assert.equal(picture('rgb565', 64).length, 8192)
})

test('bands are red, green, blue, white inside a black border', () => {
  const px = picture('rgb332', 64)
  assert.equal(px[0], 0)
  assert.deepEqual([10, 26, 42, 58].map((y) => px[y * 64 + 10]), [0xe0, 0x1c, 0x03, 0xff])
  const wide = picture('rgb565', 64)
  const i = (10 * 64 + 10) * 2
  assert.deepEqual([wide[i], wide[i + 1]], [0xf8, 0x00])
})

test('--bytes sizes the picture for the refusal step', () => {
  for (const n of [4095, 4097]) {
    const p = params({ name: 'bench', format: 'rgb332', size: 64, bytes: n })
    assert.equal(Buffer.from(p.avatar_b64, 'base64').length, n)
    assert.equal(p.w, 64)
  }
})

test('an unknown format is refused', () => {
  assert.throws(() => picture('rgb888', 64))
})
