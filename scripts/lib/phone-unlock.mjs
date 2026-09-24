// scripts/lib/phone-unlock.mjs
//
// The phone half of phone unlock, in Node's own crypto: an implementation
// independent of common/src/phone_unlock.rs, held to the same vectors
// (common/tests/fixtures/phone-unlock-v1.json). The bench client uses it to
// stand in for Cambium, and it is the reference Cambium's Kotlin follows.
//
// Construction (see the Rust module for the reasoning):
//   K        = HKDF-SHA256(salt SALT, ikm S, info "phone")          32 bytes
//   hint     = hex(HMAC-SHA256(K, "hint" || author))[..16]
//   okm      = HKDF-SHA256(salt SALT, ikm K, info "announce" || author) 64 bytes
//   content  = base64(0x01 || nonce(12) || ChaCha20(okm[0..32], nonce) ^ json
//                     || HMAC-SHA256(okm[32..64], 0x01 || nonce || ct))

import { createCipheriv, createHmac, hkdfSync, timingSafeEqual } from 'node:crypto'

const SALT = Buffer.from('heartwood-phone-unlock-v1')
export const ANNOUNCE_KIND = 24135
export const DELIVERY_KIND = 24136
// Enrolment hand-off, Sapwood (or this bench) -> phone: an ephemeral event from
// a throwaway key tagged ["h", R] with the phone's one-off rendezvous tag, whose
// content is the board's enrolment answer passed through untouched. The board
// never sees it. Cambium: unlock/Enrolment.kt.
export const HANDOFF_KIND = 24137
export const LABEL_MAX_BYTES = 16
export const MAX_ANNOUNCE_AGE_SECS = 120
export const MAX_FUTURE_SKEW_SECS = 60

const hkdf = (ikm, info, len) => Buffer.from(hkdfSync('sha256', ikm, SALT, info, len))

/** K from the phone's slot secret S (32-byte Buffer). */
export function phoneKey(slotSecret) {
  return hkdf(slotSecret, Buffer.from('phone'), 32)
}

/** The `h` tag value for a one-time author pubkey (32-byte Buffer). */
export function hint(k, author) {
  return createHmac('sha256', k).update('hint').update(author).digest('hex').slice(0, 16)
}

export function hintMatches(k, author, received) {
  const ours = Buffer.from(hint(k, author))
  const theirs = Buffer.from(String(received))
  return ours.length === theirs.length && timingSafeEqual(ours, theirs)
}

function contentKeys(k, author) {
  const okm = hkdf(k, Buffer.concat([Buffer.from('announce'), author]), 64)
  return { enc: okm.subarray(0, 32), mac: okm.subarray(32) }
}

// OpenSSL's chacha20 takes a 16-byte IV: a 32-bit little-endian block counter
// then the 96-bit nonce. The Rust side is IETF ChaCha20 from counter 0.
function chacha(key, nonce, data) {
  const c = createCipheriv('chacha20', key, Buffer.concat([Buffer.alloc(4), nonce]))
  return Buffer.concat([c.update(data), c.final()])
}

/** Seal a context object (keys in LockContext's field order). */
export function sealContext(k, author, context, nonce) {
  const { enc, mac } = contentKeys(k, author)
  const body = Buffer.concat([
    Buffer.from([1]),
    nonce,
    chacha(enc, nonce, Buffer.from(JSON.stringify(context))),
  ])
  const tag = createHmac('sha256', mac).update(body).digest()
  return Buffer.concat([body, tag]).toString('base64')
}

/** Open a sealed context, or return null if it is not for this K and author. */
export function openContext(k, author, content) {
  if (typeof content !== 'string' || content.length > 2048) return null
  const blob = Buffer.from(content, 'base64')
  if (blob.toString('base64') !== content || blob.length < 1 + 12 + 32 || blob[0] !== 1) return null
  const body = blob.subarray(0, blob.length - 32)
  const tag = blob.subarray(blob.length - 32)
  const { enc, mac } = contentKeys(k, author)
  if (!timingSafeEqual(createHmac('sha256', mac).update(body).digest(), tag)) return null
  try {
    const context = JSON.parse(chacha(enc, body.subarray(1, 13), body.subarray(13)).toString('utf8'))
    return context?.v === 1 ? context : null
  } catch {
    return null
  }
}

/** The delivery plaintext the board expects inside NIP-44. */
export function deliveryJson(id, slotSecret) {
  return `{"v":1,"id":${id},"s":"${slotSecret.toString('hex')}"}`
}

/**
 * 'prompt' | 'duplicate' | 'stale' | 'replay' | 'not-locked'
 * `last` is { boot, author } (author as hex) of the newest announcement this
 * phone already prompted for on this board, or null. A repeat needs the same
 * count AND author: every boot has a new author, so a count that failed to
 * persist still prompts.
 */
export function judge(context, authorHex, createdAt, now, last) {
  if (context.t !== 'locked') return 'not-locked'
  if (createdAt + MAX_ANNOUNCE_AGE_SECS < now || createdAt > now + MAX_FUTURE_SKEW_SECS) return 'stale'
  if (last && context.boot < last.boot) return 'replay'
  if (last && context.boot === last.boot && last.author === authorHex) return 'duplicate'
  return 'prompt'
}

/**
 * The code Cambium shows when it asks to become an unlock phone:
 *   heartwood-unlock:enrol?v=1&p=<64 hex>&r=<32 hex>&label=<name>&relay=<url>&relay=...
 * Returns { enrolPubkey, rendezvous, label, relays } or null. Everything in it is
 * public: P opens only the hand-off, R is used once, the relays are where the
 * phone waits. Mirrors Cambium's EnrolmentCode.parse.
 */
export function parseEnrolmentCode(text) {
  const prefix = 'heartwood-unlock:enrol?'
  if (typeof text !== 'string' || !text.startsWith(prefix)) return null
  const params = []
  for (const pair of text.slice(prefix.length).split('&')) {
    const eq = pair.indexOf('=')
    if (eq <= 0) continue
    let value
    try {
      value = decodeURIComponent(pair.slice(eq + 1).replace(/\+/g, ' '))
    } catch {
      return null
    }
    params.push([pair.slice(0, eq), value])
  }
  const one = (name) => {
    const found = params.filter(([k]) => k === name)
    return found.length === 1 ? found[0][1] : null
  }
  if (one('v') !== '1') return null
  const enrolPubkey = one('p')
  const rendezvous = one('r')
  const label = one('label')
  if (!/^[0-9a-f]{64}$/.test(enrolPubkey ?? '') || !/^[0-9a-f]{32}$/.test(rendezvous ?? '')) return null
  if (!label?.trim() || Buffer.byteLength(label) > LABEL_MAX_BYTES) return null
  const relays = params.filter(([k]) => k === 'relay').map(([, v]) => v)
  const relayOk = (url) => /^wss?:\/\/\S+$/.test(url) && url.length <= 256
  if (!relays.length || !relays.every(relayOk)) return null
  return { enrolPubkey, rendezvous, label, relays }
}
