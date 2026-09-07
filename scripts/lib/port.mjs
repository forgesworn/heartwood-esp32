// scripts/lib/port.mjs
//
// node-serialport wiring for the bench scripts: resolve the module, open the
// port, and expose a request/response call over the frame codec.
//
// The module resolution is the same two-candidate dance every script here has
// always done — a local `serialport` if the checkout has one, otherwise
// Sapwood's, via SAPWOOD_DIR. It lives here now so the next script does not
// have to copy it a tenth time.

import { buildFrame, createFrameReader, NACK, pollForReply } from './frame.mjs'

async function resolveSerialPort(env) {
  const candidates = [
    'serialport',
    new URL(`${env.SAPWOOD_DIR ?? '../sapwood'}/node_modules/serialport/dist/index.js`,
      new URL('../../', import.meta.url)).href,
  ]
  for (const candidate of candidates) {
    try {
      return (await import(candidate)).SerialPort
    } catch {
      // try the next candidate
    }
  }
  throw new Error('cannot resolve node-serialport; set SAPWOOD_DIR to a checkout that has it')
}

/**
 * Open `path` and return a framed session.
 *
 * `request(type, want, options)` resends until one of `want` (a NACK is always
 * accepted) comes back, or the deadline passes — see pollForReply for why a
 * single long read is not enough on a board whose relay loop is blocking on
 * WiFi. Pass `deadlineMs: 0` for a one-shot when the caller genuinely wants
 * "answer now or not at all", such as a prompt already counting down on the
 * device's own screen.
 */
export async function openFramedPort(path, { env = process.env, baudRate = 115200 } = {}) {
  const SerialPort = await resolveSerialPort(env)
  const port = new SerialPort({ path, baudRate })
  await new Promise((resolve, reject) => {
    port.once('open', resolve)
    port.once('error', reject)
  })

  // One reader for the life of the session. Replies to a request that already
  // timed out are stragglers, not answers, so anything nobody is waiting for
  // is dropped here rather than confusing the next call.
  const read = createFrameReader()
  const waiters = []
  port.on('data', (chunk) => {
    for (const frame of read(chunk)) {
      for (let i = waiters.length - 1; i >= 0; i--) {
        if (waiters[i].want.includes(frame.type)) waiters.splice(i, 1)[0].resolve(frame)
      }
    }
  })

  const waitFor = (want) => (timeoutMs) => new Promise((resolve) => {
    const waiter = { want, resolve }
    waiters.push(waiter)
    setTimeout(() => {
      const i = waiters.indexOf(waiter)
      if (i !== -1) waiters.splice(i, 1)[0].resolve(null)
    }, timeoutMs)
  })

  return {
    port,
    /**
     * Arm a listener for one of `want` without sending anything.
     *
     * For callers that own their own send/retry policy — `authenticateSession`
     * arms before every send precisely so a fast ACK cannot land in the gap
     * between writing and starting to listen.
     */
    waitFor(want, timeoutMs) {
      return waitFor(want.includes(NACK) ? want : [...want, NACK])(timeoutMs)
    },
    /** Write one frame. Pair with `waitFor` when you are driving the retries. */
    send(type, payload = Buffer.alloc(0)) {
      port.write(buildFrame(type, payload))
    },
    /** Fire a frame and wait for one of `want` (NACK always included). */
    request(type, want, { payload = Buffer.alloc(0), deadlineMs = 90_000, intervalMs = 2_000 } = {}) {
      const wanted = want.includes(NACK) ? want : [...want, NACK]
      const send = () => port.write(buildFrame(type, payload))
      if (deadlineMs === 0) {
        const pending = waitFor(wanted)(intervalMs)
        send()
        return pending
      }
      return pollForReply({ send, waitFor: waitFor(wanted), deadlineMs, intervalMs })
    },
    /**
     * Fire once and wait a long time for the answer. For the frames that put an
     * approval card on the device's OLED: resending would restart the prompt
     * under the owner's finger, so these get one shot and a patient read.
     */
    requestApproval(type, want, { payload = Buffer.alloc(0), timeoutMs = 70_000 } = {}) {
      const wanted = want.includes(NACK) ? want : [...want, NACK]
      const pending = waitFor(wanted)(timeoutMs)
      port.write(buildFrame(type, payload))
      return pending
    },
    close() {
      port.close()
    },
  }
}
