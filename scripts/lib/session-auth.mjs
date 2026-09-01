// Retry SESSION_AUTH because native USB can enumerate before the firmware has
// reached its locked command loop. The listener is armed before each send so a
// fast ACK cannot land in the gap between write and read.
export async function authenticateSession({
  sendAuth,
  waitForAck,
  attempts = 6,
  timeoutMs = 10_000,
  onAttempt = () => {},
}) {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    onAttempt(attempt, attempts)
    const pending = waitForAck(timeoutMs)
    sendAuth()
    const reply = await pending
    if (reply) return { reply, attempt }
  }
  return null
}
