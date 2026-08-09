# NIP-NONCE-COMMITMENT: Host-Committed Nonces for NIP-46 Remote Signing

`draft` `optional`

Two additional NIP-46 methods, `sign_event_commit` and `sign_event_reveal`,
that let a client force a remote signer to commit to its BIP-340 signing nonce
before the client reveals randomness of its own. The final nonce is a function
of both, so a signer cannot choose its nonces freely, and the covert channel by
which malicious signer firmware could leak key material through signature
nonces is reduced from a broadcast to, at worst, a low-rate abort channel.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as defined in
RFC 2119.

## Motivation

A NIP-46 signer is trusted with an nsec precisely so that nothing else has to
be. That trust has one channel left open: the signature itself. BIP-340 lets a
signer add 32 bytes of auxiliary randomness to its nonce derivation, and
nothing in the protocol constrains that choice. Malicious firmware can grind
`aux_rand` until the resulting signature encodes a few chosen bits, and leak an
entire seed over a few dozen perfectly valid signatures. The user sees normal
events, normally signed. No log, no display, no policy engine notices anything.

This is not hypothetical caution. The hardware wallet world has already been
through it: Blockstream's Anti-Exfil protocol exists because a compromised
signing device leaking through nonces was judged a realistic threat for
Bitcoin, and hardware Nostr signers now hold keys of comparable value to their
owners. Open source and reproducible builds shrink the window for malicious
firmware but cannot close it; a verifier can only check the build they
verified, not the one that shipped.

Sign-to-contract closes the channel cryptographically. The signer commits to
its nonce point before it learns randomness the client contributes; the final
nonce is the committed point tweaked by a hash of both. The signer cannot
grind what it cannot predict.

## Protocol

Both methods travel as ordinary NIP-46 requests inside kind 24133 envelopes.
`P` is the signer's x-only public key, `m` the event id to be signed, `n` the
secp256k1 group order, and `G` its generator. `TaggedHash` is as defined in
BIP-340.

### Round one: `sign_event_commit`

The client draws 32 fresh random bytes `rho` and sends its hash, keeping `rho`
secret:

```json
{
  "id": "<request-id>",
  "method": "sign_event_commit",
  "params": ["<event-json>", "<hex SHA256(rho)>"]
}
```

The signer derives its nonce `k0` per BIP-340 nonce derivation, with the
received commitment `t` included in the hashed input alongside the message, so
that `k0` is bound to both. It computes `R0 = k0·G` and replies with the
33-byte compressed encoding:

```json
{
  "id": "<request-id>",
  "result": "{\"commitment\": \"<hex R0>\", \"ref\": \"<opaque>\"}"
}
```

The signer MUST NOT produce a signature for `m` at this stage, MUST bind the
pending state to `(m, t)`, and MUST discard the pending state after a timeout
(60 seconds is RECOMMENDED) or after a single reveal attempt, successful or
not. `k0` MUST be fresh per request and MUST never be reused.

### Round two: `sign_event_reveal`

The client reveals its randomness:

```json
{
  "id": "<request-id-2>",
  "method": "sign_event_reveal",
  "params": ["<ref>", "<hex rho>"]
}
```

The signer verifies `SHA256(rho) = t` for the pending request, and MUST refuse
with an error otherwise. It then computes

```
e_c = int(TaggedHash("NonceCommit/tweak", bytes(R0) || rho)) mod n
k   = (k0 + e_c) mod n
```

and completes an otherwise standard BIP-340 signature for `m` using `k` as the
secret nonce (including the even-Y normalisation BIP-340 requires). The result
is the signed event, exactly as `sign_event` would return it.

### Client verification

The signature is valid BIP-340; any verifier accepts it. The client that ran
the protocol additionally checks the commitment:

```
r == x(R0 + e_c·G)
```

where `r` is the first 32 bytes of the signature and `e_c` is recomputed from
`R0` and `rho`. Negation for even-Y does not change the x-coordinate, so the
equation holds for a compliant signer regardless of parity. If the check
fails, the client MUST treat the signer as malicious: discard the signature,
refuse further requests over that connection, and surface the failure to the
user. A commitment mismatch is not an error condition to retry; it is the
attack this protocol exists to catch.

## What this does and does not achieve

The signer chooses `k0` knowing `t` but not `rho`, so it cannot predict the
final nonce at commitment time; grinding signatures into a covert channel
stops working. What remains is an abort channel: a malicious signer that
dislikes the final nonce can refuse to answer the reveal, leaking at most a
fraction of a bit per interaction at the cost of visible failures. This is the
same residual accepted by Anti-Exfil, and no interactive scheme does better
without a second signing party.

The protection is only as good as the client's `rho`. A client whose
randomness the signer can predict has rebuilt the original problem, and a
client that reuses `rho` MUST be considered broken.

Threshold signing (FROST-style bunkers) also removes unilateral nonce choice,
by ensuring no single party holds the key at all. The two approaches serve
different deployments: threshold schemes need multiple keyholders and a
coordination protocol, while this one protects the common case of a single
hardware signer with two extra messages and no new keys.

Clients MUST fall back to plain `sign_event` when a signer does not implement
these methods, and SHOULD indicate to the user that nonce commitment is not in
effect. A signer that advertises the methods and then fails commitment checks
is worse than one that never offered them; see above.

## Costs

One extra round trip per signature. Over relays this doubles signing latency,
which is material for interactive use and immaterial for anything batched;
over local transports (USB-bridged signers, LAN bunkers) it is microseconds.
Clients MAY reserve the protocol for high-value events and MAY apply it per
connection rather than per signature. Signers carry one pending `(m, t, k0)`
per in-flight request; the state is small, bounded and expiring.

## Reference implementation

Planned for Heartwood (heartwood-esp32) as a `heartwood_`-prefixed method pair
first, promoted to the unprefixed names here if adopted more widely. The
protocol requires nothing exotic of a signer: one point multiplication and one
tagged hash beyond a standard BIP-340 signature.
