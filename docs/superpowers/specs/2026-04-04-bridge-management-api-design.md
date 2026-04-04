# Bridge Management API for Sapwood

**Date:** 2026-04-04
**Status:** Approved, ready for implementation

## Summary

Extend the heartwood-bridge with an axum HTTP server so Sapwood can manage the ESP32 over the local network. The bridge becomes the single entry point for both relay traffic (NIP-46) and device management (Sapwood API).

## Architecture

The bridge gains an axum HTTP server running on a second tokio task alongside the existing relay event loop. Both share `Arc<Mutex<RawSerial>>`. Relay handlers use `.lock()` (blocking wait). HTTP handlers use `.try_lock()` (immediate fail with 423 "device busy" if the serial port is held by a signing request).

```
                    +---------------------------+
                    |     heartwood-bridge      |
                    |                           |
  Nostr relays <--->  relay event loop (tokio)  |
                    |          |                |
                    |    Arc<Mutex<RawSerial>>   |
                    |          |                |
  Browser <-------->  axum HTTP server (:3100)  |
                    |   /api/* + static files   |
                    +---------------------------+
                               |
                          USB serial
                               |
                            ESP32
```

### New CLI flags

- `--api-port 3100` (default 3100)
- `--sapwood-dir /opt/sapwood/dist` (optional, serves static files)
- `--cors` (enable CORS headers, default off for local serving, on when no sapwood-dir)

### Static file serving

If `--sapwood-dir` is provided and the directory exists, the bridge serves Sapwood's `dist/` files at the root path. If not provided, only the API endpoints are available (Sapwood loads from GitHub Pages with CORS).

### CORS

When `--cors` is enabled (or auto-enabled when no `--sapwood-dir`), all `/api/*` responses include:
- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type`

## API endpoints

All under `/api/`. JSON responses.

| Method | Path | Serial frame | Response |
|--------|------|-------------|----------|
| GET | `/api/status` | PROVISION_LIST (0x05) | `{ masters: MasterInfo[], bridge: { mode, relays, authenticated } }` |
| GET | `/api/clients/:slot` | POLICY_LIST_REQUEST (0x27) | `ClientPolicy[]` |
| DELETE | `/api/clients/:slot/:pubkey` | POLICY_REVOKE (0x29) | `{ ok: true }` or 409 |
| PUT | `/api/clients/:slot` | POLICY_UPDATE (0x2A) | `{ ok: true }` |
| POST | `/api/device/factory-reset` | FACTORY_RESET (0x24) | `{ ok: true }` (60s timeout for button) |
| POST | `/api/device/ota` | OTA_BEGIN/CHUNK/FINISH | Chunked upload with progress |
| GET | `/api/bridge/info` | None (in-memory) | `{ mode, relays, uptime, bunker_uri }` |
| POST | `/api/bridge/restart` | None | Graceful shutdown, systemd restarts |
| WS | `/api/logs` | None | Streams ESP-IDF log lines |

### Error responses

- `423 Locked` -- serial port busy (try_lock failed, signing in progress)
- `504 Gateway Timeout` -- ESP32 didn't respond within timeout
- `502 Bad Gateway` -- ESP32 sent NACK

### Serial port contention

HTTP handlers use `try_lock()` on the serial mutex. If the relay event loop holds the lock (signing in progress), the HTTP handler immediately returns 423 with `{ error: "Device busy -- signing in progress" }`. The UI shows this and can retry.

## Sapwood dual-mode transport

Sapwood gains a second transport backend alongside Web Serial:

- **SerialTransport** (existing) -- Web Serial API, direct USB
- **HttpTransport** (new) -- fetch to `/api/*`, WebSocket for `/api/logs`

Both produce the same event shapes. Components don't know which is active. The ConnectionPicker offers "Connect USB" (Web Serial) and "Connect to Pi" (HTTP, prompts for address). Pi address saved to localStorage.

## Grant status

Foundation work. Not a G23 milestone. Extends existing shipped bridge with a management interface.
