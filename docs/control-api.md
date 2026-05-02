# mqvpn Control API — Wire Protocol Reference

The mqvpn server exposes a JSON control API over TCP. This document is the
authoritative wire-protocol contract for all clients, including the Go
Prometheus exporter.

---

## 1. Overview

- **Transport:** TCP (plaintext, no TLS)
- **Framing:** Newline-terminated JSON objects. The server also accepts a bare
  JSON object terminated by its closing `}` brace, whichever arrives first.
- **Request:** one JSON object per connection (max 4 KB)
- **Response:** one JSON object, newline-terminated; server closes the
  connection after writing the response.
- **Idle timeout:** 5 seconds — connections that do not deliver a complete
  request within 5 seconds are closed without a response.
- **Concurrency:** maximum 8 simultaneous control connections. A 9th connection
  receives `{"ok":false,"error":"too many connections"}` and is immediately
  closed.

---

## 2. Connection

### Default endpoint

`127.0.0.1:9090`

The bind address defaults to `127.0.0.1`. Both IPv4 and IPv6 loopback
addresses are accepted.

### Configuration

```bash
# Enable the control API on port 9090 (loopback only)
sudo mqvpn --mode server ... --control-port 9090

# Bind to a specific address
sudo mqvpn --mode server ... --control-port 9090 --control-addr 127.0.0.1
```

### Security

The control API has **no authentication and no TLS**. If you bind to a
non-loopback address, the server emits a startup `WARN` log:

```
control API: binding to non-loopback address <addr> — the control API has no authentication
```

Front with nginx or another authenticating proxy if you need to expose the
port beyond localhost.

---

## 3. Request Format

A single UTF-8 JSON object, terminated by its closing `}` brace or a newline
character (`\n`). Maximum size: **4 096 bytes** (`CTRL_MAX_REQ`).

All requests must contain a `"cmd"` string field. Unknown commands return an
error response rather than closing the connection.

```json
{"cmd":"<command>", ...}
```

---

## 4. Response Format

A single JSON object followed by a newline (`\n`). The server closes the TCP
connection immediately after writing the response.

```json
{"ok": true, ...}
{"ok": false, "error": "<reason>"}
```

- `ok` is always present and is a boolean.
- When `ok` is `false`, an `error` string is present describing the failure.
- Additional fields (documented per command) are present only when `ok` is
  `true`, unless noted otherwise.

**Overflow guard:** if an internal response would exceed 128 KB (worst-case
`get_status` with many clients), the server instead returns:

```json
{"ok":false,"error":"response too large"}
```

---

## 5. Commands

### 5.1 `add_user`

Add a user (name + pre-shared key) to the server's active auth table. If the
name already exists, the key is updated in place.

**Request**

```json
{"cmd":"add_user","name":"alice","key":"alice-secret"}
```

| Field  | Type   | Required | Description                          |
|--------|--------|----------|--------------------------------------|
| `name` | string | yes      | Username (max 63 chars)              |
| `key`  | string | yes      | Pre-shared key (max 255 chars)       |

**Response — success**

```json
{"ok":true}
```

**Response — errors**

```json
{"ok":false,"error":"name and key required"}
{"ok":false,"error":"add_user failed (-N)"}
```

- `"name and key required"` — one or both fields are missing or cannot be
  parsed.
- `"add_user failed (-N)"` — the underlying library call returned error code
  `-N`; check server logs for details.

---

### 5.2 `remove_user`

Remove a user from the auth table. Does not forcibly disconnect an active
session; the session expires naturally after authentication fails on the next
reconnect.

**Request**

```json
{"cmd":"remove_user","name":"alice"}
```

| Field  | Type   | Required | Description |
|--------|--------|----------|-------------|
| `name` | string | yes      | Username    |

**Response — success**

```json
{"ok":true}
```

**Response — errors**

```json
{"ok":false,"error":"name required"}
{"ok":false,"error":"user not found"}
```

- `"name required"` — the `name` field is missing or cannot be parsed.
- `"user not found"` — no user with that name is registered.

---

### 5.3 `list_users`

Return the list of usernames currently registered in the auth table.

**Request**

```json
{"cmd":"list_users"}
```

**Response**

```json
{"ok":true,"users":["alice","bob"]}
```

| Field   | Type            | Description                        |
|---------|-----------------|------------------------------------|
| `users` | array of string | Registered usernames; may be empty |

---

### 5.4 `get_stats`

Return aggregate server statistics. Extended in v0.4.0 to include QUIC
datagram counters and uptime.

**Request**

```json
{"cmd":"get_stats"}
```

**Response**

```json
{
  "ok":true,
  "n_clients":2,
  "bytes_tx":12345678,"bytes_rx":9876543,
  "dgram_sent":89012,"dgram_recv":84551,
  "dgram_lost":421,"dgram_acked":88341,
  "uptime_sec":3601
}
```

| Field        | Type    | Description                                                    |
|--------------|---------|----------------------------------------------------------------|
| `n_clients`  | integer | Number of currently connected clients                          |
| `bytes_tx`   | uint64  | Total bytes written to the TUN interface (server → clients)    |
| `bytes_rx`   | uint64  | Total bytes read from the TUN interface (clients → server)     |
| `dgram_sent` | uint64  | QUIC datagrams the server successfully sent (xret == XQC_OK), all sessions |
| `dgram_recv` | uint64  | QUIC datagrams the server forwarded to the TUN interface, all sessions. Excludes datagrams dropped before forwarding (TTL ≤ 1 → ICMP Time Exceeded, source-IP mismatch, malformed frame). |
| `dgram_lost` | uint64  | Total QUIC datagrams declared lost, all sessions               |
| `dgram_acked`| uint64  | Total QUIC datagrams acknowledged, all sessions                |
| `uptime_sec` | uint64  | Seconds since `mqvpn_server_create` was called                 |

Notes:
- `bytes_tx`/`bytes_rx` are post-tunnel (TUN-layer) byte counts, not raw UDP
  wire bytes.
- `dgram_*` counters are server-wide aggregates across all active sessions.

---

### 5.5 `get_status`

Return per-client and per-path detail for all currently connected clients.

**Request**

```json
{"cmd":"get_status"}
```

**Response**

```json
{
  "ok":true,
  "n_clients":1,
  "clients":[
    {
      "user":"alice","endpoint":"1.2.3.4:443",
      "connected_sec":42,
      "bytes_tx":1000,"bytes_rx":2000,
      "paths":[
        {
          "path_id":0,"srtt_ms":31,"min_rtt_ms":18,
          "cwnd":196608,"in_flight":1024,
          "bytes_tx":900,"bytes_rx":1900,
          "pkt_sent":50,"pkt_recv":49,"pkt_lost":1,
          "state":0
        }
      ]
    }
  ]
}
```

**Top-level fields**

| Field      | Type    | Description                         |
|------------|---------|-------------------------------------|
| `n_clients`| integer | Number of active client entries     |
| `clients`  | array   | Per-client objects (see below)      |

**Client object**

| Field           | Type   | Description                                        |
|-----------------|--------|----------------------------------------------------|
| `user`          | string | Username                                           |
| `endpoint`      | string | Client's remote address and port (`ip:port`)       |
| `connected_sec` | uint64 | Seconds since the session was established          |
| `bytes_tx`      | uint64 | TUN bytes sent to this client                      |
| `bytes_rx`      | uint64 | TUN bytes received from this client                |
| `paths`         | array  | Per-path objects (see below)                       |

**Path object**

| Field        | Type   | Description                                              |
|--------------|--------|----------------------------------------------------------|
| `path_id`    | uint64 | xquic path identifier                                    |
| `srtt_ms`    | uint64 | Smoothed RTT in milliseconds (derived from µs)           |
| `min_rtt_ms` | uint64 | Minimum observed RTT in milliseconds (derived from µs)   |
| `cwnd`       | uint64 | Congestion window in bytes                               |
| `in_flight`  | uint64 | Bytes currently in flight                                |
| `bytes_tx`   | uint64 | Bytes sent on this path                                  |
| `bytes_rx`   | uint64 | Bytes received on this path                              |
| `pkt_sent`   | uint64 | QUIC packets sent on this path                           |
| `pkt_recv`   | uint64 | QUIC packets received on this path                       |
| `pkt_lost`   | uint64 | QUIC packets declared lost on this path                  |
| `state`      | uint   | xquic transport path state (numeric, see note below)     |

> **Note on `state`:** the numeric value is the raw xquic transport-layer path
> state, **not** the mqvpn scheduler's logical role (primary / standby / etc.).
> Treat it as an opaque integer for diagnostic purposes; do not map it to
> scheduler roles without consulting the xquic source.

---

### 5.6 `get_build_info` *(new in v0.4.0)*

Return build-time metadata: version string, active scheduler, and whether FEC
support was compiled in.

**Request**

```json
{"cmd":"get_build_info"}
```

**Response**

```json
{"ok":true,"version":"0.4.0","scheduler":"backup_fec","fec_enabled":1}
```

| Field        | Type    | Description                                                    |
|--------------|---------|----------------------------------------------------------------|
| `version`    | string  | Version string from `mqvpn_version_string()`                   |
| `scheduler`  | string  | Active multipath scheduler: `minrtt`, `wlb`, `backup_fec`, or `unknown` |
| `fec_enabled`| integer | `1` if built with `XQC_ENABLE_FEC`; `0` otherwise             |

---

### 5.7 `get_fec_stats` *(new in v0.4.0)*

Return per-user FEC and multipath statistics for an active session. Requires
that the server was built with `XQC_ENABLE_FEC`.

**Request**

```json
{"cmd":"get_fec_stats","user":"alice"}
```

| Field  | Type   | Required | Description                  |
|--------|--------|----------|------------------------------|
| `user` | string | yes      | Username of the active session |

**Response — success**

```json
{
  "ok":true,"user":"alice",
  "enable_fec":1,"mp_state":1,
  "fec_send_cnt":142,"fec_recover_cnt":17,
  "lost_dgram_cnt":23,
  "total_app_bytes":9123456,"standby_app_bytes":421337
}
```

| Field               | Type    | Description                                                       |
|---------------------|---------|-------------------------------------------------------------------|
| `user`              | string  | Echoed username from the request                                  |
| `enable_fec`        | uint    | `1` if FEC is enabled for this session, `0` otherwise            |
| `mp_state`          | uint    | Multipath scheduler state for this session (xquic numeric value)  |
| `fec_send_cnt`      | uint64  | FEC repair packets sent (xquic uint32 widened to uint64)          |
| `fec_recover_cnt`   | uint64  | Packets recovered via FEC (xquic uint32 widened to uint64)        |
| `lost_dgram_cnt`    | uint64  | QUIC datagrams lost for this session                              |
| `total_app_bytes`   | uint64  | Total application bytes delivered via all paths                   |
| `standby_app_bytes` | uint64  | Application bytes delivered via the standby path                  |

**Response — errors**

```json
{"ok":false,"error":"user required"}
{"ok":false,"error":"user not found"}
{"ok":false,"error":"fec not built"}
```

- `"user required"` — the `user` field is missing or cannot be parsed.
- `"user not found"` — no active session exists for that username.
- `"fec not built"` — the server was compiled without `XQC_ENABLE_FEC`, or an
  internal null-pointer guard was triggered. Check `get_build_info` first.

---

## 6. Error Reference

| Error string             | Returned by                                    |
|--------------------------|------------------------------------------------|
| `"missing cmd"`          | any request (no `cmd` field present)           |
| `"unknown cmd"`          | any request with an unrecognised `cmd` value   |
| `"too many connections"` | connection accepted when 8 slots already used  |
| `"response too large"`   | any command (internal buffer overflow guard)   |
| `"name and key required"`| `add_user`                                     |
| `"add_user failed (-N)"` | `add_user` (N = underlying error code)         |
| `"name required"`        | `remove_user`                                  |
| `"user not found"`       | `remove_user`, `get_fec_stats`                 |
| `"user required"`        | `get_fec_stats`                                |
| `"fec not built"`        | `get_fec_stats`                                |

---

## 7. Compatibility

mqvpn follows semantic versioning for the control API:

- **Additive changes** (new commands, new optional response fields) are
  backward-compatible and do not require a version bump beyond a minor version
  increment.
- **Existing field names and JSON key order** within a response are stable
  across patch and minor releases. Consumers must still tolerate unknown fields
  (future-proofing).
- **Removing or renaming** a command or a response field is a
  **breaking change** and requires a major version bump.
- `get_stats` was extended in v0.4.0 with `dgram_sent`, `dgram_recv`,
  `dgram_lost`, `dgram_acked`, and `uptime_sec`. Consumers that only read
  `n_clients`, `bytes_tx`, and `bytes_rx` remain unaffected.

---

## 8. Examples (CLI)

These commands can be pasted directly into a terminal on the server host. The
`-q1` flag tells `nc` to close the write side 1 second after EOF, allowing the
server's response to be read before the connection drops.

```bash
# Query overall health
echo '{"cmd":"get_status"}' | nc -q1 127.0.0.1 9090

# Query build metadata (scheduler, FEC support)
echo '{"cmd":"get_build_info"}' | nc -q1 127.0.0.1 9090

# Query aggregate server stats (bytes, datagrams, uptime)
echo '{"cmd":"get_stats"}' | nc -q1 127.0.0.1 9090

# Query per-user FEC counters
echo '{"cmd":"get_fec_stats","user":"alice"}' | nc -q1 127.0.0.1 9090

# List registered users
echo '{"cmd":"list_users"}' | nc -q1 127.0.0.1 9090

# Add a user at runtime
echo '{"cmd":"add_user","name":"carol","key":"carol-secret"}' | nc -q1 127.0.0.1 9090

# Remove a user at runtime
echo '{"cmd":"remove_user","name":"carol"}' | nc -q1 127.0.0.1 9090
```

On macOS, replace `-q1` with `-G 1` (BSD netcat).
