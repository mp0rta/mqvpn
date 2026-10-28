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

**Overflow guard:** if an internal response would exceed 256 KiB
(`CTRL_MAX_RESP_BYTES`; worst-case `get_status` with many clients), the
server instead returns:

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
| `name` | string | yes      | Username (max 63 UTF-8 bytes)        |
| `key`  | string | yes      | Pre-shared key (max 255 chars)       |

**Response — success**

```json
{"ok":true}
```

**Response — errors**

```json
{"ok":false,"error":"name and key required"}
{"ok":false,"error":"name exceeds 63 bytes"}
{"ok":false,"error":"add_user failed (-N)"}
```

- `"name and key required"` — one or both fields are missing or cannot be
  parsed.
- `"name exceeds 63 bytes"` — the decoded username exceeds 63 UTF-8 bytes.
  Overlong names are rejected rather than truncated; existing users and their
  keys are unchanged.
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
| `name` | string | yes      | Username (max 63 UTF-8 bytes) |

**Response — success**

```json
{"ok":true}
```

**Response — errors**

```json
{"ok":false,"error":"name required"}
{"ok":false,"error":"name exceeds 63 bytes"}
{"ok":false,"error":"user not found"}
```

- `"name required"` — the `name` field is missing or cannot be parsed.
- `"name exceeds 63 bytes"` — the decoded username exceeds 63 UTF-8 bytes.
  Overlong names do not remove a user with a matching prefix.
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

Return aggregate server statistics. Extended in v0.5.0 to include QUIC
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
  "pkts_lane_tcp":0,"pkts_lane_dgram":0,
  "pkts_lane_raw":0,"pkts_lane_tcp_dropped":0,
  "tcp_flows_active":1,"tcp_flows_total":7,
  "tcp_flows_rejected":2,"raw_markers_active":0,
  "udp_tx_sends":54120,"udp_tx_datagrams":889304,
  "udp_rx_receives":812004,"udp_rx_datagrams":1031887,
  "tcp_reset_econnreset":4,"tcp_reset_econnreset_tail_flows":1,
  "tcp_reset_econnreset_tail_bytes":65536,
  "tcp_reset_error":1,"tcp_reset_error_tail_flows":0,
  "tcp_reset_error_tail_bytes":0,"tcp_idle_evicted":12,
  "tcp_reset_held":1,"tcp_reset_held_fin":1,"tcp_reset_held_expired":0,
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
| `pkts_lane_tcp`   | uint64 | Hybrid mode: packets actually handed to the TCP lane (lwIP). Server-side: always 0 (the server does not classify TUN-ingress packets). |
| `pkts_lane_dgram` | uint64 | Hybrid mode: packets sent via the datagram lane. Server-side: always 0. |
| `pkts_lane_raw`   | uint64 | Hybrid mode: packets sent via the raw CONNECT-IP lane, including TCP candidates that fell back to RAW (sticky-RAW, cap-rejected, non-SYN on an unknown flow, lane-less build). `pkts_lane_tcp` + `pkts_lane_dgram` + `pkts_lane_raw` partitions every classified packet exactly once. Server-side: always 0. |
| `pkts_lane_tcp_dropped` | uint64 | Hybrid mode: TCP-lane packets lwIP refused (e.g. no matching pcb). Client-only; always 0 server-side. |
| `tcp_flows_active`   | uint64 | Hybrid mode: currently open TCP-lane flows. Client: the TCP-lane flow table's live count. Server: the whole-server count of open egress TCP flows. Both wired from real state. |
| `tcp_flows_total`    | uint64 | Hybrid mode: cumulative TCP-lane flows opened since start (never decrements). Client: SYNs the flow table admitted. Server: egress flows admitted. |
| `tcp_flows_rejected` | uint64 | Hybrid mode: cumulative flows refused by a cap. Client: SYNs rejected pre-lwIP (flow-table cap or alloc failure). Server: cap-503 rejections (whole-server fd-budget cap + per-session `TcpMaxFlows` cap; ACL 403s and 5xx syscall failures are not caps and are not counted). |
| `raw_markers_active` | uint64 | Hybrid mode: sticky-RAW markers currently held in the client's TCP-lane flow table (5-tuples pinned to RAW under `tcp=auto`). Client-only; always 0 server-side. |
| `udp_tx_sends` | uint64 | Outer-UDP send syscalls that placed at least one datagram on the wire. |
| `udp_tx_datagrams` | uint64 | Outer-UDP datagrams the kernel accepted. `udp_tx_datagrams / udp_tx_sends` is the achieved transmit batching factor; 1.0 means every datagram cost its own syscall. Exactly 1.0 with `UdpGso = false` and on platforms without the batched send path. |
| `udp_rx_receives` | uint64 | Outer-UDP receive syscalls that returned data. |
| `udp_rx_datagrams` | uint64 | Outer-UDP datagrams delivered to the library. `udp_rx_datagrams / udp_rx_receives` is the achieved receive coalescing factor. Exactly 1.0 with `UdpGro = false`; it also stays near 1.0 when the peer is not batching its sends, since the kernel then has nothing to coalesce, and over a loopback/veth path regardless of the peer. |
| `tcp_reset_econnreset` | uint64 | Hybrid mode: TCP-lane streams the server reset because its egress socket reported `ECONNRESET` (the origin reset the connection). A stream reset discards the data the transport still holds for that stream, so one that follows data can truncate it. A counter. |
| `tcp_reset_econnreset_tail_flows` | uint64 | The subset of `tcp_reset_econnreset` whose reset left origin bytes behind (a non-zero tail, below). |
| `tcp_reset_econnreset_tail_bytes` | uint64 | Summed tails of `tcp_reset_econnreset`. The tail is an estimate, because the transport exposes no per-stream acknowledged offset: the bytes the stream accepted within one second before the reset, plus bytes read from the origin that it had not accepted yet. It overstates the loss when the path drains that second's bytes sooner, and understates it when the send queue holds more than a second. |
| `tcp_reset_error` | uint64 | As `tcp_reset_econnreset`, for every other relay error on the egress socket or the stream. |
| `tcp_reset_error_tail_flows` | uint64 | As `tcp_reset_econnreset_tail_flows`, for `tcp_reset_error`. |
| `tcp_reset_error_tail_bytes` | uint64 | As `tcp_reset_econnreset_tail_bytes`, for `tcp_reset_error`. |
| `tcp_idle_evicted` | uint64 | Hybrid mode: TCP-lane flows closed by the `[Hybrid] TcpIdleTimeoutSec` sweep. They move no bytes for the whole timeout, so their reset loses nothing; counted apart from the relay errors above. |
| `tcp_reset_held` | uint64 | `[Hybrid] ResetHoldMs`: origin resets the server held instead of propagating, because they came after data (a non-zero tail, origin bytes accepted within the hold, or origin bytes not yet read). The server stopped writing to the origin, relayed what it had sent, and ended the stream with FIN. Each is also counted under `tcp_reset_econnreset`, or under `tcp_reset_error` when the origin sent FIN before its reset (seen as `EPIPE`). A counter; always `0` with the key at `0` (the default). |
| `tcp_reset_held_fin` | uint64 | Of `tcp_reset_held`, the streams whose FIN was handed to the transport: the whole response is queued and the stream ends normally once delivered. |
| `tcp_reset_held_expired` | uint64 | Of `tcp_reset_held`, the streams that had not closed within `ResetHoldMs` and were reset as they would have been without the key. Not exclusive with `tcp_reset_held_fin` (a FIN can be followed by expiry). After a FIN this loses only what the client had not yet acknowledged; if it is a large share of `tcp_reset_held`, the hold is shorter than the path needs to deliver a stream window. |
| `uptime_sec` | uint64  | Seconds since `mqvpn_server_create` was called                 |

Notes:
- `bytes_tx`/`bytes_rx` are post-tunnel (TUN-layer) byte counts, not raw UDP
  wire bytes.
- `dgram_*` counters are server-wide aggregates across all active sessions.
- The eight hybrid-mode fields (`pkts_lane_*`, `tcp_flows_*`,
  `raw_markers_active`) are additive and stay 0 whenever the hybrid
  classifier is disabled. `tcp_flows_active`, `tcp_flows_total`, and
  `tcp_flows_rejected` are wired on both client and server (with the
  per-side semantics in the table above); `pkts_lane_*`,
  `pkts_lane_tcp_dropped`, and `raw_markers_active` are client-only
  concepts and always report 0 on the server. See §9 for background and a
  link to the `[Hybrid]` configuration reference.

---

### 5.5 `get_status`

Return per-client and per-path detail for all currently connected clients.

> **Monitoring caveat — per-user keys required for multi-client setups.**
> The `user` field reports the auth identity that matched. Clients
> authenticating with the server's global `auth_key` are reported as
> `"(global)"`. If multiple clients share a single key, every session is
> emitted with `user="(global)"`, so any consumer that uses `user` as a
> series label (Prometheus exporter, Grafana JSON datasource) cannot tell
> them apart and the duplicate label set typically drops the entire scrape.
>
> For multi-client monitoring give each client its own entry under
> `users` in `server.conf`, or register them at runtime via `add_user`
> (§5.1). Sharing one `auth_key` across multiple clients still works for
> the VPN data plane but is not supported by the monitoring path.

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
      "user":"alice","endpoint":"1.2.3.4:443","scheduler":"wlb",
      "connected_sec":42,
      "bytes_tx":1000,"bytes_rx":2000,
      "n_paths":1,"paths":[
        {
          "path_id":0,"srtt_ms":31,"min_rtt_ms":18,
          "cwnd":196608,"in_flight":1024,
          "bytes_tx":900,"bytes_rx":1900,
          "pkt_sent":50,"pkt_recv":49,"pkt_lost":1,
          "state":2,"state_label":"active",
          "reinject_tx_bytes":0
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
| `scheduler`     | string | Scheduler this client's connection uses for the server-to-client direction. Equals the server default unless the client asked for another one, `AllowClientScheduler` is on, and none of the exceptions in the configuration guide applied. Added in v0.18.0. |
| `connected_sec` | uint64 | Seconds since the session was established          |
| `bytes_tx`      | uint64 | TUN bytes sent to this client                      |
| `bytes_rx`      | uint64 | TUN bytes received from this client                |
| `n_paths`       | int    | Number of entries in `paths`                       |
| `paths`         | array  | Per-path objects (see below), at most 8, in xquic's order. A closed path stays in the connection until it ends, so a client can have more than 8: then every path that is not closed is listed (the first 8 if there are more), and the first closed ones fill the entries left. Closed and open entries can alternate. |

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
| `pkt_lost`     | uint64 | QUIC packets declared lost on this path                                                                            |
| `state`        | uint   | xquic transport path state (numeric). **Legacy** — prefer `state_label` for new code; the numeric value is the raw `xqc_path_state_t` and may shift if xquic re-orders the enum. |
| `state_label`  | string | Stable label for the state — one of `init`, `validating`, `active`, `closing`, `closed`, `unknown`. Added in v0.5.0. |
| `reinject_tx_bytes` | uint64 | Cumulative bytes speculatively duplicated onto this path by reinjection (`[Multipath] Reinjection`; see README). 0 when reinjection is `off` (the default). Added in v0.15.0. |

> **Note on `state`:** the numeric value is the raw xquic transport-layer path
> state, **not** the mqvpn scheduler's logical role (primary / standby / etc.).
> Treat it as an opaque integer for diagnostic purposes; do not map it to
> scheduler roles without consulting the xquic source.

---

### 5.6 `get_build_info` *(new in v0.5.0)*

Return build-time metadata: version string, active scheduler, and whether FEC
support was compiled in.

**Request**

```json
{"cmd":"get_build_info"}
```

**Response**

```json
{"ok":true,"version":"0.6.0","scheduler":"backup_fec","fec_enabled":1}
```

| Field        | Type    | Description                                                    |
|--------------|---------|----------------------------------------------------------------|
| `version`    | string  | Version string from `mqvpn_version_string()`                   |
| `scheduler`  | string  | Server default scheduler (`Scheduler`); per-client values are in `get_status`. One of `minrtt`, `wlb`, `wlb_udp_pin`, `backup_fec`, or `unknown` |
| `fec_enabled`| integer | `1` if built with `XQC_ENABLE_FEC`; `0` otherwise             |

---

### 5.7 `get_fec_stats` *(new in v0.5.0)*

Return per-user FEC and multipath statistics for an active session. Requires
that the server was built with `XQC_ENABLE_FEC`.

**Request**

```json
{"cmd":"get_fec_stats","user":"alice"}
```

| Field  | Type   | Required | Description                  |
|--------|--------|----------|------------------------------|
| `user` | string | yes      | Username of the active session (max 63 UTF-8 bytes) |

**Response — success**

```json
{
  "ok":true,"user":"alice",
  "enable_fec":1,"mp_state":1,"mp_state_label":"active_with_standby",
  "fec_send_cnt":142,"fec_recover_cnt":17,
  "lost_dgram_cnt":23,
  "total_app_bytes":9123456,"standby_app_bytes":421337
}
```

| Field               | Type    | Description                                                       |
|---------------------|---------|-------------------------------------------------------------------|
| `user`              | string  | Echoed username from the request                                  |
| `enable_fec`        | uint    | `1` if FEC is enabled for this session, `0` otherwise            |
| `mp_state`          | uint    | Raw `xqc_conn_stats_t.mp_state` (xquic). Takes only the values `0` (no multipath attempted: `create_path_count <= 1`), `1` (multipath established and validated: `create_path_count > 1 && validated_path_count > 1`), or `2` (multipath attempted but not validated: `create_path_count > 1 && validated_path_count <= 1`). **Legacy diagnostic only — prefer `mp_state_label` for alerts and dashboards.** |
| `mp_state_label`    | string  | mqvpn-derived label that walks `xqc_conn_stats_t.paths_info[]` and classifies the active paths by `path_app_status`. Independent of the numeric `mp_state`. One of `single_path` (no multipath or only one active path), `active_with_standby` (≥ 2 active paths, mix of available + standby — full redundancy), `standby_only` (≥ 1 standby and zero available — primary down, **degraded**), `active_only` (≥ 2 active paths, all available, no standby designated), or `unknown` (NULL stats). Added in v0.5.0. |
| `fec_send_cnt`      | uint64  | FEC repair packets sent (xquic uint32 widened to uint64)          |
| `fec_recover_cnt`   | uint64  | Packets recovered via FEC (xquic uint32 widened to uint64)        |
| `lost_dgram_cnt`    | uint64  | QUIC datagrams lost for this session                              |
| `total_app_bytes`   | uint64  | Total application bytes delivered via all paths                   |
| `standby_app_bytes` | uint64  | Application bytes delivered via the standby path                  |

**Response — errors**

```json
{"ok":false,"error":"user required"}
{"ok":false,"error":"name exceeds 63 bytes"}
{"ok":false,"error":"user not found"}
{"ok":false,"error":"fec not built"}
```

- `"user required"` — the `user` field is missing or cannot be parsed.
- `"name exceeds 63 bytes"` — the decoded username in `user` exceeds 63 UTF-8 bytes.
- `"user not found"` — no active session exists for that username.
- `"fec not built"` — the server was compiled without `XQC_ENABLE_FEC`, or an
  internal null-pointer guard was triggered. Check `get_build_info` first.

---

### 5.8 `get_all_fec_stats` *(new in v0.5.0)*

Bulk variant of `get_fec_stats`: returns one entry per active (tunnel-
established) session in a single response. Designed for scrapers (e.g. the
Prometheus exporter) that would otherwise issue one TCP connection per user
and risk hitting the `CTRL_MAX_CONNS=8` concurrency cap.

Requires that the server was built with `XQC_ENABLE_FEC`.

**Request**

```json
{"cmd":"get_all_fec_stats"}
```

**Response — success**

```json
{
  "ok":true,"n_clients":2,
  "clients":[
    {"user":"alice","enable_fec":1,"mp_state":1,"mp_state_label":"active_with_standby",
     "fec_send_cnt":142,"fec_recover_cnt":17,"lost_dgram_cnt":23,
     "total_app_bytes":9123456,"standby_app_bytes":421337},
    {"user":"bob","enable_fec":1,"mp_state":0,"mp_state_label":"single_path",
     "fec_send_cnt":0,"fec_recover_cnt":0,"lost_dgram_cnt":0,
     "total_app_bytes":555555,"standby_app_bytes":0}
  ]
}
```

| Field        | Type    | Description                                                                 |
|--------------|---------|-----------------------------------------------------------------------------|
| `n_clients`  | integer | Number of entries in `clients`. May be `0` if no sessions are active. Same nomenclature as `get_status` (a connected user is a "client"; "users" is reserved for `list_users`'s registered auth-table superset). |
| `clients`    | array   | One entry per active session. Each entry has the same fields as `get_fec_stats` minus the request echo, plus `mp_state_label`. |

**Response — errors**

```json
{"ok":false,"error":"fec not built"}
{"ok":false,"error":"response too large"}
```

- `"fec not built"` — same semantics as `get_fec_stats`. Consumers should
  stop probing FEC for the rest of this scrape.
- `"response too large"` — only possible if the user count grows beyond what
  fits in the 256 KiB response limit (`CTRL_MAX_RESP_BYTES`; currently
  `MQVPN_MAX_USERS=64`, well within budget).

---

## 6. Error Reference

| Error string             | Returned by                                    |
|--------------------------|------------------------------------------------|
| `"missing cmd"`          | any request that is not a JSON object with a string `cmd` (unparseable JSON, a non-object root, a missing or non-string `cmd`) |
| `"unknown cmd"`          | any request with an unrecognised `cmd` value   |
| `"too many connections"` | connection accepted when 8 slots already used  |
| `"response too large"`   | any command (internal buffer overflow guard)   |
| `"name and key required"`| `add_user`                                     |
| `"name exceeds 63 bytes"`| `add_user`, `remove_user`, `get_fec_stats`       |
| `"add_user failed (-N)"` | `add_user` (N = underlying error code)         |
| `"name required"`        | `remove_user`                                  |
| `"user not found"`       | `remove_user`, `get_fec_stats`                 |
| `"user required"`        | `get_fec_stats`                                |
| `"fec not built"`        | `get_fec_stats`, `get_all_fec_stats`           |

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
- `get_stats` was extended in v0.5.0 with `dgram_sent`, `dgram_recv`,
  `dgram_lost`, `dgram_acked`, and `uptime_sec`. Consumers that only read
  `n_clients`, `bytes_tx`, and `bytes_rx` remain unaffected.
- `get_stats` was extended again in v0.9.0 with the hybrid-mode
  lane/flow counters (`pkts_lane_tcp`, `pkts_lane_dgram`, `pkts_lane_raw`,
  `pkts_lane_tcp_dropped`, `tcp_flows_active`, `tcp_flows_total`,
  `tcp_flows_rejected`, `raw_markers_active`). All eight now report real
  values on the client with `Tcp = stream` or `Tcp = auto`
  (`tcp_flows_active`, `tcp_flows_total`, `tcp_flows_rejected`, and
  `raw_markers_active` were previously stubbed at 0); `tcp_flows_active`,
  `tcp_flows_total`, and `tcp_flows_rejected` are also wired server-side.
  In the same change, `pkts_lane_tcp` changed meaning — from "packets
  classified into the TCP lane" (classify-time) to "packets actually handed
  to the TCP lane / lwIP" (post-sticky-verdict), so under `Tcp = auto` a
  sticky-RAW flow's packets now count in `pkts_lane_raw` instead. See
  §5.4's field table for which fields stay 0 server-side by design.
  Existing JSON consumers remain unaffected. Note for C API consumers: this
  is the first time `mqvpn_stats_t` has grown since its introduction — the
  struct producers write `sizeof(mqvpn_stats_t)` bytes, so binaries linked
  against the shared library must be recompiled against the new header. The
  shared-library SOVERSION was bumped 1 → 2 for exactly this reason.
- `get_stats` was extended in v0.16.0 with the outer-UDP offload counters
  `udp_tx_sends`, `udp_tx_datagrams`, `udp_rx_receives`, and
  `udp_rx_datagrams`. Existing JSON consumers remain unaffected. The two
  transmit-side fields also grow `mqvpn_stats_t`, so the same C-API caveat as
  the v0.9.0 entry above applies: `mqvpn_client_get_stats` /
  `mqvpn_server_get_stats` write `sizeof(mqvpn_stats_t)` bytes without
  consulting the caller's `struct_size`, so binaries linked against the shared
  library must be recompiled against the new header — the shared-library
  SOVERSION was bumped 2 → 3 for exactly this reason.
  The receive-side pair is deliberately NOT in `mqvpn_stats_t`:
  UDP GRO is configured and un-coalesced entirely in the platform layer, which
  the library never observes, so those two are read straight from the platform
  by the control socket (`ctrl_socket_create`) instead.
- `get_status` client objects gained `scheduler` in v0.18.0 (JSON only; the C
  struct `mqvpn_client_info_t` is unchanged). Additive; existing JSON
  consumers remain unaffected.
- `get_stats` gained `tcp_reset_econnreset`, `tcp_reset_error` (each with
  `_tail_flows` and `_tail_bytes`) and `tcp_idle_evicted`: the TCP-lane stream
  resets the server issues, by cause, and how many left origin bytes behind.
  Additive; existing JSON consumers remain unaffected. The fields grow
  `mqvpn_stats_t` (which also gains the client's `tcp_reset_by_peer*`
  counters, read through `mqvpn_client_get_stats`), so the C-API caveat of
  the v0.9.0 and v0.16.0 entries above applies: binaries linked against the
  shared library must be recompiled against the new header.
- `get_stats` gained `tcp_reset_held`, `tcp_reset_held_fin` and
  `tcp_reset_held_expired` for the `[Hybrid] ResetHoldMs` key. Additive;
  existing JSON consumers remain unaffected. They grow `mqvpn_stats_t` with
  the same recompile caveat as the entry above.
- `get_status` path objects gained `reinject_tx_bytes` in v0.15.0 — the
  per-path bytes speculatively duplicated by reinjection. Additive; existing
  JSON consumers remain unaffected. The value is read from the server's
  internal reinjection snapshot, not `mqvpn_path_stats_t`, so there is no
  C-API struct growth and no recompile caveat.
- `get_status` paths gained a `state_label` string in v0.5.0 alongside the
  existing numeric `state`; `get_fec_stats` gained `mp_state_label` similarly.
  Consumers that only read the numeric fields remain unaffected, but new code
  should prefer the labels — the numeric values are raw xquic enums and may
  shift if upstream re-orders them.
- `get_all_fec_stats` was added in v0.5.0 as a bulk variant of `get_fec_stats`.

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

# Query FEC counters for ALL active sessions (bulk; preferred for scrapers)
echo '{"cmd":"get_all_fec_stats"}' | nc -q1 127.0.0.1 9090

# List registered users
echo '{"cmd":"list_users"}' | nc -q1 127.0.0.1 9090

# Add a user at runtime
echo '{"cmd":"add_user","name":"carol","key":"carol-secret"}' | nc -q1 127.0.0.1 9090

# Remove a user at runtime
echo '{"cmd":"remove_user","name":"carol"}' | nc -q1 127.0.0.1 9090
```

On macOS, replace `-q1` with `-G 1` (BSD netcat).

---

## 9. Hybrid mode configuration keys

Hybrid mode relays inner TCP connections over HTTP/3 streams. Its runtime
counters are available through `get_stats` (§5.4), but **the control API
cannot enable, disable, or reconfigure hybrid mode**.

Configure it through the `[Hybrid]` section in INI files
(`server.conf` / `client.conf`) or the `"hybrid"` object in JSON configuration
files. These JSON keys are configuration-file keys, not control API request
fields.

See [Configuration → `[Hybrid]`](../website/guide/configuration.md#hybrid)
for the keys and defaults, and [Hybrid Mode](../website/guide/hybrid-mode.md)
for behavior, examples, and known limitations.
