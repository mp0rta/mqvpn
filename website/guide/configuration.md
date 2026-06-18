# Configuration

mqvpn supports both INI and JSON config files. If the file content starts with `{`, it is parsed as JSON; otherwise as INI. CLI arguments override config values.

## INI Format

### Server

```ini
# /etc/mqvpn/server.conf
[Interface]
Listen = 0.0.0.0:443
Subnet = 10.0.0.0/24
Subnet6 = 2001:db8:1::/112
# MTU = 1280

[TLS]
Cert = /etc/mqvpn/server.crt
Key = /etc/mqvpn/server.key

[Auth]
Key = mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=
User = alice:<ALICE_PSK>
User = bob:<BOB_PSK>

[Multipath]
Scheduler = wlb
# CC = bbr2                     # Congestion control (bbr2|bbr|cubic|none)
```

### Client

```ini
# /etc/mqvpn/client.conf
[Server]
Address = 203.0.113.1:443

[Auth]
Key = mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=

[Interface]
TunName = mqvpn0
DNS = 1.1.1.1, 8.8.8.8
LogLevel = info
# MTU = 1280

[Multipath]
Scheduler = wlb
# CC = bbr2                     # Congestion control (bbr2|bbr|cubic|none)
Path = eth0
Path = wlan0
```

## JSON Format

JSON config is useful for structured management and automation tooling.

### Server

```json
{
  "mode": "server",
  "listen": "0.0.0.0:443",
  "tun_name": "mqvpn0",
  "log_level": "info",
  "subnet": "10.0.0.0/24",
  "subnet6": "2001:db8:1::/112",
  "cert_file": "/etc/mqvpn/server.crt",
  "key_file": "/etc/mqvpn/server.key",
  "auth_key": "<YOUR_PSK_HERE>",
  "users": [
    { "name": "alice", "key": "<ALICE_PSK>" },
    { "name": "bob", "key": "<BOB_PSK>" }
  ],
  "max_clients": 64,
  "scheduler": "wlb",
  "cc": "bbr2"
}
```

### Client

```json
{
  "mode": "client",
  "server_addr": "203.0.113.1:443",
  "tun_name": "mqvpn0",
  "log_level": "info",
  "auth_key": "<YOUR_PSK_HERE>",
  "insecure": false,
  "dns": ["1.1.1.1", "8.8.8.8"],
  "kill_switch": false,
  "reconnect": true,
  "reconnect_interval": 5,
  "scheduler": "wlb",
  "cc": "bbr2",
  "paths": ["eth0", "wlan0"]
}
```

## Multi-User Authentication

The server can authenticate multiple users, each with their own PSK. In JSON config, add a `users` array where each entry is either an object (`{"name":"alice","key":"..."}`) or a shorthand string (`"alice:key"`). In INI config, use repeatable `User = NAME:KEY` lines in the `[Auth]` section. You can also use the [Control API](#control-api) to manage users at runtime.

When both `auth_key` (global key) and `users` are set, clients can authenticate with either. To restrict access to named users only, remove `auth_key` from the config.

Removing a user via the Control API also disconnects any active sessions authenticated with that username.

::: warning Monitoring requires per-user keys
Sharing a single `auth_key` across multiple clients works for the VPN data plane, but the Control API and the Prometheus exporter identify clients by their `user` label. Sessions authenticated with the global `auth_key` are reported as `user="(global)"`, so multiple clients collide on the same label and the Prometheus scrape is dropped. For multi-client monitoring give each client its own entry under `users` (or register them at runtime via `add_user`).
:::

## Running with Config Files

```bash
sudo mqvpn --config /etc/mqvpn/server.conf
sudo mqvpn --config /etc/mqvpn/server.json
```

## Config Reference

### `[Server]` (client only)

| Key | Description | Default |
|-----|-------------|---------|
| `Address` | Server address (`HOST:PORT`, e.g. `[2001:db8::1]:443` for IPv6) | Required |
| `Insecure` | Skip TLS certificate verification | `false` |

### `[Interface]`

| Key | Description | Default |
|-----|-------------|---------|
| `Listen` | Listen address (`HOST:PORT`, server only) | `0.0.0.0:443` |
| `Subnet` | Client IPv4 pool (server only) | `10.0.0.0/24` |
| `Subnet6` | Client IPv6 pool (server only) | — |
| `TunName` | TUN device name | `mqvpn0` |
| `DNS` | DNS servers (comma-separated) | — |
| `LogLevel` | Log level (`debug`, `info`, `warn`, `error`) | `info` |
| `KillSwitch` | Block traffic outside the VPN tunnel (client only) | `false` |
| `Reconnect` | Enable automatic reconnection (client only) | `true` |
| `ReconnectInterval` | Seconds between reconnection attempts | `5` |
| `MTU` | TUN MTU (1280–9000). Client: cap — if the negotiated MTU is lower, the negotiated value is used. Server: sets the TUN MTU directly. | auto (client ~1382 negotiated, server 1382) |

### `[TLS]` (server only)

| Key | Description | Default |
|-----|-------------|---------|
| `Cert` | TLS certificate path (PEM) | Required |
| `Key` | TLS private key path (PEM) | Required |

### `[Auth]`

| Key | Description | Default |
|-----|-------------|---------|
| `Key` | Pre-shared key (base64, generate with `mqvpn --genkey`) | Required unless `User` is set |
| `User` | Per-user PSK in `NAME:KEY` format (repeatable) | — |
| `MaxClients` | Maximum concurrent clients (server only) | `64` |

### `[Multipath]`

| Key | Description | Default |
|-----|-------------|---------|
| `Scheduler` | Scheduler algorithm (`minrtt`, `wlb`, `wlb_udp_pin`, or `backup_fec`) | `wlb` |
| `CC` | Congestion control algorithm (`bbr2`, `bbr`, `cubic`, or `none`) | `bbr2` |
| `Path` | Network interface to bind (repeatable) | Default interface |

See [Multipath](./multipath) for scheduler details.

> `backup_fec` is experimental and requires both peers to run mqvpn ≥ 0.4.0
> with FEC build enabled (`-DXQC_ENABLE_FEC=ON -DXQC_ENABLE_XOR=ON`).
> See [Multipath](./multipath#backup-fec-experimental).

> `CC = none` (no congestion control) requires xquic built with `-DXQC_ENABLE_UNLIMITED=ON`.

### `[Reorder]`

A flow-aware reorder buffer for inner UDP traffic. It targets a single inner connection (e.g. inner QUIC) that is itself spread across multiple paths by mqvpn's multipath aggregation: by holding briefly out-of-order datagrams and delivering them in order, it reduces the reordering the inner endpoint sees. Disabled by default (`Enabled = off`); when off the section has no effect and packets are forwarded unchanged.

> **Scope:** the reorder buffer currently applies to **inner UDP flows only. Inner TCP is not yet handled by the reorder buffer (TODO).** Inner TCP instead relies on the scheduler's flow-pinning (`wlb` / `wlb_udp_pin`), which keeps a TCP flow on a single path, plus TCP's own reordering tolerance (RACK/SACK).

| Key | Description | Default |
|-----|-------------|---------|
| `Enabled` | Master switch (`on` / `off`) | `off` |
| `MaxWaitMs` | How long to hold a gap before skipping the missing datagram (ms) | `30` |
| `CapPackets` | Max buffered datagrams per flow (power of two) | `1024` |
| `MaxBytesPerFlow` | Max buffered bytes per flow | `1572864` |
| `ClassifyWindow` | Datagrams observed to classify a flow's direction (`0` disables ACK-direction demotion) | `64` |
| `AckDemoteMaxLarge` | Large-packet count at or below which a flow is judged ACK-direction | `3` |
| `SmallPacketThreshold` | Inner payload bytes splitting small vs. large | `200` |
| `ResetMarkPackets` | FLOW_RESET marks emitted when a flow restarts | `8` |
| `ResetIdleGraceMs` | Honor a FLOW_RESET only after the flow has been idle this long (ms) | `10000` |
| `MaxFlows` | Max tracked flows | `65536` |
| `GlobalMaxBytes` | Shared buffer byte budget across all flows | `67108864` |
| `IngressIdleSec` | Receiver idle eviction timeout (must be `< EgressIdleSec`) | `30` |
| `EgressIdleSec` | Sender idle eviction timeout | `300` |

Demotion in the ACK direction is automatic: a flow that looks like an ACK/control stream (mostly small packets) is moved to pass-through so it is never delayed. This is internal behaviour, not a configurable knob — tune it indirectly via `ClassifyWindow` / `AckDemoteMaxLarge` / `SmallPacketThreshold`.

Reorder is a throughput-vs-latency trade-off — it helps bulk transfers but adds up to `MaxWaitMs` of delay to every flow it touches. Since one tunnel usually carries both kinds of traffic, per-port `[ReorderRule]` sections let you enable it where it helps (bulk inner QUIC) and pass latency-sensitive traffic through (DNS, NTP, real-time UDP). Unmatched UDP is pass-through by default, so you only need rules for the ports you want reordered:

```ini
[Reorder]
Enabled = on

[ReorderRule]          # bulk inner QUIC: reorder on
Proto = udp
Port = 443
Profile = fiber_lte

[ReorderRule]          # DNS: never add latency
Proto = udp
Port = 53
Profile = default_udp
```

…or from the JSON equivalent. The `reorder` object uses snake_case keys mapping 1:1 to the INI keys above, and `reorder_rules` is an array of `{proto, port, profile}` objects (each rule may also carry optional `max_wait_ms` / `cap_packets` overrides):

```json
{
  "reorder": {
    "enabled": "on",
    "max_wait_ms": 30,
    "cap_packets": 1024,
    "max_bytes_per_flow": 1572864,
    "classify_window": 64,
    "ack_demote_max_large": 3,
    "small_packet_threshold": 200,
    "reset_mark_packets": 8,
    "reset_idle_grace_ms": 10000,
    "max_flows": 65536,
    "global_max_bytes": 67108864,
    "ingress_idle_sec": 30,
    "egress_idle_sec": 300
  },
  "reorder_rules": [
    { "proto": "udp", "port": 443, "profile": "cellular_bond" },
    { "proto": "udp", "port": 4500, "profile": "fiber_lte", "max_wait_ms": 50, "cap_packets": 2048 }
  ]
}
```

### Profile presets

Each profile carries an empirically-tuned `(MaxWaitMs, CapPackets)` preset. The values were chosen from a multipath `netem` sweep across 16 link environments — full methodology and per-environment data are in the [reorder-only multipath report](https://github.com/mp0rta/mqvpn/blob/main/docs/report/2026-06-18-reorder-only-datagram-multipath-connect-ip-en.md):

| Profile | `MaxWaitMs` | `CapPackets` | Notes |
|---------|------------:|-------------:|-------|
| `cellular_bond` | `50` | `1024` | Cellular bonding (e.g. dual-LTE) |
| `fiber_lte` | `50` | `2048` | Mixed fiber + LTE; larger cap for higher BDP |
| `quic_bulk` | `50` | `1024` | Back-compat alias of `cellular_bond` |
| `low_latency` | — | — | Reserved; no preset (inert) |
| `default_udp` | — | — | Matched but **not** reordered (pass-through / OFF) |

**Precedence** for a rule's effective `(MaxWaitMs, CapPackets)`, highest first:

1. The rule's own explicit `MaxWaitMs` / `CapPackets` key.
2. A global `[Reorder]` explicit `MaxWaitMs` / `CapPackets`.
3. The rule's profile preset (above).
4. The builtin default (`MaxWaitMs = 30`, `CapPackets = 1024`).

In short, a number written explicitly always beats the profile. This is why a config that sets a global `[Reorder] MaxWaitMs` alongside `Profile = quic_bulk` keeps using the explicit global value unchanged.

### When to enable reorder

Reorder is **off by default** and is meant to be opt-in only within its useful range. Empirically that range is an RTT spread of roughly **15–100 ms**, paths with jitter, or **asymmetric bandwidth**.

- **Strong bandwidth asymmetry (≳ 8:1):** consider raising `MaxWaitMs` to `150`–`200` (unverified — treat as a follow-up to validate on your link).
- **Extreme RTT spread (≥ 285 ms, GEO-satellite class):** reorder is a net loss here; leave it off for that traffic with `Profile = default_udp`.

### `[ReorderRule]` (repeatable)

| Key | Description | Default |
|-----|-------------|---------|
| `Proto` | Matched L4 protocol (`udp`) | `udp` |
| `Port` | Matched port (source or destination) | — |
| `Profile` | `cellular_bond`, `fiber_lte`, `quic_bulk`, `low_latency`, or `default_udp` | `quic_bulk` |
| `MaxWaitMs` | Per-rule override of the hold time (ms). `0` is rejected with a warning — to pass a port through untouched use `Profile = default_udp` instead | profile preset |
| `CapPackets` | Per-rule override of the per-flow buffer cap. Must be a non-zero power of two, or it is rejected with a warning | profile preset |

## MTU Guidelines

### Default (auto) — most deployments

For most setups, leave `MTU` unset. The auto-negotiated value (~1382) works on standard Ethernet (1500), PPPoE (1492), and mobile networks.

### When to set MTU explicitly

| Scenario | Recommendation |
|----------|----------------|
| Standard Ethernet / mobile | Leave unset (auto ~1382) |
| Deeply nested tunnels (mqvpn → WG → another tunnel) | Calculate remaining MTU; set if near 1280 |

On the client, if `MTU` is set, mqvpn uses `min(config MTU, negotiated MTU)`; a warning is logged when the config value exceeds the negotiated value. On the server, `MTU` sets the TUN MTU directly (default 1382).

::: tip
On the client, setting `MTU` above the negotiated value (~1382) has no effect — the negotiated value is always the upper bound. On the server, the configured value is applied to the TUN device as-is; packets exceeding a client's negotiated MSS are answered with ICMP Packet Too Big so that the sender's Path MTU Discovery can adjust.
:::

### How mqvpn determines TUN MTU

mqvpn negotiates the TUN MTU from the QUIC DATAGRAM Maximum Segment Size (MSS) at connection time. With the default `max_pkt_out_size` of 1400, the overhead breakdown is:

```
max_pkt_out_size           1400 bytes
 − QUIC short header         13 bytes
 − DATAGRAM frame header      3 bytes
 − MASQUE datagram header      2 bytes
                           ─────────
 = TUN MTU                  1382 bytes
```

This negotiation happens at connection time on the **client**, and the client TUN MTU follows it. The **server** sets its TUN MTU once at startup (1382 by default, or the configured value). When a packet exceeds a particular client's negotiated MSS, the server returns ICMP Packet Too Big to the original sender, carrying that client's MSS as the MTU value; the sender's Path MTU Discovery then lowers its packet size. The shared server TUN MTU never needs to shrink for individual clients.

### Running other tunnels inside mqvpn

When running a tunnel protocol (WireGuard, IPsec, GRE, etc.) inside the mqvpn tunnel, the inner tunnel's overhead reduces the effective MTU. Verify that the remaining MTU meets the inner protocol's requirements.

**Example: WireGuard inside mqvpn**

```
mqvpn TUN MTU                    1382 bytes
 − WireGuard overhead (IPv6)        80 bytes
                                 ─────────
 = WireGuard inner MTU            1302 bytes
   → IPv6 minimum (1280)            ✓
   → QUIC/HTTP3 UDP payload        1254 bytes > 1200  ✓
```

### Constraints

| Constraint | Value | Source |
|------------|-------|--------|
| Config minimum | 1280 | IPv6 minimum MTU (RFC 8200) |
| Config maximum | 9000 | Jumbo frame MTU |
| QUIC minimum UDP payload | 1200 | RFC 9000 §14 (handshake requirement) |
| Auto value | ~1382 (client: negotiated; server: fixed default) | Derived from `max_pkt_out_size` (1400) |

## Control API

A running server can be managed at runtime over a local TCP socket using JSON commands. This is useful for adding or removing users without restarting the server.

### Enable

```bash
sudo mqvpn --mode server ... --control-port 9090
```

The control API binds to `127.0.0.1` by default. It has no authentication, so only bind to trusted interfaces.

### Enable from config file

The control API can also be enabled from `/etc/mqvpn/server.conf`:

```ini
[Control]
Listen = 127.0.0.1:9090
```

…or from the JSON equivalent:

```json
{
  "control_listen": "127.0.0.1:9090"
}
```

CLI flags (`--control-port`, `--control-addr`) override the config-file values per field. `--control-port 0` explicitly disables the API even if `[Control] Listen` is set in the config.

### Commands

Add a user:

```bash
echo '{"cmd":"add_user","name":"carol","key":"carol-secret"}' | nc 127.0.0.1 9090
```

Remove a user:

```bash
echo '{"cmd":"remove_user","name":"carol"}' | nc 127.0.0.1 9090
```

Removing a user also disconnects any active sessions authenticated with that username.

List users:

```bash
echo '{"cmd":"list_users"}' | nc 127.0.0.1 9090
```

Get stats:

```bash
echo '{"cmd":"get_stats"}' | nc 127.0.0.1 9090
```

Get detailed status (per-client, per-path):

```bash
echo '{"cmd":"get_status"}' | nc 127.0.0.1 9090
```

Or use the built-in status command for human-readable output:

```bash
mqvpn --status --control-port 9090
```

All commands return a JSON response with an `"ok"` field. Each connection handles one command, then the server closes the connection.

## systemd

If you installed via the deb package or install.sh, the systemd units are already in place. For source builds, install manually:

```bash
sudo cmake --install build --prefix /usr/local
```

### Server

If you used install.sh, `/etc/mqvpn/server.conf` is already generated. To configure manually, copy the example:

```bash
sudo cp /etc/mqvpn/server.conf.example /etc/mqvpn/server.conf
sudo vi /etc/mqvpn/server.conf   # edit cert paths, auth key, etc.
sudo systemctl enable --now mqvpn-server
```

### Client (template unit)

The client uses a template unit — the instance name maps to the config file:

```bash
sudo cp /etc/mqvpn/client.conf.example /etc/mqvpn/client-home.conf
sudo vi /etc/mqvpn/client-home.conf   # edit server address, auth key, etc.
sudo systemctl enable --now mqvpn-client@home
# → reads /etc/mqvpn/client-home.conf
```

::: info
The systemd units expect INI `.conf` files. The server unit's NAT helper scripts also parse the INI config directly, so JSON cannot be used with the standard units as-is.
:::
