# Hybrid Mode (TCP Lane)

Hybrid mode terminates inner TCP connections locally on the client (via an embedded [lwIP](https://savannah.nongnu.org/projects/lwip/) stack) and relays them over a dedicated HTTP/3 request **stream** instead of the datagram CONNECT-IP path.

Why: raw multipath spreads a flow's datagrams across paths, and a single inner TCP flow interprets the resulting cross-path reordering as loss and backs off. The TCP stream lane removes the inner TCP end-to-end assumption — the QUIC stream layer restores ordering — so **even a single TCP flow aggregates the bandwidth of all paths**. In our benchmark a single `iperf3` flow goes from 96 Mbps (raw) to ~187 Mbps (hybrid) on a 2×100 Mbps bond — see [Benchmarks](../benchmarks/#hybrid-tcp-lane-aggregation-v0-9-0).

The trade-off is a small per-flow overhead (local TCP termination + stream framing) and that the server, not the far endpoint, answers the TCP handshake for relayed flows.

## How packets are classified

Classification is per packet on the client, with the lane decision latched per TCP flow at SYN time:

```
TUN packet
  │
  ▼
classifier (per packet: protocol + Tcp mode + tunnel-subnet carve-out)
  │
  ├─ TCP, Tcp=stream (or Tcp=auto with ≥2 active paths)
  │     └─▶ tcp lane (client-side lwIP) ─▶ HTTP/3 request stream ─▶ server egress connect()
  ├─ UDP (parseable)
  │     └─▶ datagram lane (existing reorder/STAMP path) ─▶ CONNECT-IP DATAGRAM
  └─ everything else (incl. TCP under Tcp=raw, or Tcp=auto with <2 active paths)
        └─▶ raw lane (existing, unchanged) ─▶ CONNECT-IP DATAGRAM
```

With the default `Tcp = auto`, a TCP flow takes the stream lane only when ≥2 paths are active at SYN time — single-path clients keep the plain datagram path, where the lane's overhead buys nothing. The decision is made once per flow and never re-evaluated.

## Enabling it

Hybrid mode is **disabled by default**; existing deployments see no behavior change. It must be enabled on both sides.

### Server

```ini
# /etc/mqvpn/server.conf
[Hybrid]
Enabled = true
# EgressAllow = 10.0.5.0/24   # only if relayed TCP must reach private ranges
```

### Client

```ini
# /etc/mqvpn/client.conf
[Hybrid]
Enabled = true
Tcp = auto        # stream | raw | auto (default)
```

…or the JSON equivalent (`"hybrid": {"enabled": true, "tcp": "auto"}`). The full key reference (flow caps, timeouts, egress ACL) is in [Configuration → `[Hybrid]`](./configuration#hybrid).

## Server-side egress ACL

Relayed TCP leaves the server as a normal outbound `connect()`, so the server enforces a **default-deny egress ACL for private ranges** — RFC1918, loopback, and link-local targets are refused even with nothing configured. This is a safety default against a compromised or misconfigured client using the VPN server as a pivot into its internal network.

If relayed TCP legitimately needs to reach a private target, punch an explicit hole:

```ini
[Hybrid]
Enabled = true
EgressAllow = 10.0.5.0/24
EgressDeny = 10.0.5.13/32   # evaluated after EgressAllow
```

## Monitoring

The control API's `get_stats` exposes the lane's runtime counters on both client and server: `tcp_flows_active`, `tcp_flows_total`, `tcp_flows_rejected`, plus per-lane packet counters (`pkts_lane_*`). See [docs/control-api.md §5.4](https://github.com/mp0rta/mqvpn/blob/main/docs/control-api.md) for field semantics.

## iOS builds

iOS builds (`ios/build-ios.sh`) compile the lane with a reduced lwIP footprint
(the `MQVPN_LWIP_IOS_PROFILE` build flag: ~256 KiB TCP windows and 64-flow
pool sizing instead of ~2 MiB / 256) to fit the iOS Network Extension memory
ceiling. Android builds use their own profile — desktop windows with the smaller 512-pcb pool, giving a 256-flow ceiling; desktop and router builds get a 8192-pcb pool and a 4096-flow ceiling. The profile is paired with the
QUIC-side [`[Advanced] RecvRateLimit`](./configuration#advanced) receive-rate
cap — shrinking the inner TCP windows alone does not bound the outer QUIC
connection's own buffering, so the iOS client sets both. The full budget arithmetic and measured
numbers are in
[docs/hybrid_h2_memory_budget.md §5](https://github.com/mp0rta/mqvpn/blob/main/docs/hybrid_h2_memory_budget.md).

## Known limitations

- **TCP to private targets needs an explicit `EgressAllow`.** The client cannot see the server's ACL, so lwIP answers the inner SYN locally before the server's egress `connect()` is attempted; an ACL denial surfaces to the app as a later RST rather than an immediate connection refusal.
- **Client-address pools wider than `/24` can deny intra-VPN TCP between clients.** The client only exempts its own `/24` from the TCP lane; with a wider pool, add an `EgressAllow` covering the pool (the server logs a startup warning for this case).
- A handful of IPv6 forms lwIP cannot deliver (v4-mapped, multicast, unspecified source) are routed to the raw lane instead of the TCP lane.
