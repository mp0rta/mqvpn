# Multipath

mqvpn uses [Multipath QUIC](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) to send traffic over multiple network paths simultaneously. This enables:

- **Seamless failover** — If one path goes down, traffic continues on the remaining paths to minimize disruption during path changes.
- **Bandwidth aggregation** — Combine bandwidth from multiple interfaces (e.g., WiFi + LTE). Aggregation works best with multiple concurrent flows; to aggregate a single TCP flow, use [hybrid mode](./hybrid-mode).

## Setting Up Multipath

### CLI

Use `--path` to specify each network interface:

```bash
sudo ./build/mqvpn --mode client --server 203.0.113.1:443 \
    --auth-key <key> --path eth0 --path wlan0
```

### Config File

```ini
[Multipath]
Scheduler = wlb
Path = eth0
Path = wlan0
```

::: tip
Without any `--path` flags or `Path` entries, mqvpn uses the default interface (single path mode).
:::

## Schedulers

The scheduler decides how to distribute packets across paths. mqvpn supports the following schedulers:

### WLB (Weighted Load Balancing) — Default

WLB combines path weighting and flow-aware scheduling for QUIC datagrams:

- Estimates each path's throughput from live metrics (loss, RTT, cwnd) and uses the result as a traffic distribution ratio
- Uses deficit-based WRR to distribute traffic across active paths
- Pins inner TCP flows (by flow hash) to a path to reduce reordering in VPN tunnels
- Uses soft pinning when the pinned path is temporarily cwnd-blocked (spillover without permanent re-pin)
- Falls back to MinRTT for non-datagram/control packets and when no active schedulable path is available

```bash
--scheduler wlb
```

### WLB UDP Pin (`wlb_udp_pin`)

A variant of WLB that keeps each UDP connection on a single path, on top of the
TCP pinning that plain WLB already does.

```bash
--scheduler wlb_udp_pin
```

**Use this when** you have inner UDP traffic that maintains its own packet
ordering and you observe throughput degradation under plain `wlb`. The
mechanism: when mqvpn spreads packets across paths with different latencies,
an inner protocol that tracks ordering may mistake the reorder for packet
loss, slow itself down, and throughput drops. `wlb_udp_pin` keeps the packets
of each UDP connection on one path so this reorder doesn't happen.

Note that with a single inner UDP connection, `wlb_udp_pin` is capped at one
path's bandwidth. As long as the inner protocol runs over a single sequence
space, you cannot aggregate bandwidth across paths without the inner protocol
itself going multipath. The point of `wlb_udp_pin` here is to give you a
steady "one path's worth" of throughput, rather than per-packet striping under
plain `wlb` potentially collapsing to less than one path's throughput under
reorder.

**Stick with plain `wlb`** when your UDP traffic tolerates packet reorder.
mqvpn then spreads packets across paths per-packet, giving better combined
bandwidth than pinning. There's also a practical limit on `wlb_udp_pin`:
mqvpn tracks UDP connections in a fixed-size table, so if your traffic creates
thousands of short-lived UDP flows per second, `wlb_udp_pin` can lose track of
older flows and the pinning becomes unreliable. For those cases plain `wlb` is
safer.

In short: try `wlb_udp_pin` if you observe degraded UDP throughput under
`wlb`. Otherwise leave it on `wlb`.

### MinRTT (Minimum Round-Trip Time)

MinRTT sends each packet on the path with the lowest current RTT. It is simpler but may not utilize available bandwidth as efficiently.

- Optimizes for latency over throughput
- Simpler algorithm, more predictable behavior

```bash
--scheduler minrtt
```

### Failover

One path carries all traffic. Backup paths are kept up, with a small probe
about once a second, but carry no data while the primary works. When the
primary stops delivering, traffic moves to a backup; when the primary comes
back, traffic moves back to it. Use it when a backup link is metered or slow
(e.g., wired primary with an LTE backup).

```bash
sudo ./build/mqvpn --mode client --server 203.0.113.1:443 \
    --auth-key <key> --scheduler failover --request-server-scheduler \
    --path eth0 --backup-path wwan0
```

```ini
[Multipath]
Scheduler = failover
RequestServerScheduler = true
Path = eth0
BackupPath = wwan0
```

- With no `--backup-path` / `BackupPath`, the first path is the primary and
  every later path is a backup. With `BackupPath` entries, every `Path` is a
  primary: traffic is spread over the primaries like `minrtt`, and the
  backups are used only when no primary works.
- A path keeps its role when it goes down and comes back: a primary that
  returns carries the traffic again.
- The download direction follows the server's scheduler: set
  `Scheduler = failover` on the server, or `AllowClientScheduler = true` on
  the server and `RequestServerScheduler = true` on the client.
- A primary that loses every packet while its link stays up is detected after
  a few probe timeouts, typically well under a second on a 10 ms path.

### Backup FEC (experimental)

Sends regular traffic on the AVAILABLE path and FEC repair symbols on the
STANDBY path. Designed for lossy primary links (e.g., spotty WiFi) backed by
a more reliable standby (e.g., LTE).

```
--scheduler backup_fec
```

**When to use**: WiFi+LTE multipath in lossy environments. Repair symbols on
the standby path enable instant recovery from primary-path losses without
waiting for retransmission RTTs.

**When NOT to use**:

- Single-path setups (no standby path = no place for repair symbols)
- High-bandwidth scenarios where you want bandwidth aggregation (use `wlb` instead)
- Both endpoints must be on mqvpn ≥ 0.4.0 with FEC build enabled
  (`-DXQC_ENABLE_FEC=ON -DXQC_ENABLE_XOR=ON`)

**Tuning**: Default config uses XOR FEC with ~33% per-block overhead (see
`src/mqvpn_scheduler.h` `MQVPN_FEC_*` macros). No CLI flags exposed for FEC
parameters in this experimental release.

**Performance**: See [weekly benchmarks](../benchmarks/weekly) for measured
throughput vs WLB across loss rates 1%–10%.

### Scheduler Selection Guide

| Scenario | Recommended |
|----------|-------------|
| General use, bandwidth aggregation | **WLB + [Hybrid Mode](./hybrid-mode)** |
| Inner UDP needing single-path delivery | **`wlb_udp_pin`** |
| Latency-sensitive applications | MinRTT (trades off bandwidth aggregation; for live streams, consider [redundant mode](#redundant-mode)) |
| Combinations of poor-quality links | MinRTT + [Hybrid Mode](./hybrid-mode) (consider adding Reinjection or the reorder buffer as needed) |
| Metered or slow backup, used only when the primary fails | `failover` |
| Lossy primary + reliable standby (experimental) | `backup_fec` |


## Reinjection (Speculative Duplication)

Reinjection sends copies of selected packets over a second path. It costs
some extra bandwidth, and in return the tunnel rides out packet loss and
sudden link trouble much more smoothly. Off by default, and independent of
the scheduler choice: originals are scheduled normally, while copies are
always placed on a *different* path than their origin.

Ref: [XLINK (SIGCOMM 2021)](https://conferences.sigcomm.org/sigcomm/2021/files/papers/3452296.3472893.pdf)

```ini
[Multipath]
# off | deadline | idle
Reinjection = deadline
```

| Mode | What gets copied | Use it for |
|------|------------------|------------|
| `deadline` | Stream-lane (TCP-side) data still awaiting delivery confirmation that is running late, plus everything sent on a link judged unhealthy | Insurance for tunnels running [Hybrid Mode](./hybrid-mode), which carries TCP over QUIC streams: does nothing (and costs nothing) most of the time, and minimizes the hiccup at the moment a link suddenly goes bad |
| `idle` | Recent still-unconfirmed stream data (TCP side only), in moments when the tunnel has nothing else to send | Low-cost smoothing of occasional hiccups in interactive use (SSH, browsing). No tuning needed |

**Why a hiccup can happen at all**: when a link goes bad, the scheduler does
steer new data to the healthy link — but data already sent on the failing
link still has to be recovered, and in-order delivery makes everything behind
it wait, even data that already arrived via the healthy link (multipath
head-of-line blocking). A silently dead link is only detected after a timeout
of hundreds of milliseconds, so in the worst case that wait approaches a
second. `deadline` resends the late data on the healthy link right away,
reducing that wait.

Deadline-mode tuning (defaults shown):

```ini
# duplicate when older than 1.1 × min_srtt (100–1000)
ReinjectionSrttFactorPct = 110
# upper clamp on the deadline (1–60000)
ReinjectionHardDeadlineMs = 500
# lower clamp (1–60000; clamped down to the hard deadline)
ReinjectionDeadlineLowerBoundMs = 20
```

Notes:

- Reinjection is sender-side: each side's setting protects the traffic it
  *sends*, so enable it on the **server** to protect download traffic (and on
  the client for upload).
- Per-path duplicated bytes are reported as `reinject_tx_bytes` in the
  control API `get_status` response.
- Requires two or more active paths; silently inactive otherwise.

## Redundant Mode

Redundant mode sends copies of outgoing UDP packets over more than one path at
once. If one connection drops for a few seconds, the copies on the others
usually keep a live stream going. Off by default.

```ini
[Multipath]
Redundant = true
# optional: only UDP to these destination ports
RedundantPorts = 4200
# recommended with redundant mode
CC = bbr
```

On Android, turn on the **Redundant Mode** switch (the port list is the
**Redundant Ports** field). The app then uses `CC = bbr` for you.

- **When to use it**: live streaming such as SRT over phone connections,
  especially with a short latency setting, and connections that drop out for a
  few seconds at a time.
- **What it costs**: the traffic it covers uses up to twice the data with two
  paths, three times with three. Set
  `RedundantPorts` to cover only your stream, for example `4200`, or a
  comma-separated list such as `4200,9000` (up to 16 ports). Without it, all
  UDP is duplicated. TCP is never duplicated by this mode.
- **Every connection should carry the whole stream (recommended)**: each connection sends a
  full copy, so each one needs enough upload speed for the stream on its own,
  with some room to spare. For a 20 Mbps stream, every connection must manage
  at least 20 Mbps up. One connection slowing down for a while is fine as long
  as another can still carry the stream. When none can, mqvpn stops copying
  and sends each packet once, as with `Redundant = false`, and tries copying
  again later once a connection looks fast enough; the log notes each switch
  (`redundant mode: ...`). The stream can still lose more packets than with
  `Redundant = false`, so if your connections are often slower than the stream,
  leave redundant mode off.
- **Use `CC = bbr` on the client (recommended)**: `CC` decides how fast mqvpn
  sends data. Cellular connections are wireless, so they can lose a few
  packets even when they are not busy. The default, `bbr2`, slows down after
  such losses, which can leave the connection too slow to carry the full
  stream. `bbr` keeps its speed. In our benchmarks, `bbr` performed better
  with redundant mode.
- **Duplicates reach the application**: mqvpn does not remove the extra
  copies, so the receiving application sees every packet more than once. SRT
  and similar protocols discard duplicates; check that your application does
  before using this mode for other UDP traffic.
- **Using Reorder together with redundant mode**: outgoing UDP packets covered
  by redundant mode bypass Reorder, so Reorder neither puts them in order nor
  removes their duplicates. With an empty `RedundantPorts` list, all outgoing
  UDP bypasses Reorder. Reorder still follows its settings and rules for other
  traffic and downloads.
- **Upload only**: it applies to what the client sends. Download traffic is
  unchanged. The server ignores the setting.
- A path that is still starting up or has gone down gets no copies. A path
  that falls behind the others gets none until it catches up. If only one path
  is usable, packets are sent once on it.
- Right after connecting, a stream can still lose a few packets for about the
  first second while the connections speed up.
- Redundant mode has no effect with `Scheduler = backup_fec`, because the
  second path stays on standby.

This replaces the former `Reinjection = dgram` mode, which has been removed.
A config file that still says `dgram` prints a warning and runs with
`Reinjection = off`; use `Redundant = true` instead.

## Path Weighting

WLB automatically updates path weights from live transport metrics. You do not need to configure weights manually.

How it works:
- **Loss, RTT, and cwnd** are used to estimate each path's throughput, which becomes its traffic distribution weight
- Deficit WRR uses those weights to assign packets/flows across available paths
- Existing TCP flow pins are reused, and stale pins are evicted on idle/loss/path failure
- Weights and deficits are refreshed at round boundaries and on path recovery events

This means asymmetric paths (e.g., 300 Mbps wired + 80 Mbps wireless) are utilized efficiently without any manual tuning.

## How It Works

```
┌─────────────────┐                          ┌─────────────────┐
│   Application   │                          │    Internet     │
├─────────────────┤                          ├─────────────────┤
│   TUN (mqvpn0)  │                          │   TUN (mqvpn0)  │
├─────────────────┤                          ├─────────────────┤
│  MASQUE         │    HTTP Datagrams        │  MASQUE         │
│  CONNECT-IP     │◄──(Context ID = 0)──────►│  CONNECT-IP     │
├─────────────────┤                          ├─────────────────┤
│  Multipath QUIC │◄── Path A (eth0)  ─────►│  Multipath QUIC │
│                 │◄── Path B (wlan0) ─────►│                 │
├─────────────────┤                          ├─────────────────┤
│  UDP (eth0/wlan)│                          │   UDP (eth0)    │
└─────────────────┘                          └─────────────────┘
     Client                                      Server
```

Each path is a separate UDP socket bound to a specific network interface. Multipath QUIC manages the paths at the QUIC layer — the server sees a single QUIC connection with multiple paths.

## Benchmarks

For failover and bandwidth aggregation measurements in a simulated dual-path environment (300 Mbps + 80 Mbps with netem), see the [benchmark report](https://github.com/mp0rta/mqvpn/blob/main/docs/benchmarks_netns.md).

## Protocol Standards

| Protocol | Spec |
|----------|------|
| MASQUE CONNECT-IP | [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) |
| HTTP Datagrams | [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) |
| QUIC Datagrams | [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) |
| Multipath QUIC | [draft-ietf-quic-multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) |
| HTTP/3 | [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) |
