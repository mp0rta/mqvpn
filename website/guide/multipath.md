# Multipath

mqvpn uses [Multipath QUIC](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) to send traffic over multiple network paths simultaneously. This enables:

- **Seamless failover** — If one path goes down, traffic continues on the remaining paths to minimize disruption during path changes.
- **Bandwidth aggregation** — Combine bandwidth from multiple interfaces (e.g., WiFi + LTE). Aggregation works best with multiple concurrent flows; single TCP flows may see limited benefit due to flow pinning (see [WLB](#wlb-weighted-load-balancing-default)).

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

### Which Scheduler to Use?

| Scenario | Recommended |
|----------|-------------|
| General use, bandwidth aggregation | **WLB** |
| Inner UDP needing single-path delivery | **`wlb_udp_pin`** |
| Latency-sensitive applications | MinRTT |
| Asymmetric paths (different speeds) | **WLB** |
| Similar-speed paths | Either works well |
| Lossy primary + reliable standby (experimental) | `backup_fec` |

## Dynamic Path Management

At the libmqvpn API level, paths can be added or removed while the VPN is running. This is useful for mobile scenarios where network interfaces come and go (e.g., connecting to WiFi while on LTE).

At the library level, the platform uses `mqvpn_client_add_path_fd()` to add a new UDP socket as a path, and the path manager handles the lifecycle automatically. When a path is removed (interface goes down), traffic seamlessly shifts to the remaining paths.

In the standard CLI, paths are specified at startup with `--path` flags. The platform layer then monitors those interfaces at runtime (netlink on Linux, `PF_ROUTE` on macOS): when an interface goes down its path is dropped automatically, and when the interface comes back with a usable address the socket is re-created and the path is re-added — backed by a periodic recovery timer. Discovery of brand-new interfaces that were never registered at startup is not implemented; only interfaces named via `--path` participate in this monitoring.

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
