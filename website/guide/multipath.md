# Multipath

mqvpn uses [Multipath QUIC](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) to send traffic over multiple network paths simultaneously. This enables:

- **Seamless failover** — If one path goes down, traffic continues on the remaining paths with zero downtime.
- **Bandwidth aggregation** — Combine bandwidth from multiple interfaces (e.g., WiFi + LTE).

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

The scheduler decides how to distribute packets across paths. mqvpn supports two schedulers:

### WLB (Weighted Loss-Based) — Default

WLB dynamically adjusts traffic distribution based on each path's measured loss rate and capacity. It aims to maximize aggregate throughput.

- Adapts to changing network conditions in real-time
- Handles asymmetric paths well (e.g., 300 Mbps wired + 80 Mbps wireless)
- Outperforms MinRTT by ~21% in benchmarks

```bash
--scheduler wlb
```

### MinRTT (Minimum Round-Trip Time)

MinRTT sends each packet on the path with the lowest current RTT. It is simpler but may not utilize available bandwidth as efficiently.

- Optimizes for latency over throughput
- Simpler algorithm, more predictable behavior

```bash
--scheduler minrtt
```

### Which Scheduler to Use?

| Scenario | Recommended |
|----------|-------------|
| General use, bandwidth aggregation | **WLB** |
| Latency-sensitive applications | MinRTT |
| Asymmetric paths (different speeds) | **WLB** |
| Similar-speed paths | Either works well |

## Dynamic Path Management

Paths can be added or removed while the VPN is running. This is useful for mobile scenarios where network interfaces come and go (e.g., connecting to WiFi while on LTE).

At the library level, the platform uses `mqvpn_client_add_path_fd()` to add a new UDP socket as a path, and the path manager handles the lifecycle automatically. When a path is removed (interface goes down), traffic seamlessly shifts to the remaining paths.

On the CLI, paths are specified at startup with `--path` flags. The client monitors the specified interfaces and automatically handles path availability changes.

## Path Weighting

The WLB scheduler automatically weights paths based on measured loss rate and available capacity. You do not need to configure weights manually — the scheduler adapts in real-time.

How it works:
- Each path's **loss rate** is continuously measured from QUIC ACK feedback
- Paths with lower loss receive proportionally more traffic
- **Capacity estimation** uses the QUIC congestion window to gauge each path's throughput potential
- The scheduler rebalances every few RTTs, adapting to changing conditions

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

## Protocol Standards

| Protocol | Spec |
|----------|------|
| MASQUE CONNECT-IP | [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) |
| HTTP Datagrams | [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) |
| QUIC Datagrams | [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) |
| Multipath QUIC | [draft-ietf-quic-multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) |
| HTTP/3 | [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) |
