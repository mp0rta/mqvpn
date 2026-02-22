# mqvpn Benchmark Report (netns)

Asymmetric dual-path environment emulated with Linux network namespaces and tc netem.

| Path | Rate | Delay |
|------|:---:|:---:|
| Path A (primary) | 300 Mbit | 10ms |
| Path B (secondary) | 80 Mbit | 30ms |
| **Combined theoretical max** | **380 Mbps** | — |

## 1. Failover — Zero Downtime on Either Path Failure

WLB scheduler achieves zero downtime regardless of which path fails. Traffic seamlessly shifts to the surviving path.

### Path A failure (primary, 300 Mbit)

![Path A Failover](failover_netns_pathA.png)

**0 downtime** — traffic instantly shifts to Path B at t=20s.

| Phase | Throughput (avg) | Detail |
|-------|:---:|--------|
| Pre-fault (t=0–19.5s) | 276 Mbps | Dual-path, both paths active |
| Degraded (t=20–40s) | 73 Mbps | Path B capacity only |
| Recovery (t=40–50s) | 71 Mbps | Path A revalidated, traffic redistributed |
| Post-recovery (t=50–60s) | 290 Mbps | Full dual-path restored |

### Path B failure (secondary, 80 Mbit)

![Path B Failover](failover_netns_pathB.png)

**0 downtime** — minimal impact since Path A carries most traffic.

| Phase | Throughput (avg) | Detail |
|-------|:---:|--------|
| Pre-fault (t=0–19.5s) | 274 Mbps | Dual-path, both paths active |
| Degraded (t=20–40s) | 264 Mbps | Path A capacity (barely noticeable dip) |
| Post-recovery (t=50–60s) | 277 Mbps | Full dual-path restored |

Losing the secondary path has almost no visible impact on throughput in this case.

## 2. Bandwidth Aggregation — WLB vs MinRTT

![Bandwidth Aggregation Comparison](aggregate_compare_minrtt_vs_wlb_netns.png)

WLB distributes TCP flows across paths proportional to capacity. MinRTT sends all packets on the lowest-latency path, leaving the secondary path underutilized.

| Streams | MinRTT (Mbps) | WLB (Mbps) | WLB vs MinRTT | WLB % of Max |
|:---:|:---:|:---:|:---:|:---:|
| 1 | 264 | 256 | -3% | 67% |
| 4 | 255 | 277 | **+9%** | 73% |
| 8 | 270 | 306 | **+13%** | 81% |
| 16 | 263 | **319** | **+21%** | **84%** |
| 32 | 289 | 310 | +7% | 82% |

- WLB peak: **319 Mbps** — 84% of theoretical max (380 Mbps)
- MinRTT peak: **289 Mbps** — 76% of theoretical max
- MinRTT always selects the lowest-latency path (Path A: 300M/10ms) for every packet, so Path B (80M/30ms) remains mostly idle even when available

## Test Conditions

| Parameter | Value |
|-----------|-------|
| Environment | Linux network namespace (netns) |
| Path emulation | tc netem |
| Congestion control | BBR2+ |

### Failover

```
iperf3 -c <tunnel_ip> -t 60 -P 4 --interval 0.5 --json
```

- Fault injection at t=20s: `ip netns exec <server_ns> ip link set <path_if> down`
- Fault recovery at t=40s: `ip netns exec <server_ns> ip link set <path_if> up`

### Aggregate

```
iperf3 -c <tunnel_ip> -t 10 -P <streams> --json
```

- Streams sweep: 1, 2, 4, 8, 16, 32, 64
- Each stream count measured twice: single-path (Path A only) and multipath (Path A + B)
