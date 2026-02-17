# mpvpn M3 Benchmark Report

Date: 2026-02-17
Environment: Local machine (2x ISP) → Kagoya VPS (1 Gbps shared)
Underlay: Tailscale (single-path) / Direct IP (multipath)

## Latency

| Path | Min (ms) | Avg (ms) | Max (ms) | Loss |
|------|----------|----------|----------|------|
| Direct (Tailscale) | 20.5 | 21.0 | 22.3 | 12% |
| VPN tunnel | 20.8 | 21.4 | 21.8 | 18% |

## Throughput

| Test | Direction | Mbps | Notes |
|------|-----------|------|-------|
| Direct (no VPN, iperf3 TCP) | UL | 92.0 | retrans=137 |
| 1-path QUIC (iperf3 TCP) | UL | 25.6 | retrans=12 |
| 1-path QUIC (iperf3 TCP) | DL | 29.1 | retrans=166 |
| 1-path QUIC (iperf3 UDP) | UL | 200.0 | loss=72.8%, jitter=0.6ms |
| 1-path QUIC (iperf3 UDP) | DL | 200.0 | loss=49.3%, jitter=0.2ms |
| 2-path QUIC (iperf3 TCP) | UL | 91.5 | retrans=1511 |
| 2-path QUIC (iperf3 TCP) | DL | 15.1 | retrans=812 |
| 2-path QUIC (iperf3 UDP) | UL | 500.0 | loss=80.3%, jitter=0.2ms |

## Failover Test

60-second iperf3 with Path A (enp5s0) taken down at t=20s and restored at t=40s.

```
t=  0.0s:   185.5 Mbps
t=  1.0s:    97.5 Mbps
t=  2.0s:    77.6 Mbps
t=  3.0s:    87.0 Mbps
t=  4.0s:    87.1 Mbps
t=  5.0s:    89.1 Mbps
t=  6.0s:    88.1 Mbps
t=  7.0s:    98.6 Mbps
t=  8.0s:    75.5 Mbps
t=  9.0s:    98.5 Mbps
t= 10.0s:    76.6 Mbps
t= 11.0s:    88.1 Mbps
t= 12.0s:    87.1 Mbps
t= 13.0s:    88.1 Mbps
t= 14.0s:    96.5 Mbps
t= 15.0s:    77.6 Mbps
t= 16.0s:    98.6 Mbps
t= 17.0s:    86.0 Mbps
t= 18.0s:    88.1 Mbps  <-- path down
t= 19.0s:    88.1 Mbps  <-- path down
t= 20.0s:    87.0 Mbps  <-- path down
t= 21.0s:    80.7 Mbps  <-- path down
t= 22.0s:    92.3 Mbps
t= 23.0s:    90.2 Mbps
t= 24.0s:    79.7 Mbps
t= 25.0s:    92.3 Mbps
t= 26.0s:    80.8 Mbps
t= 27.0s:    92.3 Mbps
t= 28.0s:    79.7 Mbps
t= 29.0s:    78.7 Mbps
t= 30.0s:   103.8 Mbps
t= 31.0s:    91.2 Mbps
t= 32.0s:    91.2 Mbps
t= 33.0s:    81.8 Mbps
t= 34.0s:    90.2 Mbps
t= 35.0s:    81.8 Mbps
t= 36.0s:    93.3 Mbps
t= 37.0s:    79.7 Mbps
t= 38.0s:    92.3 Mbps  <-- path restored
t= 39.0s:    92.3 Mbps  <-- path restored
t= 40.0s:    80.8 Mbps  <-- path restored
t= 41.0s:    93.3 Mbps  <-- path restored
t= 42.0s:    93.3 Mbps
t= 43.0s:    81.8 Mbps
t= 44.0s:    92.3 Mbps
t= 45.0s:    91.3 Mbps
t= 46.0s:    79.7 Mbps
t= 47.0s:    91.2 Mbps
t= 48.0s:    80.7 Mbps
t= 49.0s:    92.3 Mbps
t= 50.0s:    91.2 Mbps
t= 51.0s:    79.7 Mbps
t= 52.0s:    79.7 Mbps
t= 53.0s:    90.2 Mbps
t= 54.0s:   103.8 Mbps
t= 55.0s:    91.2 Mbps
t= 56.0s:    91.2 Mbps
t= 57.0s:    79.7 Mbps
t= 58.0s:    91.2 Mbps
t= 59.0s:    92.3 Mbps
```

- Before failover (t=0-18): avg 93.5 Mbps
- During failover (t=22-38): avg 87.4 Mbps
- After restore (t=42-60): avg 88.5 Mbps
- **Result: Zero downtime — throughput maintained throughout**

## Stability (1-hour test)

- Duration: 3600s
- Throughput: 89.0 Mbps
- Retransmits: 151833
- Memory (RSS): start=7468 KB, end=7468 KB, max=7468 KB
- Memory growth: +0.0%
