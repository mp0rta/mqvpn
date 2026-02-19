# mqvpn M3 Benchmark Report

Date: 2026-02-17
Environment: Local machine (2x ISP) → ConoHa VPS (100 Mbps)
Underlay: Direct WAN (163.44.118.182)
Protocol: MASQUE CONNECT-IP (RFC 9484) over HTTP/3

IP packets are tunneled as HTTP Datagrams (Context ID=0) on an H3 Extended CONNECT stream (:protocol=connect-ip), carried over QUIC DATAGRAM frames (RFC 9221). Capsules (ADDRESS_ASSIGN, ROUTE_ADVERTISEMENT) on the CONNECT stream handle control; Multipath QUIC (RFC 9443) is a separate transport extension.

## Latency

| Path | Min (ms) | Avg (ms) | Max (ms) | Loss |
|------|----------|----------|----------|------|
| Direct WAN (IPv6) | 19.9 | 20.4 | 20.8 | 0% |
| 1-path mqvpn tunnel | 24.3 | 32.9 | 60.7 | 0% |
| 2-path mqvpn tunnel | 20.8 | 21.3 | 22.2 | 0% |

## TCP Throughput

| Test | Direction | Mbps | Notes |
|------|-----------|------|-------|
| Direct (no VPN) | UL | 104.0 | retrans=7 |
| Direct (no VPN) | DL | 107.5 | retrans=3011 |
| 1-path mqvpn | UL | 90.7 | retrans=923 |
| 1-path mqvpn | DL | 59.3 | retrans=71 |
| 2-path mqvpn | UL | 90.0 | retrans=1394 |
| 2-path mqvpn | DL | 76.7 | retrans=700 |

## UDP Throughput (Bandwidth Sweep)

iperf3 UDP at increasing target rates (10s each). Max bandwidth with loss < 1%:

| Test | Direction | Max Mbps (loss < 1%) | Next rate → loss |
|------|-----------|---------------------|-----------------|
| 1-path mqvpn | UL | 110 | 120M → 8.1% |
| 1-path mqvpn | DL | 100 | 110M → 2.1% |
| 2-path mqvpn | UL | 110 | 120M → 4.9% |
| 2-path mqvpn | DL | 90 | 95M → 15.7% |

### Sweep Details

**1-path mqvpn UL:**

| Rate | Mbps | Loss | Jitter |
|------|------|------|--------|
| 10M | 10.0 | 0.00% | 0.34ms |
| 30M | 30.0 | 0.00% | 0.16ms |
| 50M | 50.0 | 0.00% | 0.08ms |
| 70M | 70.0 | 0.00% | 0.10ms |
| 80M | 80.0 | 0.00% | 0.09ms |
| 85M | 85.0 | 0.02% | 0.15ms |
| 90M | 90.0 | 0.00% | 0.11ms |
| 95M | 95.0 | 0.00% | 0.14ms |
| 100M | 100.0 | 0.00% | 0.10ms |
| 110M | 110.0 | 0.00% | 0.14ms |
| 120M | 120.0 | 8.06% | 0.15ms | **

**1-path mqvpn DL:**

| Rate | Mbps | Loss | Jitter |
|------|------|------|--------|
| 10M | 10.0 | 0.12% | 0.11ms |
| 30M | 30.0 | 0.68% | 0.34ms |
| 50M | 50.0 | 0.24% | 0.35ms |
| 70M | 70.0 | 0.13% | 0.22ms |
| 80M | 80.0 | 2.78% | 0.49ms | **
| 85M | 85.0 | 0.12% | 3.98ms |
| 90M | 90.0 | 0.07% | 0.22ms |
| 95M | 95.0 | 0.21% | 0.07ms |
| 100M | 100.0 | 0.29% | 0.24ms |
| 110M | 110.0 | 2.12% | 0.44ms | **
| 120M | 120.0 | 19.49% | 0.31ms | **

**2-path mqvpn UL:**

| Rate | Mbps | Loss | Jitter |
|------|------|------|--------|
| 10M | 10.0 | 0.00% | 0.20ms |
| 30M | 30.0 | 0.00% | 0.12ms |
| 50M | 50.0 | 0.00% | 0.15ms |
| 70M | 70.0 | 0.00% | 0.12ms |
| 80M | 80.0 | 0.00% | 0.13ms |
| 85M | 85.0 | 0.00% | 0.11ms |
| 90M | 90.0 | 0.00% | 0.10ms |
| 95M | 95.0 | 0.00% | 0.10ms |
| 100M | 100.0 | 0.00% | 0.09ms |
| 110M | 110.0 | 0.00% | 0.14ms |
| 120M | 120.0 | 4.91% | 0.14ms | **
| 130M | 130.0 | 10.16% | 0.16ms | **
| 140M | 140.0 | 16.57% | 0.16ms | **
| 150M | 150.0 | 22.14% | 0.16ms | **
| 175M | 175.0 | 33.28% | 0.15ms | **
| 200M | 200.0 | 41.63% | 0.15ms | **

**2-path mqvpn DL:**

| Rate | Mbps | Loss | Jitter |
|------|------|------|--------|
| 10M | 10.0 | 0.00% | 0.13ms |
| 30M | 30.0 | 0.00% | 0.04ms |
| 50M | 50.0 | 0.00% | 0.06ms |
| 70M | 70.0 | 0.00% | 0.03ms |
| 80M | 80.0 | 0.00% | 0.03ms |
| 85M | 85.0 | 0.00% | 0.19ms |
| 90M | 90.0 | 0.00% | 0.38ms |
| 95M | 95.0 | 15.66% | 0.26ms | **
| 100M | 100.0 | 17.68% | 0.28ms | **
| 110M | 110.0 | 11.00% | 0.13ms | **
| 120M | 120.0 | 22.08% | 0.30ms | **

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
