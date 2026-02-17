# mpvpn

Multipath VPN for Linux using MASQUE CONNECT-IP (RFC 9484) over HTTP/3.

IP packets are tunneled as HTTP Datagrams (Context ID=0) associated with an HTTP/3 Extended CONNECT request stream (`:protocol=connect-ip`), and carried over QUIC DATAGRAM frames. Control and configuration are exchanged as Capsules (ADDRESS_ASSIGN, ROUTE_ADVERTISEMENT) on the CONNECT stream.

```
TUN (IP packet)
 → HTTP Datagram [Quarter Stream ID + Context ID=0 + payload]  (RFC 9297)
   → QUIC DATAGRAM frame  (RFC 9221)
     → UDP → WAN
```

## Features

- **MASQUE CONNECT-IP** (RFC 9484) — IP tunneling over HTTP/3
- **Multipath QUIC** (RFC 9443) — bind up to 4 network interfaces; this is a QUIC transport extension independent of MASQUE
- **Seamless failover** — zero-downtime path switching when an interface goes down
- **Dynamic TUN MTU** — derived from QUIC path MTU / `max_datagram_frame_size` minus MASQUE framing overhead, adjusted via PMTUD
- **Split tunneling** — server IP routed via original gateway to prevent routing loops
- Linux TUN device with automatic IP assignment and route configuration

## Architecture

```
Client                                          Server
┌──────────┐                                  ┌──────────┐
│   App    │                                  │  Network │
│ (iperf3) │                                  │          │
└────┬─────┘                                  └────▲─────┘
     │ IP packet                                   │ IP packet
┌────▼─────┐                                  ┌────┴─────┐
│   TUN    │ mpvpn0                            │   TUN    │ mpvpn0
└────┬─────┘                                  └────▲─────┘
     │                                             │
┌────▼─────────────────────────────────────────────┴─────┐
│           MASQUE CONNECT-IP over HTTP/3                 │
│  Data:    HTTP Datagram → QUIC DATAGRAM frame          │
│  Control: Capsules on CONNECT stream                   │
├─────────────┬─────────────┬──────────────────────┬─────┤
│  Path A     │  Path B     │  Path C              │ ... │
│  (enp5s0)   │  (enp4s0)   │  (wlan0)             │     │
│  UDP socket │  UDP socket │  UDP socket          │     │
└─────────────┴─────────────┴──────────────────────┴─────┘
        Multipath QUIC (MinRTT scheduler)
```

## Quick Start

### Prerequisites

- Linux (TUN device support)
- CMake 3.10+, GCC/Clang with C11
- libevent2 (`apt install libevent-dev`)
- Go 1.18+ (for BoringSSL build)

### Build

```bash
git clone --recurse-submodules https://github.com/mp0rta/mpvpn.git
cd mpvpn

# 1. BoringSSL
cd third_party/xquic/third_party/boringssl
mkdir -p build && cd build
cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..
make -j$(nproc) ssl crypto

# 2. xquic
cd ../../../
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DSSL_TYPE=boringssl \
      -DSSL_PATH=../third_party/boringssl \
      -DXQC_ENABLE_TESTING=OFF ..
make -j$(nproc)

# 3. mpvpn
cd ../../
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DXQUIC_BUILD_DIR=../third_party/xquic/build ..
make -j$(nproc)
```

### Run

```bash
# Generate self-signed cert (for testing)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=mpvpn'

# Server
sudo ./build/mpvpn --mode server \
  --listen 0.0.0.0:4433 \
  --cert server.crt --key server.key \
  --subnet 10.0.0.0/24

# Client (single path)
sudo ./build/mpvpn --mode client \
  --server <server-ip>:4433 \
  --insecure --path eth0

# Client (multipath)
sudo ./build/mpvpn --mode client \
  --server <server-ip>:4433 \
  --insecure --path eth0 --path eth1
```

### CLI Options

| Option | Mode | Description |
|--------|------|-------------|
| `--mode {client,server}` | both | Required. Operating mode |
| `--server HOST:PORT` | client | Server address |
| `--listen BIND:PORT` | server | Bind address (default: `0.0.0.0:443`) |
| `--cert PATH` | server | TLS certificate file |
| `--key PATH` | server | TLS private key file |
| `--subnet CIDR` | server | Client address pool (default: `10.0.0.0/24`) |
| `--tun-name NAME` | both | TUN device name (default: `mpvpn0`) |
| `--path IFACE` | client | Network interface to use (repeatable, max 4) |
| `--insecure` | client | Skip TLS certificate verification |
| `--log-level LEVEL` | both | `debug`, `info`, `warn`, or `error` |

## Benchmark Results

Tested over direct WAN: Local machine (2x ISP) → ConoHa VPS (100 Mbps).

**Latency:**

| Path | Avg (ms) | Overhead |
|------|----------|----------|
| Direct WAN | 20.4 | — |
| 2-path QUIC tunnel | 21.3 | +0.9 ms |

**TCP Throughput (iperf3 over tunnel):**

| Test | UL (Mbps) | DL (Mbps) |
|------|-----------|-----------|
| Direct (no VPN) | 104.0 | 107.5 |
| 1-path QUIC | 90.7 | 59.3 |
| 2-path QUIC | 90.0 | 76.7 |

**UDP Max Bandwidth (loss < 1%):**

| Test | UL (Mbps) | DL (Mbps) |
|------|-----------|-----------|
| 1-path QUIC | 110 | 100 |
| 2-path QUIC | 110 | 90 |

**Failover:** Zero downtime — throughput maintained when a path goes down and is restored.

**Stability:** 1-hour continuous test at 89 Mbps, zero memory growth (7.5 MB RSS).

Full results: [docs/benchmarks.md](docs/benchmarks.md)

## Project Structure

```
src/
  main.c           CLI argument parsing and entry point
  vpn_client.c     MASQUE client, QUIC connection, multipath, TUN I/O
  vpn_server.c     MASQUE server, address assignment, route advertisement
  path_mgr.c       Per-path UDP socket management (SO_BINDTODEVICE)
  tun.c            Linux TUN device creation, IP config, MTU
  addr_pool.c      CIDR-based IP address pool
  log.c            Logging (debug/info/warn/error)
scripts/
  run_test.sh              Smoke test (network namespaces)
  run_multipath_test.sh    Multipath + failover test (iperf3)
  vps_setup.sh             VPS server deployment
  vps_teardown.sh          VPS cleanup
  benchmark_report.py      Parse iperf3 JSON → Markdown report
third_party/
  xquic/           QUIC library (feature/masque branch) + BoringSSL
```

## Dependencies

| Library | Purpose |
|---------|---------|
| [xquic](https://github.com/alibaba/xquic) (feature/masque) | QUIC, HTTP/3, MASQUE CONNECT-IP |
| [BoringSSL](https://github.com/google/boringssl) | TLS 1.3 for QUIC |
| [libevent2](https://libevent.org/) | Event loop |

## RFCs

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) — QUIC
- [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) — QUIC Unreliable Datagram Extension
- [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) — HTTP Datagrams and the Capsule Protocol
- [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298) — MASQUE CONNECT-UDP
- [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) — MASQUE CONNECT-IP
- [RFC 9443](https://www.rfc-editor.org/rfc/rfc9443) — Multipath Extension for QUIC

## License

[Mozilla Public License 2.0](LICENSE)
