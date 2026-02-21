# mqvpn

L3VPN built on a [fork of XQUIC](https://github.com/mp0rta/xquic/tree/feature/masque).
It implements [MASQUE CONNECT-IP (RFC 9484)](https://www.rfc-editor.org/rfc/rfc9484) over HTTP/3 using
[HTTP Datagrams (RFC 9297)](https://www.rfc-editor.org/rfc/rfc9297) / [QUIC DATAGRAM frames (RFC 9221)](https://www.rfc-editor.org/rfc/rfc9221).
Optionally, it can use XQUIC's Multipath QUIC (I-D: [draft-ietf-quic-multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/))
to keep a single tunnel alive across multiple interfaces.
This is an independent personal project focused on an end-to-end standards-based implementation.

<!-- TODO: 30-second demo GIF here -->
<!-- ![Failover demo](docs/demo/failover.gif) -->

## Features

- **Multi-client support** — Multiple clients connect simultaneously; IP-offset indexed session table for O(1) routing.
- **PSK authentication** — Pre-shared key via `authorization: Bearer` header over TLS 1.3-encrypted QUIC.
- **Seamless failover** — If one path goes down, the tunnel continues on another without reconnecting (Multipath QUIC).
- **Multiple network paths** — Bind to two or more Linux interfaces (e.g. two ISP lines, WiFi + LTE) via XQUIC's Multipath QUIC.
- **Bandwidth aggregation** — WLB scheduler combines bandwidth across paths using flow-affinity WRR with LATE-weighted estimates.
- **Configuration file** — INI-style config file for all options; CLI arguments override config values.
- **DNS override** — Client-side `/etc/resolv.conf` management with automatic backup and restore.
- **Standards-based tunnel** — MASQUE CONNECT-IP (RFC 9484) with HTTP Datagrams (RFC 9297) over QUIC DATAGRAM frames (RFC 9221). No proprietary tunnel format.

## Quick Start

```bash
# Build (see "Building" section below for full steps including BoringSSL and xquic)
git clone --recurse-submodules https://github.com/mp0rta/mqvpn.git
cd mqvpn && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release \
      -DXQUIC_BUILD_DIR=../third_party/xquic/build
make -j$(nproc)

# Generate a PSK
./mqvpn --genkey
# → e.g. mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=

# Server
sudo ./mqvpn --mode server --listen 0.0.0.0:443 \
    --cert server.crt --key server.key \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=

# Client (single path)
sudo ./mqvpn --mode client --server yourserver.com:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=

# Client (multipath — two interfaces)
sudo ./mqvpn --mode client --server yourserver.com:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4= \
    --path eth0 --path wlan0

# Client (with DNS override)
sudo ./mqvpn --mode client --server yourserver.com:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4= \
    --dns 1.1.1.1 --dns 8.8.8.8
```

## Configuration File

Instead of CLI flags, you can use an INI-style config file. CLI arguments override config file values.

**Server (`/etc/mqvpn/server.conf`):**

```ini
[Interface]
TunName = mqvpn0
Listen = 0.0.0.0:443
Subnet = 10.0.0.0/24
LogLevel = info

[TLS]
Cert = /etc/mqvpn/server.crt
Key = /etc/mqvpn/server.key

[Auth]
Key = mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=
MaxClients = 64
```

**Client (`/etc/mqvpn/client.conf`):**

```ini
[Server]
Address = yourserver.com:443
Insecure = false

[Auth]
Key = mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=

[Interface]
TunName = mqvpn0
DNS = 1.1.1.1, 8.8.8.8
LogLevel = info

[Multipath]
Scheduler = wlb
Path = eth0
Path = wlan0
```

**Start with config file:**

```bash
sudo mqvpn --config /etc/mqvpn/server.conf
sudo mqvpn --config /etc/mqvpn/client.conf
```

Mode is auto-detected from the config (`[Interface] Listen` → server, `[Server] Address` → client).

## Benchmarks

Measured over direct WAN between a Tokyo client (2 NICs: 10G + 1G) and an EC2 c6in.large instance.
Full report: [`docs/benchmarks_v2.md`](docs/benchmarks_v2.md)

| Test | UL | DL |
|------|----|----|
| 1-path mqvpn (TCP) | 361 Mbps | 475 Mbps |
| 2-path mqvpn (TCP) | 419 Mbps | 342 Mbps |
| 1-path mqvpn (UDP, loss < 1%) | 700 Mbps | 700 Mbps |
| 2-path mqvpn (UDP, loss < 1%) | 600 Mbps | 600 Mbps |
| Failover (primary path down) | **PASS** — zero downtime | — |
| Stability (1 h) | 382 Mbps avg | 482 Mbps avg |

## Architecture

```
┌─────────────────┐                          ┌─────────────────┐
│   Application   │                          │    Internet     │
│  (TCP/UDP/any)  │                          │                 │
├─────────────────┤                          ├─────────────────┤
│   TUN device    │                          │   TUN device    │
│   (mqvpn0)      │                          │   (mqvpn0)      │
├─────────────────┤                          ├─────────────────┤
│  MASQUE         │    HTTP Datagrams        │  MASQUE         │
│  CONNECT-IP     │◄──(Context ID = 0)──────►│  CONNECT-IP     │
│  (RFC 9484)     │    full IP packets       │  (RFC 9484)     │
├─────────────────┤                          ├─────────────────┤
│  HTTP/3         │    Extended CONNECT      │  HTTP/3         │
│                 │    :protocol=connect-ip  │                 │
├─────────────────┤                          ├─────────────────┤
│  Multipath QUIC │◄── Path A ──────────────►│  QUIC           │
│  (MP-QUIC)      │◄── Path B ──────────────►│  (single socket)│
├─────────────────┤                          ├─────────────────┤
│  UDP  │  UDP    │                          │      UDP        │
│ eth0  │ eth1    │                          │     eth0        │
└───────┴─────────┘                          └─────────────────┘
     Client                                      Server
```

Key design points:
- IP packets are carried as HTTP Datagrams with Context ID set to zero (full IP header, no parsing needed)
- Server uses a single UDP socket; XQUIC can receive packets from multiple peer addresses on the same connection
- XQUIC's multipath scheduler (MinRTT or WLB) selects paths; WLB uses flow-affinity WRR for bandwidth aggregation
- Failover is handled at the QUIC transport layer by XQUIC — mqvpn just provides sockets and forwards packets

## How It Works

The [xquic fork](https://github.com/mp0rta/xquic/tree/feature/masque) adds MASQUE CONNECT-IP (RFC 9484) to XQUIC's QUIC/HTTP3 stack. mqvpn is the VPN application layer on top: TUN devices, routes, IP address assignment, and server-side NAT.

On connection, the client sends an HTTP/3 Extended CONNECT request with `:protocol=connect-ip`. The server replies with control capsules (`ADDRESS_ASSIGN`, `ROUTE_ADVERTISEMENT`). mqvpn configures the TUN device and routing table with the assigned IP, then enters a forwarding loop: TUN reads become HTTP Datagrams, incoming datagrams get written back to the TUN.

For multipath, mqvpn creates per-interface UDP sockets and registers them as additional QUIC paths via `xqc_conn_create_path()`. XQUIC handles path validation, packet scheduling, and failover transparently.

The server side is simple: one UDP socket, one TUN device, NAT via iptables. It does not need to know about multipath — XQUIC sees packets arriving from different source addresses on the same connection.

## Building

### Requirements

- Linux (kernel 3.x+ for TUN support)
- CMake 3.22+ (required for BoringSSL build)
- GCC or Clang (C11)
- Go (latest stable; needed when running BoringSSL tests)
- libevent 2.x

### Build Steps

```bash
git clone --recurse-submodules https://github.com/mp0rta/mqvpn.git
cd mqvpn

# 1. Build BoringSSL (required by xquic)
cd third_party/xquic/third_party/boringssl
mkdir -p build && cd build
cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..
make -j$(nproc) ssl crypto
cd ../../../../..

# 2. Build xquic
cd third_party/xquic
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DSSL_TYPE=boringssl \
      -DSSL_PATH=../third_party/boringssl \
      -DXQC_ENABLE_BBR2=ON ..
make -j$(nproc)
cd ../../..

# 3. Build mqvpn
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DXQUIC_BUILD_DIR=../third_party/xquic/build ..
make -j$(nproc)
```

### Server Setup

```bash
# Generate certs, configure NAT, and start server
sudo scripts/start_server.sh

# Or with custom options
sudo scripts/start_server.sh --listen 0.0.0.0:4433 --subnet 10.0.0.0/24
```

With this setup, the client's default route points through the mqvpn tunnel. All traffic flows: client app → TUN (mqvpn0) → QUIC tunnel → server → NAT → internet. The client automatically configures routing so that only the server address bypasses the tunnel.

## Usage

```
mqvpn [--config PATH] --mode client|server [options]

General:
  --config PATH             INI config file (CLI args override config values)
  --mode client|server      Operating mode (auto-detected from config)
  --genkey                  Generate a random PSK and exit
  --scheduler minrtt|wlb    Multipath scheduler (default: wlb)
  --log-level LEVEL         debug|info|warn|error (default: info)
  --tun-name NAME           TUN device name (default: mqvpn0)
  --help                    Show help

Client:
  --server HOST:PORT        Server address
  --path IFACE              Network interface for multipath (repeatable)
  --auth-key KEY            PSK for authentication
  --dns ADDR                DNS server (repeatable, max 4)
  --insecure                Disable TLS cert verification (testing only)

Server:
  --listen BIND:PORT        Listen address (default: 0.0.0.0:443)
  --subnet CIDR             Client IP pool (default: 10.0.0.0/24)
  --cert PATH               TLS certificate file
  --key PATH                TLS private key file
  --auth-key KEY            PSK for client authentication
  --max-clients N           Max concurrent clients (default: 64)
```

### Security Notes

- `--insecure` disables certificate verification and is intended for local/testing use only. For production, use a publicly trusted CA certificate.
- PSK authentication protects against unauthorized connections. The key is transmitted over QUIC's TLS 1.3 channel, so it is never exposed in plaintext on the wire.
- When `--auth-key` is not set on the server, any client can connect without authentication.

## Testing

```bash
# Unit tests
cc -o tests/test_config tests/test_config.c src/config.c src/log.c -Isrc && ./tests/test_config
cc -o tests/test_auth tests/test_auth.c src/auth.c src/log.c -Isrc && ./tests/test_auth
cc -o tests/test_session tests/test_session.c src/addr_pool.c src/log.c -Isrc && ./tests/test_session
cc -o tests/test_dns tests/test_dns.c src/dns.c src/log.c -Isrc && ./tests/test_dns
cc -o tests/test_flow_sched tests/test_flow_sched.c src/flow_sched.c src/log.c -Isrc && ./tests/test_flow_sched

# Integration test (requires root, uses network namespaces)
sudo scripts/run_test.sh

# Multipath integration test (2 paths, failover, recovery)
sudo scripts/run_multipath_test.sh
```

## Roadmap

### v0.1.0 — First public release
- [x] TLS certificate verification by default (self-signed certs accepted; `--insecure` disables all checks)
- [x] Tunnel source IP validation (prevent IP spoofing through the tunnel)
- [x] CI with GitHub Actions (build + netns smoke tests)
- [x] Bandwidth aggregation scheduler (WLB: LATE-weighted flow-affinity WRR with BBR bandwidth estimates)

### v0.2.0 — Multi-client, auth, DNS & config file
- [x] Multi-client support (IP-offset indexed session table, O(1) routing)
- [x] Pre-shared key authentication (Bearer token over HTTP/3 Extended CONNECT)
- [x] Client-side DNS configuration (resolv.conf management with backup/restore)
- [x] INI-style configuration file (`mqvpn --config /etc/mqvpn/client.conf`)
- [x] `mqvpn --genkey` for PSK generation

### Future
- [ ] Per-client token authentication
- [ ] WiFi + LTE multipath testing
- [ ] Android client (VpnService + WiFi/LTE handover)
- [ ] IPv6 support
- [ ] Replace `ip` command with netlink API
- [ ] Performance optimization (GSO/GRO, io_uring, batch send)
- [ ] Interop testing with other MASQUE implementations (masque-go, Google QUICHE)
- [ ] DATAGRAM Capsule fallback (RFC 9297 stream-based carriage when QUIC DATAGRAMs are unavailable)

## Protocol Standards

| Protocol | Specification | Implemented by |
|----------|--------------|----------------|
| MASQUE CONNECT-IP | [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) | xquic fork |
| HTTP Datagrams | [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) | xquic fork |
| QUIC Datagrams | [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) | XQUIC |
| Multipath QUIC | [draft-ietf-quic-multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) | XQUIC |
| HTTP/3 | [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) | XQUIC |

## License

mqvpn is licensed under [Apache-2.0](LICENSE).
Copyright (c) 2026 github.com/mp0rta.

mqvpn uses a [fork of XQUIC](https://github.com/mp0rta/xquic/tree/feature/masque) (Apache-2.0) as a git submodule. The fork adds MASQUE CONNECT-IP (RFC 9484) and HTTP Datagrams (RFC 9297) on top of XQUIC's QUIC, HTTP/3, and Multipath QUIC transport. Plans to contribute the MASQUE implementation upstream.

## Acknowledgments

- [XQUIC](https://github.com/alibaba/xquic) — QUIC, HTTP/3, and Multipath QUIC library by Alibaba
- IETF QUIC and MASQUE working groups for the protocol specifications
