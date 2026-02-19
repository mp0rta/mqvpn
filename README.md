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

- **Seamless failover** — If one path goes down, the tunnel continues on another without reconnecting (Multipath QUIC).
- **Multiple network paths** — Bind to two or more Linux interfaces (e.g. two ISP lines, WiFi + LTE) via XQUIC's Multipath QUIC.
- **Standards-based tunnel** — MASQUE CONNECT-IP (RFC 9484) with HTTP Datagrams (RFC 9297) over QUIC DATAGRAM frames (RFC 9221). No proprietary tunnel format.
- **HTTP/3-native** — Runs over UDP/443 using standardized HTTP/3 + QUIC DATAGRAM mechanisms.

## Quick Start

```bash
# Build (see "Building" section below for full steps including BoringSSL and xquic)
git clone --recurse-submodules https://github.com/mp0rta/mqvpn.git
cd mqvpn && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release \
      -DXQUIC_BUILD_DIR=../third_party/xquic/build
make -j$(nproc)

# Server
sudo ./mqvpn --mode server --listen 0.0.0.0:443 \
    --cert server.crt --key server.key

# Client (single path)
sudo ./mqvpn --mode client --server yourserver.com:443

# Client (multipath — two interfaces)
sudo ./mqvpn --mode client --server yourserver.com:443 \
    --path eth0 --path eth1
```

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
- XQUIC's MinRTT scheduler selects the lowest-latency path per packet
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
      -DSSL_PATH=../third_party/boringssl ..
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
# Generate self-signed certificate (for testing)
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout certs/server.key -out certs/server.crt \
    -days 365 -nodes -subj "/CN=mqvpn"

# Enable NAT
sudo sysctl -w net.ipv4.ip_forward=1
IFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+')
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o $IFACE -j MASQUERADE
sudo iptables -A FORWARD -s 10.0.0.0/24 -j ACCEPT
sudo iptables -A FORWARD -d 10.0.0.0/24 -j ACCEPT

# Start server
sudo ./build/mqvpn --mode server --listen 0.0.0.0:443 \
    --subnet 10.0.0.0/24 --cert certs/server.crt --key certs/server.key
```

With this setup, the client's default route points through the mqvpn tunnel. All traffic flows: client app → TUN (mqvpn0) → QUIC tunnel → server → NAT → internet. The client automatically configures routing so that only the server address bypasses the tunnel.

## Usage

```
mqvpn --mode client|server [options]

Client options:
  --server HOST:PORT     Server address
  --path IFACE           Network interface (repeatable, for multipath)
  --insecure             Skip TLS certificate verification (self-signed certs work without this)
  --tun-name NAME        TUN device name (default: mqvpn0)
  --log-level LEVEL      debug|info|warn|error (default: info)

Server options:
  --listen BIND:PORT     Listen address (default: 0.0.0.0:443)
  --subnet CIDR          Client IP pool (default: 10.0.0.0/24)
  --cert PATH            TLS certificate file
  --key PATH             TLS private key file
  --log-level LEVEL      debug|info|warn|error (default: info)
```

## Roadmap

### v0.1.0 — First public release
- [x] TLS certificate verification by default (self-signed certs accepted; `--insecure` disables all checks)
- [x] Tunnel source IP validation (prevent IP spoofing through the tunnel)
- [x] CI with GitHub Actions (build + netns smoke tests)

### v0.2.0 — Multi-client & auth
- [ ] Multi-client support (per-connection session management)
- [ ] Pre-shared key / token authentication

### Future
- [ ] WiFi + LTE multipath testing
- [ ] Android client (VpnService + WiFi/LTE handover)
- [ ] IPv6 support
- [ ] Replace `ip` command with netlink API
- [ ] Performance optimization (GSO/GRO, io_uring, batch send)
- [ ] Interop testing with other MASQUE implementations (masque-go, Google QUICHE)
- [ ] Bandwidth aggregation scheduler (try weighted round-robin by cwnd / BBR bandwidth estimate)

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
