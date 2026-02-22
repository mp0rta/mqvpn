# mqvpn

L3VPN built on a [fork of XQUIC](https://github.com/mp0rta/xquic/tree/feature/masque).
It implements [MASQUE CONNECT-IP (RFC 9484)](https://www.rfc-editor.org/rfc/rfc9484) over HTTP/3 using
[HTTP Datagrams (RFC 9297)](https://www.rfc-editor.org/rfc/rfc9297) / [QUIC DATAGRAM frames (RFC 9221)](https://www.rfc-editor.org/rfc/rfc9221).
Optionally, it can use XQUIC's Multipath QUIC (I-D: [draft-ietf-quic-multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/))
to keep a single tunnel alive across multiple interfaces.
This is an independent personal project focused on an end-to-end standards-based implementation.

## Features

- **Multi-client support** — Multiple clients connect simultaneously; IP-offset indexed session table for O(1) routing.
- **PSK authentication** — Pre-shared key via `authorization: Bearer` header over TLS 1.3-encrypted QUIC.
- **Seamless failover** — If one path goes down, the tunnel continues on another without reconnecting (Multipath QUIC).
- **Multiple network paths** — Bind to two or more Linux interfaces (e.g. two ISP lines, WiFi + LTE) via XQUIC's Multipath QUIC.
- **Bandwidth aggregation** — Implemented a bandwidth-aggregation scheduler for multipath QUIC datagrams (WLB), combining flow-affinity WRR with LATE-based bandwidth estimates.(implemented in our XQUIC fork)
  - [Performance comparison: WLB vs. MinRTT scheduler](docs/benchmarks_netns.md#2-bandwidth-aggregation--wlb-vs-minrtt)
- **Configuration file** — INI-style config file for all options; CLI arguments override config values.
- **DNS override** — Client-side `/etc/resolv.conf` management with automatic backup and restore. Prevents DNS leak by routing all queries through the tunnel.
- **Standards-based tunnel** — MASQUE CONNECT-IP (RFC 9484) with HTTP Datagrams (RFC 9297) over QUIC DATAGRAM frames (RFC 9221). No proprietary tunnel format.

## Quick Start

```bash
# Build (BoringSSL + xquic + mqvpn)
git clone --recurse-submodules https://github.com/mp0rta/mqvpn.git
cd mqvpn
./build.sh

# Server (generates certs, configures NAT, starts server)
sudo scripts/start_server.sh
# → Generated auth key: mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=

# Or with custom listen address and tunnel subnet (client IP pool)
sudo scripts/start_server.sh --listen 0.0.0.0:4433 --subnet 10.0.0.0/24

# Client (single path)
sudo ./build/mqvpn --mode client --server yourserver.com:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=

# Client (multipath — two interfaces)
sudo ./build/mqvpn --mode client --server yourserver.com:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4= \
    --path eth0 --path wlan0

# Client (with DNS override)
sudo ./build/mqvpn --mode client --server yourserver.com:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4= \
    --dns 1.1.1.1 --dns 8.8.8.8
```

`start_server.sh` generates a self-signed certificate, configures NAT/forwarding, and starts the server. The client's default route points through the tunnel — all traffic flows: client app → TUN (mqvpn0) → QUIC tunnel → server → NAT → internet.

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

Asymmetric dual-path test (Path A: 300M/10ms, Path B: 80M/30ms) using Linux network namespaces.
Full report: [`docs/benchmarks_netns.md`](docs/benchmarks_netns.md)

| Test | Result |
|------|--------|
| Failover (Path A down) | **0 downtime**, instant shift to Path B |
| Failover (Path B down) | **0 downtime**, barely noticeable dip |
| Bandwidth aggregation (WLB, 16 streams) | **319 Mbps** — 84% of theoretical max (380 Mbps) |
| WLB vs MinRTT (16 streams) | WLB **+21%** over MinRTT |

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
- libevent 2.x

### Build Steps

```bash
git clone --recurse-submodules https://github.com/mp0rta/mqvpn.git
cd mqvpn
./build.sh            # builds BoringSSL, xquic, and mqvpn
./build.sh --clean    # full rebuild from scratch
```

The build script uses incremental builds — only recompiles changed files on subsequent runs.

<details>
<summary>Manual build steps</summary>

```bash
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

</details>

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
  --server HOST:PORT        Server address (IPv4 only; IPv6 planned for v0.2.0)
  --path IFACE              Network interface for multipath (repeatable)
  --auth-key KEY            PSK for authentication
  --dns ADDR                DNS server (repeatable, max 4)
  --insecure                Accept untrusted certs (testing only)

Server:
  --listen BIND:PORT        Listen address (default: 0.0.0.0:443)
  --subnet CIDR             Client IP pool (default: 10.0.0.0/24)
  --cert PATH               TLS certificate file
  --key PATH                TLS private key file
  --auth-key KEY            PSK for client authentication
  --max-clients N           Max concurrent clients (default: 64)
```

### Security Notes

- By default, TLS certificate verification is strict — self-signed or untrusted CA certificates are rejected. Use a publicly trusted CA certificate (e.g. Let's Encrypt) for production.
- `--insecure` accepts certificates that fail verification (self-signed, unknown CA, etc.) and is intended for local/testing use only.
- `--auth-key` is required for server mode. The server refuses to start without it. Generate one with `mqvpn --genkey`.
- PSK authentication protects against unauthorized connections. The key is transmitted over QUIC's TLS 1.3 channel, so it is never exposed in plaintext on the wire.

## Testing

```bash
# Unit tests
cd build && ctest --output-on-failure

# Integration test (requires root, uses network namespaces)
sudo scripts/run_test.sh

# Multipath integration test (2 paths, failover, recovery)
sudo scripts/run_multipath_test.sh
```

## Roadmap

### v0.1.0 — First public release
- [x] Strict TLS certificate verification by default (`--insecure` to accept untrusted certs)
- [x] Tunnel source IP validation (prevent IP spoofing through the tunnel)
- [x] CI with GitHub Actions (build + netns smoke tests)
- [x] Bandwidth aggregation scheduler (WLB: LATE-weighted flow-affinity WRR with BBR bandwidth estimates)
- [x] Multi-client support (IP-offset indexed session table, O(1) routing)
- [x] Pre-shared key authentication (Bearer token over HTTP/3 Extended CONNECT)
- [x] Client-side DNS configuration (resolv.conf management with backup/restore)
- [x] INI-style configuration file (`mqvpn --config /etc/mqvpn/client.conf`)
- [x] `mqvpn --genkey` for PSK generation

### v0.2.0 — Always-on & operational hardening
- [ ] Automatic reconnection (reconnect on connection drop / network change)
- [ ] Kill switch (prevent traffic leaking outside the tunnel)
- [ ] systemd service unit (`mqvpn-server.service`, `mqvpn-client@.service`)
- [ ] Let's Encrypt / ACME integration for TLS certificates
- [ ] IPv6 support

### Future
- [ ] Per-client token authentication
- [ ] WiFi + LTE multipath testing
- [ ] Android client (VpnService + WiFi/LTE handover)
- [ ] resolvectl integration (systemd-resolved environments)
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
