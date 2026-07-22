<div align="center">
  <h1>
  <img src="website/public/img/mqvpn-lockup-violet-light.svg" alt="mqvpn" width="400">
  </h1>
  <p><b>All your connections. One stronger connection.</b></p>
  <p>
    <a href="https://docs.mqvpn.org/">Documentation</a> |
    <a href="https://discord.gg/rjEqtBNtF">Discord community</a>
  </p>
</div>

mqvpn is an open-source VPN that combines multiple internet connections—such as Wi-Fi, cellular, Starlink, and multiple ISPs—for bandwidth aggregation and seamless failover.

## Table of Contents

<!--toc:start-->
- [Features](#features)
- [Installation](#installation)
  - [Server](#server)
  - [Client (deb package)](#client-deb-package)
  - [Windows client](#windows-client)
  - [macOS client](#macos-client)
  - [Verifying downloads](#verifying-downloads)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [INI config](#ini-config)
  - [JSON config](#json-config)
- [Schedulers](#schedulers)
- [Reorder buffer (datagram lane)](#reorder-buffer-datagram-lane)
- [Hybrid mode (TCP lane)](#hybrid-mode-tcp-lane)
- [systemd](#systemd)
- [Control API](#control-api)
- [Benchmarks](#benchmarks)
- [Architecture](#architecture)
- [Building](#building)
  - [Android SDK](#android-sdk)
- [Testing](#testing)
- [Usage](#usage)
- [Roadmap](#roadmap)
- [Protocol Standards](#protocol-standards)
- [Community](#community)
- [Disclaimer](#disclaimer)
- [Commercial Support](#commercial-support)
- [License](#license)
- [Acknowledgments](#acknowledgments)
<!--toc:end-->

## Features

- **Multipath** — Bind multiple interfaces (WiFi + LTE, dual ISP). Seamless failover and bandwidth aggregation via WLB scheduler.
- **Standards-based** — MASQUE CONNECT-IP (RFC 9484), no proprietary tunnel format.
- **Dual-stack** — IPv4 + IPv6 inside the tunnel.
- **Multi-Platform** — Available on Linux (server/client), Windows (client only), macOS (client only) and Android (client only) support.
- **PSK auth** — Pre-shared key over TLS 1.3.
- **DNS override** — Prevents DNS leaks. Uses `resolvectl` on systemd-resolved systems, falls back to resolv.conf.


## Installation

### Server

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh | sudo bash
```

This downloads the latest release, installs the binary, and generates a self-signed TLS certificate, auth key, and server config at `/etc/mqvpn/server.conf`. Add `--start` to start the server and register it for automatic startup on boot:

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh \
    | sudo bash -s -- --start
```

> **Note:** The self-signed certificate requires `--insecure` on the client. For production, replace with a trusted certificate (e.g. Let's Encrypt) and omit `--insecure`.

Options can be combined:

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh \
    | sudo bash -s -- --start --port 10020 --subnet 10.8.0.0/24
```

Uninstall: re-run the install script with `--uninstall`.
```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh \
    | sudo bash -s -- --uninstall
```

### Client (deb package)

Download the latest `.deb` from [Releases](https://github.com/mp0rta/mqvpn/releases/latest):

```bash
# Replace VERSION and ARCH as needed (e.g., 0.6.0, amd64)
curl -LO https://github.com/mp0rta/mqvpn/releases/latest/download/mqvpn_VERSION_ARCH.deb
sudo dpkg -i mqvpn_*.deb
```

### Windows client

Pre-built binaries are shipped for Windows amd64 and arm64. Download `mqvpn_<VERSION>_windows_<ARCH>.zip` from [Releases](https://github.com/mp0rta/mqvpn/releases/latest), extract, and follow the bundled `README.txt` (admin PowerShell required).

### macOS client

Pre-built binaries are shipped for Apple silicon (arm64). Download `mqvpn_<VERSION>_darwin_arm64.tar.gz` from [Releases](https://github.com/mp0rta/mqvpn/releases/latest), extract, and follow the bundled `README.txt` (sudo required).

### Verifying downloads

Release artifacts carry [build provenance attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
signed via Sigstore. To verify a download was built by this repository's
release workflow:

```bash
gh attestation verify mqvpn_<VERSION>_<ARCH>.deb --owner mp0rta
```

A `SHA256SUMS` file is also attached to each release.

## Quick Start

After installing the server and client (see [Installation](#installation)):

```bash
# Client (single path)
sudo mqvpn --mode client --server YOUR_SERVER:443 \
    --auth-key YOUR_AUTH_KEY --insecure

# Client (multipath)
sudo mqvpn --mode client --server YOUR_SERVER:443 \
    --auth-key YOUR_AUTH_KEY --path eth0 --path wlan0 --insecure

# Client (with DNS override)
sudo mqvpn --mode client --server YOUR_SERVER:443 \
    --auth-key YOUR_AUTH_KEY --dns 1.1.1.1 --dns 8.8.8.8 --insecure
```

> **Notes:**
> - On Linux, without `--path`, the client uses the default interface (single path); multipath requires two or more `--path` flags. On Windows, `--path` is always required (one or more); see `docs/windows_build.md`.
> - The server needs its listen port open for UDP (default: 443). All client traffic is routed through the tunnel.

## Configuration

Config files support both INI and JSON. CLI arguments override config values.
### INI config

```ini
# /etc/mqvpn/server.conf
[Interface]
Listen = 0.0.0.0:443
Subnet = 10.0.0.0/24
Subnet6 = 2001:db8:1::/112
# MTU = 1280                   # TUN MTU (1280–9000, default: auto = ~1382)

[TLS]
Cert = /etc/mqvpn/server.crt
Key = /etc/mqvpn/server.key       # TLS private key (PEM file)

[Auth]
Key = mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=   # PSK example (mqvpn --genkey)
User = alice:alice-secret
User = bob:bob-secret

[Multipath]
Scheduler = wlb
# CC = bbr2                     # Congestion control (bbr2|bbr|cubic|none, default: bbr2)
```

```ini
# /etc/mqvpn/client.conf
[Server]
Address = 203.0.113.1:443
# ServerName = vpn.example.com  # TLS SNI / cert verify name (default: use Address host)

[Auth]
Key = mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=

[Interface]
DNS = 1.1.1.1, 8.8.8.8
# MTU = 1280                   # TUN MTU (1280–9000, default: auto = ~1382)

[Multipath]
Scheduler = wlb
# CC = bbr2                     # Congestion control (bbr2|bbr|cubic|none, default: bbr2)
Path = eth0
Path = wlan0
```

### JSON config

The loader auto-detects JSON files (first non-space char is `{`).

Server example:

```json
{
    "mode": "server",
    "listen": "0.0.0.0:443",
    "subnet": "10.0.0.0/24",
    "subnet6": "fd00:abcd::/112",
    "cert_file": "/etc/mqvpn/server.crt",
    "key_file": "/etc/mqvpn/server.key",
    "auth_key": "legacy-fallback-key",
    "users": [
        { "name": "alice", "key": "alice-secret" },
        "bob:bob-secret"
    ],
    "max_clients": 64,
    "scheduler": "wlb",
    "cc": "bbr2"
}
```

Client example:

```json
{
    "mode": "client",
    "server_addr": "203.0.113.1:443",
    "tls_server_name": "vpn.example.com",
    "auth_key": "client-key",
    "insecure": false,
    "dns": ["1.1.1.1", "8.8.8.8"],
    "paths": ["eth0", "wlan0"],
    "reconnect": true,
    "reconnect_interval": 5,
    "kill_switch": false,
    "manage_routes": false,
    "scheduler": "wlb",
    "cc": "bbr2"
}
```

Notes:
- `users` is server-side auth and accepts either objects (`{"name","key"}`) or `"name:key"` strings.
- `auth_key` remains supported as a single legacy/global key.
- `mode` is optional if it can be inferred (`listen` implies server).
- `manage_routes` defaults to `true`; set it to `false` on router/embedded integrations where an external orchestrator owns the host routing table and mqvpn should only bring up the TUN.
- **[mqvpn-prometheus-exporter](https://github.com/mp0rta/mqvpn-prometheus-exporter) requires per-user keys.** Using mqvpn-prometheus-exporter, you can correct and visualize mqvpn metrics. If you use it, sharing a single `auth_key` across
  multiple clients works for the VPN data plane, but the control API
  surfaces those sessions as `user="(global)"` and the Prometheus exporter
  cannot distinguish them — series labels collide and the scrape is
  dropped. For multi-client deployments register each client under `users`
  (or via `add_user` over the control API) so each gets a distinct `user`
  label.

```bash
sudo mqvpn --config /etc/mqvpn/server.conf
sudo mqvpn --config /etc/mqvpn/client.conf
```

## Schedulers

| Scheduler       | TCP        | UDP        | Typical use                                     |
|-----------------|------------|------------|-------------------------------------------------|
| `minrtt`        | min RTT    | min RTT    | latency-first                                   |
| `wlb` (default) | flow pin   | unpinned   | general use; UDP packets distributed per-packet |
| `wlb_udp_pin`   | flow pin   | flow pin   | each UDP connection kept on a single path       |
| `backup_fec`    | redundant  | redundant  | resilience-first (requires XQC_ENABLE_FEC)      |

**Choosing wlb vs wlb_udp_pin:** Plain `wlb` distributes UDP packets across
paths per-packet, which gives better aggregate throughput when the inner
protocol tolerates reorder. Some inner UDP protocols, however, maintain their
own packet ordering and may treat reorder as packet loss — under asymmetric-RTT
paths this can slow them down and throughput drops. `wlb_udp_pin` keeps each
UDP connection on a single path to avoid that case. If you observe degraded UDP
throughput under `wlb`, try `wlb_udp_pin`; otherwise `wlb` is the better
default.

**Trade-off note (`wlb_udp_pin`):** the xquic WLB flow table is a fixed 4096-entry
open-addressed structure with 60s idle eviction. Workloads with very high
short-flow UDP churn (e.g. high-rate DNS, mDNS bursts) may evict longer-lived
inner flows under probe-region pressure. `wlb_udp_pin` is intended for tunnels
carrying a small-to-moderate set of long-lived inner UDP flows; high-churn UDP
profiles are better served by `wlb`.

## Reorder buffer (datagram lane)

A single inner UDP/QUIC flow striped across paths with different RTTs arrives
reordered, and many inner protocols treat reorder as loss and back off. The
reorder buffer holds datagrams in a short receive-side window and releases them
in order, so one inner flow can aggregate both paths — the datagram-lane
counterpart to what the [hybrid TCP stream lane](#hybrid-mode-tcp-lane) does for
TCP. Off by default; negotiated end-to-end (both client and server must enable
it) and a no-op when either side has it off.

```ini
[Reorder]
Enabled = on
MaxWaitMs = 50           # reorder window: hold out-of-order datagrams up to this long
CapPackets = 1024        # per-flow buffer cap (packets)

# Optional: target specific inner flows with a tuned preset
[ReorderRule]
Proto = udp
Port = 443
Profile = cellular_bond  # cellular_bond (wait=50ms, cap=1024) | fiber_lte (wait=50ms, cap=2048)
```

INI/JSON only (no CLI flag). Best on asymmetric-RTT path pairs (e.g. Wi-Fi +
LTE); for symmetric, loss-dominated paths leave it off. See
[docs/report/](docs/report/) for the parameter sweep and measured numbers.

## Hybrid mode (TCP lane)

Optionally terminates inner TCP connections locally (embedded lwIP) and relays them over a dedicated HTTP/3 request stream instead of the datagram CONNECT-IP path — trades small per-flow overhead for multipath TCP aggregation (see docs/report/ for measured numbers).

```
TUN packet
  │
  ▼
classifier (per packet: protocol + Tcp mode + tunnel-subnet carve-out)
  │
  ├─ TCP, Tcp=stream (or Tcp=auto with ≥2 active paths)
  │     └─▶ tcp lane (client-side lwIP) ─▶ HTTP/3 request stream ─▶ server egress connect()
  ├─ UDP (parseable)
  │     └─▶ datagram lane (existing reorder/STAMP path) ─▶ CONNECT-IP DATAGRAM
  └─ everything else (incl. TCP under Tcp=raw, or Tcp=auto with <2 active paths)
        └─▶ raw lane (existing, unchanged) ─▶ CONNECT-IP DATAGRAM
```

```ini
[Hybrid]
Enabled = true
Tcp = auto              # stream | raw | auto (per-flow: TCP lane once >=2 paths are active)
TcpMaxFlows = 256        # concurrent TCP-lane flow cap (client) / per-session cap (server)
EgressAllow = 10.0.5.0/24  # server: punch a hole through the default-deny egress ACL
```

Disabled by default; existing users see no behavior change. See
[docs/control-api.md §9](docs/control-api.md#9-hybrid-mode-configuration-keys)
for the full `[Hybrid]` config key reference and the `get_stats` counters
this mode exposes.

## systemd

```bash
# Server
sudo cp /etc/mqvpn/server.conf.example /etc/mqvpn/server.conf
sudo vi /etc/mqvpn/server.conf   # edit cert/key paths, auth key, etc.
sudo systemctl enable --now mqvpn-server

# Client (template — instance name maps to config file)
sudo cp /etc/mqvpn/client.conf.example /etc/mqvpn/client-home.conf
sudo vi /etc/mqvpn/client-home.conf   # edit server address, auth key, etc.
sudo systemctl enable --now mqvpn-client@home
```

## Control API

A running server can be managed at runtime over a TCP port using newline-delimited JSON.

Control API: see [docs/control-api.md](docs/control-api.md) for the full wire-protocol reference (all 8 commands, request/response schemas, error strings).

### Enable

The control API is **disabled by default**. Enable it via any of the following:

#### From `install.sh`

```bash
sudo bash install.sh --enable-control            # port 9090
sudo bash install.sh --enable-control 9091
```

#### From INI (`/etc/mqvpn/server.conf`)

```ini
[Control]
Listen = 127.0.0.1:9090
```

#### From JSON (`/etc/mqvpn/server.json`)

```json
{
  "control_listen": "127.0.0.1:9090"
}
```

#### From CLI (per-field override of the config file)

```bash
sudo mqvpn --mode server ... --control-port 9090

# Bind to a specific address (default: 127.0.0.1)
sudo mqvpn --mode server ... --control-port 9090 --control-addr 127.0.0.1
```

> **Security:** bind only to `127.0.0.1` (the default) unless the port is protected by a firewall or network policy. The control API has no authentication.

### Commands

#### Add a user

```bash
echo '{"cmd":"add_user","name":"carol","key":"carol-secret"}' | nc 127.0.0.1 9090
```
```json
{"ok":true}
```

Calling `add_user` with an existing name updates the key in place.

#### Remove a user

```bash
echo '{"cmd":"remove_user","name":"carol"}' | nc 127.0.0.1 9090
```
```json
{"ok":true}
```

#### List users

```bash
echo '{"cmd":"list_users"}' | nc 127.0.0.1 9090
```
```json
{"ok":true,"users":["alice","bob"]}
```

#### Get stats

```bash
echo '{"cmd":"get_stats"}' | nc 127.0.0.1 9090
```
```json
{"ok":true,"n_clients":2,"bytes_tx":983040,"bytes_rx":458752}
```

#### Error response

```json
{"ok":false,"error":"user not found"}
```

### From code (Python example)

```python
import socket, json

def ctrl(port, cmd):
    with socket.create_connection(("127.0.0.1", port)) as s:
        s.sendall((json.dumps(cmd) + "\n").encode())
        return json.loads(s.makefile().readline())

ctrl(9090, {"cmd": "add_user",    "name": "dave", "key": "dave-secret"})
ctrl(9090, {"cmd": "remove_user", "name": "dave"})
print(ctrl(9090, {"cmd": "list_users"}))   # {'ok': True, 'users': ['alice', 'bob']}
print(ctrl(9090, {"cmd": "get_stats"}))    # {'ok': True, 'n_clients': 1, ...}
```

## Benchmarks

Asymmetric dual-path (300M/10ms + 80M/30ms) via network namespaces. Full report: [`docs/benchmarks_netns.md`](docs/benchmarks_netns.md)

| Test | Result |
|------|--------|
| Failover | **0 downtime** |
| Bandwidth aggregation (WLB, 16 streams) | **319 Mbps** (84% of 380 Mbps theoretical) |
| WLB vs MinRTT | WLB **+21%** |

### Hybrid TCP-lane (v0.9.0)

Symmetric 2×100 Mbit / 25 ms, TCP uplink, `iperf3 -P {1,2,4,8,16}`, 3 reps. The hybrid TCP **stream lane** terminates TCP at the client and relays it in-order over a QUIC STREAM, so even a single flow aggregates both paths — where raw multipath (datagram tunneling) makes one flow back off on cross-path reorder. Hybrid ON reaches **~187 Mbps** (≈93 % of the 200 Mbps aggregate) at *every* stream count:

| WLB, streams (`-P`) | 1 | 2 | 4 | 8 | 16 |
|---|---|---|---|---|---|
| hybrid OFF (raw) | 96 | 177 | 167 | 177 | 178 |
| hybrid ON (lane) | **187** | 186 | 188 | 188 | 188 |
| gain | **+95 %** | +5 % | +12 % | +6 % | +6 % |

Charts: [MinRTT](bench_results/hybrid_mode/hybrid_mode_minrtt_1783350878.png) · [WLB](bench_results/hybrid_mode/hybrid_mode_wlb_1783350878.png) — bench: [`benchmarks/bench_hybrid_scheduler.sh`](benchmarks/bench_hybrid_scheduler.sh) · data: [`bench_results/hybrid_mode/`](bench_results/hybrid_mode/)

## Architecture

```
┌─────────────────┐                          ┌─────────────────┐
│   Application   │                          │    Internet     │
├─────────────────┤                          ├─────────────────┤
│   TUN (mqvpn0)  │                          │   TUN (mqvpn0)  │
├─────────────────┤                          ├─────────────────┤
│  MASQUE         │    HTTP Datagrams        │  MASQUE         │
│  CONNECT-IP     │◄──(Context ID = 0)──────►│  CONNECT-IP     │
├─────────────────┤                          ├─────────────────┤
│  Multipath QUIC │◄── Path A ──────────────►│  Multipath QUIC │
│                 │◄── Path B ──────────────►│                 │
├─────────────────┤                          ├─────────────────┤
│  UDP (eth0/wlan)│                          │   UDP (eth0)    │
└─────────────────┘                          └─────────────────┘
     Client                                      Server
```

## Building

Requirements: Linux, CMake 3.10+, GCC/Clang (C11), libevent 2.x

```bash
git clone --recurse-submodules https://github.com/mp0rta/mqvpn.git
cd mqvpn
./build.sh            # builds BoringSSL, xquic, and mqvpn
./build.sh --clean    # full rebuild
```

<details>
<summary>Manual build steps</summary>

```bash
# 1. Build BoringSSL
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
      -DXQC_ENABLE_BBR2=ON \
      -DXQC_ENABLE_FEC=ON \
      -DXQC_ENABLE_XOR=ON ..
make -j$(nproc)
cd ../../..

# 3. Build mqvpn
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DXQUIC_BUILD_DIR=../third_party/xquic/build ..
make -j$(nproc)
```

</details>

### Android SDK

```bash
scripts/build_android.sh --abi arm64-v8a    # cross-compile C libs
cd android && ./gradlew assembleDebug       # build SDK + demo app
```

<details>
<summary>Module structure</summary>

```
android/
├── sdk-native/    # JNI bridge → libmqvpn_jni.so
├── sdk-runtime/   # MqvpnPoller (tick-loop)
├── sdk-network/   # NetworkMonitor, PathBinder
├── sdk-core/      # MqvpnVpnService, MqvpnManager, TunnelBridge
└── app/           # Demo app (Jetpack Compose)
```
</details>

## Testing

```bash
cd build && ctest --output-on-failure       # C library unit tests
sudo scripts/ci_e2e/run_test.sh             # E2E (netns, requires root)
sudo scripts/run_multipath_test.sh          # multipath failover
cd android && ./gradlew test                # Android SDK unit tests
```

## Usage

```
mqvpn [--config PATH] --mode client|server [options]

  --server IP:PORT       Server address (client)
  --path IFACE           Multipath interface (repeatable)
  --auth-key KEY         PSK authentication
  --user NAME:KEY        Add server user credential (repeatable)
  --dns ADDR             DNS server (repeatable)
  --insecure             Accept untrusted certs (testing only)
  --listen BIND:PORT     Listen address (server, default: 0.0.0.0:443)
  --subnet CIDR          Client IPv4 pool (server)
  --subnet6 CIDR         Client IPv6 pool (server)
  --scheduler minrtt|wlb|wlb_udp_pin|backup_fec
                         Multipath scheduler (default: wlb)
  --cc bbr2|bbr|cubic|none
                         Congestion control algorithm (default: bbr2)
  --control-port PORT    TCP port for JSON control API (server)
  --control-addr ADDR    Bind address for control API (default: 127.0.0.1)
  --genkey               Generate PSK and exit
  --help                 Show all options
```

## Roadmap

- [x] v0.1.0 — TLS verification, WLB scheduler, multi-client, PSK auth, DNS, config file
- [x] v0.2.0 — Reconnection, kill switch, IPv6, ICMP PTB, systemd service
- [x] v0.3.0 — libmqvpn (sans-I/O), Android Kotlin SDK, network detection
- [x] Per-client token auth
- [x] resolvectl DNS support (with resolv.conf fallback)
- [x] v0.4.0 — Experimental backup_fec scheduler, Windows client, server control API support
- [ ] netlink API for routing (replace fork+exec of `ip` command)
- [ ] Performance: GSO/GRO, sendmmsg, native Android I/O
- [ ] Interop testing (masque-go, QUICHE)

## Protocol Standards
mqvpn is designed to comply with the following RFCs as much as possible.

| Protocol | Spec |
|----------|------|
| MASQUE CONNECT-IP | [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) |
| HTTP Datagrams | [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) |
| QUIC Datagrams | [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) |
| Multipath QUIC | [draft-ietf-quic-multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) |
| HTTP/3 | [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) |

## Community

Welcome to join the [mqvpn community on Discord](https://discord.gg/rjEqtBNtF) to ask questions, discuss use cases, share feedback, and contribute to the project.

## Disclaimer

mqvpn is licensed under the Apache License 2.0 and is provided **"AS IS"**, without warranties or conditions of any kind.

Use of mqvpn is at your own risk. Users are solely responsible for validating its suitability, security, and operational safety, especially in production or commercial environments.

## Commercial Support

If you need commercial support, integration consulting, managed deployments, or SLA inquiries, contact contact@mp0rta.dev.

You can also contact me via Discord.


## License

Apache-2.0

Copyright (c) 2026 mp0rta

The "mqvpn" name and logo are not covered by the license — see
[TRADEMARK.md](TRADEMARK.md).

## Acknowledgments

- [XQUIC](https://github.com/alibaba/xquic) by Alibaba
- IETF QUIC and MASQUE working groups
