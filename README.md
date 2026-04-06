# mqvpn

Multipath QUIC VPN using [MASQUE CONNECT-IP (RFC 9484)](https://www.rfc-editor.org/rfc/rfc9484) over [HTTP Datagrams (RFC 9297)](https://www.rfc-editor.org/rfc/rfc9297) / [QUIC DATAGRAMs (RFC 9221)](https://www.rfc-editor.org/rfc/rfc9221), built on a [fork of XQUIC](https://github.com/mp0rta/xquic/tree/feature/masque) with [Multipath QUIC](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/).

## Features

- **Multipath** — Bind multiple interfaces (WiFi + LTE, dual ISP). Seamless failover and bandwidth aggregation via WLB scheduler.
- **Standards-based** — MASQUE CONNECT-IP (RFC 9484), no proprietary tunnel format.
- **Dual-stack** — IPv4 + IPv6 inside the tunnel.
- **Android SDK** — Kotlin SDK via JNI. Apps implement `onCreateTun()` and `onVpnStateChanged()`.
- **PSK auth** — Pre-shared key over TLS 1.3.
- **DNS override** — Prevents DNS leak by routing queries through the tunnel.

## Quick Start

```bash
git clone --recurse-submodules https://github.com/mp0rta/mqvpn.git
cd mqvpn && ./build.sh

# Server
sudo scripts/start_server.sh
# → Generated auth key example: mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=

# Client (single path)
sudo ./build/mqvpn --mode client --server 203.0.113.1:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4= --insecure

# Client (multipath)
sudo ./build/mqvpn --mode client --server 203.0.113.1:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4= --path eth0 --path wlan0 --insecure

# Client (with DNS override)
sudo ./build/mqvpn --mode client --server 203.0.113.1:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4= --dns 1.1.1.1 --dns 8.8.8.8 --insecure

# Server (dual-stack — IPv4 + IPv6)
sudo scripts/start_server.sh --subnet 10.0.0.0/24 --subnet6 fd00:abcd::/112
```

`start_server.sh` generates a self-signed certificate, configures NAT/forwarding, and starts the server. For dual-stack, `--subnet6` enables IPv6 inside the tunnel — the server automatically configures IPv6 forwarding and NAT66. No special client flags needed.

> **Notes:**
> - `--insecure` skips TLS certificate verification (self-signed certs). For production, use a trusted certificate (e.g. Let's Encrypt) and omit `--insecure`.
> - Without `--path`, the client uses the default interface (single path). Multipath requires two or more `--path` flags.
> - The server needs its listen port open for UDP (default: 443, configurable with `--listen`). All client traffic is routed through the tunnel (default route via TUN device).
> - Generate an auth key with `mqvpn --genkey`, or let `start_server.sh` generate one automatically.

## Configuration

Config files support both INI and JSON. CLI arguments override config values.

```ini
# /etc/mqvpn/server.conf
[Interface]
Listen = 0.0.0.0:443
Subnet = 10.0.0.0/24
Subnet6 = 2001:db8:1::/112

[TLS]
Cert = /etc/mqvpn/server.crt
Key = /etc/mqvpn/server.key       # TLS private key (PEM file)

[Auth]
Key = mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=   # PSK example (mqvpn --genkey)
User = alice:alice-secret
User = bob:bob-secret

[Multipath]
Scheduler = wlb
```

```ini
# /etc/mqvpn/client.conf
[Server]
Address = 203.0.113.1:443

[Auth]
Key = mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=

[Interface]
DNS = 1.1.1.1, 8.8.8.8

[Multipath]
Scheduler = wlb
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
    "scheduler": "wlb"
}
```

Client example:

```json
{
    "mode": "client",
    "server_addr": "203.0.113.1:443",
    "auth_key": "client-key",
    "insecure": true,
    "dns": ["1.1.1.1", "8.8.8.8"],
    "paths": ["eth0", "wlan0"],
    "reconnect": true,
    "reconnect_interval": 5,
    "kill_switch": false,
    "scheduler": "wlb"
}
```

Notes:
- `users` is server-side auth and accepts either objects (`{"name","key"}`) or `"name:key"` strings.
- `auth_key` remains supported as a single legacy/global key.
- `mode` is optional if it can be inferred (`listen` implies server).

```bash
sudo mqvpn --config /etc/mqvpn/server.conf
sudo mqvpn --config /etc/mqvpn/client.conf
```

## systemd

```bash
# Server
sudo cp systemd/server.conf.example /etc/mqvpn/server.conf
# JSON alternative
sudo cp systemd/server.json.example /etc/mqvpn/server.json
sudo systemctl enable --now mqvpn-server

# Client (template — instance name maps to config file)
sudo cp systemd/client.conf.example /etc/mqvpn/client-home.conf
# JSON alternative
sudo cp systemd/client.json.example /etc/mqvpn/client-home.json
sudo systemctl enable --now mqvpn-client@home
```

## Control API

A running server can be managed at runtime over a TCP port using newline-delimited JSON.

### Enable

```bash
# CLI
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
  --scheduler minrtt|wlb Multipath scheduler (default: wlb)
  --control-port PORT    TCP port for JSON control API (server)
  --control-addr ADDR    Bind address for control API (default: 127.0.0.1)
  --genkey               Generate PSK and exit
  --help                 Show all options
```

## Roadmap

- [x] v0.1.0 — TLS verification, WLB scheduler, multi-client, PSK auth, DNS, config file
- [x] v0.2.0 — Reconnection, kill switch, IPv6, ICMP PTB, systemd service
- [x] v0.3.0 — libmqvpn (sans-I/O), Android Kotlin SDK, network detection
- [ ] Per-client token auth
- [ ] resolvectl / netlink API
- [ ] Performance: GSO/GRO, sendmmsg, native Android I/O
- [ ] Interop testing (masque-go, QUICHE)

## Protocol Standards

| Protocol | Spec |
|----------|------|
| MASQUE CONNECT-IP | [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) |
| HTTP Datagrams | [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) |
| QUIC Datagrams | [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) |
| Multipath QUIC | [draft-ietf-quic-multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) |
| HTTP/3 | [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) |

## Disclaimer

mqvpn is licensed under the Apache License 2.0 and is provided **"AS IS"**, without warranties or conditions of any kind.

Use of mqvpn is at your own risk. Users are solely responsible for validating its suitability, security, and operational safety, especially in production or commercial environments.

## License

Apache-2.0

Copyright (c) 2026 mp0rta

## Acknowledgments

- [XQUIC](https://github.com/alibaba/xquic) by Alibaba
- IETF QUIC and MASQUE working groups
