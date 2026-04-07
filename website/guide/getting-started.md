# Getting Started

mqvpn is a multipath QUIC VPN that uses MASQUE CONNECT-IP (RFC 9484) for standards-based IP tunneling over Multipath QUIC.

## Prerequisites

- Linux (kernel 3.x+ with TUN support)
- Git
- CMake 3.10+
- GNU Make
- GCC or Clang (C11)
- libevent 2.x
- Network access for the first build (BoringSSL is cloned from GitHub)

## Quick Start

### 1. Build

```bash
git clone --recurse-submodules https://github.com/mp0rta/mqvpn.git
cd mqvpn && ./build.sh
```

See [Building](./building) for detailed instructions and other platforms.

### 2. Start the Server

```bash
sudo scripts/start_server.sh
# → Generated auth key example: mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=
```

`start_server.sh` generates a self-signed certificate, configures NAT/forwarding, and starts the server.

::: warning
The server needs its listen port open for UDP (default: 443, configurable with `--listen`). All client traffic is routed through the tunnel (default route via TUN device).
:::

For dual-stack (IPv4 + IPv6):

```bash
sudo scripts/start_server.sh --subnet 10.0.0.0/24 --subnet6 fd00:abcd::/112
```

### 3. Connect a Client

Single path:

```bash
sudo ./build/mqvpn --mode client --server 203.0.113.1:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4= --insecure
```

Multipath (two interfaces):

```bash
sudo ./build/mqvpn --mode client --server 203.0.113.1:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4= \
    --path eth0 --path wlan0 --insecure
```

With DNS override (prevents DNS leaks):

```bash
sudo ./build/mqvpn --mode client --server 203.0.113.1:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4= \
    --dns 1.1.1.1 --dns 8.8.8.8 --insecure
```

::: tip
`--insecure` skips TLS certificate verification (for self-signed certs). For production, use a trusted certificate (e.g., Let's Encrypt) and omit `--insecure`.
:::

::: tip
Without `--path`, the client uses the default interface (single path). Multipath requires two or more `--path` flags. See [Multipath](./multipath) for details.
:::

## Generate an Auth Key

```bash
mqvpn --genkey
```

Or let `start_server.sh` generate one automatically.

## CLI Reference

```
mqvpn --config PATH
mqvpn --mode client|server [options]

  --server HOST:PORT     Server address (client, e.g. `[2001:db8::1]:443` for IPv6)
  --path IFACE           Multipath interface (repeatable)
  --auth-key KEY         PSK authentication
  --user NAME:KEY        Per-user PSK (repeatable, server)
  --dns ADDR             DNS server (repeatable)
  --insecure             Accept untrusted certs (testing only)
  --tun-name NAME        TUN device name (default: mqvpn0)
  --listen BIND:PORT     Listen address (server, default: 0.0.0.0:443)
  --subnet CIDR          Client IPv4 pool (server)
  --subnet6 CIDR         Client IPv6 pool (server)
  --cert PATH            TLS certificate (server)
  --key PATH             TLS private key (server)
  --scheduler minrtt|wlb Multipath scheduler (default: wlb)
  --max-clients N        Max concurrent clients (server, default: 64)
  --control-port PORT    TCP port for control API (server)
  --control-addr ADDR    Bind address for control API (default: 127.0.0.1)
  --status               Query server status via control API and exit
  --log-level LVL        Log level (debug|info|warn|error)
  --no-reconnect         Disable automatic reconnection (client)
  --kill-switch          Block traffic outside the VPN tunnel (client)
  --genkey               Generate PSK and exit
  --help                 Show all options
```

When `--config` is provided, `--mode` is inferred from the config file. CLI arguments override config values.

## Next Steps

- [Building](./building) — Build from source on Linux, Windows, and Android
- [Configuration](./configuration) — Config file reference
- [Multipath](./multipath) — Multipath setup and scheduler options
