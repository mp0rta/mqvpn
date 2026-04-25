# Getting Started

mqvpn is a multipath QUIC VPN that uses MASQUE CONNECT-IP (RFC 9484) for standards-based IP tunneling over Multipath QUIC.

## Installation

### Server

On an Ubuntu/Debian VPS, run the following to install the binary and generate a certificate, auth key, and server config.

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh | sudo bash
```

Add `--start` to also start the server and register it for automatic startup on boot.

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh \
    | sudo bash -s -- --start
```

Port and subnet can be customized with additional options.

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh \
    | sudo bash -s -- --start --port 10020 --subnet 10.8.0.0/24
```

To uninstall, re-run the script with `--uninstall` (add `--purge` to also remove config files).

::: warning
The install script generates a self-signed certificate. Clients must use `--insecure` to connect. For production, replace the certificate with a trusted one (e.g., Let's Encrypt) and omit `--insecure`.
:::

### Client (deb package)

Download the latest `.deb` from [Releases](https://github.com/mp0rta/mqvpn/releases/latest).

```bash
# Replace VERSION and ARCH as needed (e.g., 0.5.0, amd64)
curl -LO https://github.com/mp0rta/mqvpn/releases/latest/download/mqvpn_VERSION_ARCH.deb
sudo dpkg -i mqvpn_*.deb
```

### Build from source

See [Building](./building) for instructions.

## Quick Start

After installing the server and client, connect using the auth key and address shown by the install script.

Single path:

```bash
sudo mqvpn --mode client --server YOUR_SERVER:443 \
    --auth-key YOUR_AUTH_KEY --insecure
```

Multipath (multiple interfaces):

```bash
sudo mqvpn --mode client --server YOUR_SERVER:443 \
    --auth-key YOUR_AUTH_KEY --path eth0 --path wlan0 --insecure
```

With DNS override (prevents DNS leaks):

```bash
sudo mqvpn --mode client --server YOUR_SERVER:443 \
    --auth-key YOUR_AUTH_KEY --dns 1.1.1.1 --dns 8.8.8.8 --insecure
```

::: tip
Without `--path`, the client uses the default interface (single path). Multipath requires two or more `--path` flags. See [Multipath](./multipath) for details.
:::

::: warning
The server needs its listen port open for UDP (default: 443). All client traffic is routed through the tunnel.
:::

## Generate an Auth Key

```bash
mqvpn --genkey
```

The install script and `start_server.sh` generate one automatically.

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
