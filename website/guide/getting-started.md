# Getting Started

mqvpn is an L3 multipath VPN built on MASQUE CONNECT-IP (RFC 9484) and Multipath QUIC.

## Installation

### Server

#### Debian and Ubuntu (deb packages)

The `mqvpn` deb contains the VPN program for both client and server; `mqvpn-server` adds the server service, NAT setup, and first-run configuration. Download the `mqvpn` and `mqvpn-server` debs of the same version from [Releases](https://github.com/mp0rta/mqvpn/releases/latest), then install both.

```bash
# Replace VERSION and ARCH as needed (e.g., 0.19.3, amd64)
curl -LO https://github.com/mp0rta/mqvpn/releases/latest/download/mqvpn_VERSION_ARCH.deb
curl -LO https://github.com/mp0rta/mqvpn/releases/latest/download/mqvpn-server_VERSION_ARCH.deb
sudo apt install ./mqvpn_VERSION_ARCH.deb ./mqvpn-server_VERSION_ARCH.deb
```

The install generates a certificate, auth key, and server config, then starts the server and registers it for automatic startup on boot. It keeps a certificate or config that already exists. The generated config turns on hybrid mode and the reorder buffer on the server side; each takes effect only for clients that also turn it on. It also sets `AllowClientScheduler = true`, so a client can ask for its own download scheduler.

The install prints the auth key and a client command. Run `sudo mqvpn-server-info` to show them again.

The install asks for an optional public hostname for the certificate. It asks for a client subnet only when the default `10.0.0.0/24` overlaps a network of the server, and for the port only when UDP 443 is already in use. To set values in advance, for example in automation:

```bash
echo 'mqvpn-server mqvpn-server/subnet string 10.8.0.0/24' | sudo debconf-set-selections
sudo env MQVPN_PORT=10020 apt install ./mqvpn_VERSION_ARCH.deb ./mqvpn-server_VERSION_ARCH.deb
```

These values apply only to a new `/etc/mqvpn/server.conf`. To change a running server, edit `/etc/mqvpn/server.conf` and run `sudo systemctl restart mqvpn-server`.

`sudo apt remove mqvpn-server` stops the server and keeps `/etc/mqvpn`. `sudo apt purge mqvpn-server` also deletes the generated config, auth key, and certificate, so every client then needs the new auth key. Files that you created yourself stay. More details: `/usr/share/doc/mqvpn-server/README.Debian`.

::: tip Upgrading from 0.19.2 or earlier
The server files moved from the `mqvpn` deb to the new `mqvpn-server` deb. Install both debs together. Your `/etc/mqvpn` config stays as it is. If you used the install script before, first run it with `--uninstall` (it keeps `/etc/mqvpn`).
:::

#### Other Linux distributions (install script)

Run the following to install the binary to `/usr/local` and generate the same certificate, auth key, and server config as the deb.

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
Both install methods generate a self-signed certificate when the server has none. With that certificate, clients must use `--insecure` to connect. For production, replace the certificate with a trusted one (e.g., Let's Encrypt) and omit `--insecure`. The deb keeps a certificate that is already in place, and `sudo mqvpn-server-info` adds `--insecure` to the client command only for a self-signed certificate.
Point `--cert` (or `Cert` / `cert_file` in a config file) at the full chain file (for Let's Encrypt, `fullchain.pem`): clients do not fetch missing intermediates.
:::

### Client (Debian and Ubuntu)

Download the latest `mqvpn` deb from [Releases](https://github.com/mp0rta/mqvpn/releases/latest).

```bash
# Replace VERSION and ARCH as needed (e.g., 0.6.0, amd64)
curl -LO https://github.com/mp0rta/mqvpn/releases/latest/download/mqvpn_VERSION_ARCH.deb
sudo dpkg -i mqvpn_*.deb
```

### Windows client

Pre-built binaries are shipped for Windows amd64 and arm64. Download `mqvpn_<VERSION>_windows_<ARCH>.zip` from [Releases](https://github.com/mp0rta/mqvpn/releases/latest), extract, and follow the bundled `README.txt` (admin PowerShell required).

### macOS client

Pre-built binaries are shipped for Apple silicon (arm64). Download `mqvpn_<VERSION>_darwin_arm64.tar.gz` from [Releases](https://github.com/mp0rta/mqvpn/releases/latest), extract, and follow the bundled `README.txt` (sudo required).

### Build from source

See [Building](./building) for instructions.

## Quick Start

After installing the server and client, connect using the auth key and address that the server install showed. On a deb install, `sudo mqvpn-server-info` shows them again. The commands below use `--insecure` for a self-signed certificate; omit it if the server has a trusted certificate.

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
  --tls-server-name NAME TLS SNI / cert verify name (client)
  --insecure             Accept untrusted certs (testing only)
  --tun-name NAME        TUN device name (default: mqvpn0)
  --listen BIND:PORT     Listen address (server, default: 0.0.0.0:443)
  --subnet CIDR          Client IPv4 pool (server)
  --subnet6 CIDR         Client IPv6 pool (server)
  --cert PATH            TLS certificate (server)
  --key PATH             TLS private key (server)
  --scheduler SCHED      Multipath scheduler: minrtt|wlb|wlb_udp_pin|backup_fec
                         (default: wlb)
  --cc ALGO              Congestion control: bbr2|bbr|cubic|none (default: bbr2)
  --mtu N                TUN MTU (1280-9000, default: auto)
  --path-mtu N           Underlay MTU to size QUIC packets for (1280-9000, default: 0)
  --pmtud                Discover the path MTU (both ends); --path-mtu is the upper limit
  --max-clients N        Max concurrent clients (server, default: 64)
  --control-port PORT    TCP port for control API (server)
  --control-addr ADDR    Bind address for control API (default: 127.0.0.1)
  --status               Query server status via control API and exit
  --log-level LVL        Log level (debug|info|warn|error)
  --no-reconnect         Disable automatic reconnection (client)
  --kill-switch          Block traffic outside the VPN tunnel (client)
  --no-manage-routes     Do not modify the host routing table (client)
  --genkey               Generate PSK and exit
  --version              Show version and exit
  --help                 Show all options
```

When `--config` is provided, `--mode` is inferred from the config file. CLI arguments override config values.

## Next Steps

- [Building](./building) — Build from source on Linux, Windows, and Android
- [Configuration](./configuration) — Config file reference
- [Multipath](./multipath) — Multipath setup and scheduler options
