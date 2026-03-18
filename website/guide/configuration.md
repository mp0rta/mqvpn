# Configuration

mqvpn uses an INI-style config file. CLI arguments override config values.

## Server Config

```ini
# /etc/mqvpn/server.conf
[Interface]
Listen = 0.0.0.0:443
Subnet = 10.0.0.0/24
Subnet6 = 2001:db8:1::/112

[TLS]
Cert = /etc/mqvpn/server.crt
Key = /etc/mqvpn/server.key

[Auth]
Key = mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=

[Multipath]
Scheduler = wlb
```

## Client Config

```ini
# /etc/mqvpn/client.conf
[Server]
Address = 203.0.113.1:443

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

## Running with Config Files

```bash
sudo mqvpn --config /etc/mqvpn/server.conf
sudo mqvpn --config /etc/mqvpn/client.conf
```

## Config Reference

### `[Server]` (client only)

| Key | Description | Default |
|-----|-------------|---------|
| `Address` | Server address (`IP:PORT`) | Required |
| `Insecure` | Skip TLS certificate verification | `false` |

### `[Interface]`

| Key | Description | Default |
|-----|-------------|---------|
| `Listen` | Listen address (server only) | `0.0.0.0:443` |
| `Subnet` | Client IPv4 pool (server only) | `10.0.0.0/24` |
| `Subnet6` | Client IPv6 pool (server only) | — |
| `TunName` | TUN device name | `mqvpn0` |
| `DNS` | DNS servers (comma-separated) | — |
| `LogLevel` | Log level (`debug`, `info`, `warn`, `error`) | `info` |

### `[TLS]` (server only)

| Key | Description | Default |
|-----|-------------|---------|
| `Cert` | TLS certificate path (PEM) | Required |
| `Key` | TLS private key path (PEM) | Required |

### `[Auth]`

| Key | Description | Default |
|-----|-------------|---------|
| `Key` | Pre-shared key (base64, generate with `mqvpn --genkey`) | Required |

### `[Multipath]`

| Key | Description | Default |
|-----|-------------|---------|
| `Scheduler` | Scheduler algorithm (`minrtt` or `wlb`) | `wlb` |
| `Path` | Network interface to bind (repeatable) | Default interface |

See [Multipath](./multipath) for scheduler details.

## systemd

### Server

```bash
sudo cp systemd/server.conf.example /etc/mqvpn/server.conf
# Edit /etc/mqvpn/server.conf with your settings
sudo systemctl enable --now mqvpn-server
```

### Client (template unit)

The client uses a template unit — the instance name maps to the config file:

```bash
sudo cp systemd/client.conf.example /etc/mqvpn/client-home.conf
sudo systemctl enable --now mqvpn-client@home
# This reads /etc/mqvpn/client-home.conf
```
