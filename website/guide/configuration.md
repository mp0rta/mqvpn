# Configuration

mqvpn supports both INI and JSON config files. The format is detected automatically from the file extension (`.conf` for INI, `.json` for JSON). CLI arguments override config values.

## INI Format

### Server

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

### Client

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

## JSON Format

JSON config is useful for structured management and automation tooling.

### Server

```json
{
  "mode": "server",
  "listen": "0.0.0.0:443",
  "subnet": "10.0.0.0/24",
  "subnet6": "2001:db8:1::/112",
  "cert_file": "/etc/mqvpn/server.crt",
  "key_file": "/etc/mqvpn/server.key",
  "auth_key": "<YOUR_PSK_HERE>",
  "users": [
    { "name": "alice", "key": "<ALICE_PSK>" },
    { "name": "bob", "key": "<BOB_PSK>" }
  ],
  "max_clients": 64,
  "scheduler": "wlb"
}
```

### Client

```json
{
  "mode": "client",
  "server_addr": "203.0.113.1:443",
  "auth_key": "<YOUR_PSK_HERE>",
  "insecure": false,
  "dns": ["1.1.1.1", "8.8.8.8"],
  "kill_switch": false,
  "reconnect": true,
  "reconnect_interval": 5,
  "scheduler": "wlb",
  "paths": ["eth0", "wlan0"]
}
```

## Multi-User Authentication

The server can authenticate multiple users, each with their own PSK. Add a `users` array in the JSON config or use the [Control API](#control-api) to manage users at runtime.

When both `auth_key` (global key) and `users` are set, clients can authenticate with either. To restrict access to named users only, remove `auth_key` from the config.

## Running with Config Files

```bash
sudo mqvpn --config /etc/mqvpn/server.conf
sudo mqvpn --config /etc/mqvpn/server.json
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

## Control API

A running server can be managed at runtime over a local TCP socket using JSON commands. This is useful for adding or removing users without restarting the server.

### Enable

```bash
sudo mqvpn --mode server ... --control-port 9090
```

The control API binds to `127.0.0.1` by default. It has no authentication, so only bind to trusted interfaces.

### Commands

Add a user:

```bash
echo '{"cmd":"add_user","name":"carol","key":"carol-secret"}' | nc 127.0.0.1 9090
```

Remove a user:

```bash
echo '{"cmd":"remove_user","name":"carol"}' | nc 127.0.0.1 9090
```

List users:

```bash
echo '{"cmd":"list_users"}' | nc 127.0.0.1 9090
```

Get stats:

```bash
echo '{"cmd":"get_stats"}' | nc 127.0.0.1 9090
```

All commands return a JSON response with an `"ok"` field.

## systemd

Install the binary and unit files first (one-time setup):

```bash
sudo cmake --install build --prefix /usr/local
```

### Server

```bash
sudo cp systemd/server.json.example /etc/mqvpn/server.json
# Edit /etc/mqvpn/server.json with your settings
sudo systemctl enable --now mqvpn-server
```

### Client (template unit)

The client uses a template unit — the instance name maps to the config file:

```bash
sudo cp systemd/client.json.example /etc/mqvpn/client-home.json
sudo systemctl enable --now mqvpn-client@home
# This reads /etc/mqvpn/client-home.json
```
