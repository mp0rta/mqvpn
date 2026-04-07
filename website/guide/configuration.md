# Configuration

mqvpn supports both INI and JSON config files. If the file content starts with `{`, it is parsed as JSON; otherwise as INI. CLI arguments override config values.

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
User = alice:<ALICE_PSK>
User = bob:<BOB_PSK>

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
  "tun_name": "mqvpn0",
  "log_level": "info",
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
  "tun_name": "mqvpn0",
  "log_level": "info",
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

The server can authenticate multiple users, each with their own PSK. In JSON config, add a `users` array where each entry is either an object (`{"name":"alice","key":"..."}`) or a shorthand string (`"alice:key"`). In INI config, use repeatable `User = NAME:KEY` lines in the `[Auth]` section. You can also use the [Control API](#control-api) to manage users at runtime.

When both `auth_key` (global key) and `users` are set, clients can authenticate with either. To restrict access to named users only, remove `auth_key` from the config.

Removing a user via the Control API also disconnects any active sessions authenticated with that username.

## Running with Config Files

```bash
sudo mqvpn --config /etc/mqvpn/server.conf
sudo mqvpn --config /etc/mqvpn/server.json
```

## Config Reference

### `[Server]` (client only)

| Key | Description | Default |
|-----|-------------|---------|
| `Address` | Server address (`HOST:PORT`, e.g. `[2001:db8::1]:443` for IPv6) | Required |
| `Insecure` | Skip TLS certificate verification | `false` |

### `[Interface]`

| Key | Description | Default |
|-----|-------------|---------|
| `Listen` | Listen address (`HOST:PORT`, server only) | `0.0.0.0:443` |
| `Subnet` | Client IPv4 pool (server only) | `10.0.0.0/24` |
| `Subnet6` | Client IPv6 pool (server only) | — |
| `TunName` | TUN device name | `mqvpn0` |
| `DNS` | DNS servers (comma-separated) | — |
| `LogLevel` | Log level (`debug`, `info`, `warn`, `error`) | `info` |
| `KillSwitch` | Block traffic outside the VPN tunnel (client only) | `false` |
| `Reconnect` | Enable automatic reconnection (client only) | `true` |
| `ReconnectInterval` | Seconds between reconnection attempts | `5` |

### `[TLS]` (server only)

| Key | Description | Default |
|-----|-------------|---------|
| `Cert` | TLS certificate path (PEM) | Required |
| `Key` | TLS private key path (PEM) | Required |

### `[Auth]`

| Key | Description | Default |
|-----|-------------|---------|
| `Key` | Pre-shared key (base64, generate with `mqvpn --genkey`) | Required unless `User` is set |
| `User` | Per-user PSK in `NAME:KEY` format (repeatable) | — |
| `MaxClients` | Maximum concurrent clients (server only) | `64` |

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

Removing a user also disconnects any active sessions authenticated with that username.

List users:

```bash
echo '{"cmd":"list_users"}' | nc 127.0.0.1 9090
```

Get stats:

```bash
echo '{"cmd":"get_stats"}' | nc 127.0.0.1 9090
```

Get detailed status (per-client, per-path):

```bash
echo '{"cmd":"get_status"}' | nc 127.0.0.1 9090
```

Or use the built-in status command for human-readable output:

```bash
mqvpn --status --control-port 9090
```

All commands return a JSON response with an `"ok"` field. Each connection handles one command, then the server closes the connection.

## systemd

Install the binary and unit files first (one-time setup):

```bash
sudo cmake --install build --prefix /usr/local
```

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

::: info
The systemd units expect INI `.conf` files. The server unit's NAT helper scripts also parse the INI config directly, so JSON cannot be used with the standard units as-is.
:::
