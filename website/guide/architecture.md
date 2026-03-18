# Architecture

mqvpn is built as a **sans-I/O C library** (`libmqvpn`) with platform-specific layers on top. This design separates the VPN protocol engine from all I/O operations, making it portable to any platform.

## Sans-I/O Design

The library performs **no I/O** — it never calls `read()`, `write()`, `sendto()`, or `recvfrom()`. Instead, the platform layer drives the library by calling `tick()` and injecting data through function calls.

```
┌───────────────────────────────────────────────┐
│  Platform Layer (owns I/O)                    │
│  ┌──────────┐  ┌───────────┐  ┌───────────┐  │
│  │ Linux CLI│  │ Android   │  │ Windows   │  │
│  │ (poll)   │  │ (Handler) │  │ (IOCP)    │  │
│  └────┬─────┘  └─────┬─────┘  └─────┬─────┘  │
│       │ tick()        │ tick()       │ tick()  │
├───────┴───────────────┴──────────────┴────────┤
│  libmqvpn (core engine — NO I/O)              │
│  ┌──────────────────────────────────────────┐ │
│  │ mqvpn_client.c / mqvpn_server.c          │ │
│  │ mqvpn_config.c / auth.c                  │ │
│  │ path_mgr.c / flow_sched.c / addr_pool.c  │ │
│  └──────────────────────────────────────────┘ │
│       │ xquic callbacks                       │
├───────┴───────────────────────────────────────┤
│  xquic (QUIC / HTTP/3 / MASQUE engine)        │
│  BoringSSL (TLS 1.3)                          │
└───────────────────────────────────────────────┘
```

### Why Sans-I/O?

- **Portability** — Each platform provides its own event loop (libevent, Android Handler, GCD, IOCP). The library doesn't force a threading model.
- **Testability** — The `tick()` function drives state transitions synchronously, making unit tests deterministic with no timing issues.
- **Power efficiency** — The platform controls when to wake the CPU. The library reports idle state via `interest.is_idle`.
- **No dependencies** — `libmqvpn` depends only on xquic and BoringSSL. No libevent, no pthreads.

This is the same pattern used by [WireGuard (BoringTun)](https://github.com/cloudflare/boringtun) and [msquic](https://github.com/microsoft/msquic).

## Data Flow

The platform layer drives the library through a simple loop:

```c
// 1. Create config and client
cfg = mqvpn_config_new(MQVPN_MODE_CLIENT);
mqvpn_config_set_server(cfg, "1.2.3.4", 443);
mqvpn_config_set_auth_key(cfg, "base64...");
client = mqvpn_client_new(cfg, &callbacks, user_ctx);

// 2. Add network paths (UDP sockets)
mqvpn_client_add_path_fd(client, udp_fd, &desc);

// 3. Connect and drive the engine
mqvpn_client_connect(client);

while (running) {
    poll(fds, nfds, next_ms);

    // Inject received UDP data
    if (udp_readable)
        mqvpn_client_on_socket_recv(client, path, buf, len, &peer, peerlen);

    // Inject TUN packets
    if (tun_readable)
        mqvpn_client_on_tun_packet(client, pkt, len);

    // Drive the engine — processes queued work, fires callbacks
    mqvpn_client_tick(client, &next_ms);
}
```

## Callback Model

The library communicates back to the platform through callbacks:

| Callback | When | Platform Action |
|----------|------|-----------------|
| `tun_output` | Decrypted packet ready | Write to TUN device |
| `send_packet` | Encrypted packet ready | Send via UDP socket |
| `tunnel_config_ready` | Server assigned IP/MTU | Create and configure TUN device |
| `state_changed` | Connection state transition | Update UI, handle reconnection |
| `path_event` | Path status change | Log, adjust routing |
| `log` | Log message | Write to log |

All callbacks fire on the same thread that called `tick()` — no synchronization needed.

## Components

| Component | File | Purpose |
|-----------|------|---------|
| Client engine | `mqvpn_client.c` | QUIC connection, MASQUE CONNECT-IP, state machine |
| Server engine | `mqvpn_server.c` | Multi-client handling, address assignment |
| Config builder | `mqvpn_config.c` | Opaque config with setter functions, ABI-safe |
| Path manager | `path_mgr.c` | UDP path lifecycle, add/remove/probe |
| Flow scheduler | `flow_sched.c` | WLB and MinRTT packet scheduling |
| Address pool | `addr_pool.c` | Server-side IP address allocation |
| Auth | `auth.c` | PSK authentication over TLS 1.3 |

## Platform Porting

To port mqvpn to a new platform, implement:

1. **Event loop** — poll/epoll/kqueue/IOCP that calls `tick()` at the interval reported by `next_ms`
2. **UDP sockets** — Create, bind, and read from UDP sockets; pass received data to `on_socket_recv()`
3. **TUN device** — Create platform-specific TUN; write packets from `tun_output` callback; read packets and pass to `on_tun_packet()`
4. **Routing** — Set up routes to direct traffic through the TUN device
5. **DNS** — Configure DNS to prevent leaks

See `src/platform/linux/platform_linux.c` (~880 lines) as a reference implementation.
