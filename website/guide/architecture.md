# Architecture

mqvpn is built as a **[sans-I/O](https://sans-io.readthedocs.io/) C library** (`libmqvpn`) with platform-specific layers on top. This design separates the VPN protocol engine from platform-specific I/O orchestration, making it portable across platforms.

## Sans-I/O Design

The library does not embed a platform event loop or device management. It is driven via `tick()` and data-injection APIs: received UDP/TUN data is fed via `on_socket_recv()` / `on_tun_packet()`, while egress uses xquic transport callbacks to write to UDP sockets (CLI uses fd-only mode).

```
┌───────────────────────────────────────────────┐
│  Platform Layer (owns I/O)                    │
│  ┌──────────┐  ┌───────────┐  ┌───────────┐   │
│  │ Linux CLI│  │ Android   │  │ Windows   │   │
│  │(libevent)│  │ (Handler) │  │ (IOCP)    │   │
│  └────┬─────┘  └─────┬─────┘  └─────┬─────┘   │
│       │ tick()        │ tick()       │ tick() │
├───────┴───────────────┴──────────────┴────────┤
│  libmqvpn (core engine — event-loop agnostic) │
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

- **Portability** — Each platform provides its own event loop (libevent on Linux, IOCP on Windows, Android Handler on mobile -- or GCD, kqueue, etc. for future ports). The library doesn't force a threading model.
- **Testability** — The `tick()` function drives state transitions synchronously, making unit tests deterministic with no timing issues.
- **Power efficiency** — The platform controls when to wake the CPU. The library reports idle state via `interest.is_idle`.
- **Dependency separation** — The library itself does not own an event loop implementation; the platform layer owns libevent and OS-specific dependencies (including pthreads on Linux).

This is the same pattern used by [WireGuard (BoringTun)](https://github.com/cloudflare/boringtun) and [msquic](https://github.com/microsoft/msquic).

## Data Flow

The platform layer drives the library through a simple loop:

```c
// 1. Create config and client
cfg = mqvpn_config_new();
mqvpn_config_set_server(cfg, "1.2.3.4", 443);
mqvpn_config_set_auth_key(cfg, "base64...");
client = mqvpn_client_new(cfg, &callbacks, user_ctx);

// 2. Add network paths (UDP sockets)
mqvpn_client_add_path_fd(client, udp_fd, &desc);

// 3. Connect and drive the engine
mqvpn_client_connect(client);

while (running) {
    mqvpn_interest_t interest;
    mqvpn_client_get_interest(client, &interest);
    int next_ms = interest.next_timer_ms;

    poll(fds, nfds, next_ms);

    // Inject received UDP data
    if (udp_readable)
        mqvpn_client_on_socket_recv(client, path, buf, len, &peer, peerlen);

    // Inject TUN packets
    if (tun_readable)
        mqvpn_client_on_tun_packet(client, pkt, len);

    // Drive the engine — processes queued work and invokes callbacks
    mqvpn_client_tick(client);
}
```

## Callback Model

The library communicates back to the platform through callbacks:

| Callback | When | Platform Action |
|----------|------|-----------------|
| `tun_output` | Decrypted packet ready | Write to TUN device |
| `send_packet` | Send request in ops-path mode | Send via platform-provided UDP path |
| `tunnel_config_ready` | Server assigned IP/MTU | Create and configure TUN device |
| `state_changed` | Connection state transition | Update UI, handle reconnection |
| `path_event` | Path status change | Log, adjust routing |
| `log` | Log message | Write to log |

In the current CLI implementation (fd-only mode), `send_packet` is not used; socket send is done through xquic transport callbacks.

All callbacks fire on the same thread that called `tick()` — no synchronization needed.

## Components

| Component | File | Purpose |
|-----------|------|---------|
| Client engine | `mqvpn_client.c` | QUIC connection, MASQUE CONNECT-IP, state machine |
| Server engine | `mqvpn_server.c` | Multi-client handling, address assignment |
| Config builder | `mqvpn_config.c` | Opaque config with setter functions, ABI-safe |
| Path manager | `path_mgr.c` | UDP path lifecycle, creation and teardown |
| Flow scheduler | `flow_sched.c` | WLB and MinRTT packet scheduling |
| Address pool | `addr_pool.c` | Server-side IP address allocation |
| Auth | `auth.c` | PSK authentication over TLS 1.3 |

## Platform Porting

To port mqvpn to a new platform, implement:

1. **Event loop** — poll/epoll/kqueue/IOCP that calls `tick()` using `get_interest().next_timer_ms`
2. **UDP sockets** — Create, bind, and read from UDP sockets; pass received data to `on_socket_recv()`
3. **TUN device** — Create platform-specific TUN; write packets from `tun_output` callback; read packets and pass to `on_tun_packet()`
4. **Routing** — Set up routes to direct traffic through the TUN device
5. **DNS** — Configure DNS to prevent leaks

See `src/platform/linux/platform_linux.c` as a reference implementation.
