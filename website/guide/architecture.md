# Architecture

mqvpn is built as a **[sans-I/O](https://sans-io.readthedocs.io/) C library** (`libmqvpn`) with platform-specific layers on top. This design separates the VPN protocol engine from platform-specific I/O orchestration, making it portable across platforms.

## Sans-I/O Design

The library does not embed a platform event loop or device management, and it owns none of the UDP sockets the tunnel runs over, in either direction. It is driven via `tick()` and data-injection APIs: received UDP datagrams and TUN packets are pushed in via `on_socket_recv()` / `on_tun_packet()`, and every UDP send goes out through the transport ops the platform installs for each path (one shared table on the server). The one exception is the server side of the [hybrid TCP lane](./hybrid-mode), which opens the relayed TCP connections itself. For ordinary UDP sockets the library ships two implementations of those ops — a POSIX one (including Linux GSO / `sendmmsg` batching) and a Winsock one — so the platform creates, binds and closes its sockets and lets the transport read them when they become readable.

```
┌──────────────────────────────────────────────────────────────────┐
│  Platform Layer (owns I/O and the UDP sockets)                   │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │Linux CLI │ │macOS CLI │ │ Android  │ │ iOS (NE) │ │ Windows  │ │
│ │(libevent)│ │(libevent)│ │ (poll)   │ │(RunLoop) │ │(libevent)│ │
│ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ │
│      │ tick()     │ tick()     │ tick()     │ tick()     │ tick()│
├──────┴────────────┴────────────┴────────────┴────────────┴───────┤
│  libmqvpn (event-loop agnostic, owns no UDP socket)              │
│  ┌──────────────────────────────────┐ ┌────────────────────────┐ │
│  │ core engine                      │ │ bundled transports     │ │
│  │ mqvpn_client.c / mqvpn_server.c  │ │ bind/posix.c           │ │
│  │ mqvpn_config.c / auth.c          │ │ bind/winsock.c         │ │
│  │ path_state_machine.c             │ │ (transport ops for     │ │
│  │ flow_sched.c / addr_pool.c       │ │  UDP sockets)          │ │
│  └────┬─────────────────────────────┘ └────────────────────────┘ │
│       │ xquic callbacks                                          │
├───────┴──────────────────────────────────────────────────────────┤
│  xquic (QUIC / HTTP/3 / MASQUE engine)                           │
│  BoringSSL (TLS 1.3)                                             │
└──────────────────────────────────────────────────────────────────┘
```

On Apple platforms the two entry points differ: the macOS CLI uses the Darwin platform layer (`src/platform/darwin/`, libevent event loop + `utun` device), while the iOS Network Extension wraps the sans-I/O core directly in Swift — a dedicated tick thread driven by a RunLoop timer, with packets exchanged through `NEPacketTunnelFlow` (no libevent, no `utun` handling of its own).

### Why Sans-I/O?

- **Portability** — Each platform provides its own event loop (libevent on Linux, macOS and Windows, a `poll()` reactor on a dedicated engine thread on Android, a dedicated RunLoop thread in the iOS Network Extension). The library doesn't force a threading model.
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

// 2. Add a network path: the platform opens and binds a UDP socket (pinned
//    to its interface if needed), wraps it in the bundled POSIX transport
//    and registers it. The library borrows the socket and never closes it.
int fd = socket(AF_INET, SOCK_DGRAM, 0);
bind(fd, (struct sockaddr *)&local, sizeof(local));

mqvpn_bind_posix_opts_t bopts = {.struct_size = sizeof(bopts)};
void *tctx;
mqvpn_bind_posix_path_new(fd, &bopts, &tctx);
mqvpn_path_handle_t path =
    mqvpn_client_add_path(client, &desc, mqvpn_bind_posix_path_ops(), tctx, NULL);

// 3. Connect and drive the engine
mqvpn_client_connect(client);

while (running) {
    mqvpn_interest_t interest;
    mqvpn_client_get_interest(client, &interest);
    int next_ms = interest.next_timer_ms;

    poll(fds, nfds, next_ms);

    // Received UDP data: the transport reads the socket and pushes each
    // datagram in (mqvpn_client_on_socket_recv)
    if (udp_readable)
        mqvpn_bind_posix_path_drain(tctx, client, path, 64);

    // Inject TUN packets
    if (tun_readable)
        mqvpn_client_on_tun_packet(client, pkt, len);

    // Drive the engine — processes queued work, sends through the path's
    // transport ops and invokes callbacks
    mqvpn_client_tick(client);
}
```

## Callback Model

The library communicates back to the platform through callbacks:

| Callback | When | Platform Action |
|----------|------|-----------------|
| `tun_output` | Decrypted packet ready | Write to TUN device |
| `tunnel_config_ready` | Server assigned IP/MTU | Create and configure TUN device |
| `state_changed` | Connection state transition | Update UI, handle reconnection |
| `path_event` | Path status change | Log, adjust routing |
| `log` | Log message | Write to log |

Sending UDP datagrams is not a callback. Each client path carries a table of transport ops the platform installs with `mqvpn_client_add_path()`: `send` (required — takes a batch of datagrams and returns how many it accepted, or that it would block or failed), `get_stats` and `release` (optional). The server installs one shared table with `mqvpn_server_set_transport()`. The bundled POSIX and Winsock transports implement these ops for ordinary UDP sockets.

All callbacks, transport ops included, fire on the same thread that called `tick()` — no synchronization needed.

## Components

| Component | File | Purpose |
|-----------|------|---------|
| Client engine | `mqvpn_client.c` | QUIC connection, MASQUE CONNECT-IP, state machine |
| Server engine | `mqvpn_server.c` | Multi-client handling, address assignment |
| Config builder | `mqvpn_config.c` | Opaque config with setter functions, ABI-safe |
| Path state machine | `path_state_machine.c` | Per-path lifecycle: validation, retries, drop and slot reuse |
| Flow scheduler | `flow_sched.c` | WLB and MinRTT packet scheduling |
| Address pool | `addr_pool.c` | Server-side IP address allocation |
| Auth | `auth.c` | PSK authentication over TLS 1.3 |
| Bundled transports | `bind/posix.c`, `bind/winsock.c` | Transport ops for ordinary UDP sockets (POSIX, Winsock) |

## Platform Porting

To port mqvpn to a new platform, implement:

1. **Event loop** — poll/epoll/kqueue/IOCP that calls `tick()` using `get_interest().next_timer_ms`
2. **UDP sockets** — For each path, create and bind a UDP socket (pin it to its interface if the OS needs that), wrap it in a bundled transport (`mqvpn_bind_posix_path_new()` / `mqvpn_bind_winsock_path_new()` — on Windows, make the socket non-blocking first) or implement `mqvpn_path_ops_t` yourself, register it with `mqvpn_client_add_path()`, and when it becomes readable call the transport's drain helper (or push datagrams with `on_socket_recv()`). The socket stays yours: the library never closes it
3. **Path teardown** — Two contracts. When the OS reports a path gone: call `mqvpn_client_drop_path()`, stop the path's I/O and close its socket, then call `mqvpn_client_on_platform_path_released()`. At shutdown: stop reading, call `mqvpn_client_destroy()` (it finalises every registered transport not yet released), then close the sockets
4. **TUN device** — Create platform-specific TUN; write packets from `tun_output` callback; read packets and pass to `on_tun_packet()`
5. **Routing** — Set up routes to direct traffic through the TUN device
6. **DNS** — Configure DNS to prevent leaks
