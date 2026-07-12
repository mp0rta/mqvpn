# iOS PoC gate results (2026-07-12)

## Environment

| Item | Value |
|---|---|
| Device | iPhone 14 (iPhone14,7), iOS 18.6.2 |
| Xcode / SDK | Xcode 26.6, iPhoneOS 26.5 SDK, deployment target iOS 15.0 |
|  Branch / commit | `feat/ios-poc` @ ad9518c (base = main 1ce75cc, v0.10.0) |
| xquic pin | acccb18 |
| BoringSSL clone commit | 9c95ec797c65fde9e8ddffc3888f0b8c1460fe4c (unpinned clone, recorded for reproducibility) |
| Server | test-server v0.9.0, UDP 443, tunnel subnet 10.0.0.0/24 (gateway 10.0.0.1) |
| Client tunnel IP | 10.0.0.8/32 (ADDRESS_ASSIGN) |
| Scheduler | default (WLB), reorder buffer OFF, hybrid lane compile-time excluded on Apple |

Notes:
- The bulk-download target for the multipath gate is served on the tunnel-inner
  gateway (`http://10.0.0.1:8080/bulk-100M.bin`), NOT the server's global IP:
  iOS NE auto-installs a physical-interface host route for
  `tunnelRemoteAddress`, so a global-IP bulk URL would bypass the tunnel.
- Log harvesting: live `idevicesyslog` on the paired Mac; `GATE|` lines are
  emitted at `.notice` so post-hoc `log collect` also retains them.

## G-i1 — single-path connectivity + no self-capture: **PASS**

Procedure: WiFi only (cellular off), tunnel started from the container app,
VPN permission granted. All observations after NE settings (default route)
were applied (client state 4 requires it).

- Handshake + tunnel establishment: server journal
  `client authenticated successfully` → `Extended CONNECT for connect-ip
  received` → `ADDRESS_ASSIGN: client=10.0.0.8/32` → `MASQUE tunnel
  established (stream_id=0, clients=1)` (23:18:13). Client:
  `GATE| state=4` (ESTABLISHED) held continuously from 23:19:14 onward.
- Ping continuity (server → client tunnel IP): `ping -i 0.2 -c 30 10.0.0.8`
  → 30/30, 0% loss, rtt min/avg/max = 24.5/27.1/61.7 ms; a second 10-ping
  burst during packet capture also 10/10.
- Self-capture check: `tcpdump -n udp port 443` on the server during the
  ping burst shows the outer QUIC flow peer as `106.73.47.104:5323` — the
  client's WiFi global/NAT address, not a tunnel-subnet address. The
  provider's path socket egresses via the physical interface (IP_BOUND_IF
  binding effective).
- User-space traffic through the tunnel: Safari browsing to external sites
  works with the tunnel up (user-confirmed).
- Reference metrics at single-path steady state: phys_footprint ≈ 2.8 MB,
  os_proc_available_memory ≈ 49.6 MB, per-path socket buffers granted
  6,291,456 B (6 MiB) for SO_SNDBUF/SO_RCVBUF on en0 (platform pre-set was
  1 MiB; the core's 7 MiB request was not rejected down to defaults).

Incidents during bring-up (not gate failures):
- First connection attempts failed with server-side `authentication failed:
  invalid or missing PSK` — stale PSK in the local client config. The QUIC
  handshake itself completed; the server stayed up (no crash observed on the
  auth-failure path in these runs).
- With the tunnel established, browsing initially failed ("no internet"):
  the NE settings carried no DNS servers, so the phone kept querying its
  WiFi LAN resolver, whose private address the full-tunnel default route
  captured and the server NATed to nowhere. Fixed by supplying resolvers in
  `NEDNSSettings` (commit ad9518c), mirroring the Android client where DNS
  comes from app-side config rather than the tunnel protocol. Safari
  browsing confirmed working after the fix.

## G-i2 — multipath distribution: PENDING

## G-i3 — failover + recovery + flap ×3: PENDING

## G-i4 — memory: PENDING

## G-i5 — verdict: PENDING
