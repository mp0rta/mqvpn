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

## G-i2 — multipath distribution: **PASS**

Procedure: WiFi + cellular both enabled, tunnel restarted → both paths ACTIVE
(`GATE| ... path[en0] st=1 ... path[pdp_ip0] st=1`, 23:52:35). Cellular came
up with IPv4 (no NAT64 blocker on this SIM). Bulk download via the container
app (sequential GETs of `http://10.0.0.1:8080/bulk-100M.bin` for 60 s),
default WLB scheduler.

Per-path byte deltas over the bulk window (23:52:35 → traffic flatline at
23:55:05):

| Path | Δtx | Δrx | Δ(tx+rx) | ≥1 MiB? |
|---|---|---|---|---|
| en0 (WiFi) | 36.9 MB | 780.1 MB | ~817 MB | PASS |
| pdp_ip0 (cellular) | 130 KB | 7.67 MB | ~7.8 MB | PASS |

Both paths stayed ACTIVE throughout; WLB distributed asymmetrically according
to path capacity (WiFi-dominant), as designed. Aggregate ~787 MB over ~150 s
(~42 Mbps through the tunnel; single-path WiFi reference earlier the same
evening: ~94 MB in ~20 s).

## G-i3 — failover + recovery + flap ×3: **FAIL (1/3), root cause identified: NWPathMonitor delivery**

Procedure: server-side `ping -i 0.2` to the client tunnel IP running
throughout; WiFi toggled off/on three times in one session (both paths ACTIVE
before each cycle). Missed pings counted by icmp_seq gaps.

| Flap | unsatisfied delivery | missed pings (≤10 = PASS) | recovery |
|---|---|---|---|
| 1 (primary-path loss, xqc_path_id 0) | **delayed ~110 s** | **578 (~116 s) — FAIL** | session survived; core retry machinery re-activated en0 on WiFi return; then the late monitor events re-added it cleanly (handle 3) |
| 2 | immediate | **0 — PASS** | fresh add_path_fd 13 s later (handle 4), 2 paths ACTIVE |
| 3 | immediate | **0 — PASS** | fresh add_path_fd 11 s later (handle 5), 2 paths ACTIVE |

Constant across all flaps: client state stayed `MQVPN_STATE_ESTABLISHED`
(never RECONNECTING); cellular path stayed ACTIVE; no slot exhaustion
(handles 3→4→5 across the flaps, MQVPN_MAX_PATHS=8 never approached).
Primary-loss slot end state (spec §1-9 observation): the en0 slot stayed
visible as `MQVPN_PATH_CLOSED` (st=4) in get_paths for ~2 min, then was
reused cleanly — no residual leak observed.

Root cause of flap 1: iOS delivered the `NWPathMonitor(.wifi)` unsatisfied
update ~110 s after the radio went off. Until it arrived, no orderly
`remove_path` ran, so the server kept scheduling downlink onto the dead WiFi
path; inner traffic blacked out even though the cellular path was ACTIVE and
the client core had classified en0 as CLOSED within seconds on its own. When
the platform event finally arrived (flaps 2/3: immediately), failover cost 0
pings. Conclusion: the failover/recovery mechanism is sound end-to-end, but
**NWPathMonitor alone is not a trustworthy event source inside an NE packet
tunnel provider** — it needs a redundant trigger. This is a platform-layer
finding; no core change implicated.

## G-i4 — memory: **PASS**

Metric: `task_vm_info.phys_footprint` (jetsam-relevant; NE limit 50 MB, gate
threshold 40 MB). All three required points far under the limit:

| Point | phys_footprint |
|---|---|
| (a) post-handshake, single path | 2,752,776 B (~2.75 MB) |
| (b) two paths ACTIVE, idle | 2,883,848 B (~2.88 MB) |
| (c) during bulk load (peak observed) | 4,800,776 B (~4.80 MB) |

Non-gate recordings: `os_proc_available_memory()` stayed ~47-50 MB at all
points (never below the 10 MB anomaly threshold). Per-path socket buffers:
both en0 and pdp_ip0 report SO_SNDBUF/SO_RCVBUF = 6,291,456 B (6 MiB) — the
platform pre-set (1 MiB) was superseded by the core's 7 MiB request being
granted at 6 MiB rather than rejected to Darwin UDP defaults.

## G-i5 — verdict: PENDING
