# Hybrid H2 TCP Lane — Per-Flow Memory Budget

Per-flow and aggregate memory cost of the hybrid TCP lane
(`src/hybrid/lwip_port/lwipopts.h`, `src/hybrid/tcp_lane.{h,c}`), derived from the
constants compiled into the current tree.

## 0. Build profiles at a glance

Pool sizing is a three-way split selected in
`src/hybrid/lwip_port/mqvpn_lwip_profile.h`; window sizing is a separate two-way
(iOS vs. rest) split in `lwipopts.h`. The pcb pool is what bounds the honored
`hybrid.TcpMaxFlows`, because `mqvpn_tcp_lane_new` clamps it to
`MEMP_NUM_TCP_PCB / 2` (§2).

| Profile | Selected by | `MEMP_NUM_TCP_PCB` | `MEMP_NUM_TCP_SEG` | Honored `TcpMaxFlows` ceiling |
|---|---|---|---|---|
| desktop / router (Linux, Windows, macOS) | default | 8192 | 8192 | 4096 |
| Android | `__ANDROID__` toolchain predefine | 512 | 2048 | 256 |
| iOS NE | `MQVPN_LWIP_IOS_PROFILE` CMake option | 128 | 512 | 64 |

The **config default stays 256 on every profile** — the ceiling only bounds what an
operator may configure upward. The desktop/router ceiling was 256 through v0.13.0;
it was raised because the OpenMPTCProuter integration aggregates a whole LAN behind
one tunnel, where 256 concurrent inner TCP flows is a real limit. Android keeps the
older pools deliberately: a handset multiplexes far fewer inner flows, and the pools
are `.bss` touched at `lwip_init()`, so the larger pcb pool would be resident cost
with no matching demand.

Sections 1–4 below describe the **desktop/router** profile unless stated otherwise;
§5c gives the iOS-profile table. Android differs from §1 only in the two pool rows.

## 1. Current defaults

| Constant | Source | Value | Note |
|---|---|---|---|
| `TCP_MSS` | lwipopts.h | 8960 B | 9000-byte MTU ceiling − 40 (IP+TCP headers); compile-time upper bound, no per-pcb override in the vendored tree |
| `TCP_RCV_SCALE` | mqvpn_lwip_profile.h | 3 (`MQVPN_LWIP_RCV_SCALE`) | window-scale shift; `TCP_WND` below is the already-scaled effective window, not the 16-bit wire value. Was 5 (2 MiB) through v0.13.0 — cut on router-topology measurement, §5d |
| `TCP_WND` | lwipopts.h | `65535 << 3` = 524,280 B (≈ 512 KiB) | dominant per-flow bound — worst-case receive-side bytes a pcb may hold once already ACKed on the wire |
| `TCP_SND_BUF` | lwipopts.h | 2 × 1024 × 1024 = 2,097,152 B (2 MiB) | per-flow send-buffer bound (`tcp_write` returns `ERR_MEM` above this) |
| `TCP_SNDLOWAT` | lwipopts.h | `TCP_MSS` = 8960 B | inert (netconn/socket-only field, both compiled out); pinned only to satisfy init.c's sanity check |
| `TCP_SND_QUEUELEN` | lwipopts.h | `(4×TCP_SND_BUF + TCP_MSS−1) / TCP_MSS` = 937 segments | per-pcb segment cap |
| `MEMP_NUM_TCP_PCB` | mqvpn_lwip_profile.h | 8192 (Android 512) | lwIP-side hard cap; sets the honored `TcpMaxFlows` ceiling at pool/2 = 4096, but is not the real enforcement point (see §2). ≈ 2.44 MiB of `.bss` at 312 B per `struct tcp_pcb` (LP64), faulted in only once a lane exists — `lwip_init()` runs lazily from `lwip_glue.c`, so hybrid-disabled builds pay nothing resident |
| `MEMP_NUM_TCP_SEG` | mqvpn_lwip_profile.h | 8192 (Android 2048) | global pool shared by every flow (≈ 256 KiB of `.bss` at 32 B per `struct tcp_seg`); a single flow filling its 937-segment `TCP_SND_QUEUELEN` leaves room for only ≈ 8 flows to be simultaneously saturated. Tracks the pcb pool so a fully-occupied flow table still has segments per flow — at the old 2048 against a 4096-flow cap it could not hold even one segment per flow. `tcp_write` returning `ERR_MEM` here is treated as backpressure by `tcp_lane.c`, not as an error |
| `PBUF_POOL_SIZE` | lwipopts.h | 256 | see §1a |
| `PBUF_POOL_BUFSIZE` | lwipopts.h | `LWIP_MEM_ALIGN_SIZE(TCP_MSS + 40 + PBUF_LINK_ENCAPSULATION_HLEN)` ≈ 9000 B aligned | see §1a |
| `TCP_LANE_RAW_MARKER_CAP` | tcp_lane.c | 4096 | sticky-RAW marker cap, compile-time (`#ifndef`-overridable for tests) |
| `TCP_LANE_CLOSING_CAP` | tcp_lane.c | 4096 | post-close routing-marker cap, same shape as the RAW cap |
| hash bucket array | tcp_lane.c `pick_buckets` | 8192 buckets × 8 B pointer = 64 KiB | sized from `tcp_max_flows + TCP_LANE_RAW_MARKER_CAP` (256 + 4096 → next pow2). Unchanged at the 4096 ceiling: 4096 + 4096 lands on the same 8192 buckets, so raising the flow cap costs nothing here |
| `MQVPN_TCP_LANE_BP_HIGH_WATER` | tcp_lane.h | 262,144 B (256 KiB) | see §2 — not the per-flow hard bound |
| `MQVPN_TCP_LANE_BP_LOW_WATER` | tcp_lane.h | 65,536 B (64 KiB) | resume threshold, prevents withhold/resume flapping |

### 1a. PBUF_POOL status

`PBUF_POOL_SIZE` is 256 (≈ 2.3 MiB of static/BSS reservation: 256 pbufs ×
~9000 usable bytes each). It is kept nonzero to satisfy an unconditional compile-time
check in `init.c` (`TCP_WND <= PBUF_POOL_SIZE * (PBUF_POOL_BUFSIZE - headers)` when
`MEMP_MEM_MALLOC == 0 && PBUF_POOL_SIZE > 0`), independent of whether any code path
draws from the pool.

Since commit `f20aa36` ("PBUF_RAM ingress to stop cross-flow PBUF_POOL exhaustion"),
`mqvpn_lwip_input` allocates every ingress packet as `PBUF_RAM` (exact-size, heap-backed),
not `PBUF_POOL`. The pool is therefore statically reserved but unused on the data path in
this build: the only `pbuf_alloc(..., PBUF_POOL)` call sites in the vendored lwIP tree are
in `netif/ppp/vj.c`, `netif/ppp/pppos.c`, `netif/slipif.c`, `netif/lowpan6_common.c`, and
the Unix-port `pcapif.c`/`tapif.c` drivers — none of which are compiled here (confirmed
against `build-debug/compile_commands.json`). `PBUF_POOL_SIZE` could drop to a minimal
placeholder or 0 to reclaim the ~2.3 MiB reservation.

## 2. What bounds per-flow memory

The uplink backpressure watermarks (`MQVPN_TCP_LANE_BP_HIGH_WATER` / `_LOW_WATER`) are
hysteresis thresholds on the relay-owned retry stash, not a hard per-flow memory cap.
Bytes lwIP has already delivered to the TCP-lane receive callback were sequenced and
ACKed on the wire; they cannot be dropped and must be queued whenever xquic will not yet
accept them. Withholding `tcp_recved()` only stops the receive window from re-opening —
the peer may still fill whatever window was already advertised.

The worst-case per-flow queue is therefore larger than `TCP_WND` (512 KiB). In the
`PENDING_STREAM` case (the H3 CONNECT-TCP stream is not yet open and uplink bytes are
queued pending the 2xx gate), `tcp_lane_uplink_deliver` grants `tcp_recved()` for bytes
below `MQVPN_TCP_LANE_BP_HIGH_WATER` (256 KiB) while withholding the rest, re-opening the
window for that slice. A peer that keeps filling it can push a further 256 KiB beyond the
one-time `TCP_WND` fill, giving a worst-case uplink queue of `TCP_WND` + 256 KiB. The
dominant per-flow cost is thus `TCP_WND` + 256 KiB + `TCP_SND_BUF`, not the watermarks.

Config knobs, by when they take effect:

- **`hybrid.TcpMaxFlows` (`tcp_max_flows`, session-config key)** — default 256. The real
  enforcement point, checked in `tcp_lane.c` before lwIP sees the SYN, rather than
  `MEMP_NUM_TCP_PCB` (lwIP-side headroom). Configured values above `MEMP_NUM_TCP_PCB / 2`
  are clamped to it at lane creation (§0) and the clamp is logged, so the honored value
  is `min(configured, profile ceiling)` — raising it past the ceiling is silent-free but
  ineffective.
- **BP high/low water (compile-time, `tcp_lane.h`)** — internal constants, not exposed as
  config. Bound only the relay-stash portion of the uplink queue.
- **`lwipopts.h` window sizing (compile-time)** — `TCP_WND` + `TCP_SND_BUF`, the dominant
  per-flow cost and the only one requiring a rebuild to change.

## 3. Per-flow and aggregate cost

Per-flow worst case is one `ACTIVE` flow saturated in both directions: receive window
fully outstanding including the `PENDING_STREAM` 256 KiB re-open headroom (§2), send buffer
fully queued, one downlink chunk stashed awaiting a `tcp_write` retry, plus the flow's own
control block.

```
TCP_WND (524,280 B) + 256 KiB re-open (262,144 B) + TCP_SND_BUF (2,097,152 B)
  + downlink stash (TCP_MSS, 8,960 B) + mqvpn_tcp_flow_t (200 B)
  = 2,892,736 B ≈ 2.89 MB
```

Use **≈ 2.9 MB** as the worst case for *one* flow. **Do not multiply it by the flow count**
— the send-buffer term is not independently reachable per flow. `TCP_SND_BUF` is drained
through the *global* `MEMP_NUM_TCP_SEG` pool, and `TCP_SND_QUEUELEN` caps one pcb at 937
segments, so only ⌊8192/937⌋ ≈ 8 flows can hold a full send queue simultaneously on
desktop/router. The send side therefore contributes an aggregate ceiling of
`MEMP_NUM_TCP_SEG × payload` — ≤ 73 MB at the compile-time `TCP_MSS`, ≈ 11 MB at the real
~1382-byte tunnel MSS — regardless of how many flows exist.

What *does* scale per flow is the uplink queue, which is lane-owned and heap-backed:

```
TCP_WND (524,280 B) + PENDING_STREAM high-water (262,144 B) = 786,424 B ≈ 0.75 MiB
```

Aggregate worst case is that term times the flow count, plus the flat send-side ceiling:

```
256  ×   786,424 B =   201,324,544 B ≈ 192 MiB  (+ ≤73 MB send side)
4096 ×   786,424 B = 3,221,192,704 B ≈ 3.0 GiB  (+ ≤73 MB send side)
```

### 3a. Raising `TcpMaxFlows` toward the desktop/router ceiling

The per-flow uplink term does not shrink as the cap grows, so the aggregate worst case
scales linearly with it — at the 4096 ceiling (§0) it is ≈ 3.0 GiB (§3). That is a bound,
not a forecast: it assumes all 4096 flows are simultaneously backpressured with a full
window outstanding, which no realistic traffic mix reaches (a router's flow table is
dominated by idle and short flows, each costing the ~200 B control block plus whatever is
actually in flight).

**Cross-check against the iOS profile.** The two profiles must tell the same story, and
they do. iOS caps at 64 flows to fit a ~50 MB Network Extension ceiling; its per-flow
uplink term is `TCP_WND` (262,140) + high-water (`TCP_WND`/2 = 131,070) = 393,210 B, so
64 flows ≈ 24 MiB — comfortably inside that ceiling (§5c). Desktop/router is 64× the flow
count *and* 2× the per-flow term (786,424 / 393,210, from the 2× wider window against a
2× smaller relative high-water), i.e. 128× the iOS total: 24 MiB × 128 = 3.0 GiB. The
factor is 128, not 64, because the flow ceiling and the window sizing are independent
axes (§0). The two still differ on both, but far less than when desktop/router ran a
2 MiB window — that gap is what §5d closed.

**CPU, not memory, is likely the first wall.** lwIP demultiplexes every inbound
segment by walking `tcp_active_pcbs` linearly (`tcp_input`, `third_party/lwip/src/core/tcp_in.c`)
— there is no hash. The list is move-to-front, so a workload where a few flows carry most
packets stays cheap, but cost scales with the number of *concurrently active* flows: at
4096 the average walk is ~16× the old 256-flow ceiling. A router genuinely running
thousands of simultaneously busy inner flows can saturate a core on demultiplexing alone,
before either the flow cap or the memory bound is reached. Like the memory figure, this
scales with real concurrency and not with the configured cap — raising the cap costs
nothing until the flows actually exist.

**`TcpMaxFlows` caps a flow count, not bytes.** It bounds memory only derivatively: because
the lane-owned per-flow memory has a hard ceiling, limiting the count yields a memory bound
as `count × per-flow ceiling`. That derivation is what makes a second, byte-denominated
budget unnecessary — so there deliberately is none. The largest per-flow term is the uplink
queue:
`tcp_lane_uplink_deliver` takes ownership of each received pbuf and tracks it exactly in
`uplink_queued_bytes` (`src/hybrid/tcp_lane_uplink.c`), reaching `TCP_WND` plus the
`PENDING_STREAM` high-water — ~0.75 MiB — for a flow whose H3 stream is backpressured. The
flow cap bounds how many flows can be in that state, and it is a *true* bound rather than
an approximate one:

- A SYN over the cap never enters the lane. It falls back to the RAW CONNECT-IP lane
  (`mqvpn_client.c`), so hitting the cap costs those flows the TCP-lane treatment but does
  not break them — this is graceful degradation, not a refusal.
- `CLOSING` routing markers stop counting toward `tcp_max_flows` but cannot smuggle memory
  past the cap: `tcp_lane_mark_closing` is reached only from `tcp_lane_finish_clean_close`,
  which requires the uplink FIN to have been sent, which in turn requires the uplink queue
  to have fully drained. Every unclean teardown goes through `tcp_lane_remove_flow`, which
  frees the queue outright. So a marker never holds uplink bytes.

The operator rule is therefore just arithmetic on one knob: **the client-side worst case is
`TcpMaxFlows` × ~0.75 MiB** (≈ 3.0 GiB at 4096, ≈ 192 MiB at 256). Size the cap from the
box's RAM. Note this is the *client* knob — `TcpMaxGlobalFlows` is server-only and bounds
the server's egress fd budget, not this lane's memory.

- The honest planning figure is the *expected* concurrent-backpressured flow count, not the
  cap; the cap is the ceiling that keeps the worst case finite.
- The window sizing has already been taken as far as measurement supports (§5d): 512 KiB,
  down from the 2 MiB shipped through v0.13.0, which is what makes 4096 cost ≈ 3.0 GiB
  instead of ≈ 9.0 GiB. Going lower needs the watermarks derived from `TCP_WND` the way
  the iOS profile does — the non-iOS `BP_HIGH_WATER` is a fixed 256 KiB, and a scale below
  3 would put it at or above `TCP_WND` (compile-time guarded in mqvpn_lwip_profile.h).
  §5a measured `TCP_WND` down to 64 KiB with no aggregate goodput loss on this
  architecture — the lwIP hop is device-internal, so its window is not covering WAN
  bytes-in-flight. A build with a smaller `TCP_RCV_SCALE` cuts the dominant per-flow term
  roughly proportionally. That knob is currently exposed only through the iOS profile;
  generalizing it to desktop/router builds is unimplemented, and is the natural follow-up
  if high-flow-count deployments turn out to need it.

## 4. Fixed overhead (independent of concurrent flow count)

Paid once per `mqvpn_tcp_lane_t` instance, or up to the stated cap in the worst case, not
per active flow:

| Item | Worst-case size | Source |
|---|---|---|
| pcb pool (`MEMP_NUM_TCP_PCB`) | ≈ 2.44 MiB (8192 × 312 B; Android 512 → ≈ 156 KiB) | mqvpn_lwip_profile.h |
| TCP segment pool (`MEMP_NUM_TCP_SEG`) | ≈ 256 KiB (8192 × 32 B; Android 2048 → ≈ 64 KiB) | mqvpn_lwip_profile.h |
| PBUF_POOL static reservation | ≈ 2.3 MiB (unused on ingress, see §1a) | lwipopts.h |
| Sticky-RAW marker table (cap 4096) | ≈ 0.82 MB (`mqvpn_tcp_flow_t` = 200 B each, measured on the dual-stack layout; the 38 B key field is counted within the 200 B) | `TCP_LANE_RAW_MARKER_CAP` |
| CLOSING routing-marker table (cap 4096) | ≈ 0.82 MB, same shape (the downlink stash is freed at the CLOSING transition in `tcp_lane_mark_closing`, so a CLOSING entry never carries a live stash) | `TCP_LANE_CLOSING_CAP` |
| Hash bucket array (8192 buckets) | 64 KiB | tcp_lane.c `mqvpn_tcp_lane_new` |

Total fixed overhead ≈ 6.8 MB worst case on desktop/router (≈ 4.2 MB on Android), small
next to the ~192 MiB flow-table cost at 256 concurrent flows (§3). Only the two lwIP pools grew
with the raised ceiling — the marker tables and hash buckets were already sized for 4096
entries and are unchanged (§1).

### 5d. Router-topology window measurement (desktop/router scale 5 → 3)

§5a retired the window-shrink goodput caveat, but scoped the retirement to a topology
where the inner TCP peer sits on the *same device* as lwIP. A router breaks that: the
inner peer is a separate LAN machine, so the window has to cover a real LAN
bandwidth-delay product. Every pre-existing sweep inherited the same-device shape
(`bench_env_setup.sh` runs iperf3 inside `NS_CLIENT`), so the desktop/router window could
not be sized from them without applying §5a outside its stated scope.

`benchmarks/bench_router_window.sh` builds the missing shape — a `bench-lan` netns behind
a forwarding, MASQUERADE-ing router — and sweeps `MQVPN_LWIP_RCV_SCALE`. Run
2026-07-22, WAN legs at the harness default (300 Mbit/10 ms + 80 Mbit/30 ms, ≈ 350 Mbps
aggregate in practice), 3 reps × {P=1, P=8} per cell:

| LAN hop | P | s5 (2 MiB) | s4 (1 MiB) | s3 (512 KiB) |
|---|---|---|---|---|
| 0.5 ms/leg | 1 | 334.0 Mbps | 324.2 (−2.9 %) | 321.9 (−3.6 %) |
| 0.5 ms/leg | 8 | 355.1 Mbps | 352.1 (−0.8 %) | 353.5 (−0.5 %) |
| 4 ms/leg | 1 | 335.7 Mbps | 342.3 (+2.0 %) | 337.0 (+0.4 %) |
| 4 ms/leg | 8 | 352.2 Mbps | 355.1 (+0.8 %) | 354.4 (+0.6 %) |

Worst cell −3.6 % against a −5 % gate → scale 3 adopted. Two caveats worth stating
plainly rather than burying:

- **The window was never the binding constraint in this run.** The WAN capped throughput
  at ≈ 350 Mbps, putting the LAN BDP at 43 KiB (1 ms RTT) and 342 KiB (8 ms RTT) against
  a 512 KiB window. The run therefore shows *"512 KiB is not limiting for a realistic
  router LAN"*, not *"512 KiB is the boundary"*. The boundary is arithmetic:
  `window / RTT` caps a single inner flow at **4.2 Gbit/s over a 1 ms LAN**, 0.52 Gbit/s
  over an (unrealistic for a LAN) 8 ms one.
- **The −3.6 % cell is not a window effect.** It appears at the *low*-RTT LAN, where the
  BDP is 43 KiB — twelve times inside the window. A genuine window-BDP limit has to get
  worse as RTT grows; this one reverses sign (+0.4 %) at 8× the RTT. Ordering or CC
  variance is the likelier cause, and it stays inside the gate either way.

Raw data: `bench_results/router_window/`.

## 5. iOS profile (Network Extension, 50 MB)

This section originally scoped the ~50 MB resident-memory ceiling on iOS Network
Extensions as input for a future mobile port ("cut concurrency" vs. "shrink the window",
below), since v1 was Linux-CLI-only and no such port existed. That port now exists in-tree:
a compile-time `MQVPN_LWIP_IOS_PROFILE` build flag (`src/hybrid/lwip_port/lwipopts.h`)
shrinks the constants from §1, parameterized by `MQVPN_LWIP_IOS_RCV_SCALE` (default 2),
and sizes the pools (`MEMP_NUM_TCP_PCB` = 128) for a `tcp_max_flows` cut to 64, a ceiling the iOS client sets at runtime rather than the build flag (the config default remains 256). This is exactly the second
lever from the original estimate below, exercised together with the first rather than in
isolation. §5a revises the goodput caveat that estimate ended on against measured data;
§5b covers the QUIC-side complement; §5c gives the shipped profile's budget table.

### 5a. Retiring the window-shrink goodput caveat — for this topology

The original two-lever estimate (kept below for context) ended by noting that shrinking
`TCP_WND`/`TCP_SND_BUF` comes "at the cost of lower per-flow goodput on high-BDP links."
That caveat assumed the inner TCP hop's own window has to cover the same wide-area
bytes-in-flight an end-to-end TCP connection would. It does not, in this architecture: the
lwIP TCP lane terminates the inner TCP connection on-device and hands payload straight to
the QUIC/DATAGRAM outer transport in the same process. The hop the shrunk window bounds is
a device-internal handoff (µs-scale latency, no real BDP to fill), not the WAN path itself
— the WAN bytes-in-flight belong to the QUIC layer's own flow-control window (§5b), not the
lwIP TCP window.

Measured data (Linux netns, 2×100 Mbit/s paths per config, QUIC-side `RecvRateLimit` fixed at
125 MB/s — see §5b) supports the reframing for this topology: sweeping `TCP_RCV_SCALE` /
`TCP_WND` down through and below the iOS profile's default shows no aggregate goodput
loss.

Window sweep, hybrid-on aggregate throughput (mean of 2 schedulers × 5 path-count values ×
3 repetitions, OK rows only):

| `TCP_WND` @ scale | Config A (symmetric, 60 ms/leg) | Config B (asymmetric, 15/80 ms per leg) |
|---|---|---|
| ref, 2 MiB (scale 5 — the desktop/router default at the time; now 3, see §5d) | 186.7 Mbps | 186.6 Mbps |
| 512 KiB (scale 3 — now the desktop/router default) | 186.5 Mbps | 186.4 Mbps |
| 256 KiB (scale 2 — iOS default) | 187.0 Mbps | 186.4 Mbps |
| 64 KiB (scale 0) | 186.9 Mbps | 186.9 Mbps |

The iOS default (scale 2) lands at +0.1 % / −0.1 % aggregate versus the 2 MiB reference
across the two path configs; the worst single cell across the whole sweep is −1.1 %,
against a −5 % regression gate. Even the most aggressive 64 KiB window tested is
statistically indistinguishable from the 2 MiB reference — none of the swept window sizes
was the bottleneck on these paths.

An on-device-hop microbench (classifier + lwIP termination only, no WAN leg) confirms the
same non-limiting result at the throughput range the iOS profile actually has to
sustain: reference (scale 5) 20.58 Gbit/s vs. iOS (scale 2) 19.93 Gbit/s — both well
clear of the 10 Gbit/s gate, iOS at 96.8 % of reference.

**Scope of the retirement.** This applies to the terminated-lane architecture measured
here, where the inner TCP connection ends on-device and the outer QUIC connection alone
carries the WAN leg. It does not extend to an lwIP deployment where the TCP hop itself is
the thing crossing the WAN (no outer transport terminating it locally) — in that shape the
original caveat still holds: shrinking the window caps the achievable per-flow goodput at
the link's real bandwidth-delay product.

### 5b. QUIC-side receive-rate cap

Shrinking the inner TCP window does not, by itself, bound the outer QUIC connection's own
receive buffering — an unconstrained QUIC flow-control window can still grow to whatever
the peer/BDP estimate allows. The iOS profile pairs the lwIP shrink with a
connection-level cap on the QUIC side: `[Advanced] RecvRateLimit` (config key) →
`recv_rate_bytes_per_sec` (`mqvpn_conn_settings_input_t`, `src/mqvpn_conn_settings.h`) →
xquic. The knob is client-only (the builder hard-zeroes it for servers, since a
server-side cap would throttle client uplink instead); the iOS engine sets it to 125 MB/s.

The cap bounds the QUIC connection window to roughly `rate × srtt`, clamped at 16 MiB.
Observed in the same measurement run (downlink, debug log): initial connection window
7,500,000 B (= 125 MB/s × 60 ms srtt at connection start), steady-state 16,777,216 B (the
16 MiB clamp) once the srtt estimate settles higher. Both are bounded values, not the
engine's unbounded default — the cap is doing real work here, not sitting as a no-op
ceiling above what the connection would reach anyway.

### 5c. iOS-profile budget table

Shipped constants for `MQVPN_LWIP_IOS_PROFILE` at the default scale (2) and
`tcp_max_flows` = 64:

| Constant | Source | Value (scale 2) | Note |
|---|---|---|---|
| `TCP_RCV_SCALE` (`MQVPN_LWIP_IOS_RCV_SCALE`) | lwipopts.h | 2 (default) | down from the non-iOS 3 (which was itself 5 through v0.13.0) |
| `TCP_WND` | lwipopts.h | `65535 << 2` = 262,140 B (≈256 KiB) | shared derivation (§1) at iOS scale |
| `TCP_SND_BUF` | lwipopts.h | `65536 << 2` = 262,144 B (256 KiB) | down from 2 MiB |
| `MEMP_NUM_TCP_PCB` | mqvpn_lwip_profile.h | 128 (`tcp_max_flows`=64 + headroom) | down from 8192 desktop/router, 512 Android |
| `MEMP_NUM_TCP_SEG` | mqvpn_lwip_profile.h | 512, shared send+OOSEQ pool | down from 8192 desktop/router, 2048 Android |
| `PBUF_POOL_SIZE` | lwipopts.h | 32 (power-of-2 ladder off `TCP_WND`) | down from 256 |
| `MQVPN_TCP_LANE_BP_HIGH_WATER` | tcp_lane.h | `TCP_WND`/2 ≈ 131,070 B | down from the fixed 256 KiB |
| `MQVPN_TCP_LANE_BP_LOW_WATER` | tcp_lane.h | `TCP_WND`/8 ≈ 32,767 B | down from 64 KiB |
| `TCP_LANE_RAW_MARKER_CAP` / `TCP_LANE_CLOSING_CAP` | tcp_lane.h | 256 each | down from 4096 each |

Derived subtotal at 64 concurrent flows:

| Component | Size | Basis |
|---|---|---|
| 64 × `TCP_WND` (receive) | ≈ 16 MiB | 64 × 262,140 B |
| Shared TCP segment pool (`MEMP_NUM_TCP_SEG`) | ≈ 4.4 MiB | 512-segment cap, shared send+OOSEQ |
| `PBUF_POOL` (32 pbufs) | ≈ 0.29 MiB | 32 × `PBUF_POOL_BUFSIZE` |
| Marker tables (RAW + CLOSING, 256 each) | ≈ 0.1 MiB | §4 shape, iOS caps (512 × 200 B) |
| 64 × `TCP_MSS` downlink stash | ≈ 0.55 MiB | one stashed downlink chunk per flow (§3) |
| PCB pool (`MEMP_NUM_TCP_PCB` = 128) | ≈ 0.04 MiB | measured: `struct tcp_pcb` = 312 B × 128 |
| **Subtotal** | **≈ 21.4 MiB** | lower-bound-leaning, see below |

**Not counted in this subtotal** — it is lower-bound-leaning, not a hard ceiling: per-flow
`mqvpn_tcp_flow_t` uplink-queue/relay objects and stash bytes beyond the one downlink chunk
already counted, pbuf metadata/struct overhead on top of the payload-only accounting above,
and the hash bucket array (§4 — small, fixed, unaffected by the iOS marker-cap shrink).
Final authority is on-device measurement, not this arithmetic.

Add the QUIC-side receive-rate cap (§5b) on top: typically ≈ 7.15 MiB (`rate × srtt` at
60 ms), up to the 16 MiB clamp in the worst case. All-up: ≈ 21.4 MiB (lwIP iOS profile)
+ up to 16 MiB (QUIC cap, worst case) ≈ 37.4 MiB against the 50 MB Network Extension
ceiling, leaving headroom for process/runtime overhead outside this doc's scope.

### 5d. Original scoping estimate (kept for context)

The estimate below predates the shipped profile; §5a explains why its closing caveat no
longer holds for this architecture, and §5c gives the actual shipped numbers in its place.

Budgeting for the 50 MB ceiling, minus ≈ 1 MB of fixed overhead (assuming `PBUF_POOL_SIZE`
is trimmed per §1a and the marker caps are cut for an iOS build — e.g. 256 each, ≈ 30 KB,
negligible), leaves roughly 49 MB for the flow table. Two independent levers, each shown in
isolation (the shipped profile, §5c, applies both together):

- **Cut concurrency, keep today's window sizing** (~4.46 MB/flow): 49 MB / 4.46 MB ≈ 11
  concurrent flows — a steep drop from 256, likely too restrictive for general app traffic.
- **Keep mobile-plausible concurrency (e.g. 64 flows), shrink the window**: 49 MB / 64 ≈
  766 KB per flow. `TCP_WND` + `TCP_SND_BUF` (~4.19 MB combined) would need to shrink ~5.5×;
  for example `TCP_RCV_SCALE` 5 → 1 (`TCP_WND = 65535 << 1 = 131,070 B`) plus `TCP_SND_BUF`
  reduced to a similar order (~512–640 KB) lands in range.

## 6. Known limitations

- **Sticky-RAW markers are never idle-evicted.** They are replaced only on cap overflow, or
  on an ISN mismatch when the same 5-tuple sees a new SYN. A workload producing many
  short-lived flows misclassified sticky-RAW (e.g. under `tcp=auto`) can hold the marker
  table near its 4096-entry (~0.82 MB) cap indefinitely. This is a memory bound, not a
  correctness issue, but unlike TCP-lane flows it is not time-bounded by the idle sweep.
- **`TCP_MSS` is a compile-time upper bound.** The vendored lwIP tree exposes no per-pcb MSS
  setter (`tcp_mss(pcb)` is a read-only accessor); the effective per-pcb MSS is derived at
  connect/accept time from `netif->mtu`, clamped to `TCP_MSS`. Raising the TUN MTU ceiling
  above 9000 requires bumping `TCP_MSS` — and, per lwipopts.h's derivation, `TCP_WND` and
  `TCP_SND_BUF` alongside it — at compile time. There is no runtime knob.
- **`PBUF_POOL_SIZE` = 256 remains statically reserved** (≈ 2.3 MiB) despite being unused on
  the data path in this build (§1a). Shrinking it to a minimal placeholder or 0 is a
  tightening candidate.
- **`MEMP_NUM_TCP_SEG` (global) can bottleneck before `tcp_max_flows`.** Under a bursty
  workload only ≈ 8 flows on desktop/router (8192 segments) or ≈ 2 on Android (2048) can be
  simultaneously saturated at `TCP_SND_BUF` before the shared segment pool is exhausted,
  after which `tcp_write` backpressure — not a config cap — limits further flows from fully
  using their send buffer concurrently.
- **Inbound demultiplexing is O(active flows)** — lwIP's `tcp_input` scans `tcp_active_pcbs`
  linearly with no hash. See §3a: this is the practical scaling wall at high flow counts,
  ahead of both the memory bound and the flow cap.
