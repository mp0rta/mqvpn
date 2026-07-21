# Hybrid H2 TCP Lane — Per-Flow Memory Budget

Per-flow and aggregate memory cost of the hybrid TCP lane
(`src/hybrid/lwip_port/lwipopts.h`, `src/hybrid/tcp_lane.{h,c}`), derived from the
constants compiled into the current tree.

## 1. Current defaults

| Constant | Source | Value | Note |
|---|---|---|---|
| `TCP_MSS` | lwipopts.h | 8960 B | 9000-byte MTU ceiling − 40 (IP+TCP headers); compile-time upper bound, no per-pcb override in the vendored tree |
| `TCP_RCV_SCALE` | lwipopts.h | 5 | window-scale shift; `TCP_WND` below is the already-scaled effective window, not the 16-bit wire value |
| `TCP_WND` | lwipopts.h | `65535 << 5` = 2,097,120 B (≈ 2.00 MiB) | dominant per-flow bound — worst-case receive-side bytes a pcb may hold once already ACKed on the wire |
| `TCP_SND_BUF` | lwipopts.h | 2 × 1024 × 1024 = 2,097,152 B (2 MiB) | per-flow send-buffer bound (`tcp_write` returns `ERR_MEM` above this) |
| `TCP_SNDLOWAT` | lwipopts.h | `TCP_MSS` = 8960 B | inert (netconn/socket-only field, both compiled out); pinned only to satisfy init.c's sanity check |
| `TCP_SND_QUEUELEN` | lwipopts.h | `(4×TCP_SND_BUF + TCP_MSS−1) / TCP_MSS` = 937 segments | per-pcb segment cap |
| `MEMP_NUM_TCP_PCB` | lwipopts.h | 512 | lwIP-side hard cap, sized with headroom above the config default; not the real enforcement point (see §2) |
| `MEMP_NUM_TCP_SEG` | lwipopts.h | 2048 | global pool shared by every flow; a single flow filling its 937-segment `TCP_SND_QUEUELEN` leaves room for only ≈ 2 flows to be simultaneously saturated. `tcp_write` returning `ERR_MEM` here is treated as backpressure by `tcp_lane.c`, not as an error |
| `PBUF_POOL_SIZE` | lwipopts.h | 256 | see §1a |
| `PBUF_POOL_BUFSIZE` | lwipopts.h | `LWIP_MEM_ALIGN_SIZE(TCP_MSS + 40 + PBUF_LINK_ENCAPSULATION_HLEN)` ≈ 9000 B aligned | see §1a |
| `TCP_LANE_RAW_MARKER_CAP` | tcp_lane.c | 4096 | sticky-RAW marker cap, compile-time (`#ifndef`-overridable for tests) |
| `TCP_LANE_CLOSING_CAP` | tcp_lane.c | 4096 | post-close routing-marker cap, same shape as the RAW cap |
| hash bucket array | tcp_lane.c `pick_buckets` | 8192 buckets × 8 B pointer = 64 KiB | sized from `tcp_max_flows + TCP_LANE_RAW_MARKER_CAP` (256 + 4096 → next pow2) |
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

The worst-case per-flow queue is therefore larger than `TCP_WND` (~2 MiB). In the
`PENDING_STREAM` case (the H3 CONNECT-TCP stream is not yet open and uplink bytes are
queued pending the 2xx gate), `tcp_lane_uplink_deliver` grants `tcp_recved()` for bytes
below `MQVPN_TCP_LANE_BP_HIGH_WATER` (256 KiB) while withholding the rest, re-opening the
window for that slice. A peer that keeps filling it can push a further 256 KiB beyond the
one-time `TCP_WND` fill, giving a worst-case uplink queue of `TCP_WND` + 256 KiB. The
dominant per-flow cost is thus `TCP_WND` + 256 KiB + `TCP_SND_BUF`, not the watermarks.

Config knobs, by when they take effect:

- **`hybrid.TcpMaxFlows` (`tcp_max_flows`, session-config key)** — default 256. The real
  enforcement point, checked in `tcp_lane.c` before lwIP sees the SYN, rather than
  `MEMP_NUM_TCP_PCB` (512, lwIP-side headroom).
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
TCP_WND (2,097,120 B) + 256 KiB re-open (262,144 B) + TCP_SND_BUF (2,097,152 B)
  + downlink stash (TCP_MSS, 8,960 B) + mqvpn_tcp_flow_t (200 B)
  = 4,465,576 B ≈ 4.47 MB
```

Use **≈ 4.5 MB per concurrent flow** as the working figure. Aggregate worst case at the
default `tcp_max_flows = 256`:

```
256 × 4,465,576 B = 1,143,187,456 B ≈ 1.06 GiB (≈ 1.14 GB decimal)
```

The window/send-buffer pair dominates aggregate memory; the marker tables and PBUF_POOL
together are a few MB (§4) against roughly 1 GiB from the flow table.

## 4. Fixed overhead (independent of concurrent flow count)

Paid once per `mqvpn_tcp_lane_t` instance, or up to the stated cap in the worst case, not
per active flow:

| Item | Worst-case size | Source |
|---|---|---|
| PBUF_POOL static reservation | ≈ 2.3 MiB (unused on ingress, see §1a) | lwipopts.h |
| Sticky-RAW marker table (cap 4096) | ≈ 0.82 MB (`mqvpn_tcp_flow_t` = 200 B each, measured on the dual-stack layout; the 38 B key field is counted within the 200 B) | `TCP_LANE_RAW_MARKER_CAP` |
| CLOSING routing-marker table (cap 4096) | ≈ 0.82 MB, same shape (the downlink stash is freed at the CLOSING transition in `tcp_lane_mark_closing`, so a CLOSING entry never carries a live stash) | `TCP_LANE_CLOSING_CAP` |
| Hash bucket array (8192 buckets) | 64 KiB | tcp_lane.c `mqvpn_tcp_lane_new` |

Total fixed overhead ≈ 4.1 MB worst case, small next to the ~1 GiB flow-table cost at 256
concurrent flows.

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
| ref, 2 MiB (scale 5 — current desktop/router default) | 186.7 Mbps | 186.6 Mbps |
| 512 KiB (scale 3) | 186.5 Mbps | 186.4 Mbps |
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
| `TCP_RCV_SCALE` (`MQVPN_LWIP_IOS_RCV_SCALE`) | lwipopts.h | 2 (default) | down from 5 |
| `TCP_WND` | lwipopts.h | `65535 << 2` = 262,140 B (≈256 KiB) | shared derivation (§1) at iOS scale |
| `TCP_SND_BUF` | lwipopts.h | `65536 << 2` = 262,144 B (256 KiB) | down from 2 MiB |
| `MEMP_NUM_TCP_PCB` | lwipopts.h | 128 (`tcp_max_flows`=64 + headroom) | down from 512 |
| `MEMP_NUM_TCP_SEG` | lwipopts.h | 512, shared send+OOSEQ pool | down from 2048 |
| `PBUF_POOL_SIZE` | lwipopts.h | 32 (power-of-2 ladder off `TCP_WND`) | down from 256 |
| `MQVPN_TCP_LANE_BP_HIGH_WATER` | tcp_lane.h | `TCP_WND`/2 ≈ 131,070 B | down from 256 KiB |
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
- **`MEMP_NUM_TCP_SEG` (2048, global) can bottleneck before `tcp_max_flows` (256).** Under a
  bursty workload only ≈ 2 flows can be simultaneously saturated at `TCP_SND_BUF` before the
  shared segment pool is exhausted, after which `tcp_write` backpressure — not a config cap —
  limits further flows from fully using their send buffer concurrently.
