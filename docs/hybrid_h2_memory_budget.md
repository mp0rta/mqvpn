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
  + downlink stash (TCP_MSS, 8,960 B) + mqvpn_tcp_flow_t (176 B)
  = 4,465,552 B ≈ 4.46 MB
```

Use **≈ 4.5 MB per concurrent flow** as the working figure. Aggregate worst case at the
default `tcp_max_flows = 256`:

```
256 × 4,465,552 B = 1,143,181,312 B ≈ 1.06 GiB (≈ 1.14 GB decimal)
```

The window/send-buffer pair dominates aggregate memory; the marker tables and PBUF_POOL
together are a few MB (§4) against roughly 1 GiB from the flow table.

## 4. Fixed overhead (independent of concurrent flow count)

Paid once per `mqvpn_tcp_lane_t` instance, or up to the stated cap in the worst case, not
per active flow:

| Item | Worst-case size | Source |
|---|---|---|
| PBUF_POOL static reservation | ≈ 2.3 MiB (unused on ingress, see §1a) | lwipopts.h |
| Sticky-RAW marker table (cap 4096) | ≈ 0.72 MB (`mqvpn_tcp_flow_t` = 176 B each; the 38 B key field is counted within the 176 B) | `TCP_LANE_RAW_MARKER_CAP` |
| CLOSING routing-marker table (cap 4096) | ≈ 0.72 MB, same shape (the downlink stash is freed at the CLOSING transition in `tcp_lane_mark_closing`, so a CLOSING entry never carries a live stash) | `TCP_LANE_CLOSING_CAP` |
| Hash bucket array (8192 buckets) | 64 KiB | tcp_lane.c `mqvpn_tcp_lane_new` |

Total fixed overhead ≈ 3.9 MB worst case, small next to the ~1 GiB flow-table cost at 256
concurrent flows.

## 5. Framing against a future mobile constraint (iOS Network Extension, 50 MB)

This does not apply to v1, which is the Linux CLI client only; no iOS/Network Extension
port exists. It is recorded here because the ~50 MB resident-memory ceiling on iOS Network
Extensions is the constraint a future mobile port would have to design against.

Budgeting for that ceiling, minus ≈ 1 MB of fixed overhead (assuming `PBUF_POOL_SIZE` is
trimmed per §1a and the marker caps are cut for a mobile build — e.g. 256 each, ≈ 30 KB,
negligible), leaves roughly 49 MB for the flow table. Two independent levers, each shown in
isolation (a real port would tune both together against expected concurrency and target
link BDP):

- **Cut concurrency, keep today's window sizing** (~4.46 MB/flow): 49 MB / 4.46 MB ≈ 11
  concurrent flows — a steep drop from 256, likely too restrictive for general app traffic.
- **Keep mobile-plausible concurrency (e.g. 64 flows), shrink the window**: 49 MB / 64 ≈
  766 KB per flow. `TCP_WND` + `TCP_SND_BUF` (~4.19 MB combined) would need to shrink ~5.5×;
  for example `TCP_RCV_SCALE` 5 → 1 (`TCP_WND = 65535 << 1 = 131,070 B`) plus `TCP_SND_BUF`
  reduced to a similar order (~512–640 KB) lands in range, at the cost of lower per-flow
  goodput on high-BDP links.

These figures are scoping input for a future mobile port, not a recommendation.

## 6. Known limitations

- **Sticky-RAW markers are never idle-evicted.** They are replaced only on cap overflow, or
  on an ISN mismatch when the same 5-tuple sees a new SYN. A workload producing many
  short-lived flows misclassified sticky-RAW (e.g. under `tcp=auto`) can hold the marker
  table near its 4096-entry (~0.72 MB) cap indefinitely. This is a memory bound, not a
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
