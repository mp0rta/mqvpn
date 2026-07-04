# Hybrid H2 TCP Lane — Per-Flow Memory Budget

Analysis of the hybrid TCP lane's (`src/hybrid/lwip_port/lwipopts.h`,
`src/hybrid/tcp_lane.{h,c}`) per-flow and aggregate memory cost, computed from the
values actually compiled into the tree today (not from earlier plan-stage estimates).

## 1. Current defaults

| Constant | Source | Value | Note |
|---|---|---|---|
| `TCP_MSS` | lwipopts.h | 8960 B | 9000-byte MTU ceiling − 40 (IP+TCP headers); compile-time upper bound, no per-pcb override in the vendored tree |
| `TCP_RCV_SCALE` | lwipopts.h | 5 | wire-encoding shift; `TCP_WND` below is the already-scaled effective window, not the 16-bit wire value |
| `TCP_WND` | lwipopts.h | `65535 << 5` = 2,097,120 B (≈ 2.00 MiB) | **dominant per-flow bound** — worst-case bytes a pcb may have in flight on the receive side once already ACKed on the wire |
| `TCP_SND_BUF` | lwipopts.h | 2 × 1024 × 1024 = 2,097,152 B (2 MiB) | per-flow send-buffer bound (`tcp_write` returns `ERR_MEM` above this) |
| `TCP_SNDLOWAT` | lwipopts.h | `TCP_MSS` = 8960 B | functionally inert (netconn/socket-only field, both compiled out) — pinned only to satisfy init.c's unconditional sanity check |
| `TCP_SND_QUEUELEN` | lwipopts.h | `(4×TCP_SND_BUF + TCP_MSS−1) / TCP_MSS` = 937 segments | per-pcb segment cap |
| `MEMP_NUM_TCP_PCB` | lwipopts.h | 512 | lwIP-side hard cap, sized with headroom above the config default; **not** the real enforcement point (see §2) |
| `MEMP_NUM_TCP_SEG` | lwipopts.h | 2048 | **global** pool shared by every flow — a single flow filling its 937-segment `TCP_SND_QUEUELEN` at once leaves room for only ≈ 2 flows to be simultaneously fully saturated before the pool is exhausted; `tcp_write` returning `ERR_MEM` here is handled as backpressure by `tcp_lane.c`, not treated as an error |
| `PBUF_POOL_SIZE` | lwipopts.h | 256 | see §1a |
| `PBUF_POOL_BUFSIZE` | lwipopts.h | `LWIP_MEM_ALIGN_SIZE(TCP_MSS + 40 + PBUF_LINK_ENCAPSULATION_HLEN)` ≈ 9000 B aligned | see §1a |
| `TCP_LANE_RAW_MARKER_CAP` | tcp_lane.c | 4096 | sticky-RAW marker cap, compile-time (`#ifndef`-overridable for tests) |
| `TCP_LANE_CLOSING_CAP` | tcp_lane.c | 4096 | post-close routing-marker cap, same shape as the RAW cap |
| hash bucket array | tcp_lane.c `pick_buckets` | 8192 buckets × 8 B pointer = 64 KiB | sized from `tcp_max_flows + TCP_LANE_RAW_MARKER_CAP` (256 + 4096 → next pow2) |
| `MQVPN_TCP_LANE_BP_HIGH_WATER` | tcp_lane.h | 262,144 B (256 KiB) | see §2 — **not** the per-flow hard bound |
| `MQVPN_TCP_LANE_BP_LOW_WATER` | tcp_lane.h | 65,536 B (64 KiB) | resume threshold, prevents withhold/resume flapping |

### 1a. PBUF_POOL: live or dead?

`PBUF_POOL_SIZE` is still 256 (≈ 2.3 MiB of static/BSS reservation: 256 pbufs ×
~8946–9000 usable bytes each). lwipopts.h's own comment is explicit about why it is
still nonzero: `init.c` enforces an unconditional compile-time check
(`TCP_WND <= PBUF_POOL_SIZE * (PBUF_POOL_BUFSIZE - headers)`) whenever
`MEMP_MEM_MALLOC == 0 && PBUF_POOL_SIZE > 0`, regardless of whether this project's
code path actually draws from the pool.

Since the I1 fix (`f20aa36`, "PBUF_RAM ingress to stop cross-flow PBUF_POOL
exhaustion"), `mqvpn_lwip_input` allocates every ingress packet as `PBUF_RAM`
(exact-size, `MEM_LIBC_MALLOC`-backed heap), not `PBUF_POOL`. **The 256-entry pool is
therefore statically reserved (the BSS array exists, ~2.3 MiB) but functionally dead
on the TCP-lane ingress path** — nothing allocates out of it in production. It is a
documented tightening candidate: `PBUF_POOL_SIZE` could in principle drop to a
minimal placeholder or 0, but that requires first confirming no other lwIP-internal
facility in this build (e.g. IP reassembly, `LWIP_ARP`/output paths) still draws
pool pbufs — not verified as part of this doc, called out as follow-up only.

## 2. What actually bounds per-flow memory

The uplink backpressure watermarks (`MQVPN_TCP_LANE_BP_HIGH_WATER` /
`_LOW_WATER`) are **hysteresis thresholds on the relay-owned retry stash**, not a
hard per-flow memory cap. Bytes lwIP has already delivered to the TCP-lane recv
callback were already sequenced and ACKed on the wire — they can never be dropped
and must be queued whenever xquic won't take them yet. Withholding `tcp_recved()`
only stops the receive window from *re-opening*; the peer may still fill whatever
window was already advertised. The true worst-case per-flow queue bound is
`TCP_WND` (~2 MiB), not the 256 KiB high-water mark — both `lwipopts.h`'s own
comment and the tcp_lane.h watermark comment stress this distinction, and this doc
follows it: **the dominant per-flow cost below is `TCP_WND` + `TCP_SND_BUF`, not the
backpressure watermarks.**

Config knobs, by when they take effect:

- **`hybrid.TcpMaxFlows` (`tcp_max_flows`, config-table key, runtime/session-config)**
  — default 256. This is the *real* enforcement point (checked in `tcp_lane.c`
  before lwIP ever sees the SYN), not `MEMP_NUM_TCP_PCB` (512, lwIP-side headroom).
- **BP high/low water (compile-time, `tcp_lane.h`)** — internal constants,
  deliberately not exposed as config (no classifier/config/ABI surface). Bound only
  the relay-stash portion of the uplink queue.
- **`lwipopts.h` window sizing (compile-time)** — `TCP_WND` + `TCP_SND_BUF`. This is
  the dominant cost per flow and the only one requiring a rebuild to change.

## 3. Per-flow and aggregate cost, recomputed

**Per-flow worst case** (one `ACTIVE` flow simultaneously saturated in both
directions — recv window fully outstanding and send buffer fully queued):

```
TCP_WND (2,097,120 B) + TCP_SND_BUF (2,097,152 B) = 4,194,272 B ≈ 4.00 MiB / 4.19 MB
```

This is the number to use as "cost per concurrent flow." It is about 10% below the
plan sketch's ~4.7 MB/flow figure — the two dominant compile-time constants
(`TCP_WND`, `TCP_SND_BUF`) are unchanged from what the plan assumed; the residual
difference is attributable to secondary per-flow overhead the plan folded in
(`mqvpn_tcp_flow_t` itself is small, ~120 B per the tcp_lane.c comment in §4, and
uplink-node/pbuf-chain overhead — neither is large enough on its own to close a 10%
gap, so treat both figures as "≈ 4–5 MB/flow, window-and-sndbuf dominated" rather
than debugging the last 10%).

**Aggregate worst case** at the config default `tcp_max_flows = 256`:

```
256 × 4,194,272 B = 1,073,733,632 B ≈ 1.00 GiB (≈ 1.07 GB decimal)
```

About 10% below the plan sketch's ~1.2 GB, for the same reason as above. Both
numbers agree on the actionable conclusion: **the TCP-lane window/send-buffer pair
dominates aggregate memory, not the marker tables or PBUF_POOL** — those are a
few MB combined (see §4) against roughly 1 GB from the flow table itself.

## 4. Fixed overhead (independent of concurrent flow count)

These are paid once per `mqvpn_tcp_lane_t` instance (or up to their cap, in the
worst case), not per active flow:

| Item | Worst-case size | Source |
|---|---|---|
| PBUF_POOL static reservation | ≈ 2.3 MiB (dead on ingress, see §1a) | lwipopts.h |
| Sticky-RAW marker table (cap 4096) | ≈ 0.5 MB entries (`mqvpn_tcp_flow_t` ≈ 120 B each); keys alone 38 B × 4096 ≈ 156 KB | tcp_lane.c comment on `TCP_LANE_RAW_MARKER_CAP` |
| CLOSING routing-marker table (cap 4096) | ≈ 0.5 MB, same shape as above | tcp_lane.c comment on `TCP_LANE_CLOSING_CAP` |
| Hash bucket array (8192 buckets) | 64 KiB | tcp_lane.c `mqvpn_tcp_lane_new` |

Total fixed overhead ≈ 3.3 MB worst case — small next to the ~1 GB flow-table cost
at 256 concurrent flows.

## 5. Framing against a future mobile constraint (iOS Network Extension, 50 MB)

**Not applicable to v1** — this is the Linux CLI client only; no iOS/Network
Extension port exists yet. This section exists purely to frame today's Linux
defaults against a constraint a future mobile port would have to solve.

iOS Network Extensions are capped at roughly 50 MB of resident memory. Budgeting for
that ceiling, minus ≈ 1 MB of fixed overhead (assuming `PBUF_POOL_SIZE` is trimmed
per §1a, and the marker caps are also cut for a mobile build — e.g. 256 each instead
of 4096, ≈ 30 KB each, negligible), leaves roughly **49 MB for the flow table**.

Two independent levers, illustrated separately (neither is a recommendation, both
would need to be tuned together against expected concurrency and target link BDP):

- **Cut concurrency, keep today's window sizing** (~4.19 MB/flow): `49 MB / 4.19 MB
  ≈ 11` concurrent flows. A drop from 256 to ~11 is a severe concurrency cut,
  likely too restrictive for general browsing/app traffic.
- **Keep a mobile-plausible concurrency (e.g. 64 flows), shrink the window
  instead**: `49 MB / 64 ≈ 766 KB` per flow — `TCP_WND` + `TCP_SND_BUF` would need
  to shrink roughly 5.5× from today's ~4.19 MB combined. E.g. dropping
  `TCP_RCV_SCALE` from 5 to 1 (`TCP_WND = 65535 << 1 = 131,070 B`) and shrinking
  `TCP_SND_BUF` to the same order (~512–640 KB) would land in range, at the cost of
  lower per-flow goodput on high-BDP mobile links.

Any real mobile-port sizing decision needs both levers tuned together, not a
single-knob fix; this section is scoping data for that future work, not a proposal.

## 6. Known limitations

- **Sticky-RAW markers are never idle-evicted.** They are only replaced on cap
  overflow or on an ISN mismatch when the same 5-tuple sees a new SYN (I2). A
  workload that produces many short-lived flows misclassified sticky-RAW (e.g. under
  `tcp=auto`) can hold the marker table near its 4096-entry (~0.5 MB) cap
  indefinitely; this is a memory-bound-only cap, not a correctness issue, but it is
  not time-bounded the way TCP-lane flows are (Task 13's idle sweep).
- **`TCP_MSS` is a compile-time upper bound.** The vendored lwIP tree exposes no
  per-pcb MSS setter (`tcp_mss(pcb)` in `tcp.h` is a read-only accessor); the
  effective per-pcb MSS is derived automatically at connect/accept time from
  `netif->mtu`, clamped to `TCP_MSS`. Raising the TUN MTU ceiling above 9000 requires
  bumping `TCP_MSS` (and, per lwipopts.h's own derivation, `TCP_WND`/`TCP_SND_BUF`
  alongside it) at compile time — there is no runtime knob.
- **`PBUF_POOL_SIZE` = 256 remains statically reserved** (≈ 2.3 MiB) despite having
  no production consumer left on the ingress path after the I1 fix (§1a). Shrinking
  it is a real tightening candidate but requires confirming no other lwIP-internal
  facility in this build still draws from `PBUF_POOL` — not done here.
- **`MEMP_NUM_TCP_SEG` (2048, global) can bottleneck well before `tcp_max_flows`
  (256) does** under a bursty workload: only ≈ 2 flows can be simultaneously fully
  saturated at `TCP_SND_BUF` before the shared segment pool is exhausted, at which
  point `tcp_write` backpressure (not a config cap) is what actually limits
  additional flows from fully utilizing their send buffer concurrently.
