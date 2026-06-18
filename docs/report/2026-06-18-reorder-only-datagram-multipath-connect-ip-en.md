<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 mp0rta and mqvpn contributors -->

# Reorder-only datagram buffering for CONNECT-IP over multipath QUIC — an empirical report

---

## 1. Background — why I added a reorder buffer

MASQUE CONNECT-IP (RFC 9484) carries IP packets inside QUIC DATAGRAM frames (RFC 9221). DATAGRAMs are, by design, **neither ordered nor reliable**, and their handling is delegated to the application protocol (RFC 9221 §5.1–5.3).

In-order delivery in QUIC is the job of the **STREAM layer** (reassembly by connection-level offset, RFC 9000 §2.2). Multipath QUIC keeps that property for streams — stream data stays in order across all paths (draft-ietf-quic-multipath §5.5 in fact warns this causes head-of-line blocking, bounded by the slowest path's delay). **But DATAGRAMs bypass the STREAM layer entirely** — they have no offset and no reassembly, so nothing in QUIC, single-path or multipath, re-orders datagrams.

As a result, **datagrams spread across paths with different delays arrive reordered at the egress, and there is no layer inside QUIC to put them back in order.** When the inner traffic is a single congestion-controlled flow (inner QUIC / TCP that cannot be flow-split), the inner stack misreads this cross-path reordering as **loss**, shrinks its congestion window, and the multipath aggregation benefit is lost — in the worst case, throughput collapses below that of a single path.

mqvpn uses CONNECT-IP, i.e. DATAGRAMs, so it is directly exposed to the above.

I therefore added a **buffer at the tunnel egress that re-orders datagrams** (within the implementation latitude RFC 9221 §5.1 grants). This report quantifies **where it helps and how to tune it**.

### 1.1 Why QUIC is the inner flow under test — out-of-order tolerance is a MAY in the RFC (implementation-defined)

How badly cross-path reordering hurts the inner flow depends on how much reordering its loss detection tolerates before mistaking it for loss. Here the TCP/QUIC difference is at the RFC level:

- **Modern TCP (RACK-TLP, RFC 8985 + SACK/DSACK, RFC 2018/2883):** the reordering window **grows dynamically (SHOULD)** with observed reordering. Each time a DSACK reveals a spurious retransmission, the window expands up to `(N+1)*min_RTT/4` (capped at SRTT), learning to tolerate larger reordering (§6.2 Step 4).
- **QUIC (RFC 9002):** a **fixed** packet reordering threshold (`kPacketThreshold` = 3, RECOMMENDED, §6.1.1) is the default; RACK-style adaptive expansion is only a **MAY (implementation-defined)**.

So a QUIC stack following the RFC default **has lower out-of-order tolerance than RACK/SACK/DSACK TCP, and the adaptation is not guaranteed.** A tunnel carrying arbitrary inner QUIC flows cannot assume the inner stack adapts — which is exactly why the reorder buffer belongs on the tunnel side.

Whether the inner stack adapts depends on the implementation:

- **picoquic (the inner of this study, `e652e454`) — no dynamic expansion.** Fixed `delta_seq >= 3` ([`loss_recovery.c#L562`](https://github.com/private-octopus/picoquic/blob/e652e454b40ff94d7a0372d537fdf176d55b61f1/picoquic/loss_recovery.c#L562)). Spurious retransmissions are only recorded as telemetry (`max_reorder_gap`, [`frames.c#L2652`](https://github.com/private-octopus/picoquic/blob/e652e454b40ff94d7a0372d537fdf176d55b61f1/picoquic/frames.c#L2652)) and never fed back into the threshold. The collapses in §4 are this behaviour.
- **Google QUICHE (Chrome / Cronet) — dynamic expansion.** `use_adaptive_reordering_threshold_ = true` by default ([`general_loss_algorithm.h#L124`](https://github.com/google/quiche/blob/f001eed73bcff9389be32a36047e8945fba32553/quiche/quic/core/congestion_control/general_loss_algorithm.h#L124)); `SpuriousLossDetected()` grows `reordering_threshold_` on each spurious detection. Initial value `kDefaultPacketReorderingThreshold = 3` ([`quic_constants.h#L285`](https://github.com/google/quiche/blob/f001eed73bcff9389be32a36047e8945fba32553/quiche/quic/core/quic_constants.h#L285)).

This study quantifies the **non-adaptive picoquic case (= the RFC default tolerance)**. The residual benefit when the inner stack is an adaptive one like QUICHE is future work.

## 2. Design of the reorder-only buffer

A per-flow reordering buffer at the tunnel egress. Disciplines:

- **Reorder-only:** no retransmission, no FEC. It only reorders within a bounded wait — deliver immediately once a gap is filled; on exceeding `max_wait_ms`, give up the gap and deliver; on exceeding `cap_packets_per_flow`, evict the oldest. **It adds latency only; reliability is unchanged.**
- **Per-flow:** an independent buffer per inner 4-tuple, bounded by `max_wait_ms` / `cap`.
- **Default OFF, opt-in:** because in some environments it is a net loss (§4).
- **Non-goals:** FEC, retransmission, and inner TCP are out of scope. This is an optional shim for bandwidth aggregation, not a general reliability layer.

## 3. Experiment

### 3.1 Test environment

| Item | Value |
|------|-------|
| OS | Ubuntu 24.04.4 LTS |
| Kernel | 6.17.0-29-generic |
| netem/tc | iproute2-6.1.0 |
| CPU | 32 cores |
| mqvpn | `4047ac7` (branch `feat/reorder-sweep-picoquic-flags`) |
| xquic | `4eb63ef` |
| picoquic | `e652e454` (local build, not a submodule) |
| Topology | Linux netns, 2 paths (`benchmarks/bench_env_setup.sh`) |
| Privilege | root (netns requires `sudo`; the result dir `ci_sweep_results/` ends up root-owned, so `chown` before analysis) |

### 3.2 Workload and metrics

- **Inner:** a single HTTP/3 bulk GET via `picoquicdemo`. Congestion control = **BBR** (`-G bbr`), transfer **20 MiB**, single stream. Without congestion control (`iperf3 -u`) the reorder→false-loss chain does not appear, so a CC-driven HTTP/3 flow is used.
- **goodput [Mbps]:** from picoquicdemo's "Received … Mbps" (download) line.
- **p99 added-latency [ms]:** from the reorder engine's residence-time histogram (enqueue→deliver; in-order pass-through counted as 0 ms), read via the control API.
- **mqvpn config (this is what causes the reordering):** scheduler is `--scheduler wlb` (plain WLB), **not** `wlb_udp_pin`. Per `src/flow_sched.c`, a UDP flow is pinned to a path only under `wlb_udp_pin`; under plain `wlb` the single inner UDP/QUIC flow is **not pinned and is spread across both paths**. This non-pinned setup, combined with the netem RTT spread / jitter (§3.3), is what produces cross-path reordering (with `wlb_udp_pin` the 5-tuple would stick to one path, no reordering occurs, and the buffer would be unnecessary). The rule is `[ReorderRule] Proto = udp / Port = 5401 / Profile = quic_bulk`; `[Reorder] Enabled = on` with `MaxWaitMs` / `CapPackets` swept.

### 3.3 Environment matrix (exact netem strings, all 16 environments)

Passed to `bench_apply_netem "<Path A>" "<Path B>"` (the `ENV_NETEM` table in `sweep_reorder.sh`). Jitter is `delay TIME JITTER distribution normal` (netem has no `jitter` keyword; without `distribution normal` the p99 is underestimated).

| env | Path A | Path B | RTT spread |
|-----|--------|--------|-----------:|
| baseline | `delay 20ms rate 50mbit` | `delay 20ms rate 50mbit` | 0 |
| rtt_40 | `delay 20ms rate 50mbit` | `delay 40ms rate 50mbit` | 20 |
| rtt_70 | `delay 20ms rate 50mbit` | `delay 70ms rate 50mbit` | 50 |
| rtt_120 | `delay 20ms rate 50mbit` | `delay 120ms rate 50mbit` | 100 |
| rtt_320 | `delay 20ms rate 50mbit` | `delay 320ms rate 50mbit` | 300 |
| jit_5 | `delay 20ms 5ms distribution normal rate 50mbit` | (same) | 0 |
| jit_20 | `delay 20ms 20ms distribution normal rate 50mbit` | (same) | 0 |
| loss_05 | `delay 20ms loss 0.5% rate 50mbit` | (same) | 0 |
| loss_2 | `delay 20ms loss 2% rate 50mbit` | (same) | 0 |
| bw_4to1 | `delay 20ms rate 50mbit` | `delay 20ms rate 12mbit` | 0 |
| bw_10to1 | `delay 20ms rate 100mbit` | `delay 20ms rate 10mbit` | 0 |
| dual_lte | `delay 30ms 5ms distribution normal loss 0.5% rate 40mbit` | `delay 45ms 8ms distribution normal loss 0.5% rate 25mbit` | 15 |
| fiber_lte | `delay 8ms rate 300mbit` | `delay 40ms 8ms distribution normal loss 0.5% rate 30mbit` | 32 |
| lte_starlink | `delay 35ms 8ms distribution normal rate 40mbit` | `delay 50ms 25ms distribution normal loss 1% rate 100mbit` | 15 |
| lte_geo | `delay 35ms rate 40mbit` | `delay 320ms 20ms distribution normal loss 0.5% rate 20mbit` | 285 |
| congested | `delay 50ms 20ms distribution normal loss 2% rate 20mbit` | `delay 60ms 25ms distribution normal loss 2% rate 15mbit` | 10 |

### 3.4 Sweep method

Two-stage sweep of the performance knobs (3 repeats, median taken):

1. **Stage 1 (max_wait):** `cap=1024` fixed, `max_wait_ms ∈ {10,20,30,50,80,120,200,300}` across all 16 environments.
2. **Stage 2 (cap):** near the best wait from Stage 1, `cap_packets_per_flow ∈ {256,512,1024,2048,4096}` across the representative profiles + baseline (6 environments). This spans the BDP (300 mbit × 40 ms ≈ 1500 pkt).

Per cell, goodput and p99 added-latency are measured; per environment, the Pareto frontier (maximize goodput, minimize p99) and the recommended default = the **goodput knee** (smallest wait reaching ≥90% of peak goodput; ties broken by smallest cap) are computed. The **ON vs OFF net benefit** against `--reorder off` (RAW pass-through) is computed as well.

### 3.5 Reproduction commands

```bash
# build
cd mqvpn/.worktrees/reorder-latency-histogram      # branch feat/reorder-sweep-picoquic-flags
cmake -S . -B build-lib -DXQUIC_BUILD_DIR=third_party/xquic/build
cmake --build build-lib -j"$(nproc)"
scripts/ci_interop/build_picoquic.sh               # local build of third_party/picoquic

# ON sweep (reorder enabled, Stage 1+2, all envs; override MQVPN to the build-lib binary)
sudo MQVPN="$PWD/build-lib/mqvpn" \
     PICOQUICDEMO="$PWD/third_party/picoquic/build/picoquicdemo" \
     ./benchmarks/sweep_reorder.sh --reorder on --out ci_sweep_results/reorder_full.csv
# ≈ 474 runs, ~2-3 min each. Resumable (completed cells are skipped; --force to rerun).

# OFF baseline (RAW). Collapsed envs don't finish within the default 90s timeout (NA);
# PICO_TIMEOUT=300 turns them into real numbers (rate is independent of measurement time).
sudo MQVPN="$PWD/build-lib/mqvpn" \
     PICOQUICDEMO="$PWD/third_party/picoquic/build/picoquicdemo" \
     PICO_TIMEOUT=300 \
     ./benchmarks/sweep_reorder.sh --reorder off --out ci_sweep_results/reorder_off.csv

# analysis (after fixing root ownership)
sudo chown -R "$(id -un):$(id -gn)" ci_sweep_results
python3 benchmarks/sweep_reorder_analyze.py \
  --csv ci_sweep_results/reorder_full.csv \
  --off-csv ci_sweep_results/reorder_off.csv \
  --out ci_sweep_results/reorder_optimal.md
```

inner picoquicdemo: server `picoquicdemo -p 5401 -c <cert> -k <key> -G bbr -1 -D`; client `timeout -k 5 $PICO_TIMEOUT picoquicdemo -G bbr -D -n test <SERVER_IP> 5401 /20971520`.

## 4. Results and configuration guidance

### 4.1 ON vs OFF net benefit (which environments to enable in)

`Δ = (best-ON − OFF) / OFF`; best-ON = the max-goodput frontier point.

**✅ Enable (real cross-path reordering occurs)**

| env | RTT spread | OFF [Mbps] | best-ON [Mbps] | Δ | recommended |
|-----|------:|-----------:|---------------:|----:|---------|
| rtt_40 | 20 | 0.85 | 49.0 | **+5687%** | wait=50 |
| rtt_70 | 50 | 1.25 | 36.5 | **+2808%** | wait=50 |
| rtt_120 | 100 | 7.05 | 28.2 | +299% | wait=50 |
| jit_20 | 0 | 0.93 | 37.6 | **+3932%** | wait=50 |
| jit_5 | 0 | 3.38 | 61.4 | +1719% | wait=10 |
| dual_lte | 15 | 0.91 | 21.8 | +2280% | wait=30 |
| fiber_lte | 32 | 4.94 | 77.3 | +1467% | **wait=50, cap=2048** |
| bw_4to1 | 0 | 15.6 | 26.1 | +67% | wait=50 |
| bw_10to1 | 0 | 13.3 | 21.0 | +58% | wait=200 |

**🔴 Keep OFF (no reordering / waiting is wasted = net loss)**

| env | RTT spread | OFF [Mbps] | best-ON [Mbps] | Δ | reason |
|-----|------:|-----------:|---------------:|----:|------|
| baseline | 0 | 73.9 | 58.0 | −21.5% | no reordering, only buffer overhead |
| loss_05 | 0 | 70.7 | 52.7 | −25.5% | pure loss, no gaps to fill |
| loss_2 | 0 | 29.0 | 24.5 | −15.7% | same |
| lte_geo | 285 | 31.1 | 27.3 | −12.3% | extreme spread; waiting for the slow path backfires |
| rtt_320 | 300 | 40.1 | 35.7 | −10.8% | same |

**⚠️ Reorder is essential:** `congested` / `lte_starlink` could not finish the 20 MiB transfer even in 5 minutes with reorder OFF (< 0.55 Mbps), whereas ON reached 5.7 / 17 Mbps. In the harshest environments where RAW pass-through breaks down, the reorder buffer is what makes the transfer complete at all.

### 4.2 Sensitivity: optimal max_wait vs RTT spread

| env | spread [ms] | knee wait [ms] | knee goodput | peak wait | peak goodput |
|-----|----------:|-------------:|-----------:|-----------:|---------------:|
| baseline | 0 | 10 | 57.9 | 30 | 58.0 |
| rtt_40 | 20 | 50 | 45.7 | 200 | 49.0 |
| rtt_70 | 50 | 50 | 34.2 | 300 | 36.5 |
| rtt_120 | 100 | 50 | 28.2 | 50 | 28.2 |
| rtt_320 | 300 | 10 | 35.7 | 10 | 35.7 |

- spread 20–50 ms: the knee tracks the spread (when wait ≪ spread, gaps never fill, everything times out, and goodput collapses to ~1 Mbps).
- spread ≥100 ms: the knee plateaus at 50 ms.
- spread ≥285 ms: the smallest wait is best = reorder is counterproductive (the cost of waiting for the slow path exceeds the aggregation gain).

### 4.3 Configuration guidance (for users)

- **Enable when:** RTT spread ≈ **15–100 ms** / jitter present / asymmetric bandwidth. `max_wait_ms ≈ 50 ms` is the knee across the broad useful range. High-BDP paths (fiber, ~300 mbit) need **`cap ≥ 2048`** (1024 too small, 256/512 collapse). For low BDP, cap is irrelevant.
- **Keep OFF when:** near-symmetric with spread ≈ 0 and loss-dominated (−16% to −26% net loss), or extreme spread (≥285 ms, GEO-satellite class; counterproductive).
- The default OFF is sound; opt in only within the useful range above.

## 5. References

- RFC 9221 — Unreliable Datagram Extension to QUIC (§5.1 delegation to the app protocol / §5.2 reordering / §5.3 unreliable)
- RFC 9484 — Proxying IP in HTTP (CONNECT-IP) / RFC 9297 — HTTP Datagrams and the Capsule Protocol
- RFC 9000 — QUIC Transport (§2.2 in-order STREAM delivery by offset)
- RFC 9002 — QUIC Loss Detection (§6.1.1 `kPacketThreshold` = 3 RECOMMENDED; adaptation is a MAY)
- RFC 8985 — RACK-TLP / RFC 2018 — SACK / RFC 2883 — DSACK (dynamic growth of the reordering window)
- draft-ietf-quic-multipath (per-path packet number space / §5.5 stream HoL)
- draft-amend-iccrg-multipath-reordering (aggregation-node reorder buffering, prior art)
- picoquic `e652e454`: `loss_recovery.c#L562` (fixed `delta_seq >= 3`) / `frames.c#L2652` (telemetry)
- Google QUICHE `f001eed`: `general_loss_algorithm.h#L124` (`use_adaptive_reordering_threshold_ = true`) / `quic_constants.h#L285` (`kDefaultPacketReorderingThreshold = 3`)
- Implementation: `src/reorder.h` / `src/reorder_tx.c` / `src/reorder_rx.c` (merged to main in PR #153, default OFF)
- Harness: `benchmarks/sweep_reorder.sh` / `benchmarks/sweep_reorder_analyze.py`; output `ci_sweep_results/reorder_optimal.md`
