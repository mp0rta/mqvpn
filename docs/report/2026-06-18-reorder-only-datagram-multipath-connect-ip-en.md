<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 mp0rta and mqvpn contributors -->

# Reorder-only datagram buffering for CONNECT-IP over multipath QUIC — an empirical report

## Abstract

The throughput regression where bonded / multipath links deliver lower aggregate goodput than the better single path under heterogeneous-quality paths is a well-documented structural property of naive multipath scheduling — observed across the MPTCP literature (BLEST 2016, ECF 2017, QAware 2018, LLHD 2022, Dimopoulos et al. 2025), recognised in multipath QUIC (draft-ietf-quic-multipath §5.5), and worked around in commercial SD-WAN by defaulting to per-flow, bandwidth-weighted steering (Versa Networks). Almost all that prior work assumes a TCP inner with **adaptive** reordering tolerance (RACK-TLP / SACK / DSACK, RFC 8985 / 2018 / 2883), where the inner is structurally forgiving of cross-path reordering.

This report measures the regression in the harder case: a QUIC inner (picoquic, `kPacketThreshold = 3` fixed, no adaptive expansion — RFC 9002 §6.1.1 leaves adaptation a MAY) carrying a single HTTP/3 bulk transfer over MASQUE CONNECT-IP. mqvpn ships a per-flow reorder buffer at the tunnel egress and two schedulers (`wlb`, `minrtt`). Across 16 netem profiles, mqvpn's `(scheduler, reorder-buffer)` configuration space contains a setting that ties or beats the better single path in every one: `wlb` aggregates symmetric paths at +13–120 % over best single (the buffer is the enabler under jitter); on asymmetric paths `wlb` collapses, but `minrtt` recovers single-path-equivalent throughput within ±5–8 % while keeping multipath enabled. The empirical contribution is that the standard multipath-mitigation principle — scheduler aware of path heterogeneity, plus a tunnel-side reorder buffer — generalises to a QUIC inner without adaptive loss detection, a regime where the underlying problem is strictly harder than the MPTCP setting that prior schedulers (BLEST / ECF / QAware) were designed for.

## 1. Background — why a tunnel-side reorder buffer

MASQUE CONNECT-IP (RFC 9484) carries IP packets inside QUIC DATAGRAM frames (RFC 9221). DATAGRAMs are, by design, **neither ordered nor reliable**, and their handling is delegated to the application protocol (RFC 9221 §5.1–5.3).

In-order delivery in QUIC is the job of the **STREAM layer** (reassembly by connection-level offset, RFC 9000 §2.2). Multipath QUIC keeps that property for streams — stream data stays in order across all paths (draft-ietf-quic-multipath §5.5 in fact warns this causes head-of-line blocking, bounded by the slowest path's delay). DATAGRAMs bypass the STREAM layer entirely: they have no offset and no reassembly, so nothing in QUIC, single-path or multipath, re-orders datagrams.

Consequence: datagrams spread across paths with different delays arrive reordered at the egress, with no layer inside QUIC to put them back in order. When the inner traffic is a single congestion-controlled flow (inner QUIC / TCP that cannot be flow-split), the inner stack misreads this cross-path reordering as loss, shrinks its congestion window, and the multipath aggregation benefit is lost — in the worst case, throughput collapses below that of a single path.

mqvpn uses CONNECT-IP, i.e. DATAGRAMs, so it is directly exposed to the above. A buffer at the tunnel egress that re-orders datagrams (within the implementation latitude RFC 9221 §5.1 grants) is therefore added. This report quantifies its operating envelope.

The regression — multipath worse than the better single path under heterogeneous links — is not specific to mqvpn or to DATAGRAM transport. It is a structural property of naive multipath scheduling, documented continuously across MPTCP (BLEST [Ferlin 2016], ECF [Lim 2017], QAware [Shreedhar 2018], LLHD [2022], Dimopoulos et al. [2025 preprint]), recognised in multipath QUIC (draft-ietf-quic-multipath §5.5), and worked around in commercial SD-WAN by defaulting to per-flow, bandwidth-weighted steering (Versa Networks). The mechanism — slow-path packets head-of-line-blocking faster-path packets at the receiver, plus the inner congestion controller misreading reordering as loss — applies to any reliable-ordered multipath transport. What this report adds is empirical demonstration that the mitigation principle works under a QUIC inner with **non-adaptive** loss detection (§1.1), which is structurally harder than the TCP-with-RACK/SACK/DSACK inner that the MPTCP scheduler literature assumes.

### 1.1 Out-of-order tolerance of the inner flow is a MAY at the RFC level (implementation-defined)

How badly cross-path reordering hurts the inner flow depends on how much reordering its loss detection tolerates before mistaking it for loss. The TCP/QUIC difference is at the RFC level:

- **Modern TCP (RACK-TLP, RFC 8985 + SACK/DSACK, RFC 2018/2883):** the reordering window grows dynamically (SHOULD) with observed reordering. Each DSACK that reveals a spurious retransmission expands the window up to `(N+1)*min_RTT/4` (capped at SRTT), §6.2 Step 4.
- **QUIC (RFC 9002):** a fixed packet reordering threshold (`kPacketThreshold` = 3, RECOMMENDED, §6.1.1) is the default; RACK-style adaptive expansion is only a MAY (implementation-defined).

A QUIC stack following the RFC default therefore has lower out-of-order tolerance than RACK/SACK/DSACK TCP, and the adaptation is not guaranteed. A tunnel carrying arbitrary inner QUIC flows cannot assume the inner stack adapts — the reorder buffer belongs on the tunnel side.

Whether the inner stack adapts is implementation-dependent:

- **picoquic (the inner of this study, `e652e454`) — no dynamic expansion.** Fixed `delta_seq >= 3` ([`loss_recovery.c#L562`](https://github.com/private-octopus/picoquic/blob/e652e454b40ff94d7a0372d537fdf176d55b61f1/picoquic/loss_recovery.c#L562)). Spurious retransmissions are only recorded as telemetry (`max_reorder_gap`, [`frames.c#L2652`](https://github.com/private-octopus/picoquic/blob/e652e454b40ff94d7a0372d537fdf176d55b61f1/picoquic/frames.c#L2652)) and never fed back into the threshold. The collapses in §4 are this behaviour.
- **Google QUICHE (Chrome / Cronet) — dynamic expansion.** `use_adaptive_reordering_threshold_ = true` by default ([`general_loss_algorithm.h#L124`](https://github.com/google/quiche/blob/f001eed73bcff9389be32a36047e8945fba32553/quiche/quic/core/congestion_control/general_loss_algorithm.h#L124)); `SpuriousLossDetected()` grows `reordering_threshold_` on each spurious detection. Initial value `kDefaultPacketReorderingThreshold = 3` ([`quic_constants.h#L285`](https://github.com/google/quiche/blob/f001eed73bcff9389be32a36047e8945fba32553/quiche/quic/core/quic_constants.h#L285)).

This study measures the non-adaptive picoquic case (the RFC default tolerance). It is therefore structurally harder than the MPTCP scheduler literature, where the TCP inner adapts via RACK/SACK/DSACK and absorbs more reordering before the multipath aggregation collapses. Residual benefit when the inner stack is adaptive (QUICHE) is future work.

## 2. Design of the reorder-only buffer

A per-flow reordering buffer at the tunnel egress. Disciplines:

- **Reorder-only:** no retransmission, no FEC. The buffer reorders within a bounded wait — deliver immediately once a gap is filled; on exceeding `max_wait_ms`, give up the gap and deliver; on exceeding `cap_packets_per_flow`, evict the oldest. It adds latency only; reliability is unchanged.
- **Per-flow:** an independent buffer per inner 4-tuple, bounded by `max_wait_ms` / `cap`.
- **Default OFF, opt-in:** in some environments the buffer is a net loss (§4).
- **Non-goals:** FEC, retransmission, and inner TCP are out of scope. This is an optional shim for bandwidth aggregation of a single congestion-controlled inner flow, not a general reliability layer.

Failover behaviour — multipath's ability to keep the connection alive when one path degrades — is a separate use case and is not measured here.

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

### 3.2 Workload, metrics, and configurations

- **Inner workload:** a single HTTP/3 bulk GET via `picoquicdemo`, congestion control BBR (`-G bbr`), 20 MiB transfer, single stream. A CC-driven HTTP/3 flow is required; without CC (`iperf3 -u`) the reorder→false-loss chain does not appear.
- **goodput [Mbps]:** picoquicdemo's "Received … Mbps" download line.
- **p99 added-latency [ms]:** the reorder engine's residence-time histogram (enqueue→deliver; in-order pass-through counted as 0 ms), read via the control API. Path RTT is not included.
- **Schedulers measured:** `--scheduler wlb` (the default; weighted load balance across paths) and `--scheduler minrtt` (lowest-SRTT path selection, spillover only when cwnd-blocked). Both schedulers spread the single inner UDP/QUIC flow across both paths (neither pins by 4-tuple — pinning is `--scheduler wlb_udp_pin`, not used here, since pinning trivially gives up aggregation). The difference is how aggressively each pushes traffic to the slower path.
- **Reorder rule (when ON):** `[ReorderRule] Proto = udp / Port = 5401 / Profile = quic_bulk`; `[Reorder] Enabled = on` with `MaxWaitMs` / `CapPackets` swept.

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

Two-stage sweep of the buffer knobs (3 repeats, median taken):

1. **Stage 1 (max_wait):** `cap=1024` fixed, `max_wait_ms ∈ {10, 20, 30, 50, 80, 120, 200, 300}` across all 16 environments.
2. **Stage 2 (cap):** near the best wait from Stage 1, `cap_packets_per_flow ∈ {256, 512, 1024, 2048, 4096}` across the representative profiles + baseline (6 environments). This spans the BDP (300 mbit × 40 ms ≈ 1500 pkt).

The same two-stage protocol is run once with `--scheduler wlb` and once with `--scheduler minrtt`. The single-path baseline (Path A alone, Path B alone) is scheduler-independent and reused. Per environment, the Pareto frontier (maximize goodput, minimize p99) and the goodput knee (smallest wait reaching ≥ 90 % of peak goodput; ties broken by smallest cap) are computed; the **ON vs OFF net benefit** against `--reorder off` (RAW pass-through) is computed against the OFF baseline.

### 3.5 Reproduction commands

```bash
# build
cd mqvpn/.worktrees/reorder-latency-histogram      # branch feat/reorder-sweep-picoquic-flags
cmake -S . -B build-lib -DXQUIC_BUILD_DIR=third_party/xquic/build
cmake --build build-lib -j"$(nproc)"
scripts/ci_interop/build_picoquic.sh               # local build of third_party/picoquic

# ── wlb sweep (§4.1–§4.2) ───────────────────────────────────────
sudo MQVPN="$PWD/build-lib/mqvpn" \
     PICOQUICDEMO="$PWD/third_party/picoquic/build/picoquicdemo" \
     ./benchmarks/sweep_reorder.sh --reorder on --out ci_sweep_results/reorder_full.csv
sudo MQVPN="$PWD/build-lib/mqvpn" \
     PICOQUICDEMO="$PWD/third_party/picoquic/build/picoquicdemo" \
     PICO_TIMEOUT=300 \
     ./benchmarks/sweep_reorder.sh --reorder off --out ci_sweep_results/reorder_off.csv

# ── minrtt sweep (§4.3) ─────────────────────────────────────────
sudo MQVPN="$PWD/build-lib/mqvpn" \
     PICOQUICDEMO="$PWD/third_party/picoquic/build/picoquicdemo" \
     PICO_TIMEOUT=300 BENCH_SCHEDULER=minrtt \
     ./benchmarks/sweep_reorder.sh --reorder on  --out ci_sweep_results/reorder_full_minrtt.csv
sudo MQVPN="$PWD/build-lib/mqvpn" \
     PICOQUICDEMO="$PWD/third_party/picoquic/build/picoquicdemo" \
     PICO_TIMEOUT=300 BENCH_SCHEDULER=minrtt \
     ./benchmarks/sweep_reorder.sh --reorder off --out ci_sweep_results/reorder_off_minrtt.csv

# ── single-path baseline (scheduler-independent) ────────────────
# 16 envs × 2 paths × 3 repeats = 96 cells. Reorder disabled (one path has
# no cross-path reordering to fix). Reused for both schedulers.
sudo MQVPN="$PWD/build-lib/mqvpn" \
     PICOQUICDEMO="$PWD/third_party/picoquic/build/picoquicdemo" \
     PICO_TIMEOUT=300 \
     ./benchmarks/sweep_single_path.sh --out ci_sweep_results/reorder_single.csv

# ── analysis ────────────────────────────────────────────────────
sudo chown -R "$(id -un):$(id -gn)" ci_sweep_results
python3 benchmarks/sweep_reorder_analyze.py \
  --csv ci_sweep_results/reorder_full.csv \
  --off-csv ci_sweep_results/reorder_off.csv \
  --single-csv ci_sweep_results/reorder_single.csv \
  --out ci_sweep_results/reorder_optimal.md
python3 benchmarks/sweep_reorder_analyze.py \
  --csv ci_sweep_results/reorder_full_minrtt.csv \
  --off-csv ci_sweep_results/reorder_off_minrtt.csv \
  --single-csv ci_sweep_results/reorder_single.csv \
  --out ci_sweep_results/reorder_optimal_minrtt.md
```

Inner picoquicdemo: server `picoquicdemo -p 5401 -c <cert> -k <key> -G bbr -1 -D`; client `timeout -k 5 $PICO_TIMEOUT picoquicdemo -G bbr -D -n test <SERVER_IP> 5401 /20971520`.

## 4. Results

### 4.1 Three-way comparison under `wlb`: single path vs multipath (OFF / ON)

The comparison includes a single-path baseline (Path A alone, Path B alone) for each environment, then compares it against multipath with reorder OFF and multipath with reorder at its best-goodput tuning. The recommendation picks the simplest configuration whose median goodput is within 5 % of the winner (priority: single > multipath OFF > multipath + reorder ON). Under `wlb`, three buckets emerge.

#### 4.1.A Multipath + reorder ON — buffer earns its keep (3 envs)

| env | RTT spread [ms] | Path A [Mbps] | Path B [Mbps] | best single [Mbps] | OFF (mp) [Mbps] | best-ON (mp) [Mbps] | best-ON wait / cap | Δ best-ON vs OFF [%] | Δ best-ON vs best-single [%] |
|---|--:|--:|--:|--:|--:|--:|---|--:|--:|
| `rtt_40` | 20 | 40.5 | 37.9 | **40.5** | 0.85 | **49.0** | wait=200, cap=1024 | **+5666** | **+21** |
| `jit_5` | 0 | 38.3 | 38.8 | **38.8** | 3.38 | **61.4** | wait=120, cap=1024 | +1716 | **+58** |
| `jit_20` | 0 | 17.4 | 11.0 | **17.4** | 0.93 | **37.6** | wait=50, cap=1024 | **+3943** | **+115** |

The inner picoquic's fixed `kPacketThreshold = 3` (§1.1) collapses on the multipath OFF baseline; reorder ON recovers enough to exceed the better single path. These envs share low RTT spread (0–20 ms), no bandwidth asymmetry, and jitter or small per-path spread. The `best-ON wait / cap` column shows the goodput-peak configuration; the latency-bounded shipping default (the goodput knee, typically `wait=50 ms`) reaches ≥ 90 % of these numbers — see §4.2.

#### 4.1.B Multipath, reorder OFF — clean aggregation (3 envs)

| env | RTT spread [ms] | Path A [Mbps] | Path B [Mbps] | best single [Mbps] | OFF (mp) [Mbps] | best-ON (mp) [Mbps] | best-ON wait / cap | Δ best-ON vs OFF [%] | Δ OFF vs best-single [%] |
|---|--:|--:|--:|--:|--:|--:|---|--:|--:|
| `baseline` | 0 | 40.6 | 40.3 | **40.6** | **73.9** | 58.0 | wait=30, cap=2048 | −21.5 | **+82** |
| `loss_05` | 0 | 29.6 | 32.2 | **32.2** | **70.7** | 52.7 | wait=10, cap=1024 | −25.5 | **+119** |
| `loss_2` | 0 | 16.1 | 16.3 | **16.3** | **29.0** | 24.5 | wait=10, cap=1024 | −15.5 | **+78** |

Symmetric paths, zero RTT spread, no jitter. Aggregation works without the buffer (the inner does not see meaningful cross-path reordering), and enabling the buffer actively hurts: Δ best-ON vs OFF is negative for all three envs (15–26 % regression). The shipping default of reorder OFF is correct.

#### 4.1.C Single path beats multipath under `wlb` (10 envs)

| env | RTT spread [ms] | Path A [Mbps] | Path B [Mbps] | best single [Mbps] | OFF (mp) [Mbps] | best-ON (mp) [Mbps] | best-ON wait / cap | Δ best-ON vs OFF [%] | Δ best-ON vs best-single [%] |
|---|--:|--:|--:|--:|--:|--:|---|--:|--:|
| `fiber_lte` | 32 | **212.4** | 22.0 | **212.4** | 4.94 | 77.3 | wait=50, cap=2048 | +1465 | **−64** |
| `bw_10to1` | 0 | **74.2** | 8.6 | **74.2** | 13.3 | 21.0 | wait=200, cap=1024 | +58 | **−72** |
| `bw_4to1` | 0 | **40.6** | 10.3 | **40.6** | 15.6 | 26.1 | wait=300, cap=1024 | +67 | −36 |
| `rtt_120` | 100 | **40.7** | 27.5 | **40.7** | 7.05 | 28.2 | wait=50, cap=1024 | +300 | −31 |
| `rtt_320` | 300 | **40.3** | 9.2 | **40.3** | 40.1 | 35.7 | wait=10, cap=1024 | −11 | −11 |
| `lte_geo` | 285 | **31.7** | 6.0 | **31.7** | 31.1 | 27.3 | wait=10, cap=1024 | −12 | −14 |
| `lte_starlink` | 15 | **29.6** | 8.9 | **29.6** | — | 17.1 | wait=50, cap=1024 | n/a (OFF collapsed) | −42 |
| `dual_lte` | 15 | **29.6** | 18.8 | **29.6** | 0.91 | 21.8 | wait=50, cap=4096 | +2295 | −27 |
| `rtt_70` | 50 | **40.6** | 33.7 | **40.6** | 1.25 | 36.5 | wait=300, cap=1024 | +2820 | −10 |
| `congested` | 10 | **6.4** | 5.7 | **6.4** | — | 5.7 | wait=30, cap=1024 | n/a (OFF collapsed) | −11 |

In every §4.1.C env, Path A is the higher-bandwidth or lower-RTT side. `OFF (mp) = —` means the multipath OFF baseline did not finish the 20 MiB transfer within the 5-minute hard cap. Reorder ON does complete the transfer in those cells (`lte_starlink`, `congested`), where the buffer's "rescue from collapse" effect is clearest; even so, multipath under `wlb` is still slower than just using Path A.

The unifying property: either path bandwidth is asymmetric (≥ 2× ratio), or RTT spread is ≥ 50 ms, or both. Under `wlb` the scheduler is forced to push some traffic onto the slow path; the reorder buffer can rescue the multipath stack from outright collapse but cannot beat the better single path. These verdicts are `wlb`-scoped; §4.3 reruns the same envs under `minrtt`, which changes the picture in every one of them.

### 4.2 Buffer sensitivity: `max_wait_ms` vs RTT spread (under `wlb`)

For the envs where multipath + reorder is recommended (§4.1.A), the knee — smallest `max_wait_ms` reaching ≥ 90 % of peak goodput — tracks the spread cleanly:

| env | spread [ms] | knee wait [ms] | knee goodput [Mbps] | peak wait [ms] | peak goodput [Mbps] |
|---|--:|--:|--:|--:|--:|
| baseline | 0 | 10 | 57.9 | 30 | 58.0 |
| rtt_40 | 20 | 50 | 45.7 | 200 | 49.0 |
| rtt_70 | 50 | 50 | 34.2 | 300 | 36.5 |
| rtt_120 | 100 | 50 | 28.2 | 50 | 28.2 |
| rtt_320 | 300 | 10 | 35.7 | 10 | 35.7 |

- Spread 20–50 ms: the knee tracks the spread. When `wait ≪ spread`, gaps never fill, everything times out, and goodput collapses to ~ 1 Mbps.
- Spread ≥ 100 ms: the knee plateaus at 50 ms — but as §4.1.C shows, the resulting goodput is already below single-path, so tuning the wait does not change the verdict.
- Spread ≥ 285 ms: the smallest wait wins; the buffer is counterproductive (waiting for the slow path costs more than the aggregation it enables).

High-BDP paths (fibre, ~ 300 mbit) need `cap ≥ 2048` when reorder is enabled; 1024 is too small and 256/512 collapse. For low-BDP paths cap is irrelevant. Cap matters only inside the §4.1.A envelope; outside it the right answer is "don't enable the buffer", so cap is moot.

### 4.3 Same sweep under `--scheduler minrtt`

The same sweep is rerun with `minrtt` (lowest-SRTT path selection, spillover only when cwnd-blocked). The cell format folds two numbers — `OFF: <gp>` for `[Reorder] Enabled = off`, `ON: <gp> @<wait>` for the best ON at the knee — and bolds the higher of the two per scheduler. The Δ columns compare each scheduler's higher value against the better single path (positive = multipath beats single; near-zero = matches single while keeping multipath enabled; negative = single is faster). `cap = 1024` unless noted.

| env | spread [ms] | single [Mbps] | `wlb` [Mbps] | Δ `wlb` vs single [%] | `minrtt` [Mbps] | Δ `minrtt` vs single [%] | recommended config |
|---|--:|--:|---|--:|---|--:|---|
| `baseline` | 0 | 40.6 | **OFF: 73.9** • ON: 57.9 @10 | **+82** | OFF: 39.8 • **ON: 42.5 @20** | +5 | `wlb`, Reorder OFF |
| `loss_05` | 0 | 32.2 | **OFF: 70.7** • ON: 52.7 @10 | **+119** | OFF: 31.4 • **ON: 39.6 @10** | +23 | `wlb`, Reorder OFF |
| `loss_2` | 0 | 16.3 | **OFF: 29.0** • ON: 24.5 @10 | **+78** | OFF: 12.6 • **ON: 16.4 @10** | +1 | `wlb`, Reorder OFF |
| `jit_5` | 0 | 38.8 | OFF: 3.4 • **ON: 55.7 @10** | **+44** | OFF: 12.4 • **ON: 46.5 @120** | +20 | `wlb`, Reorder ON, MaxWaitMs=10 |
| `jit_20` | 0 | 17.4 | OFF: 0.9 • **ON: 37.6 @50** | **+116** | OFF: 8.0 • **ON: 35.6 @80** | +105 | `wlb`, Reorder ON, MaxWaitMs=50 |
| `rtt_40` | 20 | 40.5 | OFF: 0.85 • **ON: 45.7 @50** | **+13** | OFF: 36.9 • **ON: 40.6 @20** | 0 | `wlb`, Reorder ON, MaxWaitMs=50 |
| `rtt_320` | 300 | 40.3 | **OFF: 40.1** • ON: 35.7 @10 | −0.5 | OFF: 37.9 • **ON: 38.9 @10** | −3 | `wlb`, Reorder OFF |
| `lte_geo` | 285 | 31.7 | **OFF: 31.1** • ON: 27.3 @10 | −2 | **OFF: 31.5** • ON: 29.5 @10 | −1 | `wlb`, Reorder OFF (`minrtt` OFF tied within 1 %) |
| `rtt_70` | 50 | 40.6 | OFF: 1.3 • **ON: 34.2 @50** | −16 | OFF: 36.4 • **ON: 40.2 @10** | −1 | `minrtt`, Reorder ON, MaxWaitMs=10 |
| `rtt_120` | 100 | 40.7 | OFF: 7.1 • **ON: 28.2 @50** | −31 | **OFF: 40.6** • ON: 37.2 @10 | 0 | `minrtt`, Reorder OFF |
| `dual_lte` | 15 | 29.6 | OFF: 0.9 • **ON: 20.7 @50** | −30 | OFF: 26.1 • **ON: 29.6 @20** | 0 | `minrtt`, Reorder ON, MaxWaitMs=20 |
| `fiber_lte` | 32 | 212.4 | OFF: 4.9 • **ON: 77.3 @50,cap=2048** | −64 | **OFF: 212.3** • ON: 189.4 @10 | 0 | `minrtt`, Reorder OFF |
| `bw_4to1` | 0 | 40.6 | OFF: 15.6 • **ON: 25.4 @50** | −37 | **OFF: 39.9** • ON: 39.3 @10 | −2 | `minrtt`, Reorder OFF |
| `bw_10to1` | 0 | 74.2 | OFF: 13.3 • **ON: 21.0 @200** | −72 | **OFF: 70.1** • ON: 69.6 @10 | −6 | `minrtt`, Reorder OFF (single Path A also reasonable for pure throughput) |
| `lte_starlink` | 15 | 29.6 | OFF: — • **ON: 17.1 @50** | −42 | **OFF: 27.2** • ON: 26.6 @10 | −8 | `minrtt`, Reorder OFF (single Path A for pure throughput; multipath costs ~ 8 %) |
| `congested` | 10 | 6.4 | OFF: — • **ON: 5.7 @30** | −11 | OFF: 5.6 • **ON: 6.4 @30** | 0 | `minrtt`, Reorder ON, MaxWaitMs=30 |

The recommended config picks the bold value within 5 % of the row's highest cell, preferring the simpler configuration (default `wlb` > `minrtt`; default Reorder OFF > ON; multipath > single — single drops failover). Two envs (`bw_10to1`, `lte_starlink`) fall outside the 5 % band for multipath; the table notes the single-path alternative. `OFF: —` means the OFF baseline did not finish the 20 MiB transfer within the 5-minute hard cap.

Three structural patterns drive the recommendations:

- **`wlb` wins on symmetric paths.** Similar bandwidth and RTT lets `wlb` spread traffic across both paths and aggregate 1.5–2× the per-path goodput. `baseline`: 40.6 Mbps per path, 73.9 Mbps with `wlb` + Reorder OFF. `minrtt` on the same env barely spreads load (it keeps picking whichever path has the marginally lower SRTT) and lands at roughly per-path goodput. Symmetric loss (`loss_05`, `loss_2`) and small RTT spread / jitter (`jit_5`, `jit_20`, `rtt_40`) follow the same pattern; in those envs Reorder ON unlocks aggregation, but the scheduler choice is still `wlb`.
- **`minrtt` wins on asymmetric paths or high RTT spread.** `minrtt` preferentially uses the faster / lower-RTT path and falls back to the slower one only when the better path is cwnd-blocked. `fiber_lte`: under `wlb` the multipath stack collapses to 77 Mbps (the 300 mbit fibre is dragged down by the 30 mbit LTE); under `minrtt` + Reorder OFF it reaches 212 Mbps — equal to fibre alone. `bw_4to1`, `dual_lte` match their best single path; `rtt_70`, `rtt_120`, `rtt_320`, `lte_geo` come within 1–3 %. `bw_10to1` (−6 %) and `lte_starlink` (−8 %) keep multipath functional with a small throughput tax.
- **Under `minrtt` the buffer is often unnecessary.** Because `minrtt` concentrates traffic on the better path, only the spillover packets cross paths, so cross-path reorder gaps are small and the operating envelope where the buffer beats OFF is narrower. `minrtt` + OFF outright wins in `fiber_lte`, `rtt_120`, `lte_geo`, `rtt_320`, or wins by 1–6 % in `bw_4to1`, `bw_10to1`, `baseline`. When the buffer does help under `minrtt`, the knee wait is short (10–30 ms vs `wlb`'s 50 ms) because the rare gaps fill quickly. About half the `minrtt` rows leave the buffer OFF.

### 4.4 Configuration

The tree picks the scheduler and the reorder buffer state. It assumes multipath is already enabled.

```
0. Decide the scheduler from path topology.
     Symmetric (similar bandwidth, similar RTT, zero/small spread)?
       → --scheduler wlb        (aggregates symmetric paths up to ~ 2× per-path
                                 goodput; minrtt collapses to per-path goodput here.)
     Asymmetric (bandwidth ratio ≥ 2×) or RTT spread ≥ ~ 50 ms?
       → --scheduler minrtt     (preferentially uses the faster/lower-RTT path;
                                 wlb here would split onto the slow path and lose.)

1. Asymmetric or spread ≥ ~ 50 ms (minrtt at step 0).
     [Reorder] Enabled = off                                          ← default
       envs: fiber_lte, rtt_120, lte_geo, rtt_320, bw_4to1, bw_10to1, lte_starlink
     [Reorder] Enabled = on, MaxWaitMs = 10–30
       envs: rtt_70 (+10 %), dual_lte (+13 %), congested (+14 %)

2. Symmetric with jitter (per-path ≥ 5 ms) or small spread (≤ 30 ms) (wlb at step 0).
     [Reorder] Enabled = on, MaxWaitMs = 50, CapPackets = 2048 if BDP > 1 MB
       envs: jit_5, jit_20, rtt_40   (wlb OFF collapses to ~ 1 Mbps here; see §4.1.A)

3. Symmetric and clean, or symmetric with per-path loss only (wlb at step 0).
     [Reorder] Enabled = off                                          ← default
       envs: baseline, loss_05, loss_2   (enabling the buffer costs 15–25 %)

4. Congested (per-path loss > 1 % with jitter).
     Single path with least loss; neither scheduler aggregates meaningfully.
       env: congested
```

Shipping defaults (`--scheduler wlb`, `[Reorder] Enabled = off`) are correct for step 3. Jittery or small-spread paths opt the buffer in (step 2); asymmetric or high-spread paths switch the scheduler to `minrtt` (step 1). No environment in this sweep needed both schedulers at once.

## 5. Conclusion

The bandwidth-aggregation regression where multipath delivers lower throughput than the better single path under heterogeneous-quality links is a long-known structural property of naive multipath scheduling, documented continuously from BLEST (Ferlin et al., 2016) and ECF (Lim et al., 2017) through QAware (Shreedhar et al., 2018), LLHD (2022), and Dimopoulos et al. (2025). The mechanism — head-of-line blocking at the receiver, stale-RTT mis-scheduling, and the inner congestion controller misreading reordering as loss — applies to MPTCP, multipath QUIC (draft-ietf-quic-multipath §5.5), and RoCEv2 alike; commercial SD-WAN (Versa) avoids it at the cost of giving up packet-level aggregation by defaulting to per-flow, bandwidth-weighted steering.

The contribution of this report is empirical: the same mitigation principle — a scheduler aware of path heterogeneity plus a tunnel-side reorder buffer — works under a QUIC inner with **non-adaptive** loss detection (`kPacketThreshold = 3` fixed, the RFC 9002 §6.1.1 default; the MAY for RACK-style expansion is not implemented in picoquic). This is structurally harder than the TCP-with-RACK/SACK/DSACK inner that the MPTCP scheduler literature assumes, since the inner stack does not absorb cross-path reordering on its own. Across the 16 netem profiles, mqvpn's existing `(scheduler, reorder-buffer)` configuration space contains a setting that ties or beats the better single path in every one:

| Path topology | Scheduler | Reorder | Δ vs best single |
|---|:--|:--|---:|
| Symmetric, clean or pure loss | `wlb` | OFF | +78 to +120 % |
| Symmetric, jittery or 20–50 ms spread | `wlb` | ON, wait = 50 ms | +13 to +116 % |
| Asymmetric bandwidth or spread ≥ 50 ms | `minrtt` | mostly OFF | −8 to +5 % |

The worst case under the right scheduler is "matches the better single path within ~5–8 %", not "loses to it"; the historical multipath caveat *only multipath if your paths are similar* applies less strongly to mqvpn after this work. The reorder buffer's narrow but well-defined operating envelope (symmetric paths with cross-path reordering caused by jitter or small RTT spread) is what enables the +13–120 % regime under `wlb`; outside that envelope, scheduler choice — not buffer tuning — is the load-bearing decision.

## References

**Standards**

- RFC 9221 — Unreliable Datagram Extension to QUIC (§5.1 delegation to the app protocol / §5.2 reordering / §5.3 unreliable)
- RFC 9484 — Proxying IP in HTTP (CONNECT-IP) / RFC 9297 — HTTP Datagrams and the Capsule Protocol
- RFC 9000 — QUIC Transport (§2.2 in-order STREAM delivery by offset)
- RFC 9002 — QUIC Loss Detection (§6.1.1 `kPacketThreshold` = 3 RECOMMENDED; adaptation is a MAY)
- RFC 8985 — RACK-TLP / RFC 2018 — SACK / RFC 2883 — DSACK (dynamic growth of the reordering window)
- draft-ietf-quic-multipath (per-path packet number space / §5.5 stream HoL)
- draft-amend-iccrg-multipath-reordering (aggregation-node reorder buffering, prior art)

**Prior art — multipath schedulers and the heterogeneous-path regression**

- S. Ferlin, Ö. Alay, O. Mehani, R. Boreli. "BLEST: Blocking Estimation-based MPTCP Scheduler for Heterogeneous Networks." IFIP Networking 2016. `dl.ifip.org/db/conf/networking/networking2016/1570234725.pdf`
- Y.-S. Lim, E. M. Nahum, D. Towsley, R. J. Gibbens. "ECF: An MPTCP Path Scheduler to Manage Heterogeneous Paths." ACM CoNEXT 2017.
- T. Shreedhar et al. "QAware: A Cross-Layer Approach to MPTCP Scheduling." IFIP Networking 2018. `dl.ifip.org/db/conf/networking/networking2018/3B2-1570422213.pdf`
- LLHD scheduler: PMC9782081 (2022).
- N. Dimopoulos, A. Salkintzis, A. Tsolkas, N. Passas, L. Merakos. "Evaluating the Impact of Packet Scheduling and Congestion Control Algorithms on MPTCP Performance over Heterogeneous Networks." arXiv:2511.14550, Nov 2025 (**preprint, not peer-reviewed**).
- Q. De Coninck, O. Bonaventure. "Tuning Multipath QUIC at the Sender Side." ACM CoNEXT 2017. `multipath-quic.org/conext17-deconinck.pdf`
- Versa Networks. SD-WAN Configuration — Traffic Steering (default = per-flow, weighted round-robin proportional to per-path bandwidth). `docs.versa-networks.com/Secure_SD-WAN/01_Configuration_from_Director/SD-WAN_Configuration/Advanced_SD-WAN_Configuration/Configure_SD-WAN_Traffic_Steering`

**Implementations referenced**

- picoquic `e652e454`: `loss_recovery.c#L562` (fixed `delta_seq >= 3`) / `frames.c#L2652` (telemetry)
- Google QUICHE `f001eed`: `general_loss_algorithm.h#L124` (`use_adaptive_reordering_threshold_ = true`) / `quic_constants.h#L285` (`kDefaultPacketReorderingThreshold = 3`)
- Implementation: `src/reorder.h` / `src/reorder_tx.c` / `src/reorder_rx.c` (merged to main in PR #153, default OFF)
- Harness: `benchmarks/sweep_reorder.sh` (perf + OFF baseline; `BENCH_SCHEDULER=minrtt` switches scheduler for §4.3), `benchmarks/sweep_single_path.sh` (single-path baseline for the 3-way comparison in §4.1), `benchmarks/sweep_reorder_analyze.py` (Pareto + ON/OFF + 3-way table); shared netem profile table `BENCH_ENV_NETEM` in `benchmarks/bench_env_setup.sh`. Fresh runs write to the gitignored `ci_sweep_results/` (see §3.5); the archived copies that back this report's tables live under [`bench_results/`](../../bench_results/) — `reorder_full.csv` / `reorder_off.csv` / `reorder_full_minrtt.csv` / `reorder_off_minrtt.csv` / `reorder_single.csv` and the rendered `reorder_optimal.md` (wlb) + `reorder_optimal_minrtt.md` (minrtt).
- Scheduler implementation: `src/flow_sched.c` (mqvpn schedulers: `minrtt`, `wlb`, `wlb_udp_pin`, `backup_fec`)
