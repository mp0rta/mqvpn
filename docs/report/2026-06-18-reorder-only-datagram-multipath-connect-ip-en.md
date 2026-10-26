<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 mp0rta and mqvpn contributors -->

# Reorder-only datagram buffering for CONNECT-IP over multipath QUIC — an empirical report

## Abstract

When paths differ in quality, naive multipath scheduling can deliver less goodput than the better path alone. This is well documented for MPTCP (BLEST 2016, ECF 2017, QAware 2018, LLHD 2022, Dimopoulos et al. 2025) and for multipath QUIC (draft-ietf-quic-multipath §5.5); commercial SD-WAN avoids it by steering each flow onto one path, weighted by bandwidth (Versa Networks). Almost all of that work assumes a TCP inner whose reordering tolerance adapts (RACK-TLP / SACK / DSACK, RFC 8985 / 2018 / 2883), so the inner already forgives much of the cross-path reordering.

This report measures the harder case: a QUIC inner with a fixed reordering threshold (picoquic, `kPacketThreshold = 3`; RFC 9002 §6.1.1 makes adaptation a MAY) carrying one HTTP/3 bulk transfer over MASQUE CONNECT-IP. mqvpn has a per-flow reorder buffer at the tunnel egress and two schedulers, `wlb` and `minrtt`. In every one of 16 netem profiles, some `(scheduler, reorder buffer)` setting ties or beats the better single path: `wlb` aggregates symmetric paths at +14–108 % over the best single path (under jitter the buffer is what makes this work); on asymmetric paths `wlb` collapses, but `minrtt` stays within 0 to −8 % of the best single path with multipath still enabled. The result: the usual mitigation — a scheduler that accounts for path differences, plus a reorder buffer in the tunnel — also works when the inner QUIC does not adapt its loss detection, a harder setting than the MPTCP one that BLEST / ECF / QAware were designed for.

## 1. Background — why a tunnel-side reorder buffer

MASQUE CONNECT-IP (RFC 9484) carries IP packets in QUIC DATAGRAM frames (RFC 9221). DATAGRAMs are **neither ordered nor reliable** by design; the application protocol handles them (RFC 9221 §5.1–5.3).

In QUIC, in-order delivery is the job of the **STREAM layer** (reassembly by offset, RFC 9000 §2.2). Multipath QUIC keeps stream data in order across paths (draft-ietf-quic-multipath §5.5 warns that this causes head-of-line blocking bounded by the slowest path's delay). DATAGRAMs skip the STREAM layer: they have no offset and no reassembly, so nothing in QUIC, single-path or multipath, puts them back in order.

So datagrams sent over paths with different delays arrive out of order at the egress, and no QUIC layer reorders them. If the inner traffic is one congestion-controlled flow (an inner QUIC or TCP connection, which cannot be split across paths), the inner stack reads the reordering as loss and shrinks its congestion window. The multipath gain is lost; in the worst case goodput falls below a single path.

mqvpn uses CONNECT-IP, so it hits this directly. It therefore adds a buffer at the tunnel egress that reorders datagrams (within the latitude RFC 9221 §5.1 grants). This report measures where that buffer helps.

None of this is specific to mqvpn or to DATAGRAMs. In any reliable, ordered multipath transport, slow-path packets head-of-line-block faster-path packets at the receiver, and the inner congestion controller reads reordering as loss (prior art in the Abstract). What this report adds is a measurement with a QUIC inner whose loss detection does **not** adapt (§1.1).

### 1.1 Out-of-order tolerance of the inner flow is a MAY at the RFC level (implementation-defined)

How much cross-path reordering hurts the inner flow depends on how much reordering its loss detection tolerates before declaring loss. TCP and QUIC differ here at the RFC level:

- **Modern TCP (RACK-TLP, RFC 8985 + SACK/DSACK, RFC 2018/2883):** the reordering window grows dynamically (SHOULD) with observed reordering. Each DSACK that reveals a spurious retransmission expands the window up to `(N+1)*min_RTT/4` (capped at SRTT), §6.2 Step 4.
- **QUIC (RFC 9002):** a fixed packet reordering threshold (`kPacketThreshold` = 3, RECOMMENDED, §6.1.1) is the default; RACK-style adaptive expansion is only a MAY (implementation-defined).

So a QUIC stack that follows the RFC default tolerates less reordering than RACK/SACK/DSACK TCP, and may never adapt. A tunnel that carries arbitrary inner QUIC cannot count on adaptation; the reorder buffer belongs in the tunnel.

Whether the inner stack adapts is implementation-dependent:

- **picoquic (the inner of this study, `e652e454`) — no dynamic expansion.** Fixed `delta_seq >= 3` ([`loss_recovery.c#L562`](https://github.com/private-octopus/picoquic/blob/e652e454b40ff94d7a0372d537fdf176d55b61f1/picoquic/loss_recovery.c#L562)). Spurious retransmissions are only recorded as telemetry (`max_reorder_gap`, [`frames.c#L2652`](https://github.com/private-octopus/picoquic/blob/e652e454b40ff94d7a0372d537fdf176d55b61f1/picoquic/frames.c#L2652)) and never fed back into the threshold. The collapses in §4 are this behaviour.
- **Google QUICHE (Chrome / Cronet) — dynamic expansion.** `use_adaptive_reordering_threshold_ = true` by default ([`general_loss_algorithm.h#L124`](https://github.com/google/quiche/blob/f001eed73bcff9389be32a36047e8945fba32553/quiche/quic/core/congestion_control/general_loss_algorithm.h#L124)); `SpuriousLossDetected()` grows `reordering_threshold_` on each spurious detection. Initial value `kDefaultPacketReorderingThreshold = 3` ([`quic_constants.h#L285`](https://github.com/google/quiche/blob/f001eed73bcff9389be32a36047e8945fba32553/quiche/quic/core/quic_constants.h#L285)).

This study measures the non-adaptive case (picoquic, the RFC default). How much the buffer still helps an adaptive inner (QUICHE) is future work.

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
| Kernel | 7.0.0-31-generic (host; runs in a privileged `ubuntu:24.04` container) |
| netem/tc | iproute2-6.1.0 |
| CPU | 32 cores |
| mqvpn | `a548ea4d` (main) + harness knobs from this report's PR |
| xquic | `5f63f07` (tag `mqvpn-v0.17.0`) |
| picoquic | `e652e454` (local build, not a submodule) |
| Topology | Linux netns, 2 paths (`benchmarks/bench_env_setup.sh`) |
| Privilege | root (netns requires `sudo`; the result dir `ci_sweep_results/` ends up root-owned, so `chown` before analysis) |

### 3.2 Workload, metrics, and configurations

- **Inner workload:** a single HTTP/3 bulk GET via `picoquicdemo`, congestion control BBR (`-G bbr`), 20 MiB transfer, single stream. A CC-driven HTTP/3 flow is required; without CC (`iperf3 -u`) the reorder→false-loss chain does not appear.
- **goodput [Mbps]:** picoquicdemo's "Received … Mbps" download line.
- **p99 added-latency [ms]:** the reorder engine's residence-time histogram (enqueue→deliver; in-order pass-through counted as 0 ms) for the data direction, i.e. the client's receive-side buffer. Path RTT is not included. The client's reorder statistics are not exposed by the shipped Linux CLI; these runs use a measurement-only build that logs them at shutdown. The histogram has power-of-two buckets, so p99 values are bucket upper bounds (1, 2, 4, … 512 ms); above 512 ms it reports the tracked maximum.
- **Schedulers measured:** `--scheduler wlb` (the default; weighted load balance across paths) and `--scheduler minrtt` (lowest-SRTT path selection, spillover only when cwnd-blocked). Both schedulers spread the single inner UDP/QUIC flow across both paths (neither pins by 4-tuple — pinning is `--scheduler wlb_udp_pin`, not used here, since pinning trivially gives up aggregation). The difference is how aggressively each pushes traffic to the slower path.
- **Reorder rule (when ON):** `[ReorderRule] Proto = udp / Port = 5401 / Profile = quic_bulk`; `[Reorder] Enabled = true` with `MaxWaitMs` / `CapPackets` swept.

### 3.3 Environment matrix (exact netem strings, all 16 environments)

Passed to `bench_apply_netem "<Path A>" "<Path B>"` (the `ENV_NETEM` table in `sweep_reorder.sh`). `RTT spread` is the difference of the two one-way netem delays; netem is applied at both ends of each path, so the round-trip difference is twice this value. Jitter is `delay TIME JITTER distribution normal` (netem has no `jitter` keyword; without `distribution normal` the p99 is underestimated).

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

Two-stage sweep of the buffer knobs (3 repeats, median taken; every cell, including OFF and single path, runs with a 300 s hard cap):

1. **Stage 1 (max_wait):** `cap=1024` fixed, `max_wait_ms ∈ {10, 20, 30, 50, 80, 120, 200, 300}` across all 16 environments.
2. **Stage 2 (cap):** at each scheduler's Stage-1 goodput-peak wait, `cap_packets_per_flow ∈ {256, 512, 1024, 2048, 4096}` across the representative profiles + baseline (6 environments). This spans the BDP (300 mbit × 40 ms ≈ 1500 pkt).

The same two-stage sweep runs once per scheduler (`wlb`, `minrtt`); the single-path baseline does not depend on the scheduler and is shared. For each environment the analysis computes the Pareto frontier (max goodput, min p99), the goodput knee (smallest wait reaching ≥ 90 % of peak goodput; ties go to the smallest cap), and the **net benefit** of ON over `--reorder off` (RAW pass-through).

### 3.5 Reproduction commands

```bash
# build
cmake -S . -B build-lib -DCMAKE_BUILD_TYPE=Release \
      -DXQUIC_BUILD_DIR="$PWD/third_party/xquic/build"
cmake --build build-lib -j"$(nproc)"
scripts/ci_interop/build_picoquic.sh               # local build of third_party/picoquic

export MQVPN="$PWD/build-lib/mqvpn" \
       PICOQUICDEMO="$PWD/third_party/picoquic/build/picoquicdemo" \
       PICO_TIMEOUT=300

# ── wlb sweep (§4.1–§4.2) ───────────────────────────────────────
# Stage 2 runs at each env's Stage-1 goodput-peak wait (STAGE2_WAITS).
sudo -E ./benchmarks/sweep_reorder.sh --stage 1 --out ci_sweep_results/reorder_full.csv
sudo -E STAGE2_WAITS="baseline=300 dual_lte=30 fiber_lte=50 lte_starlink=50 lte_geo=300 congested=80" \
     ./benchmarks/sweep_reorder.sh --stage 2 --out ci_sweep_results/reorder_full.csv
sudo -E ./benchmarks/sweep_reorder.sh --reorder off --out ci_sweep_results/reorder_off.csv

# ── minrtt sweep (§4.3) ─────────────────────────────────────────
sudo -E BENCH_SCHEDULER=minrtt \
     ./benchmarks/sweep_reorder.sh --stage 1 --out ci_sweep_results/reorder_full_minrtt.csv
sudo -E BENCH_SCHEDULER=minrtt \
     STAGE2_WAITS="baseline=80 dual_lte=30 fiber_lte=20 lte_starlink=50 lte_geo=10 congested=20" \
     ./benchmarks/sweep_reorder.sh --stage 2 --out ci_sweep_results/reorder_full_minrtt.csv
sudo -E BENCH_SCHEDULER=minrtt \
     ./benchmarks/sweep_reorder.sh --reorder off --out ci_sweep_results/reorder_off_minrtt.csv

# ── single-path baseline (scheduler-independent) ────────────────
# 16 envs × 2 paths × 3 repeats = 96 cells. Reorder disabled (one path has
# no cross-path reordering to fix). Reused for both schedulers.
sudo -E ./benchmarks/sweep_single_path.sh --out ci_sweep_results/reorder_single.csv

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

The archived CSVs in `bench_results/` come from the measurement-only client build (§3.2). The stock CLI produces the same goodput column, but its `added_*` / `gap_*` columns come from the server's buffer, which during a download sees only ACKs. The four groups above ran in parallel, one privileged container each; a check against a lone run (`rtt_40`, wait 50) agreed within run-to-run noise.

Inner picoquicdemo: server `picoquicdemo -p 5401 -c <cert> -k <key> -G bbr -1 -D`; client `timeout -k 5 $PICO_TIMEOUT picoquicdemo -G bbr -D -n test <SERVER_IP> 5401 /20971520`.

## 4. Results

### 4.1 Three-way comparison under `wlb`: single path vs multipath (OFF / ON)

Each environment compares three options: a single path (Path A or Path B alone), multipath with reorder OFF, and multipath with reorder at its best-goodput setting. The recommendation is the simplest option whose median goodput is within 5 % of the winner (single > multipath OFF > multipath + reorder ON). Under `wlb` the envs fall into three groups.

#### 4.1.A Multipath + reorder ON — buffer earns its keep (8 envs)

| env | RTT spread [ms] | Path A [Mbps] | Path B [Mbps] | best single [Mbps] | OFF (mp) [Mbps] | best-ON (mp) [Mbps] | best-ON wait / cap | Δ best-ON vs OFF [%] | Δ best-ON vs best-single [%] |
|---|--:|--:|--:|--:|--:|--:|---|--:|--:|
| `baseline` | 0 | 40.7 | 40.3 | **40.7** | 62.0 | **69.7** | wait=300, cap=4096 | +13 | **+71** |
| `rtt_40` | 20 | 40.6 | 37.9 | **40.6** | 0.9 | **62.2** | wait=200, cap=1024 | +7004 | **+53** |
| `rtt_70` | 50 | 40.7 | 33.7 | **40.7** | 0.6 | **48.8** | wait=80, cap=1024 | +7813 | **+20** |
| `jit_5` | 0 | 38.6 | 38.5 | **38.6** | 3.2 | **68.7** | wait=80, cap=1024 | +2048 | **+78** |
| `jit_20` | 0 | 33.3 | 34.0 | **34.0** | 1.0 | **47.1** | wait=200, cap=1024 | +4626 | **+39** |
| `loss_2` | 0 | 17.4 | 18.8 | **18.8** | 18.1 | **24.0** | wait=10, cap=1024 | +33 | **+28** |
| `dual_lte` | 15 | 30.3 | 19.2 | **30.3** | 0.9 | **37.9** | wait=30, cap=1024 | +4166 | **+25** |
| `congested` | 10 | 5.4 | 5.8 | **5.8** | — | **8.0** | wait=50, cap=1024 | n/a (OFF collapsed) | **+38** |

In six of these envs multipath OFF collapses because of the inner's fixed `kPacketThreshold = 3` (§1.1), and reorder ON recovers past the better single path. `baseline` and `loss_2` already aggregate with OFF; ON adds 13–33 %. All eight have RTT spread ≤ 50 ms and a single-path goodput ratio below 1.6×. `best-ON wait / cap` is the goodput peak; the lower-latency knee reaches ≥ 90 % of it (§4.2, §4.3).

#### 4.1.B Multipath, reorder OFF — clean aggregation (1 env)

| env | RTT spread [ms] | Path A [Mbps] | Path B [Mbps] | best single [Mbps] | OFF (mp) [Mbps] | best-ON (mp) [Mbps] | best-ON wait / cap | Δ best-ON vs OFF [%] | Δ OFF vs best-single [%] |
|---|--:|--:|--:|--:|--:|--:|---|--:|--:|
| `loss_05` | 0 | 30.0 | 27.9 | **30.0** | **62.2** | 61.3 | wait=10, cap=1024 | −1 | **+108** |

Symmetric paths, no RTT spread, no jitter, loss on each path. Multipath aggregates without the buffer (the inner sees little cross-path reordering), and turning the buffer on is neutral (−1 %). The default, reorder OFF, is right here.

#### 4.1.C Single path beats multipath under `wlb` (7 envs)

| env | RTT spread [ms] | Path A [Mbps] | Path B [Mbps] | best single [Mbps] | OFF (mp) [Mbps] | best-ON (mp) [Mbps] | best-ON wait / cap | Δ best-ON vs OFF [%] | Δ best-ON vs best-single [%] |
|---|--:|--:|--:|--:|--:|--:|---|--:|--:|
| `rtt_320` | 300 | **40.7** | 8.9 | **40.7** | 1.7 | 2.8 | wait=10, cap=1024 | +65 | **−93** |
| `fiber_lte` | 32 | **212.8** | 22.3 | **212.8** | 0.9 | 71.5 | wait=50, cap=4096 | +7997 | **−66** |
| `lte_geo` | 285 | **31.9** | 6.1 | **31.9** | — | 14.3 | wait=300, cap=2048 | n/a (OFF collapsed) | **−55** |
| `bw_10to1` | 0 | **73.7** | 8.7 | **73.7** | 15.1 | 38.2 | wait=200, cap=1024 | +153 | **−48** |
| `lte_starlink` | 15 | **30.2** | 16.4 | **30.2** | 0.6 | 25.5 | wait=50, cap=4096 | +3956 | **−15** |
| `bw_4to1` | 0 | **40.7** | 10.4 | **40.7** | 21.7 | 34.9 | wait=30, cap=1024 | +61 | **−14** |
| `rtt_120` | 100 | **40.7** | 27.8 | **40.7** | 1.5 | 35.3 | wait=300, cap=1024 | +2300 | **−13** |

In every §4.1.C env, Path A is the faster or lower-RTT side. `OFF (mp) = —` means multipath OFF did not finish the 20 MiB transfer within the 300 s cap. Reorder ON does finish in that cell (`lte_geo`) — the clearest case of the buffer rescuing a collapse — but `wlb` multipath is still slower than Path A alone.

What these envs share: Path B alone delivers about half of Path A or less (single-path ratio ≥ 1.8×), or RTT spread is ≥ 100 ms, or both. `wlb` still sends part of the traffic on the slow path; the buffer can prevent outright collapse but cannot beat the better single path. These verdicts are for `wlb` only; under `minrtt` (§4.3) every one of these envs comes out differently.

### 4.2 Buffer sensitivity: `max_wait_ms` vs RTT spread (under `wlb`)

Along the `rtt_*` axis, the knee — smallest `max_wait_ms` reaching ≥ 90 % of peak goodput — tracks the spread cleanly:

| env | spread [ms] | knee wait [ms] | knee goodput [Mbps] | peak wait [ms] | peak goodput [Mbps] |
|---|--:|--:|--:|--:|--:|
| baseline | 0 | 10 | 68.8 | 300 | 69.7 |
| rtt_40 | 20 | 20 | 56.1 | 200 | 62.2 |
| rtt_70 | 50 | 80 | 48.8 | 80 | 48.8 |
| rtt_120 | 100 | 120 | 35.1 | 300 | 35.3 |
| rtt_320 | 300 | 10 | 2.8 | 10 | 2.8 |

- Spread 20–50 ms: the knee tracks the spread. When `wait ≪ spread`, gaps never fill, everything times out, and goodput collapses to ~ 1 Mbps.
- Spread 100 ms: the knee still tracks the spread (120 ms) — but as §4.1.C shows, the resulting goodput is below single-path, so tuning the wait does not change the verdict.
- Spread 300 ms: no wait recovers goodput (≤ 2.8 Mbps); `minrtt` matches the single path here (§4.3).

High-BDP paths (fibre, ~ 300 mbit) need `cap ≥ 1024` with reorder ON; 256 and 512 collapse (`fiber_lte`, cap 256 → 4096: `wlb` at wait 50 gives 0.3 / 2.2 / 58.1 / 65.5 / 71.5 Mbps, `minrtt` at wait 20 gives 0.6 / 170 / 201 / 204 / 197 Mbps). The cap limits how far ahead of the oldest gap a packet may arrive, and packets beyond it are dropped, so it must cover `(wait + spread) × packet rate`. The per-flow byte limit never bound in any run. On low-BDP paths the cap does not matter, and outside the §4.1.A envelope the answer is to leave the buffer off, so the cap is moot there.

### 4.3 Same sweep under `--scheduler minrtt`

The same sweep with `minrtt` (lowest-SRTT path; spills to the other path only when cwnd-blocked). Each cell shows `OFF: <gp>` (`[Reorder] Enabled = false`) and `ON: <gp> @<wait>` (ON at the knee), with the higher value in bold. The Δ columns compare each scheduler's higher value with the better single path: positive means multipath wins, near zero means it matches while keeping multipath on, negative means the single path is faster. `cap = 1024` unless noted.

| env | spread [ms] | single [Mbps] | `wlb` [Mbps] | Δ `wlb` vs single [%] | `minrtt` [Mbps] | Δ `minrtt` vs single [%] | recommended config |
|---|--:|--:|---|--:|---|--:|---|
| `baseline` | 0 | 40.7 | OFF: 62.0 • **ON: 68.8 @10** | **+69** | OFF: 37.0 • **ON: 44.0 @50** | +8 | `wlb`, Reorder ON, MaxWaitMs=10 |
| `rtt_40` | 20 | 40.6 | OFF: 0.9 • **ON: 56.1 @20** | **+38** | OFF: 39.0 • **ON: 40.8 @20** | 0 | `wlb`, Reorder ON, MaxWaitMs=20 |
| `rtt_70` | 50 | 40.7 | OFF: 0.6 • **ON: 48.8 @80** | **+20** | OFF: 36.4 • **ON: 40.7 @10** | 0 | `wlb`, Reorder ON, MaxWaitMs=80 |
| `rtt_120` | 100 | 40.7 | OFF: 1.5 • **ON: 35.1 @120** | −14 | **OFF: 40.7** • ON: 40.4 @10 | **0** | `minrtt`, Reorder OFF |
| `rtt_320` | 300 | 40.7 | OFF: 1.7 • **ON: 2.8 @10** | −93 | **OFF: 40.7** • ON: 40.5 @10 | **0** | `minrtt`, Reorder OFF |
| `jit_5` | 0 | 38.6 | OFF: 3.2 • **ON: 63.7 @20** | **+65** | OFF: 17.1 • **ON: 52.6 @120** | +36 | `wlb`, Reorder ON, MaxWaitMs=20 |
| `jit_20` | 0 | 34.0 | OFF: 1.0 • **ON: 47.1 @200** | **+39** | OFF: 5.4 • **ON: 37.5 @120** | +10 | `wlb`, Reorder ON, MaxWaitMs=200 |
| `loss_05` | 0 | 30.0 | **OFF: 62.2** • ON: 61.3 @10 | **+108** | OFF: 26.9 • **ON: 29.9 @10** | 0 | `wlb`, Reorder OFF |
| `loss_2` | 0 | 18.8 | OFF: 18.1 • **ON: 24.0 @10** | **+28** | **OFF: 14.6** • ON: 14.0 @10 | −22 | `wlb`, Reorder ON, MaxWaitMs=10 |
| `bw_4to1` | 0 | 40.7 | OFF: 21.7 • **ON: 33.4 @10** | −18 | **OFF: 39.6** • ON: 38.4 @20 | **−3** | `minrtt`, Reorder OFF |
| `bw_10to1` | 0 | 73.7 | OFF: 15.1 • **ON: 34.7 @30** | −53 | **OFF: 72.1** • ON: 69.0 @10 | **−2** | `minrtt`, Reorder OFF |
| `dual_lte` | 15 | 30.3 | OFF: 0.9 • **ON: 34.4 @30,cap=512** | **+14** | OFF: 20.1 • **ON: 28.1 @10** | −7 | `wlb`, Reorder ON, MaxWaitMs=30 |
| `fiber_lte` | 32 | 212.8 | OFF: 0.9 • **ON: 65.5 @50,cap=2048** | −69 | **OFF: 211.8** • ON: 201.4 @10 | **0** | `minrtt`, Reorder OFF |
| `lte_starlink` | 15 | 30.2 | OFF: 0.6 • **ON: 24.0 @50** | −20 | OFF: 26.6 • **ON: 27.7 @20** | **−8** | `minrtt`, Reorder OFF (single Path A for pure throughput; multipath costs ~ 8 %) |
| `lte_geo` | 285 | 31.9 | OFF: — • **ON: 14.3 @300,cap=2048** | −55 | **OFF: 31.6** • ON: 31.5 @10,cap=256 | **−1** | `minrtt`, Reorder OFF |
| `congested` | 10 | 5.8 | OFF: — • **ON: 8.0 @50** | **+38** | OFF: 4.8 • **ON: 6.1 @20,cap=4096** | +4 | `wlb`, Reorder ON, MaxWaitMs=50 |

The recommended config is the simplest bold value within 5 % of the row's best, in this order: `wlb` before `minrtt`, Reorder OFF before ON, multipath before single (single loses failover). For `lte_starlink` no multipath setting is within 5 %; the table names the single-path alternative. `OFF: —` means the OFF run did not finish the 20 MiB transfer within the 300 s cap.

Three structural patterns drive the recommendations:

- **`wlb` wins on symmetric paths.** With similar bandwidth and RTT, `wlb` spreads traffic over both paths and reaches 1.5–2× the per-path goodput (`baseline`: 40.7 Mbps per path; 62.0 Mbps with `wlb` + OFF, 68.8 Mbps with ON). `minrtt` barely spreads load here (it keeps picking whichever path has the slightly lower SRTT) and stays near per-path goodput. Symmetric loss (`loss_05`, `loss_2`) and jitter or spread ≤ 50 ms (`jit_5`, `jit_20`, `rtt_40`, `rtt_70`, `dual_lte`) follow the same pattern; there Reorder ON enables the aggregation, but the scheduler is still `wlb`.
- **`minrtt` wins on asymmetric paths or high RTT spread.** It uses the faster / lower-RTT path and falls back to the other only when that path is cwnd-blocked. `fiber_lte`: `wlb` drops to 66 Mbps (the 300 mbit fibre is held back by the 30 mbit LTE); `minrtt` + OFF reaches 212 Mbps, the same as fibre alone. `rtt_120` and `rtt_320` match their best single path; `lte_geo`, `bw_10to1`, `bw_4to1` come within 1–3 %; `lte_starlink` keeps multipath working at −8 %.
- **Under `minrtt` the buffer is often unnecessary.** `minrtt` keeps most traffic on the better path, so only spillover packets cross paths and the gaps are small. `minrtt` + OFF wins outright in `fiber_lte`, `rtt_120`, `lte_geo`, `rtt_320`, `bw_4to1`, `bw_10to1`, `loss_2` — about half the rows. Where the buffer helps, the knee is mostly 10–20 ms (120 ms under jitter), because the few gaps fill quickly.

### 4.4 Configuration

The tree picks the scheduler and the reorder buffer state. It assumes multipath is already enabled.

```
0. Decide the scheduler from path topology.
     Symmetric (similar bandwidth, similar RTT, zero/small spread)?
       → --scheduler wlb        (aggregates symmetric paths up to ~ 2× per-path
                                 goodput; minrtt collapses to per-path goodput here.)
     Asymmetric (bandwidth ratio ≥ 2×) or RTT spread ≥ ~ 100 ms?
       → --scheduler minrtt     (preferentially uses the faster/lower-RTT path;
                                 wlb here would split onto the slow path and lose.)

1. Asymmetric or spread ≥ ~ 100 ms (minrtt at step 0).
     [Reorder] Enabled = false                                        ← default
       envs: fiber_lte, rtt_120, lte_geo, rtt_320, bw_4to1, bw_10to1, lte_starlink

2. Symmetric with jitter (per-path ≥ 5 ms) or spread ≤ 50 ms (wlb at step 0).
     [Reorder] Enabled = true, MaxWaitMs = the §4.3 knee (10–80 ms; 200 ms under
     20 ms jitter), CapPackets ≥ 1024
       envs: jit_5, jit_20, rtt_40, rtt_70, dual_lte, congested   (wlb OFF collapses
             to ~ 1 Mbps or never finishes here; see §4.1.A)
       envs: baseline (+11 %), loss_2 (+33 %)   (OFF already aggregates; ON adds this)

3. Symmetric with per-path loss only (wlb at step 0).
     [Reorder] Enabled = false                                        ← default
       env: loss_05   (enabling the buffer is neutral, −1 %)
```

The shipping defaults (`--scheduler wlb`, `[Reorder] Enabled = false`) fit step 3. Jittery or small-spread paths turn the buffer on (step 2); asymmetric or high-spread paths switch to `minrtt` (step 1). No environment in this sweep needed both schedulers at once.

## 5. Conclusion

Multipath delivering less than the better single path on mismatched links is a long-known property of naive multipath scheduling (BLEST 2016, ECF 2017, QAware 2018, LLHD 2022, Dimopoulos et al. 2025). Its causes — head-of-line blocking at the receiver, scheduling on stale RTTs, and the inner congestion controller reading reordering as loss — apply to MPTCP, multipath QUIC (draft-ietf-quic-multipath §5.5) and RoCEv2 alike; commercial SD-WAN (Versa) avoids it by steering per flow, giving up packet-level aggregation.

This report shows that the same mitigation — a scheduler that accounts for path differences plus a reorder buffer in the tunnel — works with a QUIC inner whose loss detection does not adapt (`kPacketThreshold = 3`, the RFC 9002 §6.1.1 default; picoquic does not implement the optional RACK-style expansion). That is harder than the RACK/SACK/DSACK TCP inner assumed in the MPTCP literature, because the inner does not absorb reordering itself. In all 16 netem profiles, mqvpn has a `(scheduler, reorder buffer)` setting that ties or beats the better single path:

| Path topology | Scheduler | Reorder | Δ vs best single |
|---|:--|:--|---:|
| Symmetric, clean or pure loss | `wlb` | OFF or ON | +28 to +108 % |
| Symmetric, jittery or ≤ 50 ms spread | `wlb` | ON, wait = knee | +14 to +65 % |
| Asymmetric bandwidth or spread ≥ 100 ms | `minrtt` | OFF | −8 to 0 % |

The right scheduler at worst stays within ~8 % of the better single path instead of losing to it, so the old rule *only use multipath if your paths are similar* matters less for mqvpn. The reorder buffer helps in a narrow, well-defined range — symmetric paths whose reordering comes from jitter or small RTT spread — and that range gives the +14–65 % results under `wlb`; outside it, the scheduler choice matters more than buffer tuning.

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
