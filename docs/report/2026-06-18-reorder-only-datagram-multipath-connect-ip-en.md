<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 mp0rta and mqvpn contributors -->

# Reorder-only datagram buffering for CONNECT-IP over multipath QUIC — an empirical report

---

## TL;DR (how to read this report)

mqvpn aggregates bandwidth across multiple network paths by carrying inner IP traffic over multipath QUIC + MASQUE CONNECT-IP. The catch is that DATAGRAM-mode multipath has no in-order delivery layer (§1), so when paths differ in delay the inner congestion-controlled flow mistakes the cross-path reordering for loss. This report measures, on 16 netem profiles, **which combination of scheduler (`wlb` vs `minrtt`) and reorder-buffer state (off vs on) maximises bandwidth-aggregation throughput**, against a single-path baseline.

**Read §4 in order.** §4.1 shows the verdict under the default scheduler `wlb` — and in 10 of 16 envs it says "single path is faster". **That is a `wlb` artifact, not a fundamental mqvpn limit.** §4.3 reruns the same envs under `minrtt`: in every one of those 10, `minrtt` recovers single-path-equivalent throughput while leaving multipath enabled. §4.4 is the final decision tree using both schedulers' data; §5 is the bottom line.

If you only have time for the headline, jump to §5. If you read §4.1.C, also read §4.3 — never one without the other.

---

## 1. Background — why a tunnel-side reorder buffer

MASQUE CONNECT-IP (RFC 9484) carries IP packets inside QUIC DATAGRAM frames (RFC 9221). DATAGRAMs are, by design, **neither ordered nor reliable**, and their handling is delegated to the application protocol (RFC 9221 §5.1–5.3).

In-order delivery in QUIC is the job of the **STREAM layer** (reassembly by connection-level offset, RFC 9000 §2.2). Multipath QUIC keeps that property for streams — stream data stays in order across all paths (draft-ietf-quic-multipath §5.5 in fact warns this causes head-of-line blocking, bounded by the slowest path's delay). **But DATAGRAMs bypass the STREAM layer entirely** — they have no offset and no reassembly, so nothing in QUIC, single-path or multipath, re-orders datagrams.

As a result, **datagrams spread across paths with different delays arrive reordered at the egress, and there is no layer inside QUIC to put them back in order.** When the inner traffic is a single congestion-controlled flow (inner QUIC / TCP that cannot be flow-split), the inner stack misreads this cross-path reordering as **loss**, shrinks its congestion window, and the multipath aggregation benefit is lost — in the worst case, throughput collapses below that of a single path.

mqvpn uses CONNECT-IP, i.e. DATAGRAMs, so it is directly exposed to the above. I therefore added a **buffer at the tunnel egress that re-orders datagrams** (within the implementation latitude RFC 9221 §5.1 grants). This report quantifies its operating envelope across schedulers and netem profiles.

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
- **Out of scope (for this report):** failover behaviour — multipath's ability to keep the connection alive when one path degrades or drops — is a separate use case not measured here. The configuration guidance in §4 is keyed on bandwidth-aggregation throughput only; an operator who values failover resilience may still prefer multipath even where §4.1.C says single-path is faster under stable conditions.

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
- **mqvpn scheduler config:** §4.1–§4.2 use `--scheduler wlb` (the default); §4.3 reruns under `--scheduler minrtt`. **Neither pins by 4-tuple** — the single inner UDP/QUIC flow is spread across both paths in both cases (pinning is `wlb_udp_pin`, not used here, because pinning trivially gives up aggregation). The difference is how aggressively each scheduler pushes traffic to the slower path. The cross-path reordering that the buffer is designed for is therefore present under both schedulers, but is much more pronounced under `wlb`. Reorder rule: `[ReorderRule] Proto = udp / Port = 5401 / Profile = quic_bulk`; `[Reorder] Enabled = on` with `MaxWaitMs` / `CapPackets` swept.

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

1. **Stage 1 (max_wait):** `cap=1024` fixed, `max_wait_ms ∈ {10,20,30,50,80,120,200,300}` across all 16 environments.
2. **Stage 2 (cap):** near the best wait from Stage 1, `cap_packets_per_flow ∈ {256,512,1024,2048,4096}` across the representative profiles + baseline (6 environments). This spans the BDP (300 mbit × 40 ms ≈ 1500 pkt).

The same two-stage protocol is run once with `--scheduler wlb` and once with `--scheduler minrtt`. The single-path baseline (Path A or Path B alone) is scheduler-independent and reused.

Per cell, goodput and p99 added-latency are measured; per environment, the Pareto frontier (maximize goodput, minimize p99) and the recommended default = the **goodput knee** (smallest wait reaching ≥ 90 % of peak goodput; ties broken by smallest cap) are computed. The **ON vs OFF net benefit** against `--reorder off` (RAW pass-through) is computed as well.

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
# 16 envs × 2 paths × 3 repeats = 96 cells. Reorder disabled (one path
# has no cross-path reordering to fix). Reused for both schedulers.
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

inner picoquicdemo: server `picoquicdemo -p 5401 -c <cert> -k <key> -G bbr -1 -D`; client `timeout -k 5 $PICO_TIMEOUT picoquicdemo -G bbr -D -n test <SERVER_IP> 5401 /20971520`.

## 4. Results

For each network environment, this section answers the operator-facing question: **which scheduler, with the buffer on or off?**

The four subsections are sequential and must be read in order:

- **§4.1** — three-way comparison (single / mp-OFF / mp-ON) **under `wlb` only**. Three buckets: 3 envs aggregate with the buffer on (§4.1.A), 3 aggregate without it (§4.1.B), 10 do not aggregate under `wlb` at all (§4.1.C). **§4.1.C is the source of the "multipath worse than single path" reading — its scope is `wlb`, and §4.3 shows the resolution.**
- **§4.2** — sensitivity of the reorder buffer's `max_wait_ms` to RTT spread (still `wlb`).
- **§4.3** — same sweep under **`--scheduler minrtt`**: each of the 10 §4.1.C envs ties or matches the better single path while keeping multipath enabled.
- **§4.4** — final decision tree across both schedulers' data.

Throughput-only measurement; multipath's failover value is out of scope (§2).

### 4.1 Three-way comparison **under `wlb`**: single path vs multipath (OFF / ON)

The comparison includes a **single-path baseline** for each environment: the goodput an operator would see if mqvpn were configured with only Path A (or only Path B). This baseline answers a question that an ON-vs-OFF table alone cannot: *is multipath worth using at all in this environment?*

Each row below compares three configurations on the **same netem**: single path (Path A or Path B = the env's path A or path B netem applied to a lone path), multipath with reorder OFF (RAW pass-through), and multipath with reorder at its best-goodput tuning. The recommendation picks the simplest configuration whose median goodput is within 5 % of the winner (priority: single > multipath OFF > multipath + reorder ON).

Three buckets emerge.

#### 4.1.A ✅ Multipath + reorder ON — buffer earns its keep (3 envs)

| env | RTT spread [ms] | Path A [Mbps] | Path B [Mbps] | best single [Mbps] | OFF (mp) [Mbps] | best-ON (mp) [Mbps] | best-ON wait / cap | Δ best-ON vs OFF [%] | Δ best-ON vs best-single [%] |
|---|--:|--:|--:|--:|--:|--:|---|--:|--:|
| `rtt_40` | 20 | 40.5 | 37.9 | **40.5** | 0.85 | **49.0** | wait=200, cap=1024 | **+5666** | **+21** |
| `jit_5` | 0 | 38.3 | 38.8 | **38.8** | 3.38 | **61.4** | wait=120, cap=1024 | +1716 | **+58** |
| `jit_20` | 0 | 17.4 | 11.0 | **17.4** | 0.93 | **37.6** | wait=50, cap=1024 | **+3943** | **+115** |

These are the envs where the inner picoquic's fixed `kPacketThreshold = 3` (§1.1) collapses on the multipath OFF baseline AND where reorder ON recovers enough to genuinely exceed the better single path. They share: low RTT spread (0–20 ms), no bandwidth asymmetry, and jitter or small per-path spread. `best-ON wait / cap` is the goodput-peak configuration; the latency-bounded shipping default (the goodput knee, typically `wait=50 ms`) reaches ≥ 90 % of these numbers — see §4.2.

#### 4.1.B ✅ Multipath, reorder OFF — clean aggregation (3 envs)

| env | RTT spread [ms] | Path A [Mbps] | Path B [Mbps] | best single [Mbps] | OFF (mp) [Mbps] | best-ON (mp) [Mbps] | best-ON wait / cap | Δ best-ON vs OFF [%] | Δ OFF vs best-single [%] |
|---|--:|--:|--:|--:|--:|--:|---|--:|--:|
| `baseline` | 0 | 40.6 | 40.3 | **40.6** | **73.9** | 58.0 | wait=30, cap=2048 | −21.5 | **+82** |
| `loss_05` | 0 | 29.6 | 32.2 | **32.2** | **70.7** | 52.7 | wait=10, cap=1024 | −25.5 | **+119** |
| `loss_2` | 0 | 16.1 | 16.3 | **16.3** | **29.0** | 24.5 | wait=10, cap=1024 | −15.5 | **+78** |

Symmetric, zero RTT spread, no jitter. Aggregation works without a buffer (the inner doesn't see meaningful cross-path reordering), and enabling the buffer actively hurts: Δ best-ON vs OFF is negative for all three envs (15–26 % regression). **The shipping default of reorder OFF is the correct choice here.**

#### 4.1.C 🔴 Under `wlb`: single path beats multipath (10 envs — `minrtt` fixes this; see §4.3)

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

In every §4.1.C env, Path A is the higher-bandwidth or lower-RTT side (see §3.3 for the netem strings). `OFF (mp) = —` means the multipath OFF baseline did not finish the 20 MiB transfer within the 5-minute hard cap. Reorder ON does complete the transfer in those cells (`lte_starlink`, `congested`), where the buffer's "rescue from collapse" effect is clearest — but **even with ON, multipath under `wlb` is still slower than just using Path A**.

The unifying property: either path bandwidth is asymmetric (≥ 2× ratio), or RTT spread is ≥ 50 ms, or both. Under `wlb` the scheduler is forced to push some traffic onto the slow path; the reorder buffer can rescue the multipath stack from outright collapse but cannot beat the better single path.

**Important — read this as a `wlb` verdict, not a multipath verdict.** §4.3 reruns these same 10 envs under `--scheduler minrtt`: in every one, `minrtt` recovers single-path-equivalent throughput (fiber_lte 212 vs 212 single, bw_10to1 70 vs 74, rtt_120 40.6 vs 40.7, dual_lte 29.6 vs 29.6, etc.) while keeping multipath enabled. **The operator's answer to asymmetry is therefore to change the scheduler, not to abandon multipath.**

### 4.2 Sensitivity: optimal `max_wait_ms` vs RTT spread (under `wlb`)

For the envs where multipath + reorder is recommended (§4.1.A), the knee — smallest `max_wait_ms` reaching ≥ 90 % of peak goodput — tracks the spread cleanly:

| env | spread [ms] | knee wait [ms] | knee goodput [Mbps] | peak wait [ms] | peak goodput [Mbps] |
|---|--:|--:|--:|--:|--:|
| baseline | 0 | 10 | 57.9 | 30 | 58.0 |
| rtt_40 | 20 | 50 | 45.7 | 200 | 49.0 |
| rtt_70 | 50 | 50 | 34.2 | 300 | 36.5 |
| rtt_120 | 100 | 50 | 28.2 | 50 | 28.2 |
| rtt_320 | 300 | 10 | 35.7 | 10 | 35.7 |

- spread 20–50 ms: knee tracks the spread (when wait ≪ spread, gaps never fill, everything times out, goodput collapses to ~1 Mbps).
- spread ≥ 100 ms: the knee plateaus at 50 ms — but as §4.1.C shows, the resulting goodput is already below single-path; tuning the wait further does not change that.
- spread ≥ 285 ms: the smallest wait wins = the buffer is counterproductive (cost of waiting for the slow path exceeds the aggregation gain), but again single-path wins outright.

High-BDP paths (fiber, ~300 mbit) need **`cap ≥ 2048`** when reorder is enabled; 1024 is too small and 256/512 collapse. For low-BDP paths cap is irrelevant. Cap matters only inside the §4.1.A envelope — outside it, the right answer is "don't enable the buffer", so cap is moot.

### 4.3 Same sweep under `--scheduler minrtt`

This section reruns the multipath sweep with `--scheduler minrtt` (lowest-SRTT path selection, spillover only when the chosen path is cwnd-blocked) and asks, for each environment, **which scheduler + buffer setting an operator should pick**.

How to read the table:

- For each of the two schedulers, both `[Reorder] Enabled = off` and the best `Enabled = on` tuning were measured. The cell shows the **higher of the two** along with the setting that achieved it — e.g. `73.9 — Reorder OFF` means the OFF baseline beat every ON tuning under that scheduler.
- `single [Mbps]` is the higher of Path A / Path B running alone, reused from §4.1 (it does not depend on the scheduler — a single path has nothing to schedule).
- `recommended config` picks the option within 5 % of the highest goodput, preferring the simpler configuration on ties: **`wlb` over `minrtt`** (default scheduler), **Reorder OFF over ON** (default buffer), **multipath over single** (single drops failover; §2).

For each scheduler, two numbers are folded into one cell:

- `OFF: <gp>` — median goodput with `[Reorder] Enabled = off`.
- `ON: <gp> @<wait>` — best ON goodput at the **knee** (smallest `MaxWaitMs` reaching ≥ 90 % of peak; see §4.2). `cap = 1024` for every cell below; envs needing `cap = 2048` are noted in the prose.

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
| `lte_starlink` | 15 | 29.6 | OFF: — • **ON: 17.1 @50** | −42 | **OFF: 27.2** • ON: 26.6 @10 | −8 | `minrtt`, Reorder OFF (single Path A for pure throughput; multipath costs ~8 %) |
| `congested` | 10 | 6.4 | OFF: — • **ON: 5.7 @30** | −11 | OFF: 5.6 • **ON: 6.4 @30** | 0 | `minrtt`, Reorder ON, MaxWaitMs=30 |

Within each scheduler cell, **bold** marks whichever of OFF / ON delivered the higher goodput (the deployable winner under that scheduler). The Δ columns compare each scheduler's bold value against the better single path — positive means multipath beats single; near-zero means multipath matches single (useful for failover); negative means single path is faster. The recommended config picks the bold value within 5 % of the highest cell on the row, preferring the simpler configuration (default `wlb` > `minrtt`; default Reorder OFF > ON; multipath > single — single drops failover, see §2). Two envs (`bw_10to1`, `lte_starlink`) fall outside the 5 % band for multipath; the table notes the single-path alternative so the operator can choose. `OFF: —` means the OFF baseline did not finish the 20 MiB transfer within the 5-minute hard cap (`lte_starlink`, `congested` under `wlb`). All ON cells use `CapPackets = 1024` unless noted (`fiber_lte` under `wlb` needs `cap = 2048` — see §4.2; under `minrtt` the default cap suffices because traffic is concentrated on the fast path and reorder gaps are small).

Three structural patterns drive the recommendations.

**`wlb` wins on symmetric paths** (similar bandwidth, similar RTT). It spreads traffic across both paths and aggregates 1.5–2× the per-path goodput. `baseline` is the cleanest case: 40.6 Mbps per path, 73.9 Mbps with `wlb` + Reorder OFF — true aggregation. `minrtt` on the same env barely spreads load (it keeps picking whichever path has the marginally lower SRTT) and lands at roughly the per-path goodput (45.3 Mbps). Symmetric loss (`loss_05`, `loss_2`) and small RTT spread / jitter (`jit_5`, `jit_20`, `rtt_40`) follow the same pattern — in those envs Reorder ON unlocks aggregation, but the scheduler choice is still `wlb`.

**`minrtt` wins on asymmetric paths or high RTT spread.** When one path is materially better than the other, `minrtt` preferentially uses the faster / lower-RTT path and falls back to the slower one only when the better path is congestion-blocked, typically delivering near-best-single-path goodput while keeping multipath enabled. `fiber_lte` is the strongest case: under `wlb` the multipath stack collapses to 77 Mbps (the 300 mbit fiber gets dragged down by the 30 mbit LTE); under `minrtt` + Reorder OFF it reaches 212 Mbps — equal to fiber-alone. `bw_4to1`, `dual_lte` match their best single path exactly; `rtt_70`, `rtt_120`, `rtt_320`, `lte_geo` come within 1–3 %. `bw_10to1` (−6 %) and `lte_starlink` (−8 %) are the soft cases: `minrtt` keeps the multipath stack functional but pays a small throughput tax that the operator may or may not accept depending on how much they value failover.

**Under `minrtt` the buffer is often unnecessary or only mildly helpful.** Because `minrtt` concentrates traffic on the better path, only the spillover packets cross paths, so cross-path reorder gaps are small — and the operating envelope where the buffer beats OFF is narrower than under `wlb`. In several envs `minrtt` + OFF outright wins (`fiber_lte` 212.3 vs 198.8, `rtt_120` 40.6 vs 40.4, `lte_geo` 31.5 vs 30.1, `rtt_320` tied) or beats it by only 1–6 % (`bw_4to1`, `bw_10to1`, `baseline`). When the buffer does help under `minrtt`, the knee wait is short — typically `MaxWaitMs = 10–30` ms versus `wlb`'s `50` ms — because the rare cross-path gaps fill quickly. The recommended-config column reflects this: about half the `minrtt` rows leave the buffer OFF.

### 4.4 Configuration decision tree

The tree picks the **scheduler**, the **reorder buffer state**, and any tuning, optimising for bandwidth-aggregation throughput. It assumes multipath is already enabled (two paths configured in mqvpn); failover use is independent (§2) and not a separate branch. The rationale for each step is in §4.1 (`wlb`) and §4.3 (`minrtt`).

```
0. Start by deciding the scheduler.

   Symmetric paths (similar bandwidth, similar RTT, zero / small spread)?
     → --scheduler wlb        (aggregates symmetric paths up to ~2× the
                               per-path goodput; minrtt collapses to roughly
                               single-path goodput on symmetric envs.)
   Asymmetric bandwidth (≥ 2× ratio) or RTT spread ≥ ~50 ms?
     → --scheduler minrtt     (preferentially uses the faster / lower-RTT
                               path and falls back to single-path-equivalent
                               throughput. wlb here would split traffic onto
                               the slow path and lose throughput.)

1. Asymmetric bandwidth OR RTT spread ≥ ~50 ms (you picked minrtt at step 0)?
   → Start with [Reorder] Enabled = off; multipath stays enabled for failover.
     OFF is best for: fiber_lte, rtt_120, lte_geo, rtt_320, bw_4to1,
     bw_10to1, lte_starlink (the buffer adds latency without helping —
     minrtt already concentrates traffic on the better path).
     Switch to [Reorder] Enabled = on, MaxWaitMs = 10–30 for:
       rtt_70 (+10 %), dual_lte (+13 %), congested (+14 %).
     See §4.3 for the exact per-env Δ between OFF and ON.

2. Symmetric paths with jitter (per-path ≥ 5 ms) OR small RTT spread (≤ 30 ms)
   (you picked wlb at step 0)?
   → [Reorder] Enabled = on, [Reorder] MaxWaitMs = 50
     (CapPackets = 2048 if BDP > 1 MB; otherwise the default).
     [jit_5, jit_20, rtt_40]
     Why: under wlb the OFF baseline collapses to ~1 Mbps in these envs
     because the inner picoquic reads cross-path reordering as loss (§1.1).
     The buffer recovers and exceeds the better single path (§4.2 for the
     wait/cap sensitivity).

3. Symmetric, clean (no jitter, near-zero per-path loss, zero spread)
   OR symmetric with per-path loss only (you picked wlb at step 0)?
   → [Reorder] Enabled = off.   (This is the shipping default.)
     [baseline, loss_05, loss_2]
     Why: clean wlb aggregation with no cross-path reorder for the buffer
     to fix; enabling the buffer adds 15–25 % latency cost for no gain
     (§4.1.B).

4. Congested (per-path loss > 1 % with jitter)?
   → use the single path with least loss; neither scheduler aggregates.
     [congested]
     Why: total per-path bandwidth is already the bottleneck; neither
     scheduler nor the buffer recovers throughput meaningfully.
```

**Shipping defaults** — `--scheduler wlb`, `[Reorder] Enabled = off`, multipath enabled — are correct for the symmetric / loss envs (step 3). Operators on jittery or small-spread paths opt the buffer in (step 2); operators on asymmetric or high-spread paths switch the scheduler to `minrtt` (step 1). No environment in this sweep needed both schedulers at once — the choice is a clean function of path symmetry, decided by a single CLI flag.

## 5. Bottom line — the "multipath worse than single path" failure is now opt-out

Combining §4.1 and §4.3: with mqvpn's two shipping schedulers and a single binary choice for the reorder buffer, **every one of the 16 environments in this study has a configuration that ties or beats the better single path**.

- Symmetric, clean / pure loss → `wlb` + Reorder OFF: **+78 – 120 % over best single**.
- Symmetric with jitter or 20 – 50 ms RTT spread → `wlb` + Reorder ON: **+13 – 116 % over best single**.
- Asymmetric bandwidth or RTT spread ≥ 50 ms → `minrtt` (mostly Reorder OFF): **−8 % to +5 % vs best single** — multipath stays up for failover and control-plane multiplexing without the slow path dragging throughput below the fast path.

The classic multipath failure mode — *a weaker path drags the aggregate below what the stronger path delivers alone* — used to be the default outcome on asymmetric uplinks under the historical `wlb` + buffer-OFF defaults (fiber_lte 4.9 vs 212 Mbps single; dual_lte 0.9 vs 30; bw_10to1 13 vs 74). It is **no longer a forced outcome**: switching to `minrtt` recovers single-path goodput in every such env while keeping the tunnel multipath. The worst case under the right scheduler is "matches the better single path", not "loses to it" — the historical caveat *only multipath if your paths are similar* applies less strongly to mqvpn after this work.

## References

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
- Harness: `benchmarks/sweep_reorder.sh` (perf + OFF baseline; `BENCH_SCHEDULER=minrtt` switches scheduler for §4.3), `benchmarks/sweep_single_path.sh` (single-path baseline for the 3-way comparison in §4.1), `benchmarks/sweep_reorder_analyze.py` (Pareto + ON/OFF + 3-way table); shared netem profile table `BENCH_ENV_NETEM` in `benchmarks/bench_env_setup.sh`; outputs `ci_sweep_results/reorder_optimal.md` (wlb) and `ci_sweep_results/reorder_optimal_minrtt.md` (minrtt)
- Scheduler implementation: `src/flow_sched.c` (mqvpn schedulers: `minrtt`, `wlb`, `wlb_udp_pin`, `backup_fec`)
