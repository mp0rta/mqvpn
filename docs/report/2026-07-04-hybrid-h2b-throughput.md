# Hybrid H2b: e2e throughput gates (Test 2 + Test 3)

Date: 2026-07-04
Branch: `feat/hybrid-h2` @ `1034840` (base for this measurement)
Harness: `tests/test_e2e_hybrid_h2.sh`
Environment: `docker run --rm --privileged ... mqvpn-e2e:latest` (containerized
netns/tc, CPU-contended, no real link — see caveats below).

## Test 2: single-path throughput, stream lane vs RAW

Phase A: `[Hybrid] Enabled=true / Tcp=raw`, single path, unshaped —
iperf3 through the plain CONNECT-IP tunnel (`TUNNEL_SERVER_IP`).
Phase B: `[Hybrid] Enabled=true / Tcp=stream + EgressAllow=10.222.0.0/24`,
single path, unshaped — iperf3 through the hybrid TCP-lane relay to the
egress-allowed target (`10.222.0.1`, same addressing trick as Test 1).
Gate: `(RAW - STREAM) / RAW * 100 <= 20.0`.

3 full script runs, 3 iperf3 repeats (6s each) per phase per run:

| Run | RAW_MBPS (avg) | RAW samples            | STREAM_MBPS (avg) | STREAM samples          | degradation % |
|-----|-----------------|-------------------------|---------------------|--------------------------|----------------|
| 1   | 1139.23         | 1134.3 1146.1 1137.3    | 943.50               | 939.3 949.6 941.6        | 17.2           |
| 2   | 1130.00         | 1120.6 1129.9 1139.5    | 975.63               | 983.0 972.5 971.4        | 13.7           |
| 3   | 1153.23         | 1152.1 1151.6 1156.0    | 948.00               | 946.4 947.2 950.4        | 17.8           |

Result: **PASS** all 3 runs (threshold <=20.0%, observed 13.7-17.8%).
Consistent with the mqproxy reference impl's TCP-over-stream overhead at
single path (~15-20%, docs/report/2026-06-23) — this is real lwIP/relay
overhead, not container noise (RAW itself is stable ~1.13-1.15 Gbps across
runs; the degradation band is narrow, ~4 points).

## Test 3: multipath aggregation under asymmetric netem, stream lane

Profile: `lte_starlink` (from `benchmarks/bench_env_setup.sh`'s
`BENCH_ENV_NETEM`) — Path A `delay 35ms 8ms distribution normal rate
40mbit`, Path B `delay 50ms 25ms distribution normal loss 1% rate 100mbit`.
Same profile used for both legs of the comparison below (own baseline, not
Test 2's unshaped number). Policy: same stream-lane INI as Test 2 Phase B.
Gate: `MULTI_MBPS / BEST_SINGLE_MBPS >= 1.5`.

3 full script runs, 3 iperf3 repeats (8s each) per phase per run. Path
count verified via the control API (`get_status.clients[0].n_paths == 2`)
before trusting the multipath number, not just tunnel-up:

| Run | BEST_SINGLE_MBPS (avg) | samples          | MULTI_MBPS (avg) | samples          | ratio |
|-----|--------------------------|-------------------|--------------------|-------------------|-------|
| 1   | 36.53                    | 35.3 37.3 37.0    | 89.70               | 79.0 95.3 94.8    | 2.46x |
| 2   | 36.07                    | 34.9 36.4 36.9    | 59.63               | 68.9 55.0 55.0    | 1.65x |
| 3   | 36.67                    | 35.3 37.3 37.4    | 88.57               | 84.1 92.8 88.8    | 2.42x |

Result: **PASS** all 3 runs (threshold >=1.5x, observed 1.65x-2.46x).

Note the container-variance signal: BEST_SINGLE_MBPS is stable (~36-37
Mbps, tracking the netem-imposed 40mbit cap closely) across all 3 runs, but
MULTI_MBPS swung from ~90 Mbps (runs 1, 3) down to ~60 Mbps (run 2) —
almost certainly CPU contention in the container (two shaped paths +
scheduler + lwIP relay compete for the same cores that also run tc's
netem queueing). The gate still cleared with margin (1.65x vs the 1.5x
threshold) even in the degraded run, but the margin is real, not
comfortable — this number should be re-validated on real hardware or a
less-contended CI runner before being treated as a tight bound. The
underlying aggregation behavior (stream lane rides the same
scheduler-fed inner QUIC connection as RAW) is confirmed structurally
sound; the 1.5x threshold itself was not loosened to force a pass.

## Path-count verification method

`bench_wait_for_n_paths 2 20 "$CTRL_PORT"` polls `get_status` until
`clients[0].n_paths >= 2` (or times out); Test 3's multipath phase asserts
this explicitly and fails the test if the server never confirms 2 active
paths, rather than trusting `bench_wait_tunnel` (which only pings via path
0).

## Regression check

Test 1 (curl body byte-for-byte) and Test 7 (byte-identical regression,
Phase A/B) both still PASS in every run alongside Test 2/3 — no regression
introduced by the added measurement phases.
