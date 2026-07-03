# Hybrid H2b: e2e throughput gates (Test 2 + Test 3)

Date: 2026-07-04
Branch: `feat/hybrid-h2`
Harness: `tests/test_e2e_hybrid_h2.sh`
Environment: `docker run --rm --privileged ... mqvpn-e2e:latest` (containerized
netns/tc, CPU-contended, no real link — see caveats below).

## Test 2: single-path throughput, stream lane vs RAW

Phase A: `[Hybrid] Enabled=true / Tcp=raw`, single path, unshaped —
iperf3 through the plain CONNECT-IP tunnel (`TUNNEL_SERVER_IP`).
Phase B: `[Hybrid] Enabled=true / Tcp=stream + EgressAllow=10.222.0.0/24`,
single path, unshaped — iperf3 through the hybrid TCP-lane relay to the
egress-allowed target (`10.222.0.1`, same addressing trick as Test 1).
Phase B additionally asserts the stream lane was actually exercised
(`[STATUS] lanes tcp/... > 0`) so a silent raw fallthrough can't pass.
Gate: `(RAW - STREAM) / RAW * 100 <= 20.0`.

Runs, 3 iperf3 repeats (6s each) per phase per run:

| Run | RAW_MBPS (avg) | RAW samples            | STREAM_MBPS (avg) | STREAM samples          | degradation % |
|-----|-----------------|-------------------------|---------------------|--------------------------|----------------|
| 1   | 1133.67         | 1128.4 1150.5 1122.1    | 933.87               | 942.6 928.4 930.6        | 17.6           |
| 3   | 1135.33         | 1148.8 1154.1 1103.1    | 957.53               | 971.4 940.0 961.2        | 15.7           |

(Run 2 was captured Test-3-only, but its Test 2 phase PASSed.) Result:
**PASS** all runs (threshold <=20.0%, observed 15.7-17.6%). The stream lane
carried 1.5-1.6M tcp-lane packets (verified via `[STATUS]`), so this is real
lwIP/relay overhead, consistent with the mqproxy reference impl's
TCP-over-stream overhead at single path (~15-20%, docs/report/2026-06-23) —
not container noise (RAW is stable ~1.13-1.15 Gbps).

## Test 3: multipath aggregation under asymmetric netem, stream lane

Profile: `lte_starlink` (from `benchmarks/bench_env_setup.sh`'s
`BENCH_ENV_NETEM`) — Path A `delay 35ms 8ms distribution normal rate
40mbit`, Path B `delay 50ms 25ms distribution normal loss 1% rate 100mbit`.
Policy: same stream-lane INI as Test 2 Phase B. The multipath phase asserts
the stream lane is exercised and that both paths validated (control API
`n_paths == 2`).

### Two independent aggregation proofs (corrected methodology)

An earlier version gated only `MULTI / (Path-A-leg baseline) >= 1.5x`. That
was structurally fakeable: Path A's leg is 40mbit but Path B is 100mbit, so
a scheduler that dumped ALL traffic onto Path B (zero aggregation) would
still clear 1.5x vs the 40mbit leg. Two fixes were applied:

1. **Per-path utilization assertion (primary, direct proof).** After the
   2-path iperf3 run, the server's `get_status` per-path byte counters
   (`bytes_tx + bytes_rx`, direction-robust) are read while the tunnel is
   still up. Assert BOTH paths carried real load (each > 100 KB, well above
   handshake/probe noise) AND the lighter path holds >= 20% of the heavier.
   A one-path-only scheduler fails here regardless of its throughput number.

2. **Baseline = MAX of BOTH legs (secondary).** The single-path baseline is
   measured for Path A's netem AND Path B's netem separately (both on the
   lone path slot, as sweep_single_path.sh does), and the fatter leg is
   taken as "best single path". `MULTI / max(A, B) >= 1.5` then genuinely
   requires beating the best single path — path selection alone lands ~1.0x
   and fails.

3 full script runs, 3 iperf3 repeats (8s each) per phase:

| Run | BASE_A (avg, 40mbit leg) | BASE_B (avg, 100mbit/1%-loss leg) | BEST_SINGLE = max | MULTI (avg) | MULTI samples     | ratio | per-path load lo/hi (bytes) | minshare |
|-----|---------------------------|------------------------------------|--------------------|--------------|--------------------|-------|------------------------------|----------|
| 1   | 36.57 (35.1 37.2 37.4)    | 55.07 (50.0 58.1 57.1)             | 55.07              | 85.03        | 79.0 87.8 88.3     | 1.54x | 131,911,509 / 183,468,892    | 0.72     |
| 2   | 36.50 (35.9 36.3 37.3)    | 28.93 (26.1 30.5 30.2)             | 36.50              | 60.97        | 54.0 64.0 64.9     | 1.67x | 99,731,631 / 138,627,874     | 0.72     |
| 3   | 36.37 (35.6 36.2 37.3)    | 52.97 (48.7 56.5 53.7)             | 52.97              | 90.20        | 86.4 92.3 91.9     | 1.70x | 128,697,722 / 189,305,439    | 0.68     |

Result: **PASS** all 3 runs — both the per-path assertion and the ratio gate.

**Per-path byte shares (the headline aggregation evidence):** the lighter
path consistently held 68-72% of the heavier path's bytes across all 3 runs.
That is *near-equal* fill of both paths (a clean 40:100 capacity split would
give ~40% share; the WLB scheduler drives both paths closer to balanced here
because Path B's 1% loss caps its effective rate toward Path A's). This is
unambiguous aggregation — not path selection.

**Ratio-gate margin (honest caveat):** the `MULTI/max(A,B)` ratio held
1.54-1.70x, but the worst case (1.54x, run 1) is only just above the 1.5x
threshold. The thin margin is driven by Path B's leg baseline swinging
28.9-55.1 Mbps run-to-run (its 1% loss + 25ms jitter make the single-leg
number volatile), combined with container CPU contention on the MULTI
number. A run that happens to measure Path B's leg high (~55) while MULTI
stays ~85 could dip below 1.5x. The ratio gate was NOT loosened to
accommodate this — instead the primary per-path assertion (minshare
0.68-0.72, dead consistent) is the robust aggregation proof, and the ratio
is the secondary corroboration. Recommend re-validating the ratio margin on
real hardware / a less-contended CI runner before treating 1.5x-vs-max as a
tight production bound.

### Path-count verification method

`bench_wait_for_n_paths 2 20 "$CTRL_PORT"` polls
`get_status.clients[0].n_paths` until >= 2 (or times out); the multipath
phase fails if the server never confirms 2 paths, rather than trusting
`bench_wait_tunnel` (path-0-only ping).

## Harness hardening (this revision)

- **Hang-safety:** `run_iperf3_through_tunnel` runs the iperf3 client under
  `timeout duration+15` and kills the one-shot server pid before a guarded
  `wait` — a broken tunnel now yields empty JSON -> 0.0 -> sub-floor -> FAIL
  instead of `iperf3 -s -1` blocking the suite forever.
- **Zero-sample rejection:** any iperf3 sample below `IPERF_MIN_MBPS` (1.0)
  is retried once; a persistent sub-floor sample fails the owning test
  (`assert_series_floor`) rather than diluting a denominator average and
  quietly making the ratio gates easier.
- **Stream-lane-used assertions** in Test 2 Phase B and both Test 3 stream
  phases, so each throughput phase independently proves the stream lane
  carried the traffic (guards against a silent raw regression that
  ip_forward would otherwise mask).

## Regression check

Test 1 (curl body byte-for-byte) and Test 7 (byte-identical, Phase A/B)
still PASS alongside Test 2/3 in every run. `ctest` on the host build-debug
tree: 20/20 passed (no product code changed).
