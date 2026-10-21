# SRT redundant mode acceptance across the xquic pin bump (2026-10-18)

The redundant acceptance suite (`scripts/benchmark_srt.sh`,
`SRT_BENCH_SUITE=redundant`) on the xquic pin before and after the bump from
`561aa74` to `be5ae2ad` (mp0rta/xquic#83, #85, #86, #87, #88). Both builds are
mqvpn `03a3749c` in Release; only the xquic pin differs. `Redundant = on` (arm
`mq-wlb-redundant`) against `Redundant = off` (`mq-wlb-off`), client and server
scheduler WLB, SRT latency 120 ms, 60 s per run, 3 runs per cell, arms
alternating. The two pins ran in one session, alternating per rate with the
order flipped at each rate. Run in a privileged Docker container on one host;
bare-metal numbers may differ.

Stream loss in % (min-max of the completed runs):

| rate | condition | links | arm | 561aa74 | be5ae2ad |
|---|---|---|---|---|---|
| 10 Mbit/s | R2 | A 40 + B 30 Mbit/s, light random loss | off | 0.26-0.29 | 0.23-0.32 |
| | | | redundant | 0.00-0.02 | 0.00-0.04 |
| 10 Mbit/s | R3 | A + B 100 Mbit/s, bursty loss on A | off | 2.79-3.43 | 2.04-2.89 |
| | | | redundant | 0.00 | 0.00 |
| 10 Mbit/s | R4 | as R2, A down 2 s of every 10 | off | 1.54-1.80 | 1.69-1.99 |
| | | | redundant | 0.14-0.18 | 0.13-0.21 |
| 20 Mbit/s | R2 | as above | off | 0.40-0.42 | 0.19-0.39 |
| | | | redundant | 0.00-0.03 | 0.03-0.05 |
| 20 Mbit/s | R3 | as above | off | 4.03-5.35 | 3.60-4.14 |
| | | | redundant | 0.01-0.16 | 0.00-0.06 |
| 20 Mbit/s | R4 | as above | off | 2.68-3.29 | 2.29-2.73 |
| | | | redundant | 0.12-0.15 | 0.16-0.19 |
| 35 Mbit/s | R2 | as above | off | 0.83-2.16 | 0.61-1.22 |
| | | | redundant | 0.53-0.80 | 0.84-2.04 |
| 50 Mbit/s | R2 | as above | off | 3.80-5.27 | 6.61-11.07 |
| | | | redundant | 4.13-6.00 | 8.87-12.28 |
| 50 Mbit/s | R3 | as above | off | 2.21-3.30 | 2.60-4.11 |
| | | | redundant | 0.02-0.14 | 0.14-0.24 |
| 50 Mbit/s | R4 | as above | off | 21.3-29.2 | 38.8-39.3 |
| | | | redundant | 24.4-26.4 | 38.4-40.9 |

35 Mbit/s ran R2 only (`SRT_BENCH_ONLY=R2 SRT_BENCH_RED_RATE=35`). R3's setup
failed in 3 of the 36 R3 runs (`ERR` rows in `summary.md`): the bench checks
the tunnel with two pings, and link A's bursty loss can drop both, as in
`2026-10-17-queue-gate-acceptance`.

Findings:
- Where each link can carry the stream (10 and 20 Mbit/s), the two pins
  match: redundant mode loses 0.00-0.21%, off 0.19-5.35%.
- At 35 Mbit/s, link B (30 Mbit/s) cannot carry the stream and link A
  (40 Mbit/s) carries it close to its capacity. off is unchanged; redundant
  mode loses more on `be5ae2ad` (0.84-2.04% against 0.53-0.80%) and now more
  than off. Redundant mode puts a full copy of the stream on link A. A trace
  of the redundant runs on `be5ae2ad` shows link A's bandwidth estimate
  under 90% of the stream rate, down to 75%, in about one 200 ms window in
  ten; copies then queue on A past the 120 ms budget. off splits the stream across both links (about 60%
  of the bytes on A) and keeps headroom on each. This setting is outside what
  redundant mode is recommended for (every link carries the stream).
- At 50 Mbit/s no link can carry the stream alone; R2 runs close to the two
  links' combined capacity with random loss on both, and R4 cannot carry the
  stream while link A is down. Both arms lose more on `be5ae2ad`.
- The gain of the bump shows where a link's capacity drops under load. In a
  variant that drops link A from 40 to 20 Mbit/s for 4 s of every 10 s at
  35 Mbit/s (run with an experiment copy of the script, not in the suite),
  off lost 1.0-1.7% on `be5ae2ad` against 9.6-14.2% on `561aa74`, and
  redundant mode 2.3-8.5% against 6.9-9.4%.

Reproduce (per rate, as root, with `SRT_XTRANSMIT` pointing at srt-xtransmit):

```bash
SRT_BENCH_SUITE=redundant SRT_BENCH_ONLY=R2,R3,R4 SRT_BENCH_RED_RATE=20 \
  SRT_BENCH_OUT=/tmp/out ./scripts/benchmark_srt.sh build/mqvpn
```
