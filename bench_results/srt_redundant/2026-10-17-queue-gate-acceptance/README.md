# SRT redundant mode acceptance with the queue gate (2026-10-17)

`Redundant = on` (arm `mq-wlb-redundant`) against `Redundant = off`
(`mq-wlb-off`), client scheduler WLB, server WLB, SRT latency 120 ms,
60 s per run, 3 runs per cell, arms alternating. Run in a privileged Docker
container on one host; bare-metal numbers may differ.

Taken at d567e5cc (Release build, xquic 561aa74). A path whose oldest
unacknowledged copy has waited more than 250 ms longer than the least-delayed
path's gets no new copies until it catches up. `2026-10-17-overload-acceptance`
was taken at e3ddd8bf, which capped the number of outstanding copies per path
instead; the two are not comparable run for run.

| rate | condition | links | off loss | redundant loss | note |
|---|---|---|---|---|---|
| 10 Mbit/s | R2 | A 40 + B 30 Mbit/s, light random loss | 0.20-0.31% | 0.00-0.02% | |
| 10 Mbit/s | R3 | A + B 100 Mbit/s, bursty loss on A | 3.4-3.5% | 0.00% | |
| 10 Mbit/s | R4 | as R2, A down 2 s of every 10 | 1.6-2.2% | 0.12-0.15% | |
| 20 Mbit/s | R2 | A 40 + B 30 Mbit/s, light random loss | 0.27-0.47% | 0.01-0.03% | |
| 20 Mbit/s | R3 | A + B 100 Mbit/s, bursty loss on A | 4.6-5.4% | 0.00-0.12% | |
| 20 Mbit/s | R4 | as R2, A down 2 s of every 10 | 2.3-2.9% | 0.11-0.17% | |
| 50 Mbit/s | R3 | A + B 100 Mbit/s, bursty loss on A | 1.9-4.8% | 0.00-0.31% | |
| 50 Mbit/s | R2 | A 40 + B 30 Mbit/s, light random loss | 3.3-7.2% | 3.9-6.3% | each link slower than the stream |
| 50 Mbit/s | R4 | as R2, A down 2 s of every 10 | 20-30% | 23-30% | the links cannot carry the stream while A is down |

R3's setup failed in 9 of its 36 runs (`ERROR: tunnel not established`, an
`ERR` row in `summary.md`). The bench checks the tunnel with two pings, and
link A's bursty loss can drop both; both arms were hit. R3 was therefore run a
second time at every rate (`summary-R3-rerun.md`, `raw-R3-rerun/` in
`raw.zip`), and its rows above combine the completed runs of both rounds (3 to
6 per arm).

Findings:
- Where one link can carry the stream (10 and 20 Mbit/s, and R3 at
  50 Mbit/s), redundant mode loses 0.00-0.31%, against 0.2-5.4% for off. No
  run entered overload mode.
- At 50 Mbit/s on 40 and 30 Mbit/s links (R2), no link can carry the stream
  alone. Every redundant run entered overload mode once and then sent each
  packet once; it lost 3.9-6.3% against 3.3-7.2% for off (medians 4.8% and
  3.7%).
- R4 at 50 Mbit/s needs more than link B alone carries while link A is down:
  both arms lose about a quarter of the stream. Every redundant run entered
  overload mode once.
