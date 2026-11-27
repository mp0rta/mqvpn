# SRT redundant mode acceptance (2026-10-13)

`Redundant = on` (arm `mq-wlb-redundant`) against `Redundant = off`
(`mq-wlb-off`), client scheduler WLB, server WLB, SRT latency 120 ms,
60 s per run, 3 runs per cell. Run in a privileged Docker container on one
host; bare-metal numbers may differ.

- R2: two links, 40 and 30 Mbit/s, light random loss.
- R3: two 100 Mbit/s links, one with bursty loss.
- R4: as R2, and link A drops for 2 s every 10 s.

| rate | condition | off loss | redundant loss | note |
|---|---|---|---|---|
| 10 Mbit/s | R2 | 0.28-0.31% | 0.00-0.05% | |
| 10 Mbit/s | R3 | 5.2% | 0.00% | |
| 10 Mbit/s | R4 | 1.8-2.2% | 0.07-0.19% | 3-12 packets per drop |
| 20 Mbit/s | R2 | 0.28-0.51% | 0.02-0.07% | |
| 20 Mbit/s | R3 | 4.4-6.9% | 0.00% | 31-36 dropped in the first 0.6 s |
| 20 Mbit/s | R4 | 2.4-2.9% | 0.14-0.17% | rerun; 3-25 per drop, off 358-504 |
| 50 Mbit/s | R3 | 4.9-6.0% | 0.13-0.19% | |
| 50 Mbit/s | R2 | 3.0-3.8% | 27-32% | each link slower than the stream |

Runs marked ERR in a summary (the tunnel did not come up over the lossy link
at startup) are left out of the table: 10 Mbit/s R3 off 2 and redundant 1,
50 Mbit/s R3 redundant 1.

Findings:
- The drops left at 20 and 50 Mbit/s fall in the first ~0.6 s, while the
  connections ramp up. The off arm drops packets there too. A trace showed
  every packet going out on both paths during that time, so the
  per-path limit is not the cause.
- Redundant mode needs every link to carry the stream rate on its own. At
  50 Mbit/s on 40 and 30 Mbit/s links, the copies fill both links and
  redundant mode loses far more than off, which combines the links.
- One 20 Mbit/s R4 run (1.1% loss, during outages 3-5) did not reproduce in a
  rerun of 3; the table shows the rerun, which is under `20m/r4-rerun/`.
