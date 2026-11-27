# SRT redundant mode acceptance with overload mode (2026-10-17)

`Redundant = on` (arm `mq-wlb-redundant`) against `Redundant = off`
(`mq-wlb-off`), client scheduler WLB, server WLB, SRT latency 120 ms,
60 s per run, 3 runs per cell, arms alternating. Run in a privileged Docker
container on one host; bare-metal numbers may differ.

Taken at e3ddd8bf (Release build, xquic 561aa74), with overload mode and with
the bench's `tbf` root under each netem qdisc, so the shaped queues hold what
their `limit` intends. `2026-10-13-redundant-acceptance` predates overload
mode, the queue fix and the xquic update (it used 5f63f07), so its numbers are
not comparable run for run.

- R2: two links, 40 and 30 Mbit/s, light random loss.
- R3: two 100 Mbit/s links, one with bursty loss.
- R4: as R2, and link A drops for 2 s every 10 s.

| rate | condition | off loss | redundant loss | note |
|---|---|---|---|---|
| 10 Mbit/s | R2 | 0.24-0.30% | 0.00-0.07% | |
| 10 Mbit/s | R3 | 2.9-3.3% | 0.00% | |
| 10 Mbit/s | R4 | 2.0-2.5% | 0.08-0.15% | |
| 20 Mbit/s | R2 | 0.21-0.53% | 0.00-0.03% | |
| 20 Mbit/s | R3 | 4.3-5.3% | 0.00-0.02% | |
| 20 Mbit/s | R4 | 2.2-2.6% | 0.12-0.19% | |
| 50 Mbit/s | R3 | 3.3-3.9% | 0.12-0.14% | |
| 50 Mbit/s | R2 | 4.1-4.5% | 4.5-7.9% | each link slower than the stream; 27-32% on 2026-10-13 |
| 50 Mbit/s | R4 | 23-31% | 22-25% | the links cannot carry the stream while A is down |

Every run started; there are no ERR rows.

Findings:
- Where one link can carry the stream (10 and 20 Mbit/s, and R3 at
  50 Mbit/s), redundant mode loses 0.00-0.19%, against 0.2-5.3% for off.
- At 50 Mbit/s on 40 and 30 Mbit/s links (R2), no link can carry the stream
  alone, and redundant mode falls back to sending each packet once. It loses
  4.5-7.9% against 4.1-4.5% for off; before overload mode it lost 27-32%.
  Most of its extra loss over off falls in the first ~7 s of the stream,
  before the fallback takes hold (11,600-13,500 packets dropped, against
  6,400-8,800 for off); after that the two arms drop about the same on
  average (redundant 1,100-9,100 packets, off 3,000-6,200). The client logs
  were not kept, so this timing comes from the receiver's drops
  (`pktRcvDrop` in the `.rcv.csv` files), not from the overload log lines.
- R4 at 50 Mbit/s needs more than link B alone carries while link A is down:
  both arms lose about a quarter of the stream and the sender drops packets
  too.
