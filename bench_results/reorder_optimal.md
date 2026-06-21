# Reorder sweep — Pareto-optimal analysis

Per environment: non-dominated (goodput MAXIMIZE, p99 added-latency MINIMIZE) frontier over median-of-repeats points, plus a recommended default = the goodput **knee** (smallest `max_wait_ms`, tie-break smallest cap, reaching >=90% of the env's peak goodput). The knee replaces the design's `added_p99_ms <= 0.5 * rtt_spread` rule, which selected collapsed low-wait cells (goodput ~1 Mbps but ~0 ms added latency).

## `baseline`
- rtt spread: 0 ms
- 12 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 30 | 2048 | 57.995 | 0.000 | 0.000 |  |
| 10 | 1024 | 57.852 | 0.000 | 0.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 58.0 Mbps; threshold 52.2 Mbps)
  -> **wait=10ms cap=1024** (goodput=57.852 Mbps, p99=0.000 ms)

## `bw_10to1`
- rtt spread: 0 ms
- 8 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 200 | 1024 | 21.046 | 0.000 | 0.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 21.0 Mbps; threshold 18.9 Mbps)
  -> **wait=200ms cap=1024** (goodput=21.046 Mbps, p99=0.000 ms)

## `bw_4to1`
- rtt spread: 0 ms
- 8 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 300 | 1024 | 26.088 | 0.000 | 0.000 |  |
| 50 | 1024 | 25.379 | 0.000 | 0.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 26.1 Mbps; threshold 23.5 Mbps)
  -> **wait=50ms cap=1024** (goodput=25.379 Mbps, p99=0.000 ms)

## `congested`
- rtt spread: 10 ms
- 10 cell(s); 2 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 30 | 1024 | 5.703 | 32.000 | 64.000 | **<-** |
| 20 | 1024 | 1.013 | 0.000 | 32.000 |  |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 5.7 Mbps; threshold 5.1 Mbps)
  -> **wait=30ms cap=1024** (goodput=5.703 Mbps, p99=32.000 ms)

## `dual_lte`
- rtt spread: 15 ms
- 12 cell(s); 2 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 50 | 4096 | 21.750 | 32.000 | 64.000 |  |
| 10 | 1024 | 0.969 | 0.000 | 32.000 |  |
| 30 | 1024 | 20.740 | 32.000 | 32.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 21.8 Mbps; threshold 19.6 Mbps)
  -> **wait=30ms cap=1024** (goodput=20.740 Mbps, p99=32.000 ms)

## `fiber_lte`
- rtt spread: 32 ms
- 12 cell(s); 3 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 50 | 2048 | 77.345 | 64.000 | 64.000 | **<-** |
| 20 | 1024 | 60.758 | 32.000 | 32.000 |  |
| 10 | 1024 | 5.486 | 1.000 | 32.000 |  |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 77.3 Mbps; threshold 69.6 Mbps)
  -> **wait=50ms cap=2048** (goodput=77.345 Mbps, p99=64.000 ms)

## `jit_20`
- rtt spread: 0 ms
- 8 cell(s); 2 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 50 | 1024 | 37.603 | 32.000 | 64.000 | **<-** |
| 10 | 1024 | 2.468 | 16.000 | 32.000 |  |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 37.6 Mbps; threshold 33.8 Mbps)
  -> **wait=50ms cap=1024** (goodput=37.603 Mbps, p99=32.000 ms)

## `jit_5`
- rtt spread: 0 ms
- 8 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 120 | 1024 | 61.434 | 4.000 | 8.000 |  |
| 10 | 1024 | 55.654 | 4.000 | 8.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 61.4 Mbps; threshold 55.3 Mbps)
  -> **wait=10ms cap=1024** (goodput=55.654 Mbps, p99=4.000 ms)

## `loss_05`
- rtt spread: 0 ms
- 8 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 10 | 1024 | 52.672 | 0.000 | 0.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 52.7 Mbps; threshold 47.4 Mbps)
  -> **wait=10ms cap=1024** (goodput=52.672 Mbps, p99=0.000 ms)

## `loss_2`
- rtt spread: 0 ms
- 4 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 10 | 1024 | 24.451 | 0.000 | 32.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 24.5 Mbps; threshold 22.0 Mbps)
  -> **wait=10ms cap=1024** (goodput=24.451 Mbps, p99=0.000 ms)

## `lte_geo`
- rtt spread: 285 ms
- 12 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 10 | 1024 | 27.264 | 16.000 | 16.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 27.3 Mbps; threshold 24.5 Mbps)
  -> **wait=10ms cap=1024** (goodput=27.264 Mbps, p99=16.000 ms)

## `lte_starlink`
- rtt spread: 15 ms
- 11 cell(s); 2 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 50 | 1024 | 17.053 | 64.000 | 64.000 | **<-** |
| 20 | 1024 | 3.596 | 32.000 | 64.000 |  |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 17.1 Mbps; threshold 15.3 Mbps)
  -> **wait=50ms cap=1024** (goodput=17.053 Mbps, p99=64.000 ms)

## `rtt_120`
- rtt spread: 100 ms
- 8 cell(s); 3 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 50 | 1024 | 28.153 | 64.000 | 64.000 | **<-** |
| 10 | 1024 | 6.367 | 16.000 | 16.000 |  |
| 20 | 1024 | 1.857 | 0.000 | 32.000 |  |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 28.2 Mbps; threshold 25.3 Mbps)
  -> **wait=50ms cap=1024** (goodput=28.153 Mbps, p99=64.000 ms)

## `rtt_320`
- rtt spread: 300 ms
- 8 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 10 | 1024 | 35.722 | 16.000 | 16.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 35.7 Mbps; threshold 32.1 Mbps)
  -> **wait=10ms cap=1024** (goodput=35.722 Mbps, p99=16.000 ms)

## `rtt_40`
- rtt spread: 20 ms
- 8 cell(s); 2 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 200 | 1024 | 49.010 | 32.000 | 32.000 |  |
| 10 | 1024 | 0.977 | 0.000 | 24.000 |  |
| 50 | 1024 | 45.727 | 32.000 | 32.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 49.0 Mbps; threshold 44.1 Mbps)
  -> **wait=50ms cap=1024** (goodput=45.727 Mbps, p99=32.000 ms)

## `rtt_70`
- rtt spread: 50 ms
- 8 cell(s); 3 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 300 | 1024 | 36.473 | 64.000 | 64.000 |  |
| 20 | 1024 | 28.772 | 32.000 | 32.000 |  |
| 10 | 1024 | 1.456 | 0.000 | 16.000 |  |
| 50 | 1024 | 34.202 | 64.000 | 64.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 36.5 Mbps; threshold 32.8 Mbps)
  -> **wait=50ms cap=1024** (goodput=34.202 Mbps, p99=64.000 ms)

## Optimal `max_wait_ms` vs RTT spread (rtt_* axis)

Knee = cheapest-latency sufficient wait (recommended default); peak = goodput-maximising wait (latency ignored). A knee that tracks the spread confirms the core hypothesis; a knee that stalls or a peak at the minimum wait flags the high-spread regime where reorder stops helping.

| env | rtt spread (ms) | knee wait (ms) | knee goodput (Mbps) | peak wait (ms) | peak goodput (Mbps) |
|:--|---:|---:|---:|---:|---:|
| baseline | 0 | 10 | 57.852 | 30 | 57.995 |
| rtt_40 | 20 | 50 | 45.727 | 200 | 49.010 |
| rtt_70 | 50 | 50 | 34.202 | 300 | 36.473 |
| rtt_120 | 100 | 50 | 28.153 | 50 | 28.153 |
| rtt_320 | 300 | 10 | 35.722 | 10 | 35.722 |


## reorder ON vs OFF (net benefit)

Median goodput with reorder OFF (RAW pass-through) vs the best ON config (max-goodput frontier point) and the recommended-default ON config. `Δ% = (ON − OFF) / OFF`; positive ⇒ reorder helps. The verdict uses the best-ON Δ (NET-POSITIVE > +2%, NET-NEGATIVE < −2%, else NEUTRAL) — the ceiling reorder can reach here; `best-ON p99` is the latency cost of reaching it, and rec-ON is the latency-bounded shipping config.

| env | rtt spread (ms) | OFF Mbps | best-ON Mbps | Δ best % | best-ON p99 (ms) | rec-ON Mbps | Δ rec % | verdict |
|:--|---:|---:|---:|---:|---:|---:|---:|:--|
| baseline | 0 | 73.900 | 57.995 | -21.5 | 0.000 | 57.852 | -21.7 | NET-NEGATIVE |
| bw_10to1 | 0 | 13.316 | 21.046 | 58.1 | 0.000 | 21.046 | 58.1 | NET-POSITIVE |
| bw_4to1 | 0 | 15.638 | 26.088 | 66.8 | 0.000 | 25.379 | 62.3 | NET-POSITIVE |
| dual_lte | 15 | 0.914 | 21.750 | 2280.0 | 32.000 | 20.740 | 2169.5 | NET-POSITIVE |
| fiber_lte | 32 | 4.935 | 77.345 | 1467.3 | 64.000 | 77.345 | 1467.3 | NET-POSITIVE |
| jit_20 | 0 | 0.933 | 37.603 | 3932.1 | 32.000 | 37.603 | 3932.1 | NET-POSITIVE |
| jit_5 | 0 | 3.377 | 61.434 | 1719.0 | 4.000 | 55.654 | 1547.9 | NET-POSITIVE |
| loss_05 | 0 | 70.663 | 52.672 | -25.5 | 0.000 | 52.672 | -25.5 | NET-NEGATIVE |
| loss_2 | 0 | 29.004 | 24.451 | -15.7 | 0.000 | 24.451 | -15.7 | NET-NEGATIVE |
| lte_geo | 285 | 31.088 | 27.264 | -12.3 | 16.000 | 27.264 | -12.3 | NET-NEGATIVE |
| rtt_120 | 100 | 7.053 | 28.153 | 299.2 | 64.000 | 28.153 | 299.2 | NET-POSITIVE |
| rtt_320 | 300 | 40.054 | 35.722 | -10.8 | 16.000 | 35.722 | -10.8 | NET-NEGATIVE |
| rtt_40 | 20 | 0.847 | 49.010 | 5686.9 | 32.000 | 45.727 | 5299.2 | NET-POSITIVE |
| rtt_70 | 50 | 1.254 | 36.473 | 2808.2 | 64.000 | 34.202 | 2627.1 | NET-POSITIVE |

- OFF goodput = median across `--off-csv` repeats (Enabled=off, RAW).
- best-ON = max-goodput frontier point (ceiling, latency ignored); rec-ON = recommended default = goodput knee (smallest wait, tie-break smallest cap, reaching >=90% of peak goodput).
- Envs whose OFF baseline never completed the transfer (all-NA goodput, e.g. heavily congested/loss+jitter paths) are absent here: no OFF number to divide by — itself a sign reorder is needed, since RAW pass-through failed to deliver.


## 3-way comparison: single path vs multipath (OFF / ON)

Each row compares three configs on the SAME netem: single path (Path A / Path B = the env's path A / path B netem applied to a lone path), multipath with reorder OFF (RAW pass-through), and multipath with reorder at its best-goodput frontier point. The recommendation column picks the SIMPLEST config whose median goodput is within 5% of the winner; ties go to single > mp-OFF > mp-ON. This is the user-facing answer to 'should I multipath in this env?'

| env | RTT spread [ms] | Path A [Mbps] | Path B [Mbps] | best single [Mbps] | OFF (mp) [Mbps] | best-ON (mp) [Mbps] | Δ best-ON vs best-single [%] | recommendation |
|:--|---:|---:|---:|---:|---:|---:|---:|:--|
| baseline | 0 | 40.600 | 40.339 | 40.600 | 73.900 | 57.995 | 42.8 | **multipath, reorder OFF** |
| bw_10to1 | 0 | 74.172 | 8.621 | 74.172 | 13.316 | 21.046 | -71.6 | **single path (Path A)** |
| bw_4to1 | 0 | 40.621 | 10.306 | 40.621 | 15.638 | 26.088 | -35.8 | **single path (Path A)** |
| congested | 10 | 6.414 | 5.711 | 6.414 | — | 5.703 | -11.1 | **single path (Path A)** |
| dual_lte | 15 | 29.579 | 18.759 | 29.579 | 0.914 | 21.750 | -26.5 | **single path (Path A)** |
| fiber_lte | 32 | 212.440 | 22.031 | 212.440 | 4.935 | 77.345 | -63.6 | **single path (Path A)** |
| jit_20 | 0 | 17.448 | 10.968 | 17.448 | 0.933 | 37.603 | 115.5 | **multipath + reorder ON** |
| jit_5 | 0 | 38.324 | 38.848 | 38.848 | 3.377 | 61.434 | 58.1 | **multipath + reorder ON** |
| loss_05 | 0 | 29.617 | 32.205 | 32.205 | 70.663 | 52.672 | 63.6 | **multipath, reorder OFF** |
| loss_2 | 0 | 16.097 | 16.308 | 16.308 | 29.004 | 24.451 | 49.9 | **multipath, reorder OFF** |
| lte_geo | 285 | 31.688 | 6.044 | 31.688 | 31.088 | 27.264 | -14.0 | **single path (Path A)** |
| lte_starlink | 15 | 29.558 | 8.877 | 29.558 | — | 17.053 | -42.3 | **single path (Path A)** |
| rtt_120 | 100 | 40.683 | 27.531 | 40.683 | 7.053 | 28.153 | -30.8 | **single path (Path A)** |
| rtt_320 | 300 | 40.288 | 9.210 | 40.288 | 40.054 | 35.722 | -11.3 | **single path (Path A)** |
| rtt_40 | 20 | 40.467 | 37.926 | 40.467 | 0.847 | 49.010 | 21.1 | **multipath + reorder ON** |
| rtt_70 | 50 | 40.603 | 33.708 | 40.603 | 1.254 | 36.473 | -10.2 | **single path (Path A)** |

- Path A / Path B = single-path goodput [Mbps] with the env's path A / path B netem applied (median over repeats).
- best single = max(Path A, Path B); the better single-path option a user could pick if not multipathing.
- Δ best-ON vs best-single: positive ⇒ multipath + reorder actually aggregates beyond the better single path. Near-zero or negative ⇒ multipath only matches or loses to single — the recommendation reflects this.
- recommendation picks the simplest config within 5% of the winner: a multipath stack must clearly beat single path to be recommended.
- Envs missing OFF or best-ON columns are present in --single-csv but not in the corresponding ON / OFF CSV; the recommendation still uses whatever it has.

