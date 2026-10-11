# Reorder sweep — Pareto-optimal analysis

Per environment: non-dominated (goodput MAXIMIZE, p99 added-latency MINIMIZE) frontier over median-of-repeats points, plus a recommended default = the goodput **knee** (smallest `max_wait_ms`, tie-break smallest cap, reaching >=90% of the env's peak goodput). The knee replaces the design's `added_p99_ms <= 0.5 * rtt_spread` rule, which selected collapsed low-wait cells (goodput ~1 Mbps but ~0 ms added latency).

## `baseline`
- rtt spread: 0 ms
- 12 cell(s); 4 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 80 | 4096 | 45.393 | 64.000 | 64.000 |  |
| 200 | 1024 | 42.420 | 32.000 | 64.000 |  |
| 30 | 1024 | 40.697 | 16.000 | 64.000 |  |
| 10 | 1024 | 39.539 | 8.000 | 32.000 |  |
| 50 | 1024 | 44.036 | 64.000 | 64.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 45.4 Mbps; threshold 40.9 Mbps)
  -> **wait=50ms cap=1024** (goodput=44.036 Mbps, p99=64.000 ms)

## `bw_10to1`
- rtt spread: 0 ms
- 8 cell(s); 3 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 200 | 1024 | 74.253 | 64.000 | 64.000 |  |
| 80 | 1024 | 73.856 | 32.000 | 64.000 |  |
| 10 | 1024 | 68.977 | 16.000 | 32.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 74.3 Mbps; threshold 66.8 Mbps)
  -> **wait=10ms cap=1024** (goodput=68.977 Mbps, p99=16.000 ms)

## `bw_4to1`
- rtt spread: 0 ms
- 8 cell(s); 3 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 200 | 1024 | 41.606 | 64.000 | 128.000 |  |
| 30 | 1024 | 40.262 | 32.000 | 64.000 |  |
| 10 | 1024 | 36.460 | 16.000 | 32.000 |  |
| 20 | 1024 | 38.398 | 32.000 | 64.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 41.6 Mbps; threshold 37.4 Mbps)
  -> **wait=20ms cap=1024** (goodput=38.398 Mbps, p99=32.000 ms)

## `congested`
- rtt spread: 10 ms
- 12 cell(s); 2 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 20 | 4096 | 6.051 | 64.000 | 64.000 | **<-** |
| 10 | 1024 | 4.763 | 32.000 | 64.000 |  |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 6.1 Mbps; threshold 5.4 Mbps)
  -> **wait=20ms cap=4096** (goodput=6.051 Mbps, p99=64.000 ms)

## `dual_lte`
- rtt spread: 15 ms
- 12 cell(s); 2 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 30 | 512 | 30.255 | 64.000 | 64.000 |  |
| 10 | 1024 | 28.065 | 16.000 | 32.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 30.3 Mbps; threshold 27.2 Mbps)
  -> **wait=10ms cap=1024** (goodput=28.065 Mbps, p99=16.000 ms)

## `fiber_lte`
- rtt spread: 32 ms
- 12 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 20 | 2048 | 204.137 | 16.000 | 32.000 |  |
| 10 | 1024 | 201.400 | 16.000 | 16.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 204.1 Mbps; threshold 183.7 Mbps)
  -> **wait=10ms cap=1024** (goodput=201.400 Mbps, p99=16.000 ms)

## `jit_20`
- rtt spread: 0 ms
- 8 cell(s); 3 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 300 | 1024 | 39.144 | 64.000 | 128.000 |  |
| 30 | 1024 | 24.856 | 32.000 | 64.000 |  |
| 10 | 1024 | 5.321 | 16.000 | 32.000 |  |
| 120 | 1024 | 37.456 | 128.000 | 128.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 39.1 Mbps; threshold 35.2 Mbps)
  -> **wait=120ms cap=1024** (goodput=37.456 Mbps, p99=128.000 ms)

## `jit_5`
- rtt spread: 0 ms
- 8 cell(s); 4 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 120 | 1024 | 52.576 | 128.000 | 128.000 | **<-** |
| 50 | 1024 | 45.083 | 64.000 | 128.000 |  |
| 20 | 1024 | 40.395 | 32.000 | 64.000 |  |
| 10 | 1024 | 35.499 | 16.000 | 16.000 |  |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 52.6 Mbps; threshold 47.3 Mbps)
  -> **wait=120ms cap=1024** (goodput=52.576 Mbps, p99=128.000 ms)

## `loss_05`
- rtt spread: 0 ms
- 8 cell(s); 2 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 20 | 1024 | 32.441 | 64.000 | 64.000 |  |
| 10 | 1024 | 29.858 | 16.000 | 32.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 32.4 Mbps; threshold 29.2 Mbps)
  -> **wait=10ms cap=1024** (goodput=29.858 Mbps, p99=16.000 ms)

## `loss_2`
- rtt spread: 0 ms
- 8 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 10 | 1024 | 14.029 | 32.000 | 32.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 14.0 Mbps; threshold 12.6 Mbps)
  -> **wait=10ms cap=1024** (goodput=14.029 Mbps, p99=32.000 ms)

## `lte_geo`
- rtt spread: 285 ms
- 12 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 10 | 256 | 31.530 | 0.000 | 32.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 31.5 Mbps; threshold 28.4 Mbps)
  -> **wait=10ms cap=256** (goodput=31.530 Mbps, p99=0.000 ms)

## `lte_starlink`
- rtt spread: 15 ms
- 12 cell(s); 3 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 50 | 4096 | 29.771 | 64.000 | 128.000 |  |
| 30 | 1024 | 29.049 | 32.000 | 64.000 |  |
| 10 | 1024 | 26.189 | 16.000 | 32.000 |  |
| 20 | 1024 | 27.677 | 32.000 | 64.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 29.8 Mbps; threshold 26.8 Mbps)
  -> **wait=20ms cap=1024** (goodput=27.677 Mbps, p99=32.000 ms)

## `rtt_120`
- rtt spread: 100 ms
- 8 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 10 | 1024 | 40.422 | 8.000 | 32.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 40.4 Mbps; threshold 36.4 Mbps)
  -> **wait=10ms cap=1024** (goodput=40.422 Mbps, p99=8.000 ms)

## `rtt_320`
- rtt spread: 300 ms
- 8 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 10 | 1024 | 40.466 | 8.000 | 32.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 40.5 Mbps; threshold 36.4 Mbps)
  -> **wait=10ms cap=1024** (goodput=40.466 Mbps, p99=8.000 ms)

## `rtt_40`
- rtt spread: 20 ms
- 8 cell(s); 3 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 50 | 1024 | 44.601 | 32.000 | 64.000 |  |
| 300 | 1024 | 40.956 | 4.000 | 32.000 |  |
| 10 | 1024 | 40.106 | 0.000 | 32.000 |  |
| 20 | 1024 | 40.784 | 4.000 | 32.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 44.6 Mbps; threshold 40.1 Mbps)
  -> **wait=20ms cap=1024** (goodput=40.784 Mbps, p99=4.000 ms)

## `rtt_70`
- rtt spread: 50 ms
- 8 cell(s); 2 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 80 | 1024 | 40.994 | 8.000 | 32.000 |  |
| 200 | 1024 | 40.861 | 2.000 | 16.000 |  |
| 10 | 1024 | 40.750 | 2.000 | 16.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 41.0 Mbps; threshold 36.9 Mbps)
  -> **wait=10ms cap=1024** (goodput=40.750 Mbps, p99=2.000 ms)

## Optimal `max_wait_ms` vs RTT spread (rtt_* axis)

Knee = cheapest-latency sufficient wait (recommended default); peak = goodput-maximising wait (latency ignored). A knee that tracks the spread confirms the core hypothesis; a knee that stalls or a peak at the minimum wait flags the high-spread regime where reorder stops helping.

| env | rtt spread (ms) | knee wait (ms) | knee goodput (Mbps) | peak wait (ms) | peak goodput (Mbps) |
|:--|---:|---:|---:|---:|---:|
| baseline | 0 | 50 | 44.036 | 80 | 45.393 |
| rtt_40 | 20 | 20 | 40.784 | 50 | 44.601 |
| rtt_70 | 50 | 10 | 40.750 | 80 | 40.994 |
| rtt_120 | 100 | 10 | 40.422 | 10 | 40.422 |
| rtt_320 | 300 | 10 | 40.466 | 10 | 40.466 |


## reorder ON vs OFF (net benefit)

Median goodput with reorder OFF (RAW pass-through) vs the best ON config (max-goodput frontier point) and the recommended-default ON config. `Δ% = (ON − OFF) / OFF`; positive ⇒ reorder helps. The verdict uses the best-ON Δ (NET-POSITIVE > +2%, NET-NEGATIVE < −2%, else NEUTRAL) — the ceiling reorder can reach here; `best-ON p99` is the latency cost of reaching it, and rec-ON is the latency-bounded shipping config.

| env | rtt spread (ms) | OFF Mbps | best-ON Mbps | Δ best % | best-ON p99 (ms) | rec-ON Mbps | Δ rec % | verdict |
|:--|---:|---:|---:|---:|---:|---:|---:|:--|
| baseline | 0 | 36.953 | 45.393 | 22.8 | 64.000 | 44.036 | 19.2 | NET-POSITIVE |
| bw_10to1 | 0 | 72.075 | 74.253 | 3.0 | 64.000 | 68.977 | -4.3 | NET-POSITIVE (rec only at latency cost) |
| bw_4to1 | 0 | 39.615 | 41.606 | 5.0 | 64.000 | 38.398 | -3.1 | NET-POSITIVE (rec only at latency cost) |
| congested | 10 | 4.756 | 6.051 | 27.2 | 64.000 | 6.051 | 27.2 | NET-POSITIVE |
| dual_lte | 15 | 20.128 | 30.255 | 50.3 | 64.000 | 28.065 | 39.4 | NET-POSITIVE |
| fiber_lte | 32 | 211.823 | 204.137 | -3.6 | 16.000 | 201.400 | -4.9 | NET-NEGATIVE |
| jit_20 | 0 | 5.439 | 39.144 | 619.7 | 64.000 | 37.456 | 588.7 | NET-POSITIVE |
| jit_5 | 0 | 17.088 | 52.576 | 207.7 | 128.000 | 52.576 | 207.7 | NET-POSITIVE |
| loss_05 | 0 | 26.884 | 32.441 | 20.7 | 64.000 | 29.858 | 11.1 | NET-POSITIVE |
| loss_2 | 0 | 14.619 | 14.029 | -4.0 | 32.000 | 14.029 | -4.0 | NET-NEGATIVE |
| lte_geo | 285 | 31.618 | 31.530 | -0.3 | 0.000 | 31.530 | -0.3 | NEUTRAL |
| lte_starlink | 15 | 26.643 | 29.771 | 11.7 | 64.000 | 27.677 | 3.9 | NET-POSITIVE |
| rtt_120 | 100 | 40.690 | 40.422 | -0.7 | 8.000 | 40.422 | -0.7 | NEUTRAL |
| rtt_320 | 300 | 40.681 | 40.466 | -0.5 | 8.000 | 40.466 | -0.5 | NEUTRAL |
| rtt_40 | 20 | 38.985 | 44.601 | 14.4 | 32.000 | 40.784 | 4.6 | NET-POSITIVE |
| rtt_70 | 50 | 36.426 | 40.994 | 12.5 | 8.000 | 40.750 | 11.9 | NET-POSITIVE |

- OFF goodput = median across `--off-csv` repeats (Enabled=off, RAW).
- best-ON = max-goodput frontier point (ceiling, latency ignored); rec-ON = recommended default = goodput knee (smallest wait, tie-break smallest cap, reaching >=90% of peak goodput).
- Envs whose OFF baseline never completed the transfer (all-NA goodput, e.g. heavily congested/loss+jitter paths) are absent here: no OFF number to divide by — itself a sign reorder is needed, since RAW pass-through failed to deliver.


## 3-way comparison: single path vs multipath (OFF / ON)

Each row compares three configs on the SAME netem: single path (Path A / Path B = the env's path A / path B netem applied to a lone path), multipath with reorder OFF (RAW pass-through), and multipath with reorder at its best-goodput frontier point. The recommendation column picks the SIMPLEST config whose median goodput is within 5% of the winner; ties go to single > mp-OFF > mp-ON. This is the user-facing answer to 'should I multipath in this env?'

| env | RTT spread [ms] | Path A [Mbps] | Path B [Mbps] | best single [Mbps] | OFF (mp) [Mbps] | best-ON (mp) [Mbps] | Δ best-ON vs best-single [%] | recommendation |
|:--|---:|---:|---:|---:|---:|---:|---:|:--|
| baseline | 0 | 40.737 | 40.297 | 40.737 | 36.953 | 45.393 | 11.4 | **multipath + reorder ON** |
| bw_10to1 | 0 | 73.688 | 8.671 | 73.688 | 72.075 | 74.253 | 0.8 | **single path (Path A)** |
| bw_4to1 | 0 | 40.725 | 10.357 | 40.725 | 39.615 | 41.606 | 2.2 | **single path (Path A)** |
| congested | 10 | 5.434 | 5.840 | 5.840 | 4.756 | 6.051 | 3.6 | **single path (Path B)** |
| dual_lte | 15 | 30.260 | 19.223 | 30.260 | 20.128 | 30.255 | -0.0 | **single path (Path A)** |
| fiber_lte | 32 | 212.837 | 22.323 | 212.837 | 211.823 | 204.137 | -4.1 | **single path (Path A)** |
| jit_20 | 0 | 33.267 | 33.969 | 33.969 | 5.439 | 39.144 | 15.2 | **multipath + reorder ON** |
| jit_5 | 0 | 38.586 | 38.469 | 38.586 | 17.088 | 52.576 | 36.3 | **multipath + reorder ON** |
| loss_05 | 0 | 29.954 | 27.926 | 29.954 | 26.884 | 32.441 | 8.3 | **multipath + reorder ON** |
| loss_2 | 0 | 17.448 | 18.841 | 18.841 | 14.619 | 14.029 | -25.5 | **single path (Path B)** |
| lte_geo | 285 | 31.891 | 6.124 | 31.891 | 31.618 | 31.530 | -1.1 | **single path (Path A)** |
| lte_starlink | 15 | 30.161 | 16.416 | 30.161 | 26.643 | 29.771 | -1.3 | **single path (Path A)** |
| rtt_120 | 100 | 40.694 | 27.839 | 40.694 | 40.690 | 40.422 | -0.7 | **single path (Path A)** |
| rtt_320 | 300 | 40.726 | 8.888 | 40.726 | 40.681 | 40.466 | -0.6 | **single path (Path A)** |
| rtt_40 | 20 | 40.598 | 37.878 | 40.598 | 38.985 | 44.601 | 9.9 | **multipath + reorder ON** |
| rtt_70 | 50 | 40.652 | 33.723 | 40.652 | 36.426 | 40.994 | 0.8 | **single path (Path A)** |

- Path A / Path B = single-path goodput [Mbps] with the env's path A / path B netem applied (median over repeats).
- best single = max(Path A, Path B); the better single-path option a user could pick if not multipathing.
- Δ best-ON vs best-single: positive ⇒ multipath + reorder actually aggregates beyond the better single path. Near-zero or negative ⇒ multipath only matches or loses to single — the recommendation reflects this.
- recommendation picks the simplest config within 5% of the winner: a multipath stack must clearly beat single path to be recommended.
- Envs missing OFF or best-ON columns are present in --single-csv but not in the corresponding ON / OFF CSV; the recommendation still uses whatever it has.

