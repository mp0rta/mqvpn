# Reorder sweep — Pareto-optimal analysis

Per environment: non-dominated (goodput MAXIMIZE, p99 added-latency MINIMIZE) frontier over median-of-repeats points, plus a recommended default = the goodput **knee** (smallest `max_wait_ms`, tie-break smallest cap, reaching >=90% of the env's peak goodput). The knee replaces the design's `added_p99_ms <= 0.5 * rtt_spread` rule, which selected collapsed low-wait cells (goodput ~1 Mbps but ~0 ms added latency).

## `baseline`
- rtt spread: 0 ms
- 12 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 200 | 1024 | 45.295 | 0.000 | 0.000 |  |
| 20 | 1024 | 42.499 | 0.000 | 0.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 45.3 Mbps; threshold 40.8 Mbps)
  -> **wait=20ms cap=1024** (goodput=42.499 Mbps, p99=0.000 ms)

## `bw_10to1`
- rtt spread: 0 ms
- 8 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 300 | 1024 | 74.207 | 0.000 | 0.000 |  |
| 10 | 1024 | 69.641 | 0.000 | 0.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 74.2 Mbps; threshold 66.8 Mbps)
  -> **wait=10ms cap=1024** (goodput=69.641 Mbps, p99=0.000 ms)

## `bw_4to1`
- rtt spread: 0 ms
- 8 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 300 | 1024 | 41.960 | 0.000 | 0.000 |  |
| 10 | 1024 | 39.280 | 0.000 | 0.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 42.0 Mbps; threshold 37.8 Mbps)
  -> **wait=10ms cap=1024** (goodput=39.280 Mbps, p99=0.000 ms)

## `congested`
- rtt spread: 10 ms
- 10 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 30 | 1024 | 6.444 | 0.000 | 64.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 6.4 Mbps; threshold 5.8 Mbps)
  -> **wait=30ms cap=1024** (goodput=6.444 Mbps, p99=0.000 ms)

## `dual_lte`
- rtt spread: 15 ms
- 12 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 20 | 1024 | 29.622 | 0.000 | 0.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 29.6 Mbps; threshold 26.7 Mbps)
  -> **wait=20ms cap=1024** (goodput=29.622 Mbps, p99=0.000 ms)

## `fiber_lte`
- rtt spread: 32 ms
- 12 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 30 | 1024 | 198.813 | 0.000 | 0.000 |  |
| 10 | 1024 | 189.438 | 0.000 | 0.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 198.8 Mbps; threshold 178.9 Mbps)
  -> **wait=10ms cap=1024** (goodput=189.438 Mbps, p99=0.000 ms)

## `jit_20`
- rtt spread: 0 ms
- 8 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 120 | 1024 | 36.846 | 0.000 | 8.000 |  |
| 80 | 1024 | 35.556 | 0.000 | 0.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 36.8 Mbps; threshold 33.2 Mbps)
  -> **wait=80ms cap=1024** (goodput=35.556 Mbps, p99=0.000 ms)

## `jit_5`
- rtt spread: 0 ms
- 8 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 200 | 1024 | 51.085 | 0.000 | 0.000 |  |
| 120 | 1024 | 46.537 | 0.000 | 0.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 51.1 Mbps; threshold 46.0 Mbps)
  -> **wait=120ms cap=1024** (goodput=46.537 Mbps, p99=0.000 ms)

## `loss_05`
- rtt spread: 0 ms
- 8 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 10 | 1024 | 39.552 | 0.000 | 0.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 39.6 Mbps; threshold 35.6 Mbps)
  -> **wait=10ms cap=1024** (goodput=39.552 Mbps, p99=0.000 ms)

## `loss_2`
- rtt spread: 0 ms
- 4 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 10 | 1024 | 16.450 | 0.000 | 0.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 16.4 Mbps; threshold 14.8 Mbps)
  -> **wait=10ms cap=1024** (goodput=16.450 Mbps, p99=0.000 ms)

## `lte_geo`
- rtt spread: 285 ms
- 12 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 200 | 4096 | 30.130 | 0.000 | 0.000 |  |
| 10 | 1024 | 29.455 | 0.000 | 0.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 30.1 Mbps; threshold 27.1 Mbps)
  -> **wait=10ms cap=1024** (goodput=29.455 Mbps, p99=0.000 ms)

## `lte_starlink`
- rtt spread: 15 ms
- 12 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 80 | 4096 | 29.094 | 0.000 | 0.000 |  |
| 10 | 1024 | 26.586 | 0.000 | 16.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 29.1 Mbps; threshold 26.2 Mbps)
  -> **wait=10ms cap=1024** (goodput=26.586 Mbps, p99=0.000 ms)

## `rtt_120`
- rtt spread: 100 ms
- 8 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 200 | 1024 | 40.419 | 0.000 | 0.000 |  |
| 10 | 1024 | 37.242 | 0.000 | 0.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 40.4 Mbps; threshold 36.4 Mbps)
  -> **wait=10ms cap=1024** (goodput=37.242 Mbps, p99=0.000 ms)

## `rtt_320`
- rtt spread: 300 ms
- 8 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 10 | 1024 | 38.877 | 0.000 | 0.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 38.9 Mbps; threshold 35.0 Mbps)
  -> **wait=10ms cap=1024** (goodput=38.877 Mbps, p99=0.000 ms)

## `rtt_40`
- rtt spread: 20 ms
- 8 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 120 | 1024 | 42.006 | 0.000 | 0.000 |  |
| 20 | 1024 | 40.587 | 0.000 | 0.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 42.0 Mbps; threshold 37.8 Mbps)
  -> **wait=20ms cap=1024** (goodput=40.587 Mbps, p99=0.000 ms)

## `rtt_70`
- rtt spread: 50 ms
- 8 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 120 | 1024 | 40.879 | 0.000 | 0.000 |  |
| 10 | 1024 | 40.225 | 0.000 | 0.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 40.9 Mbps; threshold 36.8 Mbps)
  -> **wait=10ms cap=1024** (goodput=40.225 Mbps, p99=0.000 ms)

## Optimal `max_wait_ms` vs RTT spread (rtt_* axis)

Knee = cheapest-latency sufficient wait (recommended default); peak = goodput-maximising wait (latency ignored). A knee that tracks the spread confirms the core hypothesis; a knee that stalls or a peak at the minimum wait flags the high-spread regime where reorder stops helping.

| env | rtt spread (ms) | knee wait (ms) | knee goodput (Mbps) | peak wait (ms) | peak goodput (Mbps) |
|:--|---:|---:|---:|---:|---:|
| baseline | 0 | 20 | 42.499 | 200 | 45.295 |
| rtt_40 | 20 | 20 | 40.587 | 120 | 42.006 |
| rtt_70 | 50 | 10 | 40.225 | 120 | 40.879 |
| rtt_120 | 100 | 10 | 37.242 | 200 | 40.419 |
| rtt_320 | 300 | 10 | 38.877 | 10 | 38.877 |


## reorder ON vs OFF (net benefit)

Median goodput with reorder OFF (RAW pass-through) vs the best ON config (max-goodput frontier point) and the recommended-default ON config. `Δ% = (ON − OFF) / OFF`; positive ⇒ reorder helps. The verdict uses the best-ON Δ (NET-POSITIVE > +2%, NET-NEGATIVE < −2%, else NEUTRAL) — the ceiling reorder can reach here; `best-ON p99` is the latency cost of reaching it, and rec-ON is the latency-bounded shipping config.

| env | rtt spread (ms) | OFF Mbps | best-ON Mbps | Δ best % | best-ON p99 (ms) | rec-ON Mbps | Δ rec % | verdict |
|:--|---:|---:|---:|---:|---:|---:|---:|:--|
| baseline | 0 | 39.771 | 45.295 | 13.9 | 0.000 | 42.499 | 6.9 | NET-POSITIVE |
| bw_10to1 | 0 | 70.119 | 74.207 | 5.8 | 0.000 | 69.641 | -0.7 | NET-POSITIVE |
| bw_4to1 | 0 | 39.871 | 41.960 | 5.2 | 0.000 | 39.280 | -1.5 | NET-POSITIVE |
| congested | 10 | 5.568 | 6.444 | 15.7 | 0.000 | 6.444 | 15.7 | NET-POSITIVE |
| dual_lte | 15 | 26.126 | 29.622 | 13.4 | 0.000 | 29.622 | 13.4 | NET-POSITIVE |
| fiber_lte | 32 | 212.332 | 198.813 | -6.4 | 0.000 | 189.438 | -10.8 | NET-NEGATIVE |
| jit_20 | 0 | 7.990 | 36.846 | 361.1 | 0.000 | 35.556 | 345.0 | NET-POSITIVE |
| jit_5 | 0 | 12.370 | 51.085 | 313.0 | 0.000 | 46.537 | 276.2 | NET-POSITIVE |
| loss_05 | 0 | 31.436 | 39.552 | 25.8 | 0.000 | 39.552 | 25.8 | NET-POSITIVE |
| loss_2 | 0 | 12.625 | 16.450 | 30.3 | 0.000 | 16.450 | 30.3 | NET-POSITIVE |
| lte_geo | 285 | 31.509 | 30.130 | -4.4 | 0.000 | 29.455 | -6.5 | NET-NEGATIVE |
| lte_starlink | 15 | 27.168 | 29.094 | 7.1 | 0.000 | 26.586 | -2.1 | NET-POSITIVE (rec only at latency cost) |
| rtt_120 | 100 | 40.625 | 40.419 | -0.5 | 0.000 | 37.242 | -8.3 | NEUTRAL |
| rtt_320 | 300 | 37.907 | 38.877 | 2.6 | 0.000 | 38.877 | 2.6 | NET-POSITIVE |
| rtt_40 | 20 | 36.937 | 42.006 | 13.7 | 0.000 | 40.587 | 9.9 | NET-POSITIVE |
| rtt_70 | 50 | 36.411 | 40.879 | 12.3 | 0.000 | 40.225 | 10.5 | NET-POSITIVE |

- OFF goodput = median across `--off-csv` repeats (Enabled=off, RAW).
- best-ON = max-goodput frontier point (ceiling, latency ignored); rec-ON = recommended default = goodput knee (smallest wait, tie-break smallest cap, reaching >=90% of peak goodput).
- Envs whose OFF baseline never completed the transfer (all-NA goodput, e.g. heavily congested/loss+jitter paths) are absent here: no OFF number to divide by — itself a sign reorder is needed, since RAW pass-through failed to deliver.


## 3-way comparison: single path vs multipath (OFF / ON)

Each row compares three configs on the SAME netem: single path (Path A / Path B = the env's path A / path B netem applied to a lone path), multipath with reorder OFF (RAW pass-through), and multipath with reorder at its best-goodput frontier point. The recommendation column picks the SIMPLEST config whose median goodput is within 5% of the winner; ties go to single > mp-OFF > mp-ON. This is the user-facing answer to 'should I multipath in this env?'

| env | RTT spread [ms] | Path A [Mbps] | Path B [Mbps] | best single [Mbps] | OFF (mp) [Mbps] | best-ON (mp) [Mbps] | Δ best-ON vs best-single [%] | recommendation |
|:--|---:|---:|---:|---:|---:|---:|---:|:--|
| baseline | 0 | 40.600 | 40.339 | 40.600 | 39.771 | 45.295 | 11.6 | **multipath + reorder ON** |
| bw_10to1 | 0 | 74.172 | 8.621 | 74.172 | 70.119 | 74.207 | 0.0 | **single path (Path A)** |
| bw_4to1 | 0 | 40.621 | 10.306 | 40.621 | 39.871 | 41.960 | 3.3 | **single path (Path A)** |
| congested | 10 | 6.414 | 5.711 | 6.414 | 5.568 | 6.444 | 0.5 | **single path (Path A)** |
| dual_lte | 15 | 29.579 | 18.759 | 29.579 | 26.126 | 29.622 | 0.1 | **single path (Path A)** |
| fiber_lte | 32 | 212.440 | 22.031 | 212.440 | 212.332 | 198.813 | -6.4 | **single path (Path A)** |
| jit_20 | 0 | 17.448 | 10.968 | 17.448 | 7.990 | 36.846 | 111.2 | **multipath + reorder ON** |
| jit_5 | 0 | 38.324 | 38.848 | 38.848 | 12.370 | 51.085 | 31.5 | **multipath + reorder ON** |
| loss_05 | 0 | 29.617 | 32.205 | 32.205 | 31.436 | 39.552 | 22.8 | **multipath + reorder ON** |
| loss_2 | 0 | 16.097 | 16.308 | 16.308 | 12.625 | 16.450 | 0.9 | **single path (Path B)** |
| lte_geo | 285 | 31.688 | 6.044 | 31.688 | 31.509 | 30.130 | -4.9 | **single path (Path A)** |
| lte_starlink | 15 | 29.558 | 8.877 | 29.558 | 27.168 | 29.094 | -1.6 | **single path (Path A)** |
| rtt_120 | 100 | 40.683 | 27.531 | 40.683 | 40.625 | 40.419 | -0.6 | **single path (Path A)** |
| rtt_320 | 300 | 40.288 | 9.210 | 40.288 | 37.907 | 38.877 | -3.5 | **single path (Path A)** |
| rtt_40 | 20 | 40.467 | 37.926 | 40.467 | 36.937 | 42.006 | 3.8 | **single path (Path A)** |
| rtt_70 | 50 | 40.603 | 33.708 | 40.603 | 36.411 | 40.879 | 0.7 | **single path (Path A)** |

- Path A / Path B = single-path goodput [Mbps] with the env's path A / path B netem applied (median over repeats).
- best single = max(Path A, Path B); the better single-path option a user could pick if not multipathing.
- Δ best-ON vs best-single: positive ⇒ multipath + reorder actually aggregates beyond the better single path. Near-zero or negative ⇒ multipath only matches or loses to single — the recommendation reflects this.
- recommendation picks the simplest config within 5% of the winner: a multipath stack must clearly beat single path to be recommended.
- Envs missing OFF or best-ON columns are present in --single-csv but not in the corresponding ON / OFF CSV; the recommendation still uses whatever it has.

