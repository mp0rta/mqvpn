# Reorder sweep — Pareto-optimal analysis

Per environment: non-dominated (goodput MAXIMIZE, p99 added-latency MINIMIZE) frontier over median-of-repeats points, plus a recommended default = the goodput **knee** (smallest `max_wait_ms`, tie-break smallest cap, reaching >=90% of the env's peak goodput). The knee replaces the design's `added_p99_ms <= 0.5 * rtt_spread` rule, which selected collapsed low-wait cells (goodput ~1 Mbps but ~0 ms added latency).

## `baseline`
- rtt spread: 0 ms
- 12 cell(s); 2 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 300 | 4096 | 69.722 | 32.000 | 32.000 |  |
| 200 | 1024 | 69.408 | 16.000 | 16.000 |  |
| 10 | 1024 | 68.786 | 16.000 | 16.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 69.7 Mbps; threshold 62.7 Mbps)
  -> **wait=10ms cap=1024** (goodput=68.786 Mbps, p99=16.000 ms)

## `bw_10to1`
- rtt spread: 0 ms
- 8 cell(s); 2 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 200 | 1024 | 38.201 | 64.000 | 64.000 |  |
| 10 | 1024 | 30.276 | 32.000 | 32.000 |  |
| 30 | 1024 | 34.652 | 64.000 | 64.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 38.2 Mbps; threshold 34.4 Mbps)
  -> **wait=30ms cap=1024** (goodput=34.652 Mbps, p99=64.000 ms)

## `bw_4to1`
- rtt spread: 0 ms
- 8 cell(s); 2 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 30 | 1024 | 34.929 | 64.000 | 64.000 |  |
| 20 | 1024 | 33.634 | 32.000 | 64.000 |  |
| 10 | 1024 | 33.385 | 32.000 | 32.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 34.9 Mbps; threshold 31.4 Mbps)
  -> **wait=10ms cap=1024** (goodput=33.385 Mbps, p99=32.000 ms)

## `congested`
- rtt spread: 10 ms
- 11 cell(s); 2 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 50 | 1024 | 8.043 | 128.000 | 128.000 | **<-** |
| 30 | 1024 | 4.015 | 64.000 | 128.000 |  |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 8.0 Mbps; threshold 7.2 Mbps)
  -> **wait=50ms cap=1024** (goodput=8.043 Mbps, p99=128.000 ms)

## `dual_lte`
- rtt spread: 15 ms
- 12 cell(s); 2 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 30 | 1024 | 37.932 | 64.000 | 64.000 |  |
| 20 | 1024 | 4.586 | 32.000 | 64.000 |  |
| 30 | 512 | 34.352 | 64.000 | 64.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 37.9 Mbps; threshold 34.1 Mbps)
  -> **wait=30ms cap=512** (goodput=34.352 Mbps, p99=64.000 ms)

## `fiber_lte`
- rtt spread: 32 ms
- 12 cell(s); 3 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 50 | 4096 | 71.497 | 128.000 | 128.000 |  |
| 30 | 1024 | 5.193 | 64.000 | 64.000 |  |
| 10 | 1024 | 2.971 | 32.000 | 32.000 |  |
| 50 | 2048 | 65.507 | 128.000 | 128.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 71.5 Mbps; threshold 64.3 Mbps)
  -> **wait=50ms cap=2048** (goodput=65.507 Mbps, p99=128.000 ms)

## `jit_20`
- rtt spread: 0 ms
- 8 cell(s); 2 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 200 | 1024 | 47.053 | 64.000 | 64.000 | **<-** |
| 30 | 1024 | 27.717 | 32.000 | 64.000 |  |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 47.1 Mbps; threshold 42.3 Mbps)
  -> **wait=200ms cap=1024** (goodput=47.053 Mbps, p99=64.000 ms)

## `jit_5`
- rtt spread: 0 ms
- 8 cell(s); 1 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 80 | 1024 | 68.703 | 16.000 | 32.000 |  |
| 20 | 1024 | 63.695 | 32.000 | 32.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 68.7 Mbps; threshold 61.8 Mbps)
  -> **wait=20ms cap=1024** (goodput=63.695 Mbps, p99=32.000 ms)

## `loss_05`
- rtt spread: 0 ms
- 8 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 10 | 1024 | 61.267 | 32.000 | 32.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 61.3 Mbps; threshold 55.1 Mbps)
  -> **wait=10ms cap=1024** (goodput=61.267 Mbps, p99=32.000 ms)

## `loss_2`
- rtt spread: 0 ms
- 8 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 10 | 1024 | 24.045 | 32.000 | 32.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 24.0 Mbps; threshold 21.6 Mbps)
  -> **wait=10ms cap=1024** (goodput=24.045 Mbps, p99=32.000 ms)

## `lte_geo`
- rtt spread: 285 ms
- 12 cell(s); 3 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 300 | 2048 | 14.303 | 512.000 | 512.000 | **<-** |
| 30 | 1024 | 1.178 | 128.000 | 128.000 |  |
| 10 | 1024 | 0.765 | 32.000 | 32.000 |  |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 14.3 Mbps; threshold 12.9 Mbps)
  -> **wait=300ms cap=2048** (goodput=14.303 Mbps, p99=512.000 ms)

## `lte_starlink`
- rtt spread: 15 ms
- 12 cell(s); 3 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 50 | 4096 | 25.503 | 128.000 | 128.000 |  |
| 30 | 1024 | 1.503 | 64.000 | 64.000 |  |
| 10 | 1024 | 0.642 | 32.000 | 64.000 |  |
| 50 | 1024 | 23.985 | 128.000 | 128.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 25.5 Mbps; threshold 23.0 Mbps)
  -> **wait=50ms cap=1024** (goodput=23.985 Mbps, p99=128.000 ms)

## `rtt_120`
- rtt spread: 100 ms
- 7 cell(s); 3 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 300 | 1024 | 35.253 | 128.000 | 128.000 |  |
| 30 | 1024 | 0.872 | 64.000 | 64.000 |  |
| 10 | 1024 | 0.643 | 32.000 | 32.000 |  |
| 120 | 1024 | 35.103 | 128.000 | 128.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 35.3 Mbps; threshold 31.7 Mbps)
  -> **wait=120ms cap=1024** (goodput=35.103 Mbps, p99=128.000 ms)

## `rtt_320`
- rtt spread: 300 ms
- 8 cell(s); 1 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 10 | 1024 | 2.774 | 32.000 | 32.000 | **<-** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 2.8 Mbps; threshold 2.5 Mbps)
  -> **wait=10ms cap=1024** (goodput=2.774 Mbps, p99=32.000 ms)

## `rtt_40`
- rtt spread: 20 ms
- 8 cell(s); 3 on frontier (rec is off-frontier — shown as extra row)

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 200 | 1024 | 62.174 | 128.000 | 128.000 |  |
| 30 | 1024 | 58.577 | 64.000 | 64.000 |  |
| 10 | 1024 | 0.929 | 16.000 | 32.000 |  |
| 20 | 1024 | 56.111 | 64.000 | 64.000 | **<- (off-frontier)** |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 62.2 Mbps; threshold 56.0 Mbps)
  -> **wait=20ms cap=1024** (goodput=56.111 Mbps, p99=64.000 ms)

## `rtt_70`
- rtt spread: 50 ms
- 6 cell(s); 2 on frontier

| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |
|---:|---:|---:|---:|---:|:--:|
| 80 | 1024 | 48.819 | 128.000 | 128.000 | **<-** |
| 30 | 1024 | 0.937 | 64.000 | 64.000 |  |

- recommended default: knee = smallest wait reaching >=90% of peak goodput (peak 48.8 Mbps; threshold 43.9 Mbps)
  -> **wait=80ms cap=1024** (goodput=48.819 Mbps, p99=128.000 ms)

## Optimal `max_wait_ms` vs RTT spread (rtt_* axis)

Knee = cheapest-latency sufficient wait (recommended default); peak = goodput-maximising wait (latency ignored). A knee that tracks the spread confirms the core hypothesis; a knee that stalls or a peak at the minimum wait flags the high-spread regime where reorder stops helping.

| env | rtt spread (ms) | knee wait (ms) | knee goodput (Mbps) | peak wait (ms) | peak goodput (Mbps) |
|:--|---:|---:|---:|---:|---:|
| baseline | 0 | 10 | 68.786 | 300 | 69.722 |
| rtt_40 | 20 | 20 | 56.111 | 200 | 62.174 |
| rtt_70 | 50 | 80 | 48.819 | 80 | 48.819 |
| rtt_120 | 100 | 120 | 35.103 | 300 | 35.253 |
| rtt_320 | 300 | 10 | 2.774 | 10 | 2.774 |


## reorder ON vs OFF (net benefit)

Median goodput with reorder OFF (RAW pass-through) vs the best ON config (max-goodput frontier point) and the recommended-default ON config. `Δ% = (ON − OFF) / OFF`; positive ⇒ reorder helps. The verdict uses the best-ON Δ (NET-POSITIVE > +2%, NET-NEGATIVE < −2%, else NEUTRAL) — the ceiling reorder can reach here; `best-ON p99` is the latency cost of reaching it, and rec-ON is the latency-bounded shipping config.

| env | rtt spread (ms) | OFF Mbps | best-ON Mbps | Δ best % | best-ON p99 (ms) | rec-ON Mbps | Δ rec % | verdict |
|:--|---:|---:|---:|---:|---:|---:|---:|:--|
| baseline | 0 | 61.975 | 69.722 | 12.5 | 32.000 | 68.786 | 11.0 | NET-POSITIVE |
| bw_10to1 | 0 | 15.073 | 38.201 | 153.4 | 64.000 | 34.652 | 129.9 | NET-POSITIVE |
| bw_4to1 | 0 | 21.699 | 34.929 | 61.0 | 64.000 | 33.385 | 53.9 | NET-POSITIVE |
| dual_lte | 15 | 0.889 | 37.932 | 4165.8 | 64.000 | 34.352 | 3763.2 | NET-POSITIVE |
| fiber_lte | 32 | 0.883 | 71.497 | 7997.3 | 128.000 | 65.507 | 7318.9 | NET-POSITIVE |
| jit_20 | 0 | 0.996 | 47.053 | 4626.3 | 64.000 | 47.053 | 4626.3 | NET-POSITIVE |
| jit_5 | 0 | 3.198 | 68.703 | 2048.5 | 16.000 | 63.695 | 1891.9 | NET-POSITIVE |
| loss_05 | 0 | 62.178 | 61.267 | -1.5 | 32.000 | 61.267 | -1.5 | NEUTRAL |
| loss_2 | 0 | 18.128 | 24.045 | 32.6 | 32.000 | 24.045 | 32.6 | NET-POSITIVE |
| lte_starlink | 15 | 0.629 | 25.503 | 3955.6 | 128.000 | 23.985 | 3714.2 | NET-POSITIVE |
| rtt_120 | 100 | 1.469 | 35.253 | 2299.6 | 128.000 | 35.103 | 2289.4 | NET-POSITIVE |
| rtt_320 | 300 | 1.679 | 2.774 | 65.3 | 32.000 | 2.774 | 65.3 | NET-POSITIVE |
| rtt_40 | 20 | 0.875 | 62.174 | 7004.2 | 128.000 | 56.111 | 6311.4 | NET-POSITIVE |
| rtt_70 | 50 | 0.617 | 48.819 | 7812.5 | 128.000 | 48.819 | 7812.5 | NET-POSITIVE |

- OFF goodput = median across `--off-csv` repeats (Enabled=off, RAW).
- best-ON = max-goodput frontier point (ceiling, latency ignored); rec-ON = recommended default = goodput knee (smallest wait, tie-break smallest cap, reaching >=90% of peak goodput).
- Envs whose OFF baseline never completed the transfer (all-NA goodput, e.g. heavily congested/loss+jitter paths) are absent here: no OFF number to divide by — itself a sign reorder is needed, since RAW pass-through failed to deliver.


## 3-way comparison: single path vs multipath (OFF / ON)

Each row compares three configs on the SAME netem: single path (Path A / Path B = the env's path A / path B netem applied to a lone path), multipath with reorder OFF (RAW pass-through), and multipath with reorder at its best-goodput frontier point. The recommendation column picks the SIMPLEST config whose median goodput is within 5% of the winner; ties go to single > mp-OFF > mp-ON. This is the user-facing answer to 'should I multipath in this env?'

| env | RTT spread [ms] | Path A [Mbps] | Path B [Mbps] | best single [Mbps] | OFF (mp) [Mbps] | best-ON (mp) [Mbps] | Δ best-ON vs best-single [%] | recommendation |
|:--|---:|---:|---:|---:|---:|---:|---:|:--|
| baseline | 0 | 40.737 | 40.297 | 40.737 | 61.975 | 69.722 | 71.2 | **multipath + reorder ON** |
| bw_10to1 | 0 | 73.688 | 8.671 | 73.688 | 15.073 | 38.201 | -48.2 | **single path (Path A)** |
| bw_4to1 | 0 | 40.725 | 10.357 | 40.725 | 21.699 | 34.929 | -14.2 | **single path (Path A)** |
| congested | 10 | 5.434 | 5.840 | 5.840 | — | 8.043 | 37.7 | **multipath + reorder ON** |
| dual_lte | 15 | 30.260 | 19.223 | 30.260 | 0.889 | 37.932 | 25.4 | **multipath + reorder ON** |
| fiber_lte | 32 | 212.837 | 22.323 | 212.837 | 0.883 | 71.497 | -66.4 | **single path (Path A)** |
| jit_20 | 0 | 33.267 | 33.969 | 33.969 | 0.996 | 47.053 | 38.5 | **multipath + reorder ON** |
| jit_5 | 0 | 38.586 | 38.469 | 38.586 | 3.198 | 68.703 | 78.1 | **multipath + reorder ON** |
| loss_05 | 0 | 29.954 | 27.926 | 29.954 | 62.178 | 61.267 | 104.5 | **multipath, reorder OFF** |
| loss_2 | 0 | 17.448 | 18.841 | 18.841 | 18.128 | 24.045 | 27.6 | **multipath + reorder ON** |
| lte_geo | 285 | 31.891 | 6.124 | 31.891 | — | 14.303 | -55.2 | **single path (Path A)** |
| lte_starlink | 15 | 30.161 | 16.416 | 30.161 | 0.629 | 25.503 | -15.4 | **single path (Path A)** |
| rtt_120 | 100 | 40.694 | 27.839 | 40.694 | 1.469 | 35.253 | -13.4 | **single path (Path A)** |
| rtt_320 | 300 | 40.726 | 8.888 | 40.726 | 1.679 | 2.774 | -93.2 | **single path (Path A)** |
| rtt_40 | 20 | 40.598 | 37.878 | 40.598 | 0.875 | 62.174 | 53.1 | **multipath + reorder ON** |
| rtt_70 | 50 | 40.652 | 33.723 | 40.652 | 0.617 | 48.819 | 20.1 | **multipath + reorder ON** |

- Path A / Path B = single-path goodput [Mbps] with the env's path A / path B netem applied (median over repeats).
- best single = max(Path A, Path B); the better single-path option a user could pick if not multipathing.
- Δ best-ON vs best-single: positive ⇒ multipath + reorder actually aggregates beyond the better single path. Near-zero or negative ⇒ multipath only matches or loses to single — the recommendation reflects this.
- recommendation picks the simplest config within 5% of the winner: a multipath stack must clearly beat single path to be recommended.
- Envs missing OFF or best-ON columns are present in --single-csv but not in the corresponding ON / OFF CSV; the recommendation still uses whatever it has.

