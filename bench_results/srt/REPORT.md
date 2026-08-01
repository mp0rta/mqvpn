# SRT over mqvpn: Single-Path vs Multipath Bonding

Benchmark report, 2026-08-01.

**Evidence for every number and claim in this report:**

- `summary.md` — full per-run tier-1 table (64 runs; every aggregate in §3
  derives from it)
- `raw.zip` — raw SRT statistics CSVs (100 ms snapshots, sender and
  receiver, per run)
- `video/` — side-by-side comparison videos (direct | bonded) for the
  V1/C3/C3h/C5 conditions, plus the tier-2 per-run data (`video/summary.md`)
- reproduction: `scripts/benchmark_srt.sh`, `scripts/benchmark_srt_video.sh`
  (conditions and knobs documented in §2)

## 1. Background

SRT is the de-facto transport for live video contribution. Its ARQ
(retransmission-based recovery) handles moderate loss on a single link well,
but two practical limits remain:

1. **Bitrate**: a stream cannot exceed what one link carries. Field setups
   (bonded cellular, dual fixed lines) routinely need more than the best
   single link provides.
2. **Link roulette**: on location it is rarely known in advance which of the
   available links will degrade (loss bursts, jitter, congestion).

mqvpn is a VPN that bonds multiple network paths at the IP layer (MASQUE
CONNECT-IP over multipath QUIC; SRT rides in QUIC DATAGRAMs). This benchmark
quantifies the claim: **an SRT stream that breaks up on any single link stays
clean over the mqvpn-bonded tunnel**, and derives the recommended
configuration.

## 2. Test Setup and Method

This section describes the testbed, the traffic and metrics, the network
conditions, and the mqvpn configuration under test.

### Testbed

Linux network namespaces connected by two veth pairs (path A / path B),
shaped with `tc netem` (rate, delay, jitter, loss). `netem limit` is set to
roughly *delay in-flight + 100 ms of queue* at each path rate, so links have
realistic buffer depth instead of netem's default multi-second queue.

Every condition is run in four configurations, called **arms** throughout
this report:

| arm | description |
|---|---|
| direct-A | SRT straight over path A (no VPN) |
| direct-B | SRT straight over path B (no VPN) |
| mqvpn-2path | SRT through mqvpn bonding both paths |
| mqvpn-1path | SRT through mqvpn on path A only (overhead/diagnostic reference) |

### Traffic and metrics

The benchmark has two tiers. Tier 1 measures packet-level stream health with
a synthetic payload; tier 2 (described under *Conditions* below) streams real
video and scores picture quality.

Tier 1 uses `srt-xtransmit` v0.3.0 (SRT 1.5.5) generating a fixed-rate
payload for 60 s per run. The sender follows the official SRT live-stream
configuration: `maxbw=0`, `inputbw=<actual rate in bytes/s>`, `oheadbw=25`
(retransmission ceiling = 1.25 × input rate).

The headline metric is **unique stream loss** = (`pktSentUnique` −
`pktRecvUnique`) / `pktSentUnique` — the fraction of unique packets sent but
never delivered to the receiving application. Unlike receiver-side drop
counts alone, this is comparable across arms: loss can also surface on the
sender side as TLPKTDROP (SRT discarding packets that can no longer arrive
within the latency budget), and pure queueing delay produces zero "drops"
while still failing a live stream. Secondary columns: `pktRcvDrop`,
`pktSndDrop`, `pktRcvBelated`, `pktRcvRetrans`, mean `msRTT`, receive rate.
A measurement floor of ~0.06% (packets still in flight at shutdown) applies
uniformly to all arms.

### Conditions

Each network condition has a short ID (P1, P2, C3, C4, C5) used throughout
the report. Send rates follow the rule *max single link < send rate ≤
0.70–0.75 × aggregate capacity* (the 0.75 bound keeps the 1.25×
retransmission ceiling inside the aggregate).

Burst loss is generated with netem's Gilbert–Elliott model (`gemodel`),
which produces clustered loss rather than uniformly random loss. Its four
parameters are the good→bad transition probability, the bad→good transition
probability, and the loss probabilities inside the bad and good states — so
`gemodel 2% 40% 70% 0.1%` means: enter a bad state with probability 2%,
leave it with probability 40%, and lose 70% of packets while in it (0.1%
otherwise).

| # | scenario | path A | path B | rate / SRT latency | repeats |
|---|---|---|---|---|---|
| P1 | practical stream, fits one link | 100 Mbit, 20 ms | 100 Mbit, 20 ms | 25 Mbps / 120 ms | 1 |
| P2 | bonding: exceeds any single link | 100 Mbit, 20 ms | 100 Mbit, 20 ms | **120 Mbps** / 120 ms | 3 |
| C3 | burst loss on one path | 100 Mbit, 50 ms + Gilbert–Elliott loss (`gemodel 2% 40% 70% 0.1%`, ≈5% measured round-trip) | 100 Mbit, 50 ms | 25 Mbps / 120 ms | 3 |
| C4 | heavy jitter on one path | 100 Mbit, 20 ± 50 ms | 100 Mbit, 40 ms | 25 Mbps / 120 ms | 3 |
| C5 | dual-cellular bonding | 40 Mbit, 40 ± 20 ms, 0.2% | 30 Mbit, 60 ± 30 ms, 0.4% | **42 Mbps** / 250 ms | 3 |

C5 models the most common field use case: two cellular carriers with
asymmetric capacity, RTT, jitter, and residual loss; 42 Mbps exceeds the
best single link. C3 uses a base RTT of 100 ms against a 120 ms latency
budget, leaving SRT roughly one retransmission opportunity.

An additional severity point, **C3h**, repeats C3 with a harsher loss model
(`gemodel 4% 30% 80% 0.5%`: mean ≈10% loss per direction; 16.4% measured
round-trip ping loss for the archived dataset), reproducible via
`SRT_BENCH_GEMODEL="4% 30% 80% 0.5%"`. Per-run values are in `summary.md`
(`C3h_*` rows).

Tier 2 streams real video with ffmpeg over SRT and scores the recording
against the source on three metrics: **VMAF** (after constant-frame-rate
normalization and PTS head alignment), **decoder error log lines**, and
**freeze seconds** (`freezedetect` after CFR normalization). Clips are 60 s
excerpts of *Big Buck Bunny* (© 2008 Blender Foundation / bigbuckbunny.org,
CC-BY 3.0), re-encoded to 1080p30 H.264 CBR at each condition's table rate —
25 and 42 Mbps are contribution-grade FHD bitrates, SRT's home turf.

Tier 2 runs the burst-loss conditions (C3, C3h) and the dual-cellular
condition (C5) from the table above, plus one tier-2-only visual-demo
condition:

- **V1 — starved uplinks**: 2 × 6 Mbit, 20 ms (congested-cellular /
  ADSL-class uplinks), streaming an 8 Mbps FHD program that fits neither
  link alone; SRT latency 150 ms.

SRT settings for the video runs: receiver `lossmaxttl=32` with the
per-condition latency (V1 150 ms, C3/C3h 120 ms, C5 250 ms); the sender is
`-re`-paced MPEG-TS with libsrt's default bandwidth control. Applying the
strict `maxbw=0`/`oheadbw=25` cap of §5 to the video runs was also tested
and measurably hurt every arm — see the note in §5 on bursty sources.

### mqvpn configuration under test

mqvpn runs with its defaults: `--scheduler wlb` (the default
weighted-load-balancing scheduler), tunnel reorder shim off, BBR2 congestion
control. The SRT receiver adds `lossmaxttl=32`. Scripts:
`scripts/benchmark_srt.sh`, `scripts/benchmark_srt_video.sh`; the full
per-run table is in this directory's `summary.md`, and the raw per-run
SRT statistics CSVs (100 ms snapshots, sender and receiver) are archived
in `raw.zip`.

## 3. Results

This section presents the tier-1 packet-level results first, then the tier-2
video-quality results.

### Tier 1 — stream loss (mean over repeats)

| condition | direct-A | direct-B | mqvpn-2path |
|---|---|---|---|
| P1 25 Mbps (fits one link) | 0.06% | 0.06% | 0.06% |
| P2 120 Mbps (exceeds any link) | 31.5% | 31.5% | **0.06%** |
| C3 burst loss on path A (≈5%) | 0.22% | 0.00% | **0.10%** |
| C3h burst loss on path A (≈10%) | 2.30% | 0.00% | **0.20%** |
| C4 heavy jitter on path A | 0.03% | 0.00% | **0.00%** |
| C5 dual-cellular 42 Mbps | 20.0% | 39.6% | **0.91%** |

(The diagnostic mqvpn-1path arm — the tunnel restricted to a single path —
is not a deployment configuration; its behaviour is analysed in §4. Full
per-run data for all four arms is in `summary.md`.)

All values include the ~0.06% shutdown-tail floor; mqvpn-2path at P2 is
therefore effectively lossless.

Mean RTT reported by SRT (ms) — the delay-health counterpart to the loss
table (a live stream can fail by delay without dropping a packet):

| condition | direct-A | direct-B | mqvpn-2path |
|---|---|---|---|
| P1 | 40 | 40 | 40 |
| P2 | 146 | 146 | **41** |
| C3 | 100 | 100 | 101 |
| C3h | 100 | 100 | 101 |
| C4 | 108 | 80 | 98 |
| C5 | 257 | 302 | **158** |

Notable secondary observations:

- **P2**: mqvpn-2path sustains 124 Mbps at the receiver (payload +
  retransmissions) with msRTT 41 ms and *zero* receiver drops across all
  three repeats, while each single link drops ~215k of 685k unique packets.
- **C3**: bonding *reduces* retransmission work versus the lossy single link
  (≈1.8k vs ≈4.9k retransmissions per run) — recovery traffic can use the
  clean path.
- **C3h**: as loss deepens, the gap widens superlinearly. The degraded single
  link goes 0.22% → 2.30% (ARQ amplification: a lost retransmission has no
  second chance inside the 120 ms budget; ≈13k retransmissions per run),
  while the bonded tunnel's loss-aware scheduling shifts traffic onto the
  clean path and holds 0.20% (≈1–3k retransmissions) — an ≈11× advantage.
- **C4**: mqvpn-2path shows elevated spurious retransmissions (~27k/run,
  ≈+19% bandwidth overhead) with zero loss: cross-path delivery under
  50 ms jitter exceeds the `lossmaxttl=32` reorder window, so SRT
  re-requests packets that are merely late. See §5 for tuning options.
- **C5**: receive rate 52 Mbps (42 Mbps payload + recovery) at msRTT
  ≈157 ms, against a 250 ms budget — comfortable field margin.

### Tier 2 — real video quality

| run | VMAF (mean) | decoder error lines | freeze (s) |
|---|---|---|---|
| V1 starved uplinks (8 Mbps FHD), direct | 8.6 | 681 | 1.2 |
| V1 starved uplinks, mqvpn 2×6 Mbit | **87.7** | 74 | 0.0 |
| C3 burst loss on path A ≈5% (25 Mbps), direct-A | 61.1 | 189 | 3.1 |
| C3 burst loss on path A ≈5%, mqvpn-2path | **92.0** | 95 | 3.8 |
| C3h burst loss on path A ≈10% (25 Mbps), direct-A | 24.6 | 545 | 1.6 |
| C3h burst loss on path A ≈10%, mqvpn-2path | **89.1** | 103 | 2.6 |
| C5 dual-cellular (42 Mbps), direct-A | 12.4 | 615 | 5.0 |
| C5 dual-cellular, mqvpn-2path | **56.5** | 293 | 4.4 |

The side-by-side comparison videos are the most direct evidence:
`video/v1_starved_uplinks_direct_vs_mqvpn.mp4` (the direct pane is a
continuous smear of macroblocking while the bonded pane plays normally),
`video/c3_burstloss_direct_vs_mqvpn.mp4`,
`video/c3h_burstloss_direct_vs_mqvpn.mp4`, and
`video/c5_cellular_direct_vs_mqvpn.mp4`.

The C5 row is deliberately hard mode: at 42 Mbps a frame spans ~175
packets, so the ≈0.9% residual loss that looks excellent at packet level
still touches most frames — the bonded pane is followable with periodic
artifacts, while the best single carrier is unwatchable. Clean pictures at
contribution rates over cellular want a larger latency budget and
`lossmaxttl` per §5. Method caveat: the burst-loss single-link VMAF is
sensitive to PTS head alignment — if loss hits the first GOP, VMAF scores a
misaligned comparison rather than visual damage; the quantitative loss
results rest on tier 1 in any case.

## 4. Discussion

This section interprets the results: where bonding delivers, where it costs
something, and one known weak spot exposed by the diagnostic arm.

**The bonding claim holds at practical scale.** A 120 Mbps stream that loses
~31% of its packets on either 100 Mbit link alone runs effectively lossless
over the bonded tunnel (P2), and the dual-cellular scenario — the most common
field deployment — goes from 20–40% loss on either carrier to 0.9% (C5).
The visual counterpart matches: VMAF 8.6 (continuous macroblocking and
smearing) on the starved single link versus 87.7 through the bonded tunnel,
best seen in the side-by-side videos under `video/`.

**Where a single healthy link suffices, mqvpn does no harm.** P1 shows no
measurable overhead at 25 Mbps, and in the loss and jitter conditions the
bonded tunnel performs at or better than the *degraded* link. The honest
framing for C3/C4 is not "the single link fails" — SRT's own ARQ handles
~5% burst loss well — but that bonding removes the need to know in advance
*which* link will degrade, while also spreading retransmission load onto the
healthy path.

**Reorder tolerance belongs in SRT, not the tunnel.** SRT already holds a
receiver buffer of `latency` milliseconds and reorders within it; what
multipath delivery adds is sequence gaps that SRT would misread as loss,
which is exactly what the `lossmaxttl` option answers. Enabling mqvpn's
tunnel-level reorder shim instead is counterproductive for SRT workloads:
under sustained real loss the shim waits on sequence gaps that will never
fill, and the added head-of-line delay can escalate into heavy stream loss.
Keep the shim at its default (off) for SRT and let the SRT layer absorb
reordering.

**Jitter-dominant paths trade bandwidth for simplicity.** With
`lossmaxttl=32` under 50 ms jitter, the default scheduler's per-packet
distribution across paths produces ~19% retransmission overhead at zero loss
(C4). Deployments where that overhead matters can either raise `lossmaxttl`
(SRT adapts its tolerance up to the configured maximum; the observed reorder
distance at 25 Mbps under 50 ms spread is ≈170 packets) or pin
jitter-sensitive streams to `--scheduler min_srtt`, which kept
retransmissions at zero in the same condition — at the cost of not
aggregating bandwidth below saturation.

**The diagnostic single-path-tunnel arm exposes a known weak spot.** The
mqvpn-1path arm (tunnel restricted to one path — not a deployment
configuration) behaves distinctively under stress. Under bandwidth overload
it can show *less* loss than the direct link (1.0% vs 31.5% at P2, 7.5% vs
20% at C5): the tunnel's congestion control paces traffic to the link's
actual capacity, so excess is dropped in an orderly way at the SRT sender
before the bottleneck, with no sequence gaps and hence no ARQ amplification.
But the remaining overload surfaces as queueing delay instead, with mean
RTT reaching 0.9 s (P2) and 3.5 s (C5) against a 250 ms budget — a stream
that arrives seconds late is equally unusable for live. Under deep burst
loss the same mechanisms compound into collapse: at C3h this arm loses ≈92%
of the stream at ≈21 s RTT, on a link where direct SRT still delivers 97.7%,
because the congestion controller's loss response throttles the tunnel to
a fraction of the link rate while the datagram queue absorbs the difference.
Neither failure mode affects the bonded configurations (the second path
absorbs the load); the single-path datagram queue behaviour is being tracked
as a separate improvement item.

## 5. Recommended Configuration

For SRT live contribution over mqvpn:

| layer | setting | value |
|---|---|---|
| mqvpn | scheduler | `wlb` (default) |
| mqvpn | reorder shim | off (default) — do not enable for SRT |
| SRT receiver | `lossmaxttl` | `32` (raise toward 128–256 on high-jitter multi-path if retransmission overhead matters) |
| SRT both | `latency` | ≥ 3 × RTT; 120 ms on stable wired paths, 250 ms on cellular |

Sender bandwidth control — **depends on the source, and this matters**:

| source type | recommendation | validated by |
|---|---|---|
| smooth constant-rate payload | `maxbw=0`, `inputbw` = actual rate in **bytes/s**, `oheadbw=25` (official SRT live config) | tier 1 (all conditions) |
| frame-paced video (ffmpeg & co.) | **libsrt defaults (no cap)**; if a cap is required, `oheadbw` 50–100 with `inputbw` measured from the actual mux rate | tier 2 (all conditions) |

This distinction is not theoretical: applying the strict `oheadbw=25` cap
(even combined with CBR remuxing) to real video degraded *every* tier-2 arm
— e.g. the bonded starved-uplinks run fell from VMAF 87.7 to 74.7, and the
dual-cellular run from 57 to 18–33. Frame-paced video is bursty and its
effective input rate is easy to under-declare; the 1.25× ceiling then
throttles retransmissions exactly when they are needed. All tier-2 results
in §3 use libsrt default sender pacing.

Send-rate sizing: **max single link < send rate ≤ 0.70–0.75 × aggregate
capacity**. Examples: 2 × 100 Mbps → 120–140 Mbps; 40 + 30 Mbps cellular
→ ~42 Mbps. The 0.75 bound reserves room for retransmissions plus tunnel
overhead.

For jitter-sensitive, latency-critical streams that fit within a single
path's capacity, `--scheduler min_srtt` remains the recommended alternative
(zero spurious retransmissions in the jitter condition).
