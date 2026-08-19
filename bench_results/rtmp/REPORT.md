# RTMP continuity benchmark — direct single-link vs mqvpn (internal report)

Date: 2026-08-10. Companion to the SRT benchmark (`bench_results/srt/`);
same netns/netem foundation, TCP-based contribution protocol instead of UDP.

**Internal report.** The `mqvpn-datagram` rows quantify the hybrid-lane
recommendation and are NOT for publication; the public subset is
`direct-a` vs `mqvpn-hybrid` plus the R3 flap material.

## 1. Setup

- mqvpn v0.16.0 CLI (`build-lib/mqvpn`), product defaults: scheduler = wlb,
  CC = bbr2, reorder shim off. Hybrid lane per arm below.
- Harness: `scripts/benchmark_rtmp.sh` (tier 1),
  `scripts/benchmark_rtmp_video.sh` (tier 2), analysis
  `benchmarks/rtmp_analyze.py` (metric definitions live in its docstring).
- Publisher: ffmpeg (BtbN static N-125856) x264 veryfast 8 Mbps 1080p30 +
  AAC 160k, OBS-like wrapper: 10 s stall watchdog, 2 s reconnect retry,
  reconnect confirmed after 3 s of progress.
- Ingest: nginx-rtmp (`libnginx-mod-rtmp`, Ubuntu 24.04), per-session FLV
  DVR (`record_unique`).
- Environment: privileged docker container (`mqvpn-e2e:deps` + nginx-rtmp
  + fonts), host kernel 7.0.0-28-generic, netns pair + 2 veth paths shaped
  with netem. All rates are netem-shaped far below line rate, so container
  overhead is immaterial.
- Stream rate 8 Mbps in all conditions (Twitch cap ≈ 8 Mbps; inside the
  YouTube 1080p60 recommended band).

### Arms

| arm | path |
|---|---|
| direct-a | RTMP straight over path A (no VPN) — "RTMP Direct" analogue |
| mqvpn-hybrid | tunnel, `[Hybrid] Tcp=stream`: TCP terminates at local lwIP, carried as QUIC STREAM over both paths |
| mqvpn-datagram | tunnel, `[Hybrid] Tcp=raw`: TCP packets as CONNECT-IP datagrams (internal comparison only) |

### Conditions

| cond | path A | path B | duration | story |
|---|---|---|---|---|
| R1 starvation (= SRT V1) | 6 mbit, 20 ms | 6 mbit, 20 ms | 60 s ×3 | either link alone < 8 Mbps |
| R2 burst loss (= SRT C3h shape) | 100 mbit, 50 ms, gemodel 4% 30% 80% 0.5% | 100 mbit, 50 ms | 60 s ×3 | cellular-style burst loss on A |
| R3 flap | 12 mbit, 10 ms | 12 mbit, 30 ms | 120 s ×3 | A hard-down (admin down + addr flush) at t=30, restored t=60 |

## 2. Tier-1 results (means over 3 reps; per-rep in `results_tier1.csv`)

### R1 starvation

| arm | disconnects | dead air s | max lag s (worst) | ingest Mbps |
|---|---|---|---|---|
| direct-a | 0.0 | 1.3 | 16.9 | 5.7 |
| mqvpn-datagram | 0.0 | 1.3 | 2.7 | 8.0 |
| mqvpn-hybrid | 0.0 | 0.0 | 0.9 | 7.8 |

direct is capped at the single link (5.7 of 8 Mbps) and falls ~17 s behind
live within 60 s. Both mqvpn arms aggregate the two 6 mbit links and carry
the full rate; hybrid holds lag under 1 s.

### R2 burst loss — the lane-comparison headline

| arm | disconnects | dead air s | max lag s (worst) | ingest Mbps |
|---|---|---|---|---|
| direct-a | 4.0 | 43.7 | 43.0 | 0.9 |
| mqvpn-datagram | 0.0 | 14.3 | 55.6 | 5.3 |
| mqvpn-hybrid | 0.0 | 1.0 | 1.0 | 7.9 |

- direct: bursty loss stalls naked TCP into watchdog kills — effectively
  unusable (0.9 Mbps delivered, 44 s dead air of 60 s).
- datagram lane: the inner TCP never disconnects (QUIC keeps the tunnel
  up) but takes the loss directly; per-rep variance is extreme
  (dead air 34.3 / 7.7 / 1.0 s across reps) — the outcome depends on how
  the single pinned flow interacts with the lossy path.
- hybrid lane: QUIC repairs loss per-path below the inner TCP; all three
  reps identical (1 s lag; the 1.0 s dead air is the t=0 start-up gap —
  under the loss itself, arrival never paused > ~0.5 s). **This is the
  data behind "route TCP workloads through the stream lane".**

### R3 flap

| arm | disconnects | dead air s | TTR s | ingest Mbps |
|---|---|---|---|---|
| direct-a | 8.7 | 33.9 | 30.6 | 8.0 |
| mqvpn-datagram | 0.0 | 1.3 | — | 8.1 |
| mqvpn-hybrid | 0.0 | 1.0 | — | 8.1 |

direct: the encoder's TCP dies with the link; reconnects fail until the
link returns (dead air ≈ flap window + watchdog). Both mqvpn arms survive
with zero disconnects — QUIC multipath absorbs the path loss and the
inner TCP never resets. The 1.0–1.3 s mqvpn dead-air figures are NOT a
failover blip: verified from `flv_samples.csv` (all reps), that window
sits at t=0 (the universal encoder start-up gap, FLV header → first media
chunk ≈ 1 s), and around the flap itself byte arrival never paused beyond
one 250 ms sampling interval. The failover is invisible at the
measurement's resolution.

TTR semantics caveat: the analyzer's raw `ttr_s` (30.4–30.7 s here) is
measured from flap-DOWN to the end of the containing no-growth window,
and that window is truncated early by the close-flush artifact (finding
2) — it is NOT "time from link recovery". From `flv_samples.csv`
directly: direct's stream returns 2.2–4.0 s after link restore, and the
total mid-stream outage is 31.5–33.8 s = the 30 s cut + that reconnect
overhead. Highly reproducible across reps.

Lag timelines: `charts/lag_R2_rep1.png`, `charts/lag_R3_rep1.png`.

## 3. Tier-2 (real video, BBB clip 8 Mbps + silent AAC)

| cond | arm | sessions | dead air s | freeze s | artifact |
|---|---|---|---|---|---|
| R1 | direct-a | 1 | 1.8 | 0.0 | `video/r1_starved_direct_vs_mqvpn.mp4` |
| R1 | mqvpn-hybrid | 1 | 1.5 | 0.0 | (same side-by-side) |
| R3 | direct-a | 9 | 34.3 | 32.8 | `video/r3_flap_direct_vs_mqvpn.mp4` |
| R3 | mqvpn-hybrid | 1 | 1.3 | 0.0 | (same side-by-side) |

The tracked `video/` files are 540 kbps two-pass web re-encodes of the
side-by-sides (kept under GitHub's upload limits; also uploaded as
user-attachments for README/website embeds). The full-rate originals are
the `R{1,3}_sbs.mp4` outputs of a tier-2 run.

The R3 side-by-side shows direct on a 32.8 s "signal lost (reconnecting)"
slate while mqvpn keeps playing. Slate length (32.8 s) is consistent with
the measured dead air (34.3 s; ~1 s sampler/buffer jitter). freeze_s counts
the slate by design — a viewer experiences dead air as a freeze.

## 4. Operational findings (worth knowing before re-running)

1. **QUIC handshake over the lossy R2 path fails probabilistically** (also
   seen in the SRT bench). One tier-1 cell hit "tunnel not established";
   the resume mechanism (`RTMP_BENCH_OUT=<same dir>`) retried just that
   cell. Expect occasional single-cell retries in R2.
2. **nginx record flushes its buffer when the session closes**, and a
   publisher stuck behind a downed link only closes at link restore — so
   "last byte growth" of an FLV can land ~30 s after its media actually
   stopped. Timeline gaps are therefore anchored to
   `first_growth + ffprobe media duration` (see `compute_gaps`).
3. **A reconnect attempt racing link-restore can leave a 0-byte stub FLV**
   (nginx opens the record file at publish start, then rejects the
   publisher because the previous session still lingers). Stubs are
   filtered by size (< 4 KB) before session pairing; growth-sample
   ownership is NOT a reliable filter (the previous session's close-flush
   can be attributed to the stub by the mtime-based sampler).
4. nginx workers must run as root in this harness (`user root;` in the
   generated conf): the default unprivileged worker cannot traverse
   0750 `/home/<user>` to the DVR dir. Bench-netns-only configuration.
5. Tier 2 needs the audio-bearing clip variant
   (`tools/clips-rtmp/clip_8m.mp4`, silent AAC track added); the SRT
   clips have no audio and are rejected by preflight.
6. The dead-air metric includes a universal ~1 s start-up gap (FLV header
   lands at publish start, first media chunk ≈ 1 s later; counted because
   measurement starts at the first ingest byte). Read small per-arm
   dead-air values against that floor before attributing them to
   loss/failover — locate the windows in `flv_samples.csv` when in doubt.

## 5. Reproduction

```bash
# image: mqvpn-e2e:deps + nginx + libnginx-mod-rtmp + fonts-dejavu-core
docker run --privileged --rm -v "$WS:$WS" -w "$WS/mqvpn" mqvpn-rtmp-bench:local \
  bash -c 'export PATH=<BtbN-ffmpeg-bin>:$PATH; \
    RTMP_BENCH_CHOWN=1000:1000 RTMP_BENCH_OUT=bench_results/rtmp/tier1_<date> \
    ./scripts/benchmark_rtmp.sh <mqvpn-binary>'
# tier 2: benchmark_rtmp_video.sh + RTMP_BENCH_CLIP_DIR=<clips-rtmp dir>
# host (no docker): sudo env PATH=... ./scripts/benchmark_rtmp.sh <binary>
```

Raw per-cell artifacts (events, lag/ingest timelines, logs) for the runs
behind this report: `raw.zip`. Full DVR/timeline video intermediates are
transient and not archived.

## 6. Follow-ups

- R4 jitter condition: deferred — R1–R3 already differentiate the arms
  decisively; add only if the publication draft needs a jitter story.
- Publication subset: direct-a vs mqvpn-hybrid tables, one lag chart
  (R3), the R3 side-by-side video, LiveU RTMP-Direct citation framing
  (documented claim only, no measured comparison).
