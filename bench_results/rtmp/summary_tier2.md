# RTMP bench — tier 2 (real video) summary

- date: 2026-08-09 17:34  kernel: 7.0.0-28-generic
- ffmpeg: ffmpeg version N-125856-g2ae2413488-20260730 Copyright (c) 2000-2026 the FFmpeg developers
- clip: clip_8m.mp4 (/home/nori/workspace/oss-speedify-proj/tools/clips-rtmp), sha256=9596913103227b4f

## R1

| arm | sessions | dead_air_s | freeze_s | timeline | sbs |
|---|---|---|---|---|---|
| direct-a | 1 | 1.8 | 0.0 | bench_results/rtmp/tier2_full_20260810/R1_direct-a/timeline.mp4 | bench_results/rtmp/tier2_full_20260810/R1_sbs.mp4 |
| mqvpn-hybrid | 1 | 1.5 | 0.0 | bench_results/rtmp/tier2_full_20260810/R1_mqvpn-hybrid/timeline.mp4 | bench_results/rtmp/tier2_full_20260810/R1_sbs.mp4 |

## R3

| arm | sessions | dead_air_s | freeze_s | timeline | sbs |
|---|---|---|---|---|---|
| direct-a | 9 | 34.3 | 32.8 | bench_results/rtmp/tier2_full_20260810/R3_direct-a/timeline.mp4 | bench_results/rtmp/tier2_full_20260810/R3_sbs.mp4 |
| mqvpn-hybrid | 1 | 1.3 | 0.0 | bench_results/rtmp/tier2_full_20260810/R3_mqvpn-hybrid/timeline.mp4 | bench_results/rtmp/tier2_full_20260810/R3_sbs.mp4 |

