# SRT real-video quality — tier 2 data (data appendix; see ../REPORT.md)

- date: 2026-08-02  kernel: 7.0.0-28-generic
- clips: 60 s excerpts of Big Buck Bunny, © 2008 Blender Foundation /
  bigbuckbunny.org, licensed CC-BY 3.0
  (https://creativecommons.org/licenses/by/3.0/), re-encoded 1080p30 H.264
  CBR at each condition's stream rate. The comparison videos in this
  directory are derivatives of that work.
  - V1: clip_8m.mp4 (sha256 prefix a310255cd0c1e8d4)
  - C3/C3h: clip_25m.mp4 (fbc2b3b9294e2184)
  - C5: clip_42m.mp4 (069b11691e15268c)
- ffmpeg: N-125856-g2ae2413488-20260730
- mqvpn: wlb scheduler, reorder shim off, cc bbr2 (defaults)
- SRT receiver: lossmaxttl=32; latency V1 150 ms / C3, C3h 120 ms / C5 250 ms
- SRT sender: ffmpeg -re-paced mpegts, libsrt default bandwidth control
  (no maxbw/inputbw/oheadbw caps — see REPORT §5 note on bursty sources)
- C3 gemodel: loss gemodel 2% 40% 70% 0.1%; C3h: 4% 30% 80% 0.5%

| run | VMAF (mean) | decoder error log lines | freeze (s) |
|---|---|---|---|
| V1_direct-A | 8.620761 | 681 | 1.2 |
| V1_mqvpn-2path | 87.728861 | 74 | 0.0 |
| C3_direct-A | 61.148358 | 189 | 3.1 |
| C3_mqvpn-2path | 92.022417 | 95 | 3.8 |
| C3h_direct-A | 24.635755 | 545 | 1.6 |
| C3h_mqvpn-2path | 89.078992 | 103 | 2.6 |
| C5_direct-A | 12.387464 | 615 | 5.0 |
| C5_mqvpn-2path | 56.537275 | 293 | 4.4 |

Artifacts in this directory (20 s side-by-side, direct | bonded):

- `v1_starved_uplinks_direct_vs_mqvpn.mp4` — V1 starved uplinks
- `c3_burstloss_direct_vs_mqvpn.mp4` — C3 burst loss (≈5%)
- `c3h_burstloss_direct_vs_mqvpn.mp4` — C3h burst loss (≈10%)
- `c5_cellular_direct_vs_mqvpn.mp4` — C5 dual-cellular (hard mode; see
  REPORT §3)
