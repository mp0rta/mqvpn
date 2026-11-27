# SRT redundant-mode baseline: Reinjection = dgram (2026-10-12)

- Binary: mqvpn `ecda0c0f` (current main at the time), the last build that still had `Reinjection = dgram`. `summary.md` shows `mqvpn: 50c9b74a`: that is `ecda0c0f` plus bench-script-only commits, so the binary's C code is `ecda0c0f`.
- Arms: `mq-wlb-off`, `mq-wlb-dgram`, `mq-minrtt-dgram` (client-side setting only, server scheduler wlb).
- Conditions: R1-R4 at 10 Mbps SRT, 60 s per run, 3 runs per arm (one `mq-minrtt-dgram` R3 run failed, no CSV).
- `dgram` was removed after this run; these results are the baseline for the `redundant` arms.
- The redundant-mode runs sit next to this directory under `bench_results/srt_redundant/`.
