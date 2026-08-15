#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
"""RTMP bench analyzer.

Subcommands:
  cell      — one cell dir -> one CSV row on stdout (called by benchmark_rtmp.sh)
  summarize — tier-1 results.csv -> markdown tables on stdout
  chart     — lag timeline PNG for one or more cells (matplotlib)

Metric definitions live here and only here:
  dead_air_s : total seconds inside windows > 1.0 s where total_bytes in
               flv_samples.csv does not increase, measured from first ingest
               byte to scenario end (a stream that never connects is 100%
               dead air).
  max_gap_s  : longest single such window.
  ttr_s      : flap-down timestamp -> end of the dead-air window containing
               (or starting after) it; NA when no flap or no dead air.
  disconnects: number of DISTINCT publish sessions that ended involuntarily —
               a session counts once if it has a stall-kill event OR an exit
               event at wallclock < scenario end - 1 s (events carry
               session=N; dedup by session id, so a stall-kill followed by
               its own exit is one disconnect).
  max_lag_s  : max over sessions of (ts - session_ts0) - (out_time -
               out_time_at_first_advancing_sample), per lag.N.csv.
  ingest_mbps: (last total_bytes - first total_bytes) * 8 / active_seconds
               / 1e6, where active_seconds excludes dead-air windows.

Lag is PER PUBLISH SESSION: each ffmpeg restart resets out_time to 0, so lag
is computed against each session's own first advancing sample and never
stitched across sessions; charts show a gap during dead air.
"""
import argparse, csv, os

DEAD_AIR_THRESHOLD_S = 1.0

def read_flv_samples(path):
    rows = []
    with open(path) as f:
        for r in csv.DictReader(f):
            try:
                rows.append((float(r["ts"]), int(r["total_bytes"])))
            except (KeyError, ValueError):
                continue
    return rows

def dead_air_windows(samples, t_end):
    """[(start, end)] windows > threshold with no byte growth, from first
    ingest byte (or scenario start if none) to t_end."""
    if not samples:
        return []
    first_byte_ts = next((ts for ts, b in samples if b > 0), None)
    if first_byte_ts is None:
        return [(samples[0][0], t_end)]
    wins, last_growth, prev_bytes = [], first_byte_ts, 0
    for ts, b in samples:
        if ts < first_byte_ts:
            continue
        if b > prev_bytes:
            if ts - last_growth > DEAD_AIR_THRESHOLD_S:
                wins.append((last_growth, ts))
            last_growth, prev_bytes = ts, b
    if t_end - last_growth > DEAD_AIR_THRESHOLD_S:
        wins.append((last_growth, t_end))
    return wins

def read_events(path):
    # Strictness is intentional: writers (run_publisher / schedule_flap)
    # complete before analysis runs, so a missing/short line here means
    # corrupted artifacts, not a race — fail loudly rather than guess.
    evs = []
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    evs.append((float(parts[0]), parts[1], parts[2:]))
    return evs

def session_of(args):
    for a in args:
        if a.startswith("session="):
            try:
                return int(a.split("=", 1)[1])
            except ValueError:
                return None
    return None

def session_lags(cell):
    """{session: [(ts, lag_s)]} lag vs the session's own start."""
    out = {}
    n = 1
    while os.path.exists(os.path.join(cell, f"lag.{n}.csv")):
        rows = []
        with open(os.path.join(cell, f"lag.{n}.csv")) as f:
            for r in csv.DictReader(f):
                try:
                    rows.append((float(r["ts"]), int(r["out_time_us"]) / 1e6))
                except (KeyError, ValueError):
                    continue
        started = [(ts, ot) for ts, ot in rows if ot > 0]
        if started:
            ts0, ot0 = started[0]
            out[n] = [(ts, (ts - ts0) - (ot - ot0)) for ts, ot in started]
        n += 1
    return out

def analyze_cell(cell, duration):
    evs = read_events(os.path.join(cell, "publisher.events"))
    if not evs:
        raise SystemExit(f"no publisher events in {cell}")
    t_start = evs[0][0]
    t_end = t_start + duration
    samples = read_flv_samples(os.path.join(cell, "flv_samples.csv"))
    # clamp: sampler overshoots scenario end by poll granularity; post-end
    # DVR flush bytes must not count
    samples = [s for s in samples if s[0] <= t_end]
    wins = dead_air_windows(samples, t_end)
    dead = sum(e - s for s, e in wins)
    max_gap = max((e - s for s, e in wins), default=0.0)
    sessions = sum(1 for _, k, _a in evs if k == "connect")
    # disconnects: distinct sessions ended involuntarily (dedup by session
    # id — a stall-kill is followed by its own exit event for the same N)
    bad_sessions = set()
    for ts, k, args in evs:
        sess = session_of(args)
        if sess is None:
            continue
        if k == "stall-kill" or (k == "exit" and ts < t_end - 1.0):
            bad_sessions.add(sess)
    disconnects = len(bad_sessions)
    flap = read_events(os.path.join(cell, "flap.log"))
    down = next((ts for ts, k, _a in flap if k == "flap-down"), None)
    ttr = "NA"
    if down is not None:
        for s, e in wins:
            if s <= down <= e or s >= down:
                ttr = f"{e - down:.1f}"
                break
    lags = session_lags(cell)
    max_lag = max((l for sess in lags.values() for _, l in sess), default=0.0)
    total_bytes = (samples[-1][1] - samples[0][1]) if samples else 0
    active = max(duration - dead, 0.001)
    mbps = total_bytes * 8 / active / 1e6
    return dict(sessions=sessions, disconnects=disconnects,
                dead_air_s=f"{dead:.1f}", max_gap_s=f"{max_gap:.1f}",
                ttr_s=ttr, max_lag_s=f"{max_lag:.1f}", ingest_mbps=f"{mbps:.2f}")

def cmd_cell(a):
    m = analyze_cell(a.cell_dir, a.duration)
    print(",".join([a.cond, a.arm, str(a.rep), str(m["sessions"]),
                    str(m["disconnects"]), m["dead_air_s"], m["max_gap_s"],
                    m["ttr_s"], m["max_lag_s"], m["ingest_mbps"]]))

def cmd_summarize(a):
    with open(a.csv) as f:
        rows = list(csv.DictReader(f))
    conds = sorted({r["cond"] for r in rows})
    print("# RTMP bench — tier 1 summary\n")
    for cond in conds:
        print(f"## {cond}\n")
        print("| arm | disconnects (mean) | dead air s (mean) | max gap s (worst) | TTR s (mean) | max lag s (worst) | ingest Mbps (mean) |")
        print("|---|---|---|---|---|---|---|")
        arms = sorted({r["arm"] for r in rows if r["cond"] == cond})
        for arm in arms:
            g = [r for r in rows if r["cond"] == cond and r["arm"] == arm]
            def mean(k):
                vs = [float(r.get(k)) for r in g if r.get(k) not in (None, "NA", "")]
                return f"{sum(vs)/len(vs):.1f}" if vs else "NA"
            def worst(k):
                vs = [float(r.get(k)) for r in g if r.get(k) not in (None, "NA", "")]
                return f"{max(vs):.1f}" if vs else "NA"
            print(f"| {arm} | {mean('disconnects')} | {mean('dead_air_s')} | "
                  f"{worst('max_gap_s')} | {mean('ttr_s')} | {worst('max_lag_s')} | {mean('ingest_mbps')} |")
        print()

def cmd_chart(a):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(10, 4))
    down_xs, up_xs = [], []
    for cell in a.cell_dirs:
        label = os.path.basename(cell.rstrip("/"))
        lags = session_lags(cell)
        # x-axis origin = when the publisher first attempted to connect
        # (cell start, matching the condition's flap schedule), not the
        # first media sample — otherwise the ~1 s encoder start-up shifts
        # every event left on the chart
        evs = read_events(os.path.join(cell, "publisher.events"))
        t0 = next((ts for ts, k, _a in evs if k == "connect"), None)
        color = None
        for sess in sorted(lags):
            pts = lags[sess]
            if t0 is None and pts:
                t0 = pts[0][0]
            xs = [ts - t0 for ts, _ in pts]
            ys = [l for _, l in pts]
            line, = ax.plot(xs, ys, color=color, label=label if color is None else None)
            color = line.get_color()
        # flap markers (cells share the schedule; dedup below by rounding)
        if t0 is not None:
            for ts, k, _a in read_events(os.path.join(cell, "flap.log")):
                if k == "flap-down":
                    down_xs.append(ts - t0)
                elif k == "flap-up":
                    up_xs.append(ts - t0)
    def cluster(vals, eps=2.0):
        # cells align to their own t0, so the shared flap schedule lands at
        # slightly different relative times per cell; merge marks within eps
        out = []
        for v in sorted(vals):
            if out and v - out[-1][-1] <= eps:
                out[-1].append(v)
            else:
                out.append([v])
        return [sum(c) / len(c) for c in out]

    for i, x in enumerate(cluster(down_xs)):
        ax.axvline(x, color="tab:red", linestyle="--", alpha=0.8,
                   label="link down" if i == 0 else None)
    for i, x in enumerate(cluster(up_xs)):
        ax.axvline(x, color="tab:green", linestyle="--", alpha=0.8,
                   label="link restored" if i == 0 else None)
    ax.set_xlabel("time (s)"); ax.set_ylabel("live lag (s)")
    ax.legend(); ax.grid(True, alpha=0.3)
    fig.tight_layout(); fig.savefig(a.out, dpi=120)
    print(a.out)

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("cell"); c.add_argument("--cell-dir", required=True)
    c.add_argument("--cond", required=True); c.add_argument("--arm", required=True)
    c.add_argument("--rep", type=int, required=True)
    c.add_argument("--duration", type=float, required=True)
    c.set_defaults(fn=cmd_cell)
    s = sub.add_parser("summarize"); s.add_argument("--csv", required=True)
    s.set_defaults(fn=cmd_summarize)
    g = sub.add_parser("chart"); g.add_argument("--out", required=True)
    g.add_argument("cell_dirs", nargs="+")
    g.set_defaults(fn=cmd_chart)
    a = p.parse_args()
    a.fn(a)

if __name__ == "__main__":
    main()
