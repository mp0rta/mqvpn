#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
"""sweep_reorder_analyze.py — Pareto-frontier analysis of the reorder sweep CSV.

Reads the CSV emitted by benchmarks/sweep_reorder.sh and produces a Markdown
report: per-environment Pareto frontier of (goodput MAXIMIZE, p99 added-latency
MINIMIZE), a recommended-default mark per environment, and an "optimal
max_wait_ms vs RTT spread" sensitivity table built from the rtt_* environments.

This is a THROWAWAY analysis helper (Python 3 stdlib only — no pandas/numpy) for
a solo dev. It is NOT production code and carries no separate test file; instead
it carries inline self-asserts (run on every invocation, see __main__) on the
Pareto logic — the one place where a silent sign-flip would yield a
plausible-but-wrong optimal table.

Input CSV schema (header row present):
  timestamp,env_name,axis,max_wait_ms,cap_pkts,repeat,goodput_mbps,added_p99_ms,
  added_max_ms,added_buffered_p99_ms,gap_count,gap_filled,gap_timeout,
  gap_overflow,delivered,picoquic_pin

Rows whose goodput_mbps is the literal "NA" (or otherwise non-numeric) are
DROPPED before analysis — never coerced to 0. An environment with no
numeric-goodput rows is reported as "(no goodput data yet — NA)".

Usage:
  python3 benchmarks/sweep_reorder_analyze.py --csv <path> [--out <md path>]
"""

import argparse
import csv
import os
import statistics
import sys
from collections import defaultdict


# ─── RTT-spread map ──────────────────────────────────────────────────────────
# rtt_spread_ms(env) = |pathB_delay - pathA_delay| in ms, mirroring the sweep
# driver's ENV_NETEM (benchmarks/sweep_reorder.sh). Envs absent from this map
# have an unknown spread and get no recommended-default mark.
RTT_SPREAD_MS = {
    "baseline": 0,
    "rtt_40": 20,       # 40 - 20
    "rtt_70": 50,       # 70 - 20
    "rtt_120": 100,     # 120 - 20
    "rtt_320": 300,     # 320 - 20
    "dual_lte": 15,     # 45 - 30
    "fiber_lte": 32,    # 40 - 8
    "lte_starlink": 15,  # 50 - 35
    "lte_geo": 285,     # 320 - 35
    "congested": 10,    # 60 - 50
    # jitter/loss/bw axes share equal path delays → spread 0.
    "jit_5": 0,
    "jit_20": 0,
    "loss_05": 0,
    "loss_2": 0,
    "bw_4to1": 0,
    "bw_10to1": 0,
}


def rtt_spread_ms(env):
    """|pathB_delay - pathA_delay| in ms, or None if the env is unknown."""
    return RTT_SPREAD_MS.get(env)


# ─── CSV ingest ──────────────────────────────────────────────────────────────
def _to_float(value):
    """Parse a float, or return None for NA / blank / non-numeric."""
    if value is None:
        return None
    s = value.strip()
    if s == "" or s.upper() == "NA":
        return None
    try:
        return float(s)
    except ValueError:
        return None


def read_rows(csv_path):
    """Read the sweep CSV. Returns (rows, all_envs).

    rows: list of dicts with NUMERIC goodput only (NA / non-numeric dropped).
    all_envs: the set of env_name values seen in the file (including all-NA
              envs), so the report can still list an env with no goodput data.
    """
    rows = []
    all_envs = set()
    with open(csv_path, newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None or "env_name" not in reader.fieldnames:
            raise ValueError(
                "CSV missing header / 'env_name' column (got: %r)"
                % (reader.fieldnames,)
            )
        for raw in reader:
            env = (raw.get("env_name") or "").strip()
            if not env:
                continue
            all_envs.add(env)
            goodput = _to_float(raw.get("goodput_mbps"))
            if goodput is None:
                continue  # drop NA / non-numeric — never coerce to 0
            p99 = _to_float(raw.get("added_p99_ms"))
            if p99 is None:
                continue  # a row without a usable p99 can't sit on the frontier
            rows.append({
                "env_name": env,
                "max_wait_ms": (raw.get("max_wait_ms") or "").strip(),
                "cap_pkts": (raw.get("cap_pkts") or "").strip(),
                "goodput_mbps": goodput,
                "added_p99_ms": p99,
                "added_buffered_p99_ms": _to_float(raw.get("added_buffered_p99_ms")),
                "gap_count": _to_float(raw.get("gap_count")),
                "gap_filled": _to_float(raw.get("gap_filled")),
                "gap_timeout": _to_float(raw.get("gap_timeout")),
                "gap_overflow": _to_float(raw.get("gap_overflow")),
            })
    return rows, all_envs


# ─── Aggregation ─────────────────────────────────────────────────────────────
def _median_or_none(values):
    vals = [v for v in values if v is not None]
    return statistics.median(vals) if vals else None


def aggregate_median(rows):
    """Group by (env_name, max_wait_ms, cap_pkts); take medians across repeats.

    Returns a list of point dicts, each carrying env/wait/cap plus the median
    goodput, p99, buffered_p99 and gap_* counters.
    """
    groups = defaultdict(list)
    for r in rows:
        key = (r["env_name"], r["max_wait_ms"], r["cap_pkts"])
        groups[key].append(r)

    points = []
    for (env, wait, cap), grp in groups.items():
        points.append({
            "env_name": env,
            "max_wait_ms": wait,
            "cap_pkts": cap,
            "goodput": _median_or_none([g["goodput_mbps"] for g in grp]),
            "p99": _median_or_none([g["added_p99_ms"] for g in grp]),
            "buffered_p99": _median_or_none([g["added_buffered_p99_ms"] for g in grp]),
            "gap_count": _median_or_none([g["gap_count"] for g in grp]),
            "gap_filled": _median_or_none([g["gap_filled"] for g in grp]),
            "gap_timeout": _median_or_none([g["gap_timeout"] for g in grp]),
            "gap_overflow": _median_or_none([g["gap_overflow"] for g in grp]),
            "repeats": len(grp),
        })
    return points


# ─── Pareto frontier ─────────────────────────────────────────────────────────
def _score(point):
    """Project a point onto its (goodput, p99) score tuple.

    Accepts either a bare (goodput, p99) tuple (used by the self-asserts) or a
    point dict with 'goodput' / 'p99' keys. Keeping a tuple-accepting form lets
    the dominance DIRECTION be pinned by plain-tuple asserts in __main__.
    """
    if isinstance(point, tuple):
        return point[0], point[1]
    return point["goodput"], point["p99"]


def _dominates(a, b):
    """True if a dominates b: goodput >= AND p99 <= with at least one strict.

    goodput is MAXIMIZED, p99 is MINIMIZED.
    """
    ga, pa = _score(a)
    gb, pb = _score(b)
    not_worse = (ga >= gb) and (pa <= pb)
    strictly_better = (ga > gb) or (pa < pb)
    return not_worse and strictly_better


def pareto_frontier(points):
    """Return the non-dominated subset of `points` (a set).

    Each point is scored on (goodput MAXIMIZE, p99 MINIMIZE). Works on bare
    (goodput, p99) tuples (returns a set of tuples) or on point dicts (returns a
    set of indices into the input, since dicts are unhashable).
    """
    items = list(points)
    if not items:
        return set()

    if all(isinstance(it, tuple) for it in items):
        # Tuple form: return the surviving tuples directly (hashable).
        survivors = set()
        for cand in items:
            if not any(_dominates(other, cand) for other in items if other != cand):
                survivors.add(cand)
        return survivors

    # Dict form: dicts aren't hashable, so return the set of surviving indices.
    survivor_idx = set()
    for i, cand in enumerate(items):
        dominated = False
        for j, other in enumerate(items):
            if i != j and _dominates(other, cand):
                dominated = True
                break
        if not dominated:
            survivor_idx.add(i)
    return survivor_idx


def frontier_points(points):
    """Convenience: the surviving point dicts (not indices), sorted by goodput desc."""
    idx = pareto_frontier(points)
    survivors = [points[i] for i in idx]
    survivors.sort(key=lambda p: (-p["goodput"], p["p99"]))
    return survivors


# ─── Report ──────────────────────────────────────────────────────────────────
def _fmt(x, nd=3):
    return "—" if x is None else f"{x:.{nd}f}"


def recommended_default(frontier, env):
    """Pick the recommended-default frontier point for `env`.

    Among frontier points with added_p99_ms <= 0.5 * rtt_spread_ms(env), choose
    the max-goodput one. Returns (point|None, note_str).
    """
    spread = rtt_spread_ms(env)
    if spread is None:
        return None, "rtt spread unknown — no recommended mark"
    threshold = 0.5 * spread
    eligible = [p for p in frontier if p["p99"] <= threshold]
    if eligible:
        best = max(eligible, key=lambda p: p["goodput"])
        return best, f"p99 <= 0.5*spread ({threshold:.1f} ms)"
    # No frontier point under the threshold — report the lowest-p99 one instead.
    if frontier:
        lowest = min(frontier, key=lambda p: p["p99"])
        note = (
            f"no point under p99<=0.5*spread ({threshold:.1f} ms); "
            f"lowest-p99 frontier point = wait={lowest['max_wait_ms']}ms "
            f"cap={lowest['cap_pkts']} (p99={_fmt(lowest['p99'])} ms, "
            f"goodput={_fmt(lowest['goodput'])} Mbps)"
        )
        return None, note
    return None, "empty frontier"


def build_report(rows, all_envs):
    """Build (markdown_text, frontier_tsv_text, summary_str)."""
    points = aggregate_median(rows)

    # Group aggregated points by env.
    by_env = defaultdict(list)
    for p in points:
        by_env[p["env_name"]].append(p)

    md = []
    md.append("# Reorder sweep — Pareto-optimal analysis")
    md.append("")
    md.append("Per environment: non-dominated (goodput MAXIMIZE, p99 added-latency "
              "MINIMIZE) frontier over median-of-repeats points, plus a "
              "recommended default (max goodput among frontier points with "
              "`added_p99_ms <= 0.5 * rtt_spread_ms`).")
    md.append("")

    tsv = ["env_name\tmax_wait_ms\tcap_pkts\tgoodput_mbps\tadded_p99_ms\trecommended"]

    rtt_sensitivity = []  # (env, spread, best_wait) rows for rtt_* envs
    recommended_count = 0

    for env in sorted(all_envs):
        md.append(f"## `{env}`")
        spread = rtt_spread_ms(env)
        spread_str = "unknown" if spread is None else f"{spread} ms"
        md.append(f"- rtt spread: {spread_str}")

        env_points = by_env.get(env, [])
        if not env_points:
            md.append("- (no goodput data yet — NA)")
            md.append("")
            continue

        frontier = frontier_points(env_points)
        rec, rec_note = recommended_default(frontier, env)
        if rec is not None:
            recommended_count += 1

        md.append(f"- {len(env_points)} cell(s); {len(frontier)} on frontier")
        md.append("")
        md.append("| wait (ms) | cap | goodput (Mbps) | p99 (ms) | buffered p99 (ms) | rec |")
        md.append("|---:|---:|---:|---:|---:|:--:|")
        for p in frontier:
            is_rec = rec is not None and p is rec
            mark = "**<-**" if is_rec else ""
            md.append(
                f"| {p['max_wait_ms']} | {p['cap_pkts']} | "
                f"{_fmt(p['goodput'])} | {_fmt(p['p99'])} | "
                f"{_fmt(p['buffered_p99'])} | {mark} |"
            )
            tsv.append(
                f"{env}\t{p['max_wait_ms']}\t{p['cap_pkts']}\t"
                f"{_fmt(p['goodput'])}\t{_fmt(p['p99'])}\t{'1' if is_rec else '0'}"
            )
        md.append("")
        md.append(f"- recommended default: {rec_note}")
        if rec is not None:
            md.append(
                f"  -> **wait={rec['max_wait_ms']}ms cap={rec['cap_pkts']}** "
                f"(goodput={_fmt(rec['goodput'])} Mbps, p99={_fmt(rec['p99'])} ms)"
            )
        md.append("")

        # Collect rtt_* sensitivity: best wait = recommended, else max-goodput frontier point.
        if env.startswith("rtt_") or env == "baseline":
            best = rec
            if best is None and frontier:
                best = max(frontier, key=lambda p: p["goodput"])
            if best is not None and spread is not None:
                rtt_sensitivity.append((env, spread, best["max_wait_ms"], best["goodput"]))

    # ── Sensitivity section ──────────────────────────────────────────────────
    md.append("## Optimal `max_wait_ms` vs RTT spread (rtt_* axis)")
    md.append("")
    if rtt_sensitivity:
        md.append("| env | rtt spread (ms) | best wait (ms) | goodput (Mbps) |")
        md.append("|:--|---:|---:|---:|")
        rtt_sensitivity.sort(key=lambda t: t[1])
        for env, spread, wait, gp in rtt_sensitivity:
            md.append(f"| {env} | {spread} | {wait} | {_fmt(gp)} |")
    else:
        md.append("(no rtt_* environments with numeric goodput in this CSV)")
    md.append("")

    summary = (
        f"{len(all_envs)} env(s); "
        f"{sum(1 for e in all_envs if by_env.get(e))} with goodput data; "
        f"{recommended_count} env(s) got a recommended default."
    )
    return "\n".join(md) + "\n", "\n".join(tsv) + "\n", summary


# ─── CLI ─────────────────────────────────────────────────────────────────────
def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sweep_reorder_analyze.py",
        description="Pareto-frontier analysis of the reorder sweep CSV.",
    )
    parser.add_argument("--csv", required=True, help="input sweep CSV path")
    parser.add_argument(
        "--out",
        default="ci_sweep_results/reorder_optimal.md",
        help="output Markdown path (default: ci_sweep_results/reorder_optimal.md)",
    )
    args = parser.parse_args(argv)

    if not os.path.exists(args.csv):
        parser.error(f"CSV not found: {args.csv}")

    try:
        rows, all_envs = read_rows(args.csv)
    except (ValueError, OSError) as exc:
        parser.error(f"failed to read CSV: {exc}")

    md_text, tsv_text, summary = build_report(rows, all_envs)

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w") as fh:
        fh.write(md_text)

    # Emit the frontier TSV next to the md for later plotting (cheap, optional).
    tsv_path = os.path.splitext(args.out)[0] + "_frontier.tsv"
    with open(tsv_path, "w") as fh:
        fh.write(tsv_text)

    print(f"[sweep_reorder_analyze] {summary}")
    print(f"[sweep_reorder_analyze] wrote {args.out} (+ {tsv_path})")
    return 0


# ─── Inline self-asserts (REQUIRED — restore the de-risk of the cut unit test) ─
# These run on EVERY invocation and fail loudly if a Pareto comparison is
# flipped. Tuples are (goodput, p99): high goodput + low p99 wins.
assert pareto_frontier([(10, 5), (10, 9), (8, 5)]) == {(10, 5)}   # (10,9),(8,5) dominated
assert pareto_frontier([(10, 5), (8, 3)]) == {(10, 5), (8, 3)}    # trade-off: both survive
assert pareto_frontier([]) == set()                               # empty in -> empty out


if __name__ == "__main__":
    sys.exit(main())
