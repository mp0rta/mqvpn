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

With --off-csv (the CSV from `sweep_reorder.sh --reorder off`), the report also
appends a "reorder ON vs OFF" net-benefit table: per environment it compares the
median RAW-baseline (OFF) goodput against the recommended-default and max-goodput
ON configs, reporting Δ% and a NET-POSITIVE/NEGATIVE/NEUTRAL verdict. This is the
only direct test of whether the reorder buffer is worth its added latency in a
given environment.

With --single-csv (the CSV from `sweep_single_path.sh`) added, a 3-way
comparison table is also produced: OFF (multipath, reorder OFF) vs best-ON
(multipath + reorder, ceiling) vs best-single (max of leg A / leg B over the
SAME netem). The recommended config column picks the simplest option whose
median goodput is within 5% of the winner, with priority single > mp-OFF >
mp-ON. This is the answer to "should the user multipath at all in this env?"
that the ON-vs-OFF table cannot give.

Usage:
  python3 benchmarks/sweep_reorder_analyze.py --csv <path> [--off-csv <path>] \
      [--single-csv <path>] [--out <md path>]
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


KNEE_FRAC_DEFAULT = 0.90


def recommended_default(env_points, env, knee_frac=KNEE_FRAC_DEFAULT):
    """Pick the recommended-default (max_wait, cap) for `env` via the goodput knee.

    The shipping default is the CHEAPEST-LATENCY config that still reaches
    near-peak goodput: among all median-aggregated cells for the env, take the
    max median goodput G*, then choose the cell with the smallest max_wait_ms
    (tie-break smallest cap) whose goodput >= knee_frac * G*.

    This REPLACES the design's `added_p99_ms <= 0.5 * rtt_spread` rule, which
    systematically selected *collapsed* low-wait cells: when max_wait << RTT
    spread the buffer times out on every gap, delivers reordered, the inner QUIC
    reads the reordering as loss and goodput collapses to ~1 Mbps — yet that cell
    adds ~0 ms latency, so it sneaks under a latency-only gate and gets
    mislabelled "optimal". A goodput-anchored knee can never pick a collapsed
    cell, and (unlike the old rule) needs no rtt_spread, so it also works on the
    spread-0 jitter/loss/bw axes. Returns (point|None, note_str).
    """
    # Skip the OFF-baseline sentinel rows (max_wait_ms / cap_pkts == "off"): the
    # downstream tie-break does int(...) on those columns, so any non-numeric
    # value would raise ValueError mid-report. This catches both the legitimate
    # OFF sentinel and any other corruption that would crash the tie-break.
    def _intlike(s):
        if not isinstance(s, str):
            return False
        return s.lstrip("-").isdigit()
    usable = [p for p in env_points
              if p["goodput"] is not None
              and _intlike(p["max_wait_ms"]) and _intlike(p["cap_pkts"])]
    if not usable:
        return None, "no goodput data with numeric wait/cap"
    g_star = max(p["goodput"] for p in usable)
    if g_star <= 0:
        return None, "peak goodput non-positive"
    threshold = knee_frac * g_star
    eligible = [p for p in usable if p["goodput"] >= threshold]
    # Cheapest latency first: smallest wait, then smallest cap.
    best = min(eligible, key=lambda p: (int(p["max_wait_ms"]), int(p["cap_pkts"])))
    note = (
        f"knee = smallest wait reaching >={knee_frac:.0%} of peak goodput "
        f"(peak {g_star:.1f} Mbps; threshold {threshold:.1f} Mbps)"
    )
    return best, note


def build_report(rows, all_envs, knee_frac=KNEE_FRAC_DEFAULT, on_points=None):
    """Build (markdown_text, frontier_tsv_text, summary_str).

    `on_points` (optional) is the pre-aggregated `aggregate_median(rows)` result;
    when None, recomputed locally. Callers in main() pass it in so the three
    report sections share one aggregation pass (avoids both wasted work and any
    drift between independently-aggregated copies of the same input).
    """
    points = on_points if on_points is not None else aggregate_median(rows)

    # Group aggregated points by env.
    by_env = defaultdict(list)
    for p in points:
        by_env[p["env_name"]].append(p)

    md = []
    md.append("# Reorder sweep — Pareto-optimal analysis")
    md.append("")
    md.append("Per environment: non-dominated (goodput MAXIMIZE, p99 added-latency "
              "MINIMIZE) frontier over median-of-repeats points, plus a "
              "recommended default = the goodput **knee** (smallest `max_wait_ms`, "
              f"tie-break smallest cap, reaching >={knee_frac:.0%} of the env's "
              "peak goodput). The knee replaces the design's "
              "`added_p99_ms <= 0.5 * rtt_spread` rule, which selected collapsed "
              "low-wait cells (goodput ~1 Mbps but ~0 ms added latency).")
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
        rec, rec_note = recommended_default(env_points, env, knee_frac)
        if rec is not None:
            recommended_count += 1

        # rec is searched over ALL env_points (recommended_default), not just the
        # frontier — so the knee CAN be Pareto-dominated by another cell (a
        # higher-wait config can beat the knee on both goodput and p99). When
        # that happens, render the rec as a separate "off-frontier" row so the
        # table and TSV both surface it; otherwise the marker would only live
        # in the trailing prose and downstream consumers joining TSV
        # `recommended==1` to the table would lose the entry.
        rec_on_frontier = rec is not None and any(p is rec for p in frontier)
        md.append(f"- {len(env_points)} cell(s); {len(frontier)} on frontier"
                  + ("" if rec is None or rec_on_frontier
                     else " (rec is off-frontier — shown as extra row)"))
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
        if rec is not None and not rec_on_frontier:
            md.append(
                f"| {rec['max_wait_ms']} | {rec['cap_pkts']} | "
                f"{_fmt(rec['goodput'])} | {_fmt(rec['p99'])} | "
                f"{_fmt(rec['buffered_p99'])} | **<- (off-frontier)** |"
            )
            tsv.append(
                f"{env}\t{rec['max_wait_ms']}\t{rec['cap_pkts']}\t"
                f"{_fmt(rec['goodput'])}\t{_fmt(rec['p99'])}\t1"
            )
        md.append("")
        md.append(f"- recommended default: {rec_note}")
        if rec is not None:
            md.append(
                f"  -> **wait={rec['max_wait_ms']}ms cap={rec['cap_pkts']}** "
                f"(goodput={_fmt(rec['goodput'])} Mbps, p99={_fmt(rec['p99'])} ms)"
            )
        md.append("")

        # Collect rtt_* sensitivity: knee wait (recommended) AND goodput-max wait,
        # so the curve shows both the cheapest-sufficient and the peak config.
        if env.startswith("rtt_") or env == "baseline":
            usable = [p for p in env_points if p["goodput"] is not None]
            if usable and spread is not None:
                argmax = max(usable, key=lambda p: p["goodput"])
                knee_wait = rec["max_wait_ms"] if rec is not None else "—"
                knee_gp = rec["goodput"] if rec is not None else None
                rtt_sensitivity.append(
                    (env, spread, knee_wait, knee_gp,
                     argmax["max_wait_ms"], argmax["goodput"])
                )

    # ── Sensitivity section ──────────────────────────────────────────────────
    md.append("## Optimal `max_wait_ms` vs RTT spread (rtt_* axis)")
    md.append("")
    if rtt_sensitivity:
        md.append("Knee = cheapest-latency sufficient wait (recommended default); "
                  "peak = goodput-maximising wait (latency ignored). A knee that "
                  "tracks the spread confirms the core hypothesis; a knee that "
                  "stalls or a peak at the minimum wait flags the high-spread "
                  "regime where reorder stops helping.")
        md.append("")
        md.append("| env | rtt spread (ms) | knee wait (ms) | knee goodput (Mbps) "
                  "| peak wait (ms) | peak goodput (Mbps) |")
        md.append("|:--|---:|---:|---:|---:|---:|")
        rtt_sensitivity.sort(key=lambda t: t[1])
        for env, spread, kwait, kgp, pwait, pgp in rtt_sensitivity:
            md.append(f"| {env} | {spread} | {kwait} | {_fmt(kgp)} | "
                      f"{pwait} | {_fmt(pgp)} |")
    else:
        md.append("(no rtt_* environments with numeric goodput in this CSV)")
    md.append("")

    summary = (
        f"{len(all_envs)} env(s); "
        f"{sum(1 for e in all_envs if by_env.get(e))} with goodput data; "
        f"{recommended_count} env(s) got a recommended default."
    )
    return "\n".join(md) + "\n", "\n".join(tsv) + "\n", summary


# ─── reorder ON vs OFF (net-benefit) ─────────────────────────────────────────
def _pct_delta(on, off):
    """Δ% of an ON value relative to the OFF baseline: (on - off)/off * 100.

    Returns None when either side is missing or the baseline is non-positive
    (avoids a divide-by-zero / meaningless ratio against a collapsed OFF run).
    """
    if on is None or off is None or off <= 0:
        return None
    return (on - off) / off * 100.0


def build_off_comparison(rows_on, off_rows, knee_frac=KNEE_FRAC_DEFAULT,
                         on_points=None):
    """Build the 'reorder ON vs OFF' markdown section.

    Per env in BOTH the ON sweep and the OFF baseline: median OFF (RAW) goodput
    vs best-ON (max-goodput frontier point = the ceiling) and, as a
    latency-bounded caveat, the recommended-default ON config.

    The verdict keys off BEST-ON, not rec-ON: rec-ON is the goodput knee (a
    near-peak but cheaper-latency config), so it can sit a few % below the
    ceiling and should not by itself decide whether reorder helps. rec-ON stays
    in the table to show the shipping config's net effect and latency.
    """
    # Median OFF goodput per env (grouped on env_name only — the off/off
    # sentinel wait/cap are irrelevant under RAW pass-through).
    off_groups = defaultdict(list)
    for r in off_rows:
        off_groups[r["env_name"]].append(r["goodput_mbps"])
    off_gp = {env: statistics.median(gs) for env, gs in off_groups.items() if gs}

    if on_points is None:
        on_points = aggregate_median(rows_on)
    by_env = defaultdict(list)
    for p in on_points:
        by_env[p["env_name"]].append(p)

    md = ["## reorder ON vs OFF (net benefit)", ""]
    shared = sorted(e for e in off_gp if by_env.get(e))
    if not shared:
        md.append("(no environments present in BOTH the ON sweep and --off-csv)")
        md.append("")
        return "\n".join(md) + "\n"

    md.append(
        "Median goodput with reorder OFF (RAW pass-through) vs the best ON config "
        "(max-goodput frontier point) and the recommended-default ON config. "
        "`Δ% = (ON − OFF) / OFF`; positive ⇒ reorder helps. The verdict uses the "
        "best-ON Δ (NET-POSITIVE > +2%, NET-NEGATIVE < −2%, else NEUTRAL) — the "
        "ceiling reorder can reach here; `best-ON p99` is the latency cost of "
        "reaching it, and rec-ON is the latency-bounded shipping config."
    )
    md.append("")
    md.append("| env | rtt spread (ms) | OFF Mbps | best-ON Mbps | Δ best % | "
              "best-ON p99 (ms) | rec-ON Mbps | Δ rec % | verdict |")
    md.append("|:--|---:|---:|---:|---:|---:|---:|---:|:--|")
    for env in shared:
        off_g = off_gp[env]
        frontier = frontier_points(by_env[env])
        rec, _ = recommended_default(by_env[env], env, knee_frac)
        best_on = max(frontier, key=lambda p: p["goodput"]) if frontier else None
        best_g = best_on["goodput"] if best_on else None
        best_p99 = best_on["p99"] if best_on else None
        rec_g = rec["goodput"] if rec else None
        d_best = _pct_delta(best_g, off_g)
        d_rec = _pct_delta(rec_g, off_g)

        if d_best is None:
            verdict = "no data"
        elif d_best > 2.0:
            verdict = "NET-POSITIVE"
        elif d_best < -2.0:
            verdict = "NET-NEGATIVE"
        else:
            verdict = "NEUTRAL"
        # Flag the case where the ceiling helps but the latency-bounded shipping
        # config does not — reorder is a win only if you accept the added latency.
        if (d_best is not None and d_best > 2.0
                and d_rec is not None and d_rec < -2.0):
            verdict += " (rec only at latency cost)"

        spread = rtt_spread_ms(env)
        spread_str = "?" if spread is None else str(spread)
        md.append(
            f"| {env} | {spread_str} | {_fmt(off_g)} | {_fmt(best_g)} | "
            f"{_fmt(d_best, 1)} | {_fmt(best_p99)} | {_fmt(rec_g)} | "
            f"{_fmt(d_rec, 1)} | {verdict} |"
        )
    md.append("")
    md.append("- OFF goodput = median across `--off-csv` repeats (Enabled=off, RAW).")
    md.append("- best-ON = max-goodput frontier point (ceiling, latency ignored); "
              "rec-ON = recommended default = goodput knee (smallest wait, "
              f"tie-break smallest cap, reaching >={knee_frac:.0%} of peak goodput).")
    md.append("- Envs whose OFF baseline never completed the transfer (all-NA "
              "goodput, e.g. heavily congested/loss+jitter paths) are absent "
              "here: no OFF number to divide by — itself a sign reorder is "
              "needed, since RAW pass-through failed to deliver.")
    md.append("")
    return "\n".join(md) + "\n"


# ─── single-path CSV ingest & 3-way comparison ──────────────────────────────
def read_single_rows(csv_path):
    """Read the single-path baseline CSV (sweep_single_path.sh).

    Schema: timestamp,env_name,leg,repeat,goodput_mbps,picoquic_pin. Returns a
    list of dicts {env_name, leg, goodput_mbps} with NA / non-numeric goodput
    dropped (never coerced to 0). The leg field is normalised to upper-case so
    'a'/'A' don't fragment the per-env grouping.
    """
    out = []
    with open(csv_path, newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None or "env_name" not in reader.fieldnames \
                or "leg" not in reader.fieldnames:
            raise ValueError(
                "single-path CSV missing 'env_name' or 'leg' column (got: %r)"
                % (reader.fieldnames,)
            )
        for raw in reader:
            env = (raw.get("env_name") or "").strip()
            leg = (raw.get("leg") or "").strip().upper()
            if not env or leg not in ("A", "B"):
                continue
            g = _to_float(raw.get("goodput_mbps"))
            if g is None:
                continue
            out.append({"env_name": env, "leg": leg, "goodput_mbps": g})
    return out


def per_leg_median(single_rows):
    """Group single-path rows by (env, leg) and take the median per group.

    Returns {env: {'A': median_or_None, 'B': median_or_None}}.
    """
    groups = defaultdict(lambda: {"A": [], "B": []})
    for r in single_rows:
        groups[r["env_name"]][r["leg"]].append(r["goodput_mbps"])
    out = {}
    for env, legs in groups.items():
        out[env] = {
            "A": statistics.median(legs["A"]) if legs["A"] else None,
            "B": statistics.median(legs["B"]) if legs["B"] else None,
        }
    return out


# Tolerance for the recommendation tie-break: a config is considered "tied" with
# the winner if its goodput is within this fraction. Within ties we prefer the
# SIMPLEST option (single path > multipath OFF > multipath + reorder ON) — a
# user-facing recommendation should not push the more complex stack unless it
# meaningfully beats the simpler one.
RECOMMEND_TOL = 0.05


def pick_recommendation(best_single, best_single_leg, off_mp, best_on_mp,
                        tol=RECOMMEND_TOL):
    """Decide the recommended configuration from 3 goodput numbers.

    Returns (label, leg_or_none). Strategy:
      1. Take the maximum of the three.
      2. Among configs within `tol` of the max, return the SIMPLEST:
         single > multipath OFF > multipath + reorder ON.
      3. Missing inputs are skipped (treated as -infinity).

    The simplicity ordering reflects user-facing cost: a single-path
    config has no scheduler/reorder tuning at all; multipath OFF needs the
    scheduler but no buffer; multipath ON adds the reorder buffer's latency.
    """
    candidates = []  # (priority, label, value, leg)
    # Lower priority number == simpler == preferred on ties.
    if best_single is not None:
        leg_label = f"single path (leg {best_single_leg})" if best_single_leg else "single path"
        candidates.append((0, leg_label, best_single, best_single_leg))
    if off_mp is not None:
        candidates.append((1, "multipath, reorder OFF", off_mp, None))
    if best_on_mp is not None:
        candidates.append((2, "multipath + reorder ON", best_on_mp, None))

    if not candidates:
        return ("no data", None)

    peak = max(c[2] for c in candidates)
    if peak <= 0:
        return ("no usable measurement", None)
    threshold = peak * (1.0 - tol)
    eligible = [c for c in candidates if c[2] >= threshold]
    # Simpler wins ties.
    winner = min(eligible, key=lambda c: c[0])
    return (winner[1], winner[3])


def build_three_way_comparison(rows_on, off_rows, single_rows,
                               knee_frac=KNEE_FRAC_DEFAULT, tol=RECOMMEND_TOL,
                               on_points=None):
    """Build the 3-way comparison Markdown section.

    Per env present in the single-path CSV, compare:
      - OFF (multipath, RAW pass-through) median goodput
      - best-ON (multipath + reorder, max-goodput frontier point)
      - leg A median, leg B median (both single path; same netem as the
        corresponding leg in the multipath setup)

    Then call pick_recommendation() to decide what to tell the user.
    """
    # OFF medians per env.
    off_groups = defaultdict(list)
    for r in off_rows:
        off_groups[r["env_name"]].append(r["goodput_mbps"])
    off_gp = {env: statistics.median(gs) for env, gs in off_groups.items() if gs}

    # ON aggregates per env (frontier-based best-ON).
    if on_points is None:
        on_points = aggregate_median(rows_on)
    on_by_env = defaultdict(list)
    for p in on_points:
        on_by_env[p["env_name"]].append(p)

    # Single-path per-leg medians.
    single = per_leg_median(single_rows)

    md = ["## 3-way comparison: single path vs multipath (OFF / ON)", ""]
    if not single:
        md.append("(no single-path data in --single-csv)")
        md.append("")
        return "\n".join(md) + "\n"

    md.append(
        "Each row compares three configs on the SAME netem: single path "
        "(leg A / B = the env's path A / B netem applied to a lone path), "
        "multipath with reorder OFF (RAW pass-through), and multipath with "
        "reorder at its best-goodput frontier point. The recommendation column "
        "picks the SIMPLEST config whose median goodput is within "
        f"{tol*100:.0f}% of the winner; ties go to single > mp-OFF > mp-ON. "
        "This is the user-facing answer to 'should I multipath in this env?'"
    )
    md.append("")
    md.append("| env | rtt spread (ms) | leg A Mbps | leg B Mbps | best single Mbps | "
              "OFF (mp) Mbps | best-ON (mp) Mbps | Δ best-ON vs best-single % | recommendation |")
    md.append("|:--|---:|---:|---:|---:|---:|---:|---:|:--|")

    for env in sorted(single.keys()):
        leg_a = single[env]["A"]
        leg_b = single[env]["B"]
        # Best single = max(legA, legB), tracking which leg won.
        if leg_a is None and leg_b is None:
            best_single, best_leg = None, None
        elif leg_a is None:
            best_single, best_leg = leg_b, "B"
        elif leg_b is None:
            best_single, best_leg = leg_a, "A"
        else:
            if leg_a >= leg_b:
                best_single, best_leg = leg_a, "A"
            else:
                best_single, best_leg = leg_b, "B"

        off_g = off_gp.get(env)
        frontier = frontier_points(on_by_env.get(env, []))
        best_on = max(frontier, key=lambda p: p["goodput"]) if frontier else None
        best_on_g = best_on["goodput"] if best_on else None

        d_on_vs_single = _pct_delta(best_on_g, best_single)

        label, rec_leg = pick_recommendation(best_single, best_leg, off_g,
                                             best_on_g, tol)

        spread = rtt_spread_ms(env)
        spread_str = "?" if spread is None else str(spread)
        md.append(
            f"| {env} | {spread_str} | {_fmt(leg_a)} | {_fmt(leg_b)} | "
            f"{_fmt(best_single)} | {_fmt(off_g)} | {_fmt(best_on_g)} | "
            f"{_fmt(d_on_vs_single, 1)} | **{label}** |"
        )
    md.append("")
    md.append("- leg A / leg B = single-path goodput with the env's path A / "
              "path B netem applied (median over repeats).")
    md.append("- best single = max(leg A, leg B); the better single-path "
              "option a user could pick if not multipathing.")
    md.append("- Δ best-ON vs best-single: positive ⇒ multipath + reorder "
              "actually aggregates beyond the better single path. Near-zero "
              "or negative ⇒ multipath only matches or loses to single — "
              "the recommendation reflects this.")
    md.append("- recommendation picks the simplest config within "
              f"{tol*100:.0f}% of the winner: a multipath stack must clearly "
              "beat single path to be recommended.")
    md.append("- Envs missing OFF or best-ON columns are present in "
              "--single-csv but not in the corresponding ON / OFF CSV; the "
              "recommendation still uses whatever it has.")
    md.append("")
    return "\n".join(md) + "\n"


# ─── CLI ─────────────────────────────────────────────────────────────────────
def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sweep_reorder_analyze.py",
        description="Pareto-frontier analysis of the reorder sweep CSV.",
    )
    parser.add_argument("--csv", required=True, help="input sweep CSV path (reorder ON)")
    parser.add_argument(
        "--off-csv",
        default=None,
        help="optional RAW-baseline CSV from `sweep_reorder.sh --reorder off`; "
             "adds the per-env ON-vs-OFF net-benefit table",
    )
    parser.add_argument(
        "--single-csv",
        default=None,
        help="optional single-path baseline CSV from `sweep_single_path.sh`; "
             "adds the 3-way comparison table (single vs multipath OFF/ON) and "
             "the user-facing recommendation column",
    )
    parser.add_argument(
        "--out",
        default="ci_sweep_results/reorder_optimal.md",
        help="output Markdown path (default: ci_sweep_results/reorder_optimal.md)",
    )
    parser.add_argument(
        "--knee-frac",
        type=float,
        default=KNEE_FRAC_DEFAULT,
        help="recommended-default knee fraction: smallest-wait cell reaching this "
             f"fraction of the env's peak goodput (default {KNEE_FRAC_DEFAULT})",
    )
    parser.add_argument(
        "--recommend-tol",
        type=float,
        default=RECOMMEND_TOL,
        help="3-way recommendation tolerance: a config is considered 'tied' "
             "with the winner if its goodput is within this fraction; ties "
             "go to the simpler config (single > mp-OFF > mp-ON). "
             f"(default {RECOMMEND_TOL})",
    )
    args = parser.parse_args(argv)
    if not 0.0 < args.knee_frac <= 1.0:
        parser.error(f"--knee-frac must be in (0, 1]; got {args.knee_frac}")
    if not 0.0 <= args.recommend_tol < 1.0:
        parser.error(f"--recommend-tol must be in [0, 1); got {args.recommend_tol}")

    if not os.path.exists(args.csv):
        parser.error(f"CSV not found: {args.csv}")

    try:
        rows, all_envs = read_rows(args.csv)
    except (ValueError, OSError) as exc:
        parser.error(f"failed to read CSV: {exc}")

    # Aggregate the ON sweep once and thread it into every builder. The three
    # report sections all derive per-env best-ON / frontier from the same input,
    # so a single aggregation pass eliminates ~50-100 ms of repeated work AND
    # closes the silent-drift vector where a future change to aggregate_median
    # could leave three independently-computed copies disagreeing.
    on_points = aggregate_median(rows)

    md_text, tsv_text, summary = build_report(
        rows, all_envs, args.knee_frac, on_points=on_points
    )

    if args.off_csv:
        if not os.path.exists(args.off_csv):
            parser.error(f"--off-csv not found: {args.off_csv}")
        try:
            off_rows, _ = read_rows(args.off_csv)
        except (ValueError, OSError) as exc:
            parser.error(f"failed to read --off-csv: {exc}")
        md_text += "\n" + build_off_comparison(
            rows, off_rows, args.knee_frac, on_points=on_points
        )
        summary += f" + ON/OFF table from {len(off_rows)} OFF row(s)."
    else:
        off_rows = []

    if args.single_csv:
        if not os.path.exists(args.single_csv):
            parser.error(f"--single-csv not found: {args.single_csv}")
        try:
            single_rows = read_single_rows(args.single_csv)
        except (ValueError, OSError) as exc:
            parser.error(f"failed to read --single-csv: {exc}")
        md_text += "\n" + build_three_way_comparison(
            rows, off_rows, single_rows, args.knee_frac,
            tol=args.recommend_tol, on_points=on_points
        )
        summary += f" + 3-way table from {len(single_rows)} single-path row(s)."

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

# ON-vs-OFF delta direction: ON faster than OFF -> positive %; collapsed/zero
# OFF baseline -> None (no meaningless ratio); missing side -> None.
assert _pct_delta(110.0, 100.0) == 10.0      # ON 10% above OFF
assert _pct_delta(90.0, 100.0) == -10.0      # ON 10% below OFF
assert _pct_delta(50.0, 0.0) is None         # OFF collapsed -> no ratio
assert _pct_delta(None, 100.0) is None       # missing ON -> None

# Knee picker: NEVER selects the collapsed low-wait cell (the whole point of
# replacing the latency-gated rule). With a peak at wait=200 (49 Mbps) and a
# collapsed wait=10 (1 Mbps), the knee is the smallest wait reaching >=90% of
# peak — here wait=50 (45.7), not wait=10.
def _pt(w, g, c="1024"):
    return {"max_wait_ms": w, "cap_pkts": c, "goodput": g, "p99": 0.0}
_knee_pts = [_pt("10", 1.0), _pt("20", 42.0), _pt("50", 45.7), _pt("200", 49.0)]
_knee, _ = recommended_default(_knee_pts, "rtt_40", 0.90)
assert _knee["max_wait_ms"] == "50", _knee   # 45.7 >= 0.9*49=44.1; 42 < 44.1
# Tie-break smallest cap when two cells clear the threshold at the same wait.
_cap_pts = [_pt("50", 49.0, "2048"), _pt("50", 48.0, "1024")]
_kc, _ = recommended_default(_cap_pts, "x", 0.90)
assert _kc["cap_pkts"] == "1024", _kc        # 48 >= 0.9*49=44.1; smaller cap wins
assert recommended_default([], "x")[0] is None  # no data -> no pick
# OFF-sentinel rows (max_wait_ms="off") must be skipped, not raise int("off").
_off_pts = [{"max_wait_ms": "off", "cap_pkts": "off", "goodput": 30.0, "p99": 0.0}]
_off_rec, _off_note = recommended_default(_off_pts, "x")
assert _off_rec is None and "numeric" in _off_note, (_off_rec, _off_note)

# pick_recommendation: simplest config within tol wins; clear winner overrides.
# (a) single barely beats mp-OFF & mp-ON -> single recommended (simplest tier).
_lab, _leg = pick_recommendation(50.0, "A", 49.0, 49.5)
assert _lab == "single path (leg A)" and _leg == "A", (_lab, _leg)
# (b) multipath ON clearly aggregates above single -> mp-ON wins.
_lab, _leg = pick_recommendation(50.0, "A", 60.0, 100.0)
assert _lab == "multipath + reorder ON" and _leg is None, (_lab, _leg)
# (c) Ties prefer simpler: single == mp-OFF within tol, single wins.
_lab, _leg = pick_recommendation(50.0, "B", 50.5, 30.0)
assert _lab == "single path (leg B)" and _leg == "B", (_lab, _leg)
# (d) Missing single (None): mp-OFF and mp-ON compete; mp-OFF wins on tie.
_lab, _leg = pick_recommendation(None, None, 50.0, 49.5)
assert _lab == "multipath, reorder OFF", (_lab, _leg)
# (e) No inputs -> no data.
_lab, _leg = pick_recommendation(None, None, None, None)
assert _lab == "no data", (_lab, _leg)
# (f) leg-B-wins case threads the leg label through.
_lab, _leg = pick_recommendation(60.0, "B", 40.0, 50.0)
assert _lab == "single path (leg B)" and _leg == "B", (_lab, _leg)


if __name__ == "__main__":
    sys.exit(main())
