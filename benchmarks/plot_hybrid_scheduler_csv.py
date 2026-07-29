#!/usr/bin/env python3
# mqvpn hybrid TCP-lane — CSV-driven variant of plot_hybrid_scheduler.py.
# One grouped-bar PNG+SVG per scheduler (OFF vs ON) from a hybrid_mode CSV.
#
# Usage: plot_hybrid_scheduler_csv.py <csv> <aggregate_cap_mbps> <cap_label> <link_label> [tag]
#   e.g. plot_hybrid_scheduler_csv.py hybrid_mode_1785306660.csv 380 \
#          "380 = 300+80 Mbit aggregate cap" \
#          "asymmetric 2-path: A=300 Mbit/10 ms, B=80 Mbit/30 ms" asym
# Invalid reps (VPN_FAIL / ZERO_BW / NO_LANE) are excluded, matching the bench
# script's own summary; 1PATH / NO_PATHDATA reps carry a valid number and count.
import csv as csvmod
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

CSV, CAP, CAP_LABEL, LINK_LABEL = sys.argv[1], float(sys.argv[2]), sys.argv[3], sys.argv[4]
TAG = sys.argv[5] if len(sys.argv) > 5 else "csv"
OUT = os.path.dirname(os.path.abspath(CSV))
STAMP = os.path.basename(CSV).rsplit("_", 1)[-1].removesuffix(".csv")

rows = [r for r in csvmod.DictReader(open(CSV))
        if r["status"] in ("OK", "1PATH", "NO_PATHDATA")]
scheds = sorted({r["scheduler"] for r in rows})
P = sorted({int(r["P"]) for r in rows})
x = np.arange(len(P))

def cell(sched, hyb, p):
    v = [float(r["bw_mbps"]) for r in rows
         if r["scheduler"] == sched and r["hybrid"] == hyb and int(r["P"]) == p]
    return (np.mean(v), np.min(v), np.max(v)) if v else (np.nan,) * 3

C_OFF = ("#c7c7c7", "#5a5a5a", "//")   # hatched baseline
C_ON  = ("#1f77b4", "#124c74", "")     # solid feature
w = 0.38

def make(sched):
    fig, ax = plt.subplots(figsize=(10, 6.2))
    stats = {k: np.array([cell(sched, k, p) for p in P]).T for k in ("off", "on")}
    for key, (fc, ec, hatch), lab, sign in (
            ("off", C_OFF, "hybrid OFF  (raw multipath)", -1),
            ("on",  C_ON,  "hybrid ON  (TCP stream lane)", +1)):
        mean, lo, hi = stats[key]
        yerr = np.vstack([mean - lo, hi - mean])
        bars = ax.bar(x + sign*w/2, mean, w, label=lab, facecolor=fc, edgecolor=ec,
                      hatch=hatch, linewidth=1.0, zorder=3,
                      yerr=yerr, error_kw=dict(ecolor="#222", elinewidth=1.0, capsize=3, zorder=4))
        ax.bar_label(bars, labels=[f"{m:.0f}" for m in mean], padding=3, fontsize=9, color="#222")

    # gain% above each ON bar — the OFF→ON lift, the point of the chart
    for i in range(len(P)):
        gain = (stats["on"][0][i] / stats["off"][0][i] - 1) * 100
        ax.annotate(f"{gain:+.0f}%", (x[i] + w/2, stats["on"][2][i]), xytext=(0, 15),
                    textcoords="offset points", ha="center", fontsize=9.5,
                    color="#0a5", fontweight="bold")

    ax.axhline(CAP, color="#999", lw=1.0, ls=(0, (5, 4)), zorder=1)
    ax.text(len(P)-0.55, CAP + 1.5, CAP_LABEL, fontsize=8.5,
            color="#777", va="bottom", ha="right")

    ax.set_xticks(x); ax.set_xticklabels([f"-P {p}" for p in P])
    ax.set_xlabel("iperf3 parallel TCP streams", fontsize=11)
    ax.set_ylabel("receiver throughput (Mbps)", fontsize=11)
    ax.set_ylim(0, CAP * 1.07)
    ax.set_title(f"mqvpn hybrid TCP-lane — {sched} scheduler\n{LINK_LABEL}", fontsize=12)
    ax.legend(loc="lower right", fontsize=10, framealpha=0.95)
    ax.grid(axis="y", color="#e5e5e5", lw=0.8, zorder=0)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(OUT, f"hybrid_mode_{TAG}_{sched}_{STAMP}.{ext}"), dpi=150)
    plt.close(fig)

for s in scheds:
    make(s)
print("wrote:", ", ".join(f"hybrid_mode_{TAG}_{s}_{STAMP}.{{png,svg}}" for s in scheds))
