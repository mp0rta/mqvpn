#!/usr/bin/env python3
# mqvpn v0.9.0 hybrid TCP-lane — one grouped-bar PNG per scheduler (OFF vs ON).
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

P = [1, 2, 4, 8, 16]
x = np.arange(len(P))
import os
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bench_results", "hybrid_mode")
os.makedirs(OUT, exist_ok=True)

# per scheduler: off/on each = (mean, min, max); plus gain%
DATA = {
    "minrtt": {
        "off":  ([114.9,164.4,151.9,164.6,169.5],[92.4,157.5,121.1,160.9,166.6],[149.9,173.1,171.6,168.7,173.5]),
        "on":   ([187.1,186.3,187.9,187.7,187.4],[185.7,186.0,186.7,186.8,186.8],[188.2,186.5,188.5,188.4,188.1]),
        "gain": [63,13,24,14,11],
    },
    "wlb": {
        "off":  ([96.2,177.4,167.4,177.2,178.0],[95.9,172.9,144.2,173.7,177.1],[96.5,179.7,179.1,179.2,178.7]),
        "on":   ([187.2,186.2,187.7,187.9,188.0],[186.3,185.6,186.9,187.1,187.8],[187.8,186.7,188.4,188.6,188.3]),
        "gain": [95,5,12,6,6],
    },
}

C_OFF = ("#c7c7c7", "#5a5a5a", "//")   # hatched baseline
C_ON  = ("#1f77b4", "#124c74", "")     # solid feature
w = 0.38

def make(sched):
    d = DATA[sched]
    fig, ax = plt.subplots(figsize=(10, 6.2))
    for key, (fc, ec, hatch), lab, sign in (
            ("off", C_OFF, "hybrid OFF  (raw multipath)", -1),
            ("on",  C_ON,  "hybrid ON  (TCP stream lane)", +1)):
        mean, lo, hi = (np.array(v, float) for v in d[key])
        yerr = np.vstack([mean - lo, hi - mean])
        bars = ax.bar(x + sign*w/2, mean, w, label=lab, facecolor=fc, edgecolor=ec,
                      hatch=hatch, linewidth=1.0, zorder=3,
                      yerr=yerr, error_kw=dict(ecolor="#222", elinewidth=1.0, capsize=3, zorder=4))
        ax.bar_label(bars, labels=[f"{m:.0f}" for m in mean], padding=3, fontsize=9, color="#222")

    # gain% above each ON bar — the OFF→ON lift, the point of the chart
    on_mean = np.array(d["on"][0]); on_hi = np.array(d["on"][2])
    for i in range(len(P)):
        ax.annotate(f"+{d['gain'][i]}%", (x[i] + w/2, on_hi[i]), xytext=(0, 15),
                    textcoords="offset points", ha="center", fontsize=9.5,
                    color="#0a5", fontweight="bold")

    ax.axhline(200, color="#999", lw=1.0, ls=(0, (5, 4)), zorder=1)
    ax.text(len(P)-0.55, 201.5, "200 = 2×100 Mbit aggregate cap", fontsize=8.5,
            color="#777", va="bottom", ha="right")

    ax.set_xticks(x); ax.set_xticklabels([f"-P {p}" for p in P])
    ax.set_xlabel("iperf3 parallel TCP streams", fontsize=11)
    ax.set_ylabel("receiver throughput (Mbps)", fontsize=11)
    ax.set_ylim(0, 214)
    ax.set_title(f"mqvpn v0.9.0 hybrid TCP-lane — {sched} scheduler\n"
                 "symmetric 2-path: 2×100 Mbit / 25 ms  "
                 "(bars = mean of 3 reps, whiskers = min–max)", fontsize=12.5)
    ax.grid(axis="y", ls=":", color="#bbb", lw=0.8, zorder=0)
    ax.set_axisbelow(True)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.09), ncol=2,
              fontsize=9.5, framealpha=0.95)
    for ext in ("png", "svg"):
        fig.savefig(f"{OUT}/hybrid_mode_{sched}_1783350878.{ext}", dpi=200,
                    bbox_inches="tight")
    plt.close(fig)
    print(f"saved {sched}")

for s in ("minrtt", "wlb"):
    make(s)
