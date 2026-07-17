#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# ci_bench_backup_fec.sh — CI lossy-primary multipath benchmark.
#
# Compares wlb vs backup_fec on a 2-path topology where the primary path
# (Path A) suffers injected packet loss and the standby path (Path B) is
# clean. backup_fec sends FEC repair symbols on Path B so a lossy Path A
# is partially recoverable without retransmission.
#
# Sweep:  loss = 1 / 3 / 5 / 10 %.  3 runs per cell, take the median.
# Output: ${CI_BENCH_RESULTS}/backup_fec.json
#
# Usage: sudo ./ci_bench_backup_fec.sh [path-to-mqvpn-binary]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/ci_bench_env.sh"

MQVPN="${1:-${MQVPN}}"

SCHEDULERS="wlb backup_fec"
LOSS_RATES="1 3 5 10"
DURATION=30
RUNS_PER_CELL=3
IPERF_PARALLEL=4

RESULTS_TMP="$(mktemp)"
trap 'ci_bench_cleanup; rm -f "$RESULTS_TMP"' EXIT
ci_bench_check_deps

echo "================================================================"
echo "  mqvpn backup_fec lossy-primary benchmark (CI)"
echo "  Binary:     $MQVPN"
echo "  Schedulers: $SCHEDULERS"
echo "  Loss %:     $LOSS_RATES"
echo "  Duration:   ${DURATION}s × ${RUNS_PER_CELL} runs/cell"
echo "================================================================"

median3() {
    # Median of 3 numbers (no jq dependency)
    python3 -c "
import sys
vals = sorted(float(x) for x in sys.argv[1:])
print(f'{vals[len(vals)//2]:.1f}')
" "$@"
}

for SCHED in $SCHEDULERS; do
    for LOSS in $LOSS_RATES; do
        echo ""
        echo "──── ${SCHED}  loss=${LOSS}% ────"

        ci_bench_setup_netns
        # Path A: primary, lossy.  Path B: standby, clean.
        ci_bench_apply_netem "loss ${LOSS}% rate 100mbit" "rate 100mbit"

        ci_bench_start_server "$SCHED"
        ci_bench_start_client "--path $VETH_A0 --path $VETH_B0" "$SCHED"
        ci_bench_wait_tunnel 15

        RUN_RESULTS=()
        for i in $(seq 1 "$RUNS_PER_CELL"); do
            JSON="$(ci_bench_run_iperf TCP DL "$DURATION" "$IPERF_PARALLEL")"
            MBPS="$(ci_bench_parse_throughput "$JSON")"
            rm -f "$JSON"
            echo "  run ${i}/${RUNS_PER_CELL}: ${MBPS} Mbps"
            RUN_RESULTS+=("$MBPS")
            sleep 1
        done

        MEDIAN="$(median3 "${RUN_RESULTS[@]}")"
        echo "  median: ${MEDIAN} Mbps"
        echo "${SCHED} ${LOSS} ${MEDIAN}" >> "$RESULTS_TMP"

        ci_bench_stop_vpn
        sleep 2
    done
done

# --- Generate output JSON ---

OUTPUT_FILE="${CI_BENCH_RESULTS}/backup_fec_$(date -u '+%Y%m%d_%H%M%S').json"
mkdir -p "$CI_BENCH_RESULTS"

python3 - "$RESULTS_TMP" "$OUTPUT_FILE" "${CI_BENCH_COMMIT:-unknown}" <<'PY'
import json, sys, datetime, platform

results_path, output_path, commit = sys.argv[1], sys.argv[2], sys.argv[3]
results = []
with open(results_path) as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) != 3:
            continue
        sched, loss, mbps = parts
        results.append({
            "scheduler": sched,
            "loss_pct": int(loss),
            "throughput_mbps_median": float(mbps),
        })

doc = {
    "test": "backup_fec",
    "metadata": {
        "commit": commit,
        "kernel": platform.uname().release,
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
    },
    "results": results,
}
with open(output_path, "w") as f:
    json.dump(doc, f, indent=2)
print(f"Wrote {output_path} ({len(results)} cells)")
PY

echo ""
echo "================================================================"
echo "  Done. Results: $OUTPUT_FILE"
echo "================================================================"
