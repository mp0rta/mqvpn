#!/bin/bash
# scripts/benchmark_rtmp.sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# RTMP continuity benchmark: direct single-link vs mqvpn (hybrid lane).
# Spec: docs/superpowers/specs/2026-08-09-rtmp-bench-design.md
# Conds : R1 starvation (=SRT V1 shape), R2 burst loss (=C3h shape), R3 flap
# Arms  : direct-a, mqvpn-hybrid, mqvpn-datagram (internal-only)
# Metric: continuity (disconnects, dead-air s, recovery s) + live lag
#
# Usage: sudo ./scripts/benchmark_rtmp.sh [mqvpn-binary]
#        RTMP_BENCH_QUICK=1  → one cell (R1 × direct-a × rep1), short duration
#        RTMP_BENCH_ARMS="direct-a mqvpn-hybrid"  → arm subset
#        RTMP_BENCH_CONDS="R3"                    → condition subset
#        RTMP_BENCH_OUT=<dir>  → reuse an output dir (required for resume:
#                                the default dir is timestamped per run)
set -euo pipefail

MQVPN="${1:-build-lib/mqvpn}"
[ -x "$MQVPN" ] || { echo "mqvpn binary not found: $MQVPN"; exit 1; }
MQVPN="$(readlink -f "$MQVPN")"
[ "$(id -u)" -eq 0 ] || { echo "needs root (netns)"; exit 1; }

OUT_DIR="${RTMP_BENCH_OUT:-bench_results/rtmp/tier1_$(date +%Y%m%d_%H%M%S)}"
CSV="${RTMP_BENCH_CSV:-${OUT_DIR}/results.csv}"
WORK_DIR="$(mktemp -d /tmp/rtmp-bench.XXXXXX)"
PSK="rtmp-bench-psk"
mkdir -p "$OUT_DIR"

. "$(dirname "$0")/benchmark_rtmp_common.sh"

cleanup() {
    if [ -n "${PUBLISHER_FFMPEG_PID:-}" ]; then
        kill -9 "$PUBLISHER_FFMPEG_PID" 2>/dev/null || true
    fi
    stop_flv_sampler; stop_flap; kill_vpn; stop_ingest
    clear_tc; teardown_netns
    rm -rf "$WORK_DIR"
    # also on abort paths — a set -e exit must not leave root-owned results
    if [ -n "${SUDO_USER:-}" ] && [ -d "$OUT_DIR" ]; then
        chown -R "$SUDO_USER:" "$OUT_DIR"
    fi
}
trap cleanup EXIT

# shellcheck disable=SC2206  # intentional word-splitting of the arm list
ARMS=(${RTMP_BENCH_ARMS:-direct-a mqvpn-hybrid mqvpn-datagram})
REPEATS="${RTMP_BENCH_REPEATS:-3}"

# cond | rate_a | netem_a | rate_b | netem_b | duration_s | flap(down:up|empty)
CONDS=(
  "R1|6mbit|delay 20ms limit 70|6mbit|delay 20ms limit 70|60|"
  "R2|100mbit|delay 50ms limit 1450 loss gemodel 4% 30% 80% 0.5%|100mbit|delay 50ms limit 1450|60|"
  "R3|12mbit|delay 10ms limit 200|12mbit|delay 30ms limit 300|120|30:60"
)
if [ "${RTMP_BENCH_QUICK:-0}" = "1" ]; then
    CONDS=("R1|6mbit|delay 20ms limit 70|6mbit|delay 20ms limit 70|20|")
    # shellcheck disable=SC2206
    ARMS=(${RTMP_BENCH_ARMS:-direct-a})
    REPEATS=1
fi
if [ -n "${RTMP_BENCH_CONDS:-}" ]; then
    filtered=()
    for spec in "${CONDS[@]}"; do
        case " ${RTMP_BENCH_CONDS} " in
            *" ${spec%%|*} "*) filtered+=("$spec") ;;
        esac
    done
    CONDS=("${filtered[@]}")
    [ "${#CONDS[@]}" -gt 0 ] || { echo "RTMP_BENCH_CONDS matched nothing"; exit 1; }
fi

# resume: a cell is done when its cond,arm,rep row exists (needs RTMP_BENCH_OUT)
declare -A DONE_KEYS
if [ -s "$CSV" ]; then
    while IFS=, read -r c a r _rest; do
        DONE_KEYS["$c,$a,$r"]=1
    done < <(tail -n +2 "$CSV")
else
    echo "cond,arm,rep,sessions,disconnects,dead_air_s,max_gap_s,ttr_s,max_lag_s,ingest_mbps" >"$CSV"
fi

setup_netns
setup_ingest_alias
generate_cert
write_rtmp_inis

for spec in "${CONDS[@]}"; do
    IFS='|' read -r cond rate_a netem_a rate_b netem_b dur flap <<<"$spec"
    echo "=== $cond  A:${rate_a}/${netem_a}  B:${rate_b}/${netem_b}  dur=${dur}s flap=${flap:-none} ==="
    apply_tc_full "$rate_a" "$netem_a" "$rate_b" "$netem_b"
    for rep in $(seq 1 "$REPEATS"); do
        for arm in "${ARMS[@]}"; do
            key="$cond,$arm,$rep"
            if [ -n "${DONE_KEYS[$key]:-}" ]; then
                echo "  [skip] $key (done)"
                continue
            fi
            cell="$OUT_DIR/${cond}_${arm}_r${rep}"
            mkdir -p "$cell"
            echo "  [$key] ..."
            ok=1
            start_ingest "$cell" || ok=0
            if [ "$ok" -eq 1 ] && [ "$arm" != "direct-a" ]; then
                run_vpn_rtmp "$arm" bench-a0 bench-b0 || ok=0
            fi
            if [ "$ok" -eq 1 ]; then
                start_flv_sampler "$cell/dvr" "$cell/flv_samples.csv"
                if [ -n "$flap" ]; then
                    schedule_flap "${flap%%:*}" "${flap##*:}" "$cell/flap.log"
                fi
                run_publisher "$cell" \
                    "rtmp://$(arm_target "$arm"):${RTMP_PORT}/live/bench" \
                    "$dur" -- "${TIER1_SRC[@]}"
                wait_flap
                stop_flv_sampler
            fi
            kill_vpn
            stop_ingest
            # restore path A state in case a failed run aborted mid-flap
            ip netns exec "$NS_CLIENT" ip link set bench-a0 up 2>/dev/null || true
            ip netns exec "$NS_CLIENT" ip addr replace ${PATH_A_CLIENT_IP}/24 dev bench-a0 2>/dev/null || true
            if [ "$ok" -eq 1 ] && row=$(python3 "$(dirname "$0")/../benchmarks/rtmp_analyze.py" \
                    cell --cell-dir "$cell" --cond "$cond" --arm "$arm" --rep "$rep" --duration "$dur"); then
                echo "$row" >>"$CSV"
                echo "    -> $row"
            else
                echo "    -> FAILED (no CSV row; artifacts kept in $cell)"
            fi
        done
    done
done
clear_tc

python3 "$(dirname "$0")/../benchmarks/rtmp_analyze.py" summarize --csv "$CSV" >"$OUT_DIR/summary.md"
echo "Results: $CSV"
echo "Summary: $OUT_DIR/summary.md"
