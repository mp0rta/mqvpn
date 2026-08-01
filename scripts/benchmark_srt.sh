#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# benchmark_srt.sh — SRT over single path vs mqvpn multipath (tier 1)
#
# Claim under test: a live SRT stream that breaks up over any single link
# stays clean when mqvpn bonds the two links.
#
# Arms  : direct-A, direct-B (no VPN), mqvpn-2path, mqvpn-1path
#         (mqvpn scheduler: minrtt by default — see SCHEDULER below)
# Conds : C1 bandwidth-starved, C2 +RTT-asym, C3 burst loss, C4 jitter
# Metric: unique stream loss = (pktSentUnique - pktRecvUnique) / pktSentUnique
#         Receiver-side drop alone is NOT arm-comparable: loss can migrate
#         to sender-side TLPKTDROP (pktSndDrop), and a bufferbloated arm can
#         deliver 100% seconds-late with zero drops (both observed in smoke).
#         rcvDrop/sndDrop are reported as secondary columns; msRTT indicates
#         delay health.
#
# Usage: sudo SRT_XTRANSMIT=/path/to/srt-xtransmit ./benchmark_srt.sh [mqvpn-binary]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="${1:-${SCRIPT_DIR}/../build/mqvpn}"
DURATION="${SRT_BENCH_DURATION:-60}"
OUT_DIR="${SRT_BENCH_OUT:-${SCRIPT_DIR}/../bench_results/srt}"
SRT_PORT=4200
# Unified recommended config, settled by the diagnostic rounds (2026-08-01):
# mqvpn defaults (scheduler=wlb, reorder shim OFF) + SRT receiver
# lossmaxttl=32. Measured at practical scale (2x100Mbit):
#   - P2 120Mbps bonding: 0.000% loss x3 (direct single link: ~30%)
#   - C3 burst loss: ~1% (the shim's real-loss head-of-line collapse — 87-93%
#     — only happens with the shim ON; lossmaxttl handles reordering at the
#     SRT layer, whose latency buffer is the right place for it)
# Overrides for comparison: SRT_BENCH_SCHED / SRT_BENCH_REORDER /
# SRT_BENCH_LOSSMAXTTL / SRT_BENCH_CC.
SCHEDULER="${SRT_BENCH_SCHED:-wlb}"

if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN" >&2
    echo "Build first: ./build.sh" >&2
    exit 1
fi
MQVPN="$(realpath "$MQVPN")"

if [ -z "${SRT_XTRANSMIT:-}" ] || [ ! -x "${SRT_XTRANSMIT}" ]; then
    cat >&2 <<'EOF'
error: SRT_XTRANSMIT is not set or not executable.

Build srt-xtransmit (upstream moved to maxsharabayko/srt-xtransmit):
  git clone --recursive https://github.com/maxsharabayko/srt-xtransmit.git
  cd srt-xtransmit && mkdir build && cd build
  cmake ../ -DCMAKE_BUILD_TYPE=Release && cmake --build . -j
Then run:
  sudo SRT_XTRANSMIT=/path/to/srt-xtransmit/build/bin/srt-xtransmit ./benchmark_srt.sh
EOF
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "error: must run as root (netns operations)" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d)"
mkdir -p "$OUT_DIR"

# shellcheck source=scripts/benchmark_srt_common.sh
# (run `shellcheck -x` from the repo root so the directive resolves)
source "${SCRIPT_DIR}/benchmark_srt_common.sh"

PSK=$("$MQVPN" --genkey 2>/dev/null)

RECEIVER_PID=""
BENCH_HAD_FAILURE=0
cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ -n "$RECEIVER_PID" ]; then
        kill "$RECEIVER_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$RECEIVER_PID" 2>/dev/null || true   # bounded even if TERM is ignored
    fi
    kill_vpn
    clear_tc
    teardown_netns
    if [ "$BENCH_HAD_FAILURE" -ne 0 ]; then
        echo "NOTE: at least one run failed — keeping ${WORK_DIR} for diagnosis"
    else
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

# csv_metric / csv_mean are provided by benchmark_srt_common.sh (sourced above)

# ---- SRT runner --------------------------------------------------------
# run_srt <run-id> <target-ip> <latency-ms> <rate-mbps>
# Starts receiver in server ns, runs sender in client ns for $DURATION.
# Stats CSVs (the data) go to $OUT_DIR/raw/; process logs (diagnostics)
# go to WORK_DIR, which is kept on failure and never committed.
# Returns nonzero when the run produced no usable stats (caller marks ERR).
run_srt() {
    local run_id="$1" target_ip="$2" latency="$3" rate_mbps="$4"
    local raw="${OUT_DIR}/raw"
    mkdir -p "$raw"
    # SRT official live-stream recommendation: absolute cap off, declare the
    # input rate, 25% retransmission overhead → send ceiling = 1.25 x input.
    # inputbw/maxbw are in BYTES per second.
    local inputbw=$(( rate_mbps * 1000000 / 8 ))
    local snd_uri="srt://${target_ip}:${SRT_PORT}?latency=${latency}&maxbw=0&inputbw=${inputbw}&oheadbw=25"
    # (This run's stale artifacts were already cleared by run_arm.)

    # statsfreq 100ms bounds the tail lost at shutdown to <=100ms of data
    # (csv_metric prefers cumulative *Total columns where available anyway).
    # No --enable-metrics: jitter/delay metrics would need sender-side
    # metadata too and feed no headline number — dropped as YAGNI.
    # SRT_BENCH_LOSSMAXTTL wires SRTO_LOSSMAXTTL (receiver-side reorder
    # tolerance: how many later packets to wait before NAKing a gap).
    # Default 32 — part of the recommended config: absorbs multipath
    # reordering at the SRT layer and cuts spurious retransmissions
    # (measured 1500 -> 183-731 at P2). Applied to ALL arms for fairness
    # (single-path arms see no reordering, so it is a no-op there).
    # Set to 0 for libsrt default behaviour.
    local lmttl="${SRT_BENCH_LOSSMAXTTL:-32}"
    local rcv_uri="srt://:${SRT_PORT}?latency=${latency}"
    [ "$lmttl" != "0" ] && rcv_uri="${rcv_uri}&lossmaxttl=${lmttl}"
    ip netns exec "$NS_SERVER" "$SRT_XTRANSMIT" receive \
        "$rcv_uri" \
        --statsfile "${raw}/${run_id}.rcv.csv" --statsfreq 100ms \
        > "${WORK_DIR}/${run_id}.rcv.log" 2>&1 &
    RECEIVER_PID=$!
    sleep 1
    if ! kill -0 "$RECEIVER_PID" 2>/dev/null; then
        echo "    ERROR: receiver died at startup (${WORK_DIR}/${run_id}.rcv.log)"
        RECEIVER_PID=""
        rm -f "${raw}/${run_id}.rcv.csv" "${raw}/${run_id}.snd.csv"
        return 1
    fi

    # Bounded sender: a hung SRT connection must not stall the whole matrix.
    # --kill-after covers a child that ignores TERM. srt-xtransmit exits 0 on
    # several runtime connection failures, so success is judged from the
    # stats files below, not the exit code.
    timeout --kill-after=10 $((DURATION + 30)) \
        ip netns exec "$NS_CLIENT" "$SRT_XTRANSMIT" generate \
        "$snd_uri" \
        --sendrate "${rate_mbps}Mbps" --duration "${DURATION}s" \
        --statsfile "${raw}/${run_id}.snd.csv" --statsfreq 100ms \
        > "${WORK_DIR}/${run_id}.snd.log" 2>&1 || true

    sleep 2   # let late packets land and final stats flush
    # INT → poll → KILL, same as kill_vpn/video_run: a wedged receiver with
    # a bare `wait` would hang the whole 18-run matrix.
    kill -INT "$RECEIVER_PID" 2>/dev/null || true
    local deadline=$((SECONDS + 5))
    while kill -0 "$RECEIVER_PID" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do
        sleep 0.2
    done
    kill -9 "$RECEIVER_PID" 2>/dev/null || true
    wait "$RECEIVER_PID" 2>/dev/null || true
    RECEIVER_PID=""

    if [ ! -s "${raw}/${run_id}.snd.csv" ] || [ ! -s "${raw}/${run_id}.rcv.csv" ]; then
        echo "    ERROR: missing/empty stats CSV for ${run_id} (logs in ${WORK_DIR})"
        # Don't leave partial CSVs where Step 7.4's `git add` would sweep
        # them into the tracked archive.
        rm -f "${raw}/${run_id}.rcv.csv" "${raw}/${run_id}.snd.csv"
        return 1
    fi

    # Coverage check on BOTH sides: a sender that died mid-run truncates the
    # denominator; a receiver that died mid-run truncates the numerator and
    # silently UNDERSTATES drop%. statsfreq=100ms → ~10 rows/s; require 80%.
    local min_rows rows side
    min_rows=$(( DURATION * 8 ))
    for side in snd rcv; do
        rows=$(awk 'END { print NR - 1 }' "${raw}/${run_id}.${side}.csv")
        if [ "$rows" -lt "$min_rows" ]; then
            echo "    ERROR: ${side} stats truncated for ${run_id} (${rows} rows < ${min_rows})"
            rm -f "${raw}/${run_id}.rcv.csv" "${raw}/${run_id}.snd.csv"
            return 1
        fi
    done
    return 0
}

# arm_target <arm> — echoes the SRT target IP for the arm
arm_target() {
    case "$1" in
        direct-A)    echo "$PATH_A_SERVER_IP" ;;
        direct-B)    echo "$PATH_B_SERVER_IP" ;;
        mqvpn-*)     echo "$TUN_SERVER_IP" ;;
    esac
}

# arm_setup <arm> — returns nonzero if VPN setup failed
arm_setup() {
    case "$1" in
        direct-*)    return 0 ;;
        mqvpn-2path) run_vpn "$SCHEDULER" bench-a0 bench-b0 ;;
        mqvpn-1path) run_vpn "$SCHEDULER" bench-a0 ;;
    esac
}

arm_teardown() {
    case "$1" in
        mqvpn-*) kill_vpn ;;
    esac
}

# ---- result storage ----------------------------------------------------
declare -A R_LOSS R_SENT R_RCVDROP R_SNDDROP R_RETRANS R_RTT R_RATE R_BELATED
RUNS=()   # ordered "<cond>_<latency>_<arm>_rN" keys

# run_arm <cond> <latency> <rate-mbps> <arm> <rep>
run_arm() {
    local cond="$1" latency="$2" rate_mbps="$3" arm="$4" rep="${5:-1}"
    local key="${cond}_${latency}_${arm}_r${rep}"
    local run_id="${key}"
    RUNS+=("$key")

    # Clear this run's artifacts up front: even a setup failure below must
    # not leave a stale CSV (from an earlier invocation) under this run ID,
    # where Step 7.4's `git add` would archive it as current data.
    rm -f "${OUT_DIR}/raw/${run_id}.rcv.csv" "${OUT_DIR}/raw/${run_id}.snd.csv"

    echo "    [${arm}] latency=${latency}ms rate=${rate_mbps}Mbps rep=${rep} ..."
    if ! arm_setup "$arm"; then
        echo "    SKIP: setup failed for ${arm}"
        BENCH_HAD_FAILURE=1
        R_LOSS[$key]="ERR"; R_SENT[$key]="-"; R_RCVDROP[$key]="-"
        R_SNDDROP[$key]="-"; R_RETRANS[$key]="-"; R_RTT[$key]="-"; R_RATE[$key]="-"
        arm_teardown "$arm"
        return 0
    fi

    if ! run_srt "$run_id" "$(arm_target "$arm")" "$latency" "$rate_mbps"; then
        BENCH_HAD_FAILURE=1
        R_LOSS[$key]="ERR"; R_SENT[$key]="-"; R_RCVDROP[$key]="-"
        R_SNDDROP[$key]="-"; R_RETRANS[$key]="-"; R_RTT[$key]="-"; R_RATE[$key]="-"
        arm_teardown "$arm"
        return 0
    fi
    arm_teardown "$arm"

    local raw="${OUT_DIR}/raw"
    local sent recvu rcvdrop snddrop retrans rtt rate belated
    # Headline: unique stream loss = unique packets sent but never delivered
    # to the receiving app. Robust across arms — receiver drop alone misses
    # sender-side TLPKTDROP, and a bufferbloated arm can deliver everything
    # seconds late with zero "drops" (both observed in smoke).
    sent=$(csv_metric "${raw}/${run_id}.snd.csv" pktSentUnique)
    recvu=$(csv_metric "${raw}/${run_id}.rcv.csv" pktRecvUnique)
    rcvdrop=$(csv_metric "${raw}/${run_id}.rcv.csv" pktRcvDrop)
    snddrop=$(csv_metric "${raw}/${run_id}.snd.csv" pktSndDrop)
    retrans=$(csv_metric "${raw}/${run_id}.rcv.csv" pktRcvRetrans)
    rtt=$(csv_mean "${raw}/${run_id}.rcv.csv" msRTT)
    rate=$(csv_mean "${raw}/${run_id}.rcv.csv" mbpsRecvRate)
    # Actual late arrivals (context for the loss number; NA on srt versions
    # that don't expose it)
    belated=$(csv_metric "${raw}/${run_id}.rcv.csv" pktRcvBelated)

    R_SENT[$key]="$sent"; R_RCVDROP[$key]="$rcvdrop"; R_SNDDROP[$key]="$snddrop"
    R_RETRANS[$key]="$retrans"; R_RTT[$key]="$rtt"; R_RATE[$key]="$rate"
    R_BELATED[$key]="$belated"
    if [[ "$sent" =~ ^[0-9]+$ ]] && [ "$sent" -gt 0 ] && [[ "$recvu" =~ ^[0-9]+$ ]]; then
        # Clamp at 0: timing edges can make recvUnique exceed sentUnique
        # by a few packets on a clean run.
        R_LOSS[$key]=$(awk "BEGIN { l = 100.0 * ($sent - $recvu) / $sent; if (l < 0) l = 0; printf \"%.3f\", l }")
    else
        # An unusable headline metric (column mismatch, zero pktSentUnique
        # after a runtime connection failure) IS a failed run — without this
        # the benchmark could exit 0 with an NA headline.
        BENCH_HAD_FAILURE=1
        R_LOSS[$key]="NA"
    fi
    echo "      loss=${R_LOSS[$key]}% sentUnique=${sent} rcvDrop=${rcvdrop} sndDrop=${snddrop} rtt=${rtt}ms"
}

declare -A COND_LOSS_NOTE

# Sanity-measure actual loss on shaped path A for stochastic netem (gemodel):
# spec requires recording measured loss, not just the configured string.
# The qdisc is applied in BOTH directions, so ping (round trip) sees
# roughly 1-(1-p)^2 — note that when interpreting the number.
measure_path_loss() {
    local cond="$1"
    local out
    # ping exits nonzero when packets were lost — which is EXPECTED here —
    # and the awk must read to EOF (no early exit: SIGPIPE would 141 the
    # writer under pipefail). Hence the END-print form and the || true.
    out=$(ip netns exec "$NS_CLIENT" ping -q -i 0.01 -c 500 -W 2 \
              "$PATH_A_SERVER_IP" 2>&1 \
          | awk '/packet loss/ { l = $0 } END { print l }') || true
    COND_LOSS_NOTE[$cond]="path A ping x500 (round trip): ${out:-no-output}"
    echo "   measured: ${COND_LOSS_NOTE[$cond]}"
}

# run_condition <cond> <label> <rate_a> <netem_a> <rate_b> <netem_b> <latency> <sendrate-mbps> <repeats> [arms...]
# Stochastic conditions (gemodel loss, jitter) pass repeats=3 so the summary
# shows dispersion, not a single draw; deterministic bandwidth conditions
# pass 1 — their effect is not sampling noise. Arms run sequentially in
# fixed order: netem state is reset by apply_tc_full per condition, and
# randomizing order would buy nothing here.
run_condition() {
    local cond="$1" label="$2" rate_a="$3" netem_a="$4" rate_b="$5" netem_b="$6"
    local latency="$7" sendrate="$8" repeats="$9"; shift 9
    local arms=("$@")
    [ ${#arms[@]} -eq 0 ] && arms=(direct-A direct-B mqvpn-2path mqvpn-1path)

    # SRT_BENCH_ONLY=<cond>[,<cond>...] runs selected conditions only
    # (cheap A/B iteration and partial-rerun recovery)
    case ",${SRT_BENCH_ONLY:-}," in
        ,,|*",${cond},"*) : ;;
        *)
            echo ""
            echo "== [${cond}] skipped (SRT_BENCH_ONLY=${SRT_BENCH_ONLY})"
            return 0
            ;;
    esac

    echo ""
    echo "== [${cond}] ${label} (repeats=${repeats})"
    echo "   A: ${rate_a}/${netem_a}   B: ${rate_b}/${netem_b}   latency=${latency}ms rate=${sendrate}Mbps"
    apply_tc_full "$rate_a" "$netem_a" "$rate_b" "$netem_b"
    case "$netem_a$netem_b" in *gemodel*) measure_path_loss "$cond" ;; esac

    local arm rep
    for rep in $(seq 1 "$repeats"); do
        for arm in "${arms[@]}"; do
            run_arm "$cond" "$latency" "$sendrate" "$arm" "$rep"
        done
    done
    clear_tc
}

# ---- main --------------------------------------------------------------
echo "================================================================"
echo "  SRT single-path vs mqvpn multipath benchmark (tier 1)"
echo "  binary:   $MQVPN"
echo "  duration: ${DURATION}s/run   scheduler: ${SCHEDULER}   reorder: ${SRT_BENCH_REORDER:-off}   lossmaxttl: ${SRT_BENCH_LOSSMAXTTL:-32}"
echo "  date:     $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

setup_netns
generate_cert

# GEMODEL (C3 burst loss) is defined in benchmark_srt_common.sh — shared
# with tier 2 so the two tiers can never drift apart on C3 shaping.

# Practical suite: 2 x 100 Mbit links (real-world shape). Send rates follow
# the rule "max single link < send rate <= 0.70-0.75 x total capacity":
#   P1  25 Mbps — realistic stream that fits either link: overhead/quality
#   P2 120 Mbps — exceeds any single link, <= 150 (= 0.75 x 200): the
#                 bonding claim. Retrans ceiling 1.25x => 150 Mbps max.
# netem limit ≈ (delay in-flight pkts) + (~100ms of queue at the path rate);
# without it netem's default 1000-pkt queue distorts every arm (measured).
#   100mbit/1316B ≈ 9500 pps → 100ms ≈ 950 pkts.
# C3/C4 use a higher base delay (RTT ≈ 100ms vs budget 120ms) so SRT gets
# roughly one retransmission chance — severity is tuned at smoke.

# NOTE: P1/P2 の direct-B は direct-A と同一条件 — 行が一致するのは正常。
run_condition P1 "practical quality (fits one link)" \
    "100mbit" "delay 20ms limit 1150" "100mbit" "delay 20ms limit 1150" 120 25 1
run_condition P2 "bonding (exceeds any single link)" \
    "100mbit" "delay 20ms limit 1150" "100mbit" "delay 20ms limit 1150" 120 120 3
run_condition C3 "burst loss on path A" \
    "100mbit" "delay 50ms limit 1450 ${GEMODEL}" "100mbit" "delay 50ms limit 1450" 120 25 3
run_condition C4 "heavy jitter on path A" \
    "100mbit" "delay 20ms 50ms limit 1650" "100mbit" "delay 40ms limit 1350" 120 25 3
# C5: dual-cellular bonding — the most common field use case. Two carriers
# with different capacity, RTT, jitter and residual loss. 42 Mbps exceeds
# the best single link (40M); retrans ceiling 52.5 = 0.75 x 70M total.
# latency 250ms is a realistic-tight field budget (~1.5 retransmission
# rounds at RTT ~160ms). Note for video interpretation: the residual ~1%
# unique loss this leaves is invisible at packet level but damages nearly
# every frame at 42 Mbps (~175 packets/frame) — clean pictures at this
# rate want a larger latency and lossmaxttl (see report §5 guidance).
# netem limits model deep-ish LTE buffers (~150ms of queue).
run_condition C5 "dual-cellular bonding (asym jitter)" \
    "40mbit" "delay 40ms 20ms limit 750 loss 0.2%" \
    "30mbit" "delay 60ms 30ms limit 600 loss 0.4%" 250 42 3

# ---- summary -----------------------------------------------------------
SUMMARY="${OUT_DIR}/summary.md"
{
    echo "# SRT single-path vs mqvpn multipath — tier 1 results"
    echo ""
    echo "- date: $(date '+%Y-%m-%d %H:%M')"
    echo "- kernel: $(uname -r)"
    echo "- srt-xtransmit: ${SRT_XTRANSMIT} ($("$SRT_XTRANSMIT" --version 2>/dev/null | head -1 || echo unknown))"
    echo "- mqvpn: $(git -C "$SCRIPT_DIR/.." rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "- duration: ${DURATION}s/run, scheduler ${SCHEDULER}, reorder ${SRT_BENCH_REORDER:-off}, lossmaxttl ${SRT_BENCH_LOSSMAXTTL:-32}, cc ${SRT_BENCH_CC:-bbr2}"
    echo "- send rates: P1/C3/C4 = 25 Mbps, P2 = 120 Mbps (sender maxbw=0, inputbw=rate, oheadbw=25)"
    echo "- C3 gemodel: ${GEMODEL}"
    for c in "${!COND_LOSS_NOTE[@]}"; do
        echo "- measured loss [${c}]: ${COND_LOSS_NOTE[$c]}"
    done
    echo ""
    echo "| run | stream loss % | pktSentUnique | rcvDrop | sndDrop | rcvBelated | rcvRetrans | msRTT | recvRate(Mbps) |"
    echo "|---|---|---|---|---|---|---|---|---|"
    for key in "${RUNS[@]}"; do
        echo "| ${key} | ${R_LOSS[$key]} | ${R_SENT[$key]} | ${R_RCVDROP[$key]:-NA} | ${R_SNDDROP[$key]:-NA} | ${R_BELATED[$key]:-NA} | ${R_RETRANS[$key]} | ${R_RTT[$key]} | ${R_RATE[$key]} |"
    done
} | tee "$SUMMARY"

echo ""
echo "Summary written to ${SUMMARY}; raw CSVs in ${OUT_DIR}/raw/"

# Propagate failure: without this the script exits 0 even with ERR rows,
# and the documented `... | tee` invocation would report success.
if [ "$BENCH_HAD_FAILURE" -ne 0 ]; then
    echo "BENCHMARK INCOMPLETE: one or more runs failed (see ERR rows above)" >&2
    exit 1
fi
