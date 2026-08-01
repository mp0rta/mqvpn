#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# benchmark_srt_video.sh — real-video SRT quality: single path vs mqvpn (tier 2)
#
# Conditions mirror the tier-1 table: C5 dual-cellular bonding (42 Mbps
# stream) and C3 burst loss (25 Mbps; C3h via SRT_BENCH_GEMODEL), each with
# arms {direct-A, mqvpn-2path}. Metrics: VMAF vs source, decoder error log
# lines, freeze seconds.
#
# Usage: sudo ./benchmark_srt_video.sh [mqvpn-binary]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="${1:-${SCRIPT_DIR}/../build/mqvpn}"
DURATION="${SRT_BENCH_DURATION:-60}"
OUT_DIR="${SRT_BENCH_OUT:-${SCRIPT_DIR}/../bench_results/srt}/video"
SRT_PORT=4201
FPS=30
SCHEDULER="${SRT_BENCH_SCHED:-wlb}"   # unified config, same rationale as tier 1

[ -f "$MQVPN" ] || { echo "error: mqvpn not found at $MQVPN" >&2; exit 1; }
MQVPN="$(realpath "$MQVPN")"
[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }

# Preflight EVERYTHING used later — a missing filter must fail here, not
# silently produce freeze=0.0 after 8 minutes of runs.
command -v ffmpeg  >/dev/null || { echo "error: ffmpeg not found" >&2; exit 1; }
command -v ffprobe >/dev/null || { echo "error: ffprobe not found" >&2; exit 1; }
command -v jq      >/dev/null || { echo "error: jq not found (VMAF JSON parsing)" >&2; exit 1; }
# word-boundary match: /srt/ alone would also match "srtp"
ffmpeg -hide_banner -protocols 2>/dev/null \
    | awk '{ for (i = 1; i <= NF; i++) if ($i == "srt") f = 1 } END { exit !f }' \
    || { echo "error: ffmpeg lacks libsrt support" >&2; exit 1; }
for filt in libvmaf freezedetect; do
    ffmpeg -hide_banner -filters 2>/dev/null | awk -v f="$filt" '$0 ~ f {ok=1} END{exit !ok}' \
        || { echo "error: ffmpeg lacks ${filt} filter" >&2; exit 1; }
done
ffmpeg -hide_banner -encoders 2>/dev/null | awk '/libx264/{f=1} END{exit !f}' \
    || { echo "error: ffmpeg lacks libx264 encoder" >&2; exit 1; }

WORK_DIR="$(mktemp -d)"
mkdir -p "$OUT_DIR"

# shellcheck source=scripts/benchmark_srt_common.sh
# (run `shellcheck -x` from the repo root so the directive resolves)
source "${SCRIPT_DIR}/benchmark_srt_common.sh"
PSK=$("$MQVPN" --genkey 2>/dev/null)

RECV_PID=""
BENCH_HAD_FAILURE=0
cleanup() {
    if [ -n "$RECV_PID" ]; then
        kill "$RECV_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$RECV_PID" 2>/dev/null || true   # bounded even if TERM is ignored
    fi
    kill_vpn; clear_tc; teardown_netns
    # SRT_BENCH_KEEP=1 preserves the recordings for post-processing
    # (side-by-side comparison videos etc.)
    if [ "$BENCH_HAD_FAILURE" -ne 0 ] || [ "${SRT_BENCH_KEEP:-0}" = "1" ]; then
        echo "NOTE: keeping ${WORK_DIR} (recordings/logs)"
    else
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

# ---- test clips --------------------------------------------------------
# resolve_clip <stream-rate-mbps>: sets CLIP / CLIP_DESC / TS_OFFSET for the
# condition about to run. Each condition streams at its table-defined rate,
# so the clip is per-condition. Default: generated testsrc2 1080p CBR at the
# given rate (cached per rate). SRT_BENCH_CLIP overrides for ALL selected
# conditions — combine with SRT_BENCH_ONLY to give each condition its own
# real-footage clip at the right bitrate.
CLIP=""; CLIP_DESC=""; TS_OFFSET=""
resolve_clip() {
    local rate="$1"
    # SRT_BENCH_CLIP_DIR: directory holding per-rate real-footage clips
    # named clip_<rate>m.mp4 — lets one invocation run every condition
    # with the right clip. SRT_BENCH_CLIP (single file) takes precedence.
    if [ -z "${SRT_BENCH_CLIP:-}" ] && [ -n "${SRT_BENCH_CLIP_DIR:-}" ] \
        && [ -f "${SRT_BENCH_CLIP_DIR}/clip_${rate}m.mp4" ]; then
        SRT_BENCH_CLIP_RESOLVED="${SRT_BENCH_CLIP_DIR}/clip_${rate}m.mp4"
    else
        SRT_BENCH_CLIP_RESOLVED="${SRT_BENCH_CLIP:-}"
    fi
    if [ -n "$SRT_BENCH_CLIP_RESOLVED" ]; then
        CLIP="$SRT_BENCH_CLIP_RESOLVED"
        # Must cover the run duration; the sender is also bounded with -t so
        # an over-long clip cannot stretch the benchmark.
        local len
        len=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$CLIP" 2>/dev/null || true)
        if ! [[ "$len" =~ ^[0-9.]+$ ]]; then
            echo "error: could not read duration of SRT_BENCH_CLIP '${CLIP}' (got '${len}')" >&2
            exit 1
        fi
        awk "BEGIN { exit !($len >= $DURATION) }" || {
            echo "error: SRT_BENCH_CLIP is shorter (${len}s) than duration (${DURATION}s)" >&2
            exit 1
        }
        CLIP_DESC="$(basename "$CLIP") sha256=$(sha256sum "$CLIP" | cut -c1-16)"
    else
        CLIP="${WORK_DIR}/clip_${rate}m.mp4"
        if [ ! -f "$CLIP" ]; then
            echo "Generating test clip (testsrc2 1080p/${FPS}fps/${DURATION}s/${rate}Mbps CBR)..."
            ffmpeg -nostdin -hide_banner -loglevel error -y \
                -f lavfi -i "testsrc2=size=1920x1080:rate=${FPS}" -t "$DURATION" \
                -c:v libx264 -preset veryfast -pix_fmt yuv420p \
                -b:v "${rate}M" -minrate "${rate}M" -maxrate "${rate}M" \
                -bufsize "$(( rate / 4 + 1 ))M" \
                -x264-params "nal-hrd=cbr:keyint=${FPS}" \
                "$CLIP"
        fi
        CLIP_DESC="testsrc2 1080p/${FPS}fps/${DURATION}s h264 ${rate}M CBR (generated)"
    fi

    # mpegts remuxing adds a constant initial PTS offset (~1.4s by default).
    # Measure it from a local remux of THIS clip so a recording's first PTS
    # can be mapped back onto the source timeline for VMAF head alignment.
    # Fail fast: a non-numeric TS_OFFSET would abort analyze() mid-matrix
    # (it gets embedded into awk source).
    local ref="${WORK_DIR}/ref_${rate}m.ts"
    ffmpeg -nostdin -hide_banner -loglevel error -y -i "$CLIP" -c copy -f mpegts "$ref"
    TS_OFFSET=$(ffprobe -v error -select_streams v:0 -show_entries frame=pts_time \
        -of csv=p=0 -read_intervals '%+#1' "$ref")
    TS_OFFSET=${TS_OFFSET%%,*}   # some ffprobe builds emit a trailing comma
    if ! [[ "$TS_OFFSET" =~ ^[0-9.]+$ ]]; then
        echo "error: could not measure mpegts PTS offset for ${CLIP} (got '${TS_OFFSET}')" >&2
        exit 1
    fi
    echo "clip: ${CLIP_DESC}; mpegts PTS offset: ${TS_OFFSET}s"
}

# ---- run one arm -------------------------------------------------------
# video_run <run-id> <target-ip> <latency-ms> <stream-rate-mbps>
# Runs in the PARENT shell (no command substitution: a subshell would hide
# RECV_PID from the EXIT trap). Result path is returned in global REC_FILE.
REC_FILE=""
video_run() {
    local run_id="$1" target_ip="$2" latency_ms="$3" rate_mbps="$4"
    local latency_us=$((latency_ms * 1000))   # ffmpeg srt latency is in us
    # Sender shaping, SRT_BENCH_SENDCAP switch:
    #   on  (default): broadcast-style CBR mux (-muxrate ≈ rate + 3%) plus
    #        the official live config maxbw=0 / inputbw=muxrate / oheadbw=25
    #   off: plain -re-paced mpegts with libsrt default bandwidth control —
    #        the configuration of the original starved-link demo runs
    local muxrate=$(( rate_mbps * 1030000 ))
    local inputbw=$(( muxrate / 8 ))
    local sendcap="&maxbw=0&inputbw=${inputbw}&oheadbw=25"
    local muxargs=(-muxrate "$muxrate")
    if [ "${SRT_BENCH_SENDCAP:-on}" = "off" ]; then
        sendcap=""
        muxargs=()
    fi
    REC_FILE="${WORK_DIR}/${run_id}.ts"
    rm -f "$REC_FILE"   # never let a stale recording masquerade as this run's

    # Process logs go to WORK_DIR (not OUT_DIR): they are diagnostics, kept
    # only when a run fails; OUT_DIR is the tracked archive.
    # ffmpeg (unlike srt-xtransmit) rejects a host-less srt:// URL — spell
    # out 0.0.0.0 for the listener.
    # -nostdin is LOAD-BEARING on both streaming ffmpegs: with a tty stdin,
    # ffmpeg calls tcsetattr, and the timeout-wrapped sender lives in its own
    # (background) process group — the kernel then STOPS it with SIGTTOU and
    # the run hangs silently (diagnosed via strace, 2026-08-01).
    # lossmaxttl on the receiver is part of the unified recommended config
    # (same knob and default as tier 1): without it, multipath reordering
    # triggers an SRT NAK/retrans storm and the C1 arm collapses
    # (measured: VMAF 6.2 vs 90+ with it).
    local lmttl="${SRT_BENCH_LOSSMAXTTL:-32}"
    local rcv_url="srt://0.0.0.0:${SRT_PORT}?mode=listener&latency=${latency_us}"
    [ "$lmttl" != "0" ] && rcv_url="${rcv_url}&lossmaxttl=${lmttl}"
    ip netns exec "$NS_SERVER" ffmpeg -nostdin -hide_banner -loglevel error -y \
        -i "$rcv_url" \
        -c copy "$REC_FILE" > "${WORK_DIR}/${run_id}.rcv.log" 2>&1 &
    RECV_PID=$!
    sleep 1
    if ! kill -0 "$RECV_PID" 2>/dev/null; then
        echo "   ERROR: receiver died at startup (${WORK_DIR}/${run_id}.rcv.log)"
        RECV_PID=""
        return 1
    fi

    timeout --kill-after=10 $((DURATION + 60)) \
        ip netns exec "$NS_CLIENT" ffmpeg -nostdin -hide_banner -loglevel error \
        -re -t "$DURATION" -i "$CLIP" -c copy -f mpegts "${muxargs[@]}" \
        "srt://${target_ip}:${SRT_PORT}?mode=caller&latency=${latency_us}${sendcap}" \
        > "${WORK_DIR}/${run_id}.snd.log" 2>&1 || true

    sleep 3
    # INT → poll → KILL, like tier 1: an ffmpeg listener stuck in SRT accept
    # can ignore INT, and a bare `wait` would then hang the whole matrix.
    kill -INT "$RECV_PID" 2>/dev/null || true
    local deadline=$((SECONDS + 5))
    while kill -0 "$RECV_PID" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do
        sleep 0.2
    done
    kill -9 "$RECV_PID" 2>/dev/null || true
    wait "$RECV_PID" 2>/dev/null || true
    RECV_PID=""
    return 0
}

# ---- metrics -----------------------------------------------------------
# analyze <run-id> <recording.ts>  → fills A_VMAF/A_ERRLINES/A_FREEZE
declare -A A_VMAF A_ERRLINES A_FREEZE
analyze() {
    local run_id="$1" rec="$2"

    if [ ! -s "$rec" ]; then
        BENCH_HAD_FAILURE=1   # keep WORK_DIR: the .ts/logs ARE the evidence
        A_VMAF[$run_id]="no-recording"
        A_ERRLINES[$run_id]="-"; A_FREEZE[$run_id]="-"
        return 0
    fi

    # Truncation check: with libvmaf shortest=1, a run whose sender died at
    # 20s would be compared only over those 20s and could report a HIGH
    # VMAF for a mostly-lost stream. Require ~90% of the intended duration.
    local rec_dur
    rec_dur=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$rec" 2>/dev/null || true)
    if ! [[ "$rec_dur" =~ ^[0-9.]+$ ]] \
       || awk "BEGIN { exit !($rec_dur < 0.9 * $DURATION) }"; then
        BENCH_HAD_FAILURE=1
        A_VMAF[$run_id]="truncated(${rec_dur:-unreadable}s)"
        A_ERRLINES[$run_id]="-"; A_FREEZE[$run_id]="-"
        return 0
    fi

    # 1) decoder error log lines (proxy for corruption — one corrupt frame
    #    can emit several lines, so this is a log-line count, not a frame
    #    count; the summary labels it accordingly)
    local errlog="${WORK_DIR}/${run_id}.errors.log"
    ffmpeg -hide_banner -loglevel error -y \
        -fflags +genpts -i "$rec" -f null - 2> "$errlog" || true
    A_ERRLINES[$run_id]=$(wc -l < "$errlog")

    # 2) freeze seconds — ffmpeg logs "lavfi.freezedetect.freeze_duration: X"
    #    where $NF is already the numeric value. A freeze still open at EOF
    #    has no duration line; flag it with a trailing "+".
    #    fps= CFR-normalizes FIRST: without it, missing frames are bare PTS
    #    gaps that freezedetect never sees (a 5s stall would report 0.0).
    local frlog="${WORK_DIR}/${run_id}.freeze.log"
    ffmpeg -hide_banner -y -fflags +genpts -i "$rec" \
        -vf "fps=${FPS},freezedetect=n=0.001:d=0.5" -f null - 2> "$frlog" || true
    A_FREEZE[$run_id]=$(awk '
        /lavfi\.freezedetect\.freeze_start/    { open = 1 }
        /lavfi\.freezedetect\.freeze_duration/ { sum += $NF; open = 0 }
        END { printf (open ? "%.1f+" : "%.1f"), sum + 0 }' "$frlog")

    # 3) VMAF with head alignment: the recording keeps the sender's mpegts
    #    PTS, so (first rec PTS - TS_OFFSET) = source time of the first
    #    surviving frame. Trim the source by that lead, CFR-normalize both
    #    inside one filtergraph (missing frames become dups = freeze), and
    #    compare. No lossy intermediate encode.
    local rec_first lead
    rec_first=$(ffprobe -v error -select_streams v:0 -show_entries frame=pts_time \
        -of csv=p=0 -read_intervals '%+#1' "$rec" 2>/dev/null || true)
    rec_first=${rec_first%%,*}   # trailing-comma quirk, same as TS_OFFSET
    # A recording broken enough that ffprobe cannot read the first PTS must
    # not crash the analysis (embedding "" or "N/A" into awk source would).
    if ! [[ "$rec_first" =~ ^[0-9.]+$ ]]; then
        BENCH_HAD_FAILURE=1
        A_VMAF[$run_id]="pts-unreadable"
        return 0
    fi
    lead=$(awk "BEGIN { o = ($rec_first) - ($TS_OFFSET); if (o < 0) o = 0; printf \"%.3f\", o }")
    local vmafjson="${WORK_DIR}/${run_id}.vmaf.json"
    if ffmpeg -hide_banner -loglevel error \
        -fflags +genpts -i "$rec" -ss "$lead" -i "$CLIP" \
        -lavfi "[0:v]fps=${FPS},settb=AVTB,setpts=PTS-STARTPTS[d];[1:v]fps=${FPS},settb=AVTB,setpts=PTS-STARTPTS[r];[d][r]libvmaf=log_fmt=json:log_path=${vmafjson}:shortest=1:n_threads=$(nproc)" \
        -f null - 2>> "${WORK_DIR}/${run_id}.analyze.log"; then
        # `|| true`: a malformed/truncated JSON must land in the parse-err
        # branch below, not abort the script via set -e on jq's exit code.
        A_VMAF[$run_id]=$(jq -r '.pooled_metrics.vmaf.mean // empty' "$vmafjson" 2>/dev/null || true)
        if [ -z "${A_VMAF[$run_id]}" ]; then
            # A wrong jq path must count as a failure: otherwise WORK_DIR
            # (and the vmaf.json needed to FIX the path) is deleted at exit.
            BENCH_HAD_FAILURE=1
            A_VMAF[$run_id]="parse-err"
        fi
    else
        BENCH_HAD_FAILURE=1
        A_VMAF[$run_id]="vmaf-failed"
    fi

    # 4) stills: first detected freeze instant (if any) + one fixed sample.
    #    Fixed timestamps alone can miss stochastic C3 corruption entirely;
    #    2 stills/run (8 total) keeps the tracked archive small — the claim
    #    needs one ugly frame and one clean frame.
    local ft t
    ft=$(awk -F': ' '/lavfi\.freezedetect\.freeze_start/ { printf "%.0f", $NF; exit }' "$frlog" || true)
    for t in ${ft:+"$ft"} 30; do
        # OUTPUT seek (-ss AFTER -i): decode from the start so the extracted
        # frame is fully reconstructed. Input seek lands mid-GOP on mpegts
        # and produces reference-less garbage frames even from clean
        # recordings — which defeats the whole point of comparison stills.
        ffmpeg -nostdin -hide_banner -loglevel error -y -fflags +genpts \
            -i "$rec" -ss "$t" -frames:v 1 \
            "${OUT_DIR}/${run_id}_t${t}.png" || true
    done
}

# ---- main --------------------------------------------------------------
setup_netns
generate_cert

# GEMODEL comes from benchmark_srt_common.sh (shared with tier 1)
RUNS=()

# video_condition <cond> <rate_a> <netem_a> <rate_b> <netem_b> <latency-ms> <stream-rate-mbps>
CLIP_NOTES=()
video_condition() {
    local cond="$1" rate_a="$2" netem_a="$3" rate_b="$4" netem_b="$5" lat="$6"
    local stream_rate="$7"

    # Same condition filter as tier 1 (needed to pair each condition with
    # its own clip via SRT_BENCH_ONLY + SRT_BENCH_CLIP)
    case ",${SRT_BENCH_ONLY:-}," in
        ,,|*",${cond},"*) : ;;
        *)
            echo "== [${cond}] skipped (SRT_BENCH_ONLY=${SRT_BENCH_ONLY})"
            return 0
            ;;
    esac

    resolve_clip "$stream_rate"
    CLIP_NOTES+=("- clip [${cond}]: ${CLIP_DESC}")
    apply_tc_full "$rate_a" "$netem_a" "$rate_b" "$netem_b"

    local arm run_id ok
    for arm in direct-A mqvpn-2path; do
        run_id="${cond}_${arm}"
        RUNS+=("$run_id")
        echo "== ${run_id}"
        # Clear this run's stale stills up front — EVERY failure path below
        # (vpn-failed, run-failed, analyze early returns) must not leave a
        # previous invocation's PNGs to be swept into the tracked archive.
        rm -f "${OUT_DIR}/${run_id}"_t*.png
        ok=1
        if [ "$arm" = mqvpn-2path ]; then
            if ! run_vpn "$SCHEDULER" bench-a0 bench-b0; then
                # kill_vpn even on setup failure: a half-started server would
                # hold port 4433 and cascade the failure into later runs.
                kill_vpn
                BENCH_HAD_FAILURE=1
                A_VMAF[$run_id]="vpn-failed"
                A_ERRLINES[$run_id]="-"; A_FREEZE[$run_id]="-"
                continue
            fi
            video_run "$run_id" "$TUN_SERVER_IP" "$lat" "$stream_rate" || ok=0
            kill_vpn
        else
            video_run "$run_id" "$PATH_A_SERVER_IP" "$lat" "$stream_rate" || ok=0
        fi
        if [ "$ok" -eq 0 ]; then
            BENCH_HAD_FAILURE=1
            A_VMAF[$run_id]="run-failed"
            A_ERRLINES[$run_id]="-"; A_FREEZE[$run_id]="-"
            continue
        fi
        analyze "$run_id" "$REC_FILE"
        echo "   vmaf=${A_VMAF[$run_id]} errlines=${A_ERRLINES[$run_id]:-?} freeze=${A_FREEZE[$run_id]:-?}s"
    done
    clear_tc
}

# Conditions: V1 is a tier-2-only visual-demo condition (defined in the
# report's conditions section): two weak uplinks (congested cellular /
# ADSL class) that cannot carry a standard FHD distribution bitrate
# individually. The rest match the tier-1 table. C3h hardcodes the same
# harsher gemodel that tier 1 reaches via SRT_BENCH_GEMODEL, so a single
# invocation covers the full tier-2 matrix.
video_condition V1 \
    "6mbit" "delay 20ms limit 70" \
    "6mbit" "delay 20ms limit 70" 150 8
video_condition C5 \
    "40mbit" "delay 40ms 20ms limit 750 loss 0.2%" \
    "30mbit" "delay 60ms 30ms limit 600 loss 0.4%" 250 42
video_condition C3 \
    "100mbit" "delay 50ms limit 1450 ${GEMODEL}" \
    "100mbit" "delay 50ms limit 1450" 120 25
video_condition C3h \
    "100mbit" "delay 50ms limit 1450 loss gemodel 4% 30% 80% 0.5%" \
    "100mbit" "delay 50ms limit 1450" 120 25

SUMMARY="${OUT_DIR}/summary.md"
{
    echo "# SRT real-video quality — tier 2 results"
    echo ""
    echo "- date: $(date '+%Y-%m-%d %H:%M')  kernel: $(uname -r)"
    for note in "${CLIP_NOTES[@]}"; do echo "$note"; done
    echo "- ffmpeg: $(ffmpeg -version 2>/dev/null | head -1)"
    echo "- C3 gemodel: ${GEMODEL}"
    echo ""
    echo "| run | VMAF (mean) | decoder error log lines | freeze (s) |"
    echo "|---|---|---|---|"
    for r in "${RUNS[@]}"; do
        echo "| $r | ${A_VMAF[$r]:-?} | ${A_ERRLINES[$r]:-?} | ${A_FREEZE[$r]:-?} |"
    done
} | tee "$SUMMARY"
echo "Stills + summary in ${OUT_DIR}"

if [ "$BENCH_HAD_FAILURE" -ne 0 ]; then
    echo "BENCHMARK INCOMPLETE: one or more runs failed (see sentinel rows above)" >&2
    exit 1
fi
