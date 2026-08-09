#!/bin/bash
# scripts/benchmark_rtmp_video.sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# RTMP tier-2 (real-video) bench: direct single-link vs mqvpn hybrid lane,
# publishing a looped real clip instead of tier 1's synthetic testsrc2.
# Conds : R1 starvation, R3 flap (subset of the tier-1 table; see
#         scripts/benchmark_rtmp.sh for the full matrix and R2).
# Arms  : direct-a, mqvpn-hybrid (mqvpn-datagram is tier-1/internal-only).
# Output: per-cell DVR FLVs are stitched into one continuous timeline.mp4
#         (dead air rendered as an explicit slate, never silently skipped),
#         freeze-seconds are measured on that timeline, and each condition
#         gets a side-by-side direct-vs-mqvpn comparison video.
#
# Usage: sudo ./scripts/benchmark_rtmp_video.sh [mqvpn-binary]
#        RTMP_BENCH_CLIP_DIR=<dir>  → directory holding clip_8m.mp4 (default:
#                                     $HOME/workspace/oss-speedify-proj/tools/clips)
#        RTMP_BENCH_OUT=<dir>       → output dir (default: timestamped)
set -euo pipefail

MQVPN="${1:-build-lib/mqvpn}"
[ -x "$MQVPN" ] || { echo "mqvpn binary not found: $MQVPN"; exit 1; }
MQVPN="$(readlink -f "$MQVPN")"
[ "$(id -u)" -eq 0 ] || { echo "needs root (netns)"; exit 1; }

# sourced before preflight so it can use the common lib's constants
# (both common files are side-effect-free at source time)
# shellcheck source=benchmark_rtmp_common.sh
# (run `shellcheck -x` from scripts/ cwd, per the task's verify recipe, so
# this relative directive resolves)
. "$(dirname "$0")/benchmark_rtmp_common.sh"

CLIP_DIR="${RTMP_BENCH_CLIP_DIR:-$HOME/workspace/oss-speedify-proj/tools/clips}"
CLIP="${CLIP_DIR}/clip_8m.mp4"

# preflight: fail fast with a clear message instead of a mid-matrix cell
# failure from a missing dependency. DRAWTEXT_FONT stays empty when
# fontconfig alone resolves drawtext's default font; only set when an
# explicit fontfile is required (checked below).
missing=()
command -v nginx >/dev/null 2>&1 || missing+=("nginx")
[ -e "$NGINX_RTMP_MODULE" ] || missing+=("nginx-rtmp module ($NGINX_RTMP_MODULE)")
command -v ffmpeg >/dev/null 2>&1 || missing+=("ffmpeg")
command -v ffprobe >/dev/null 2>&1 || missing+=("ffprobe")
command -v python3 >/dev/null 2>&1 || missing+=("python3")
[ -f "$CLIP" ] || missing+=("clip not found: ${CLIP} (set RTMP_BENCH_CLIP_DIR to the directory containing clip_8m.mp4)")

DRAWTEXT_FONT=""
if command -v ffmpeg >/dev/null 2>&1; then
    for filt in freezedetect drawtext; do
        ffmpeg -hide_banner -filters 2>/dev/null | awk -v f="$filt" '$0 ~ f {ok=1} END{exit !ok}' \
            || missing+=("ffmpeg ${filt} filter")
    done
    # field-match (not substring): -encoders output's 2nd column is the
    # exact codec name, so a substring match like /aac/ would also pass on
    # an unrelated encoder whose name merely contains "aac".
    ffmpeg -hide_banner -encoders 2>/dev/null | awk '$2=="libx264"{f=1} END{exit !f}' \
        || missing+=("ffmpeg libx264 encoder")
    ffmpeg -hide_banner -encoders 2>/dev/null | awk '$2=="aac"{f=1} END{exit !f}' \
        || missing+=("ffmpeg aac encoder")
    # drawtext needs either fontconfig defaults or an explicit fontfile; a
    # missing font must fail HERE, not 40 minutes into the matrix inside
    # compose_timeline/render_sbs.
    if ! ffmpeg -nostdin -hide_banner -loglevel error \
            -f lavfi -i "color=c=black:s=64x64:r=1:d=0.1" \
            -vf "drawtext=text=x" -frames:v 1 -f null - >/dev/null 2>&1; then
        for cand in /usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf \
                    /usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf; do
            [ -f "$cand" ] || continue
            if ffmpeg -nostdin -hide_banner -loglevel error \
                    -f lavfi -i "color=c=black:s=64x64:r=1:d=0.1" \
                    -vf "drawtext=text=x:fontfile=${cand}" -frames:v 1 -f null - >/dev/null 2>&1; then
                DRAWTEXT_FONT="$cand"
                break
            fi
        done
        if [ -z "$DRAWTEXT_FONT" ]; then
            missing+=("ffmpeg drawtext usable font (fontconfig default and DejaVu/Liberation fontfile both failed)")
        fi
    fi
fi

# Clip geometry/audio: compose_timeline re-encodes every session FLV and
# slate to IDENTICAL codec params (x264/yuv420p/30fps/aac-48k-stereo) but
# does NOT scale or synthesize audio — it trusts the clip matches the
# 1920x1080 slates already. A non-1080p or audio-less clip would still
# concat successfully (uniform codec params is all `-f concat` checks) and
# silently produce a squashed/misaligned or audio-drifting timeline. Assert
# both here, with the actual probed values, instead of discovering it in a
# finished artifact.
if [ -f "$CLIP" ] && command -v ffprobe >/dev/null 2>&1; then
    clip_wh=$(ffprobe -v error -select_streams v:0 -show_entries stream=width,height \
        -of csv=s=x:p=0 "$CLIP" 2>/dev/null || true)
    if [ "$clip_wh" != "1920x1080" ]; then
        missing+=("clip geometry: ${CLIP} probed as '${clip_wh:-unreadable}', need 1920x1080 (compose_timeline asserts this in preflight rather than scaling — see its codec-params comment)")
    fi
    clip_audio_streams=$( (ffprobe -v error -select_streams a -show_entries stream=index \
        -of csv=p=0 "$CLIP" 2>/dev/null || true) | awk 'END{print NR+0}')
    if [ "$clip_audio_streams" -eq 0 ]; then
        missing+=("clip audio: ${CLIP} probed with 0 audio streams, need >=1 (session segments/slates are re-encoded to aac 48kHz stereo and need a source track)")
    fi
fi

if [ "${#missing[@]}" -gt 0 ]; then
    echo "missing dependencies:"
    printf '  - %s\n' "${missing[@]}"
    exit 1
fi

OUT_DIR="${RTMP_BENCH_OUT:-bench_results/rtmp/tier2_$(date +%Y%m%d_%H%M%S)}"
WORK_DIR="$(mktemp -d /tmp/rtmp-bench-video.XXXXXX)"
PSK="rtmp-bench-video-psk"

# compose_timeline's concat list uses `file '<path>'` quoting (ffmpeg concat
# demuxer syntax): a single-quote inside OUT_DIR/WORK_DIR (e.g. an operator
# passing RTMP_BENCH_OUT="/tmp/joe's-run") would break that quoting and
# either fail ffmpeg or, worse, get silently misparsed. Reject it up front.
case "$OUT_DIR$WORK_DIR" in
    *"'"*)
        echo "error: OUT_DIR/WORK_DIR must not contain a single-quote (concat list uses file '<path>' quoting): OUT_DIR=$OUT_DIR WORK_DIR=$WORK_DIR"
        exit 1
        ;;
esac

mkdir -p "$OUT_DIR"

cleanup() {
    if [ -n "${PUBLISHER_FFMPEG_PID:-}" ]; then
        kill -9 "$PUBLISHER_FFMPEG_PID" 2>/dev/null || true
    fi
    stop_flv_sampler; stop_flap; kill_vpn; stop_ingest
    clear_tc; teardown_netns
    rm -rf "$WORK_DIR"
    # also on abort paths — a set -e exit must not leave root-owned results
    # RTMP_BENCH_CHOWN is a verbatim chown owner spec (e.g. "1000:1000")
    # for environments where SUDO_USER is unset, e.g. docker.
    if [ -n "${RTMP_BENCH_CHOWN:-}" ] && [ -d "$OUT_DIR" ]; then
        chown -R "$RTMP_BENCH_CHOWN" "$OUT_DIR"
    elif [ -n "${SUDO_USER:-}" ] && [ -d "$OUT_DIR" ]; then
        chown -R "$SUDO_USER:" "$OUT_DIR"
    fi
}
trap cleanup EXIT

ARMS=(direct-a mqvpn-hybrid)

# cond | rate_a | netem_a | rate_b | netem_b | duration_s | flap(down:up|empty)
# Same shaping/durations as the tier-1 driver's R1/R3 rows; R2 (burst loss)
# and mqvpn-datagram are tier-1/internal-only and out of scope here.
CONDS=(
  "R1|6mbit|delay 20ms limit 70|6mbit|delay 20ms limit 70|60|"
  "R3|12mbit|delay 10ms limit 200|12mbit|delay 30ms limit 300|120|30:60"
)

for arm in "${ARMS[@]}"; do
    arm_ini "$arm" >/dev/null || exit 1
done

# ---- gap + timeline composition -----------------------------------------

# compute_gaps <flv-samples-csv> <name=duration-1> [<name=duration-2> ...]
# Args after the csv are FLV basenames with their ffprobe'd MEDIA duration
# (seconds), chronological order. Prints one inter-session gap per
# consecutive pair on stdout; derivation to stderr (the values it derived,
# per G19).
#
# gap[i] = first_growth(next) - (first_growth(this) + media_duration(this))
#
# Deliberately NOT last-growth based: nginx's record module buffers writes
# and flushes the tail when the SESSION CLOSES, and a publisher that dies
# behind a downed link only closes when the link returns — so the file's
# last byte growth lands at link-restore, not when media stopped (observed:
# 28.6s of media, last growth 32s later, which collapsed a 33s dead-air
# slate to 0.77s). first_growth + media duration marks where the media
# actually ended on the wall clock. A growth sample is a row whose
# total_bytes increased AND whose "newest" column names this basename
# (record_unique grows one file at a time).
compute_gaps() {
    local samples="$1"; shift
    python3 - "$samples" "$@" <<'PYEOF'
import csv, sys

samples_path = sys.argv[1]
order = []
dur = {}
for spec in sys.argv[2:]:
    name, _, d = spec.rpartition("=")
    order.append(name)
    dur[name] = float(d)

rows = []
with open(samples_path) as f:
    for r in csv.DictReader(f):
        try:
            rows.append((float(r["ts"]), int(r["total_bytes"]), r["newest"]))
        except (KeyError, ValueError):
            continue
rows.sort(key=lambda r: r[0])

first_growth = {b: None for b in order}
prev_bytes = None
for ts, b, newest in rows:
    if prev_bytes is not None and b > prev_bytes and newest in first_growth:
        if first_growth[newest] is None:
            first_growth[newest] = ts
    prev_bytes = b

gaps = []
for i in range(len(order) - 1):
    a, b = order[i], order[i + 1]
    if first_growth[a] is None or first_growth[b] is None:
        print(f"compute_gaps: no growth observed for {a!r} "
              f"(first_growth={first_growth[a]}) or {b!r} "
              f"(first_growth={first_growth[b]})", file=sys.stderr)
        sys.exit(1)
    media_end = first_growth[a] + dur[a]
    gap = first_growth[b] - media_end
    print(f"compute_gaps: gap[{i}] = first_growth({b})={first_growth[b]:.3f} "
          f"- (first_growth({a})={first_growth[a]:.3f} + dur={dur[a]:.3f}) "
          f"= {gap:.3f}", file=sys.stderr)
    if gap < 0:
        print(f"compute_gaps: gap[{i}] negative ({gap:.3f}); clamping to 0 "
              f"(nginx buffering skew)", file=sys.stderr)
        gap = 0.0
    gaps.append(gap)

print(f"compute_gaps: media={sum(dur[n] for n in order):.1f}s "
      f"slates={sum(gaps):.1f}s", file=sys.stderr)
print(" ".join(f"{g:.3f}" for g in gaps))
PYEOF
}

# compose_timeline <cell-dir> <out.mp4>
# Stitches the cell's DVR FLVs (one per publish session, record_unique on)
# into one continuous timeline, with an explicit black+silence
# "signal lost" slate filling every inter-session gap — dead air must be
# visible in the artifact, never silently concatenated away.
compose_timeline() {
    local cell="$1" out="$2"
    local dvr="$cell/dvr"
    local work="$cell/timeline_work"
    mkdir -p "$work"

    # FLVs in creation order (mtime). Tab-delimited so filenames with
    # spaces survive `cut` (find -printf + awk field-splitting would not).
    mapfile -t flvs < <(find "$dvr" -maxdepth 1 -name '*.flv' -printf '%T@\t%p\n' 2>/dev/null \
        | sort -n -k1,1 | cut -f2-)

    # Drop stub FLVs that never received media. nginx's record module opens
    # the file at publish START, so a reconnect attempt that connects but
    # dies before any media arrives leaves a 0-byte FLV with no qualifying
    # session (observed in R3: the retry landing 0.4s after flap-up races
    # the lingering previous publisher and is rejected). Filter by SIZE,
    # not by growth-sample ownership: at link restore three events coincide
    # (previous session's close-flush grows total_bytes, the stub is
    # created = newest by mtime, the next session starts), so the sampler
    # can attribute the flush growth to the stub — observed: a 0-byte FLV
    # owning 2 growth samples. A real session is >=0.5s of 8 Mbps
    # (~500 KB), so a <4 KB file is unambiguously a stub.
    local kept=() f sz
    for f in "${flvs[@]}"; do
        sz=$(stat -c %s "$f")
        if [ "$sz" -ge 4096 ]; then
            kept+=("$f")
        else
            echo "compose_timeline: ignoring stub FLV $(basename "$f") (${sz} bytes < 4096)" >&2
        fi
    done
    flvs=("${kept[@]}")
    local flv_count=${#flvs[@]}

    # "sessions that sent bytes": a session counts only if its lag.N.csv
    # shows out_time_us advance past 0 (same "started" test rtmp_analyze.py's
    # session_lags() uses). Chosen because it is the one signal that is
    # unambiguously per-session (flv_samples.csv is a GLOBAL byte counter,
    # not per-file) and directly reflects "ffmpeg actually produced encoded
    # output for this session" rather than merely "connected". With stub
    # FLVs filtered above, the two counts are expected to agree; a
    # disagreement means the two data sources disagree about what happened
    # and the cell is not trustworthy — hence the hard fail below rather
    # than a guess.
    local qualifying=0 n=1
    while [ -f "$cell/lag.$n.csv" ]; do
        if awk -F, 'NR>1 && $2+0>0 {f=1} END{exit !f}' "$cell/lag.$n.csv"; then
            qualifying=$((qualifying + 1))
        fi
        n=$((n + 1))
    done

    if [ "$flv_count" -ne "$qualifying" ]; then
        echo "compose_timeline: FLV/session count mismatch in $cell: flv_count=$flv_count qualifying_sessions=$qualifying" >&2
        return 1
    fi
    if [ "$flv_count" -eq 0 ]; then
        echo "compose_timeline: no FLVs recorded in $dvr (0 qualifying sessions)" >&2
        return 1
    fi

    local basenames=() f
    for f in "${flvs[@]}"; do basenames+=("$(basename "$f")"); done

    # media duration per FLV — the wallclock anchor for gap math (see the
    # compute_gaps comment for why last-growth timestamps cannot be used)
    local durspecs=() d
    for f in "${flvs[@]}"; do
        if ! d=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$f"); then
            echo "compose_timeline: ffprobe duration failed for $f" >&2
            return 1
        fi
        d="${d%%,*}"   # some ffprobe builds append a trailing comma in csv output
        durspecs+=("$(basename "$f")=$d")
    done

    local gaps=()
    if [ "$flv_count" -gt 1 ]; then
        local gapline
        if ! gapline=$(compute_gaps "$cell/flv_samples.csv" "${durspecs[@]}"); then
            echo "compose_timeline: gap computation failed for $cell (see compute_gaps stderr above)" >&2
            return 1
        fi
        read -r -a gaps <<<"$gapline"
        if [ "${#gaps[@]}" -ne $((flv_count - 1)) ]; then
            echo "compose_timeline: expected $((flv_count - 1)) gaps, computed ${#gaps[@]}" >&2
            return 1
        fi
    fi

    # Re-encode every session FLV and every slate to IDENTICAL codec params
    # (x264 veryfast, yuv420p, 30fps, aac 48kHz stereo) — the concat
    # demuxer requires uniform params across segments; stream-copying the
    # source FLVs (variable fps/keyframes/audio) into one concat would not
    # produce a clean timeline.mp4, so re-encoding here is required. Source
    # geometry (1920x1080, matching the slates) is asserted in preflight,
    # not normalized here — no -vf scale is applied, so a clip that somehow
    # bypassed preflight would still concat "successfully" at the wrong size.
    local list="$work/concat.txt"
    : >"$list"
    local i=0
    for f in "${flvs[@]}"; do
        local seg="$work/session_${i}.mp4"
        if ! ffmpeg -nostdin -hide_banner -y -i "$f" \
                -c:v libx264 -preset veryfast -pix_fmt yuv420p -r 30 \
                -c:a aac -ar 48000 -ac 2 \
                "$seg" >"$work/session_${i}.log" 2>&1; then
            echo "compose_timeline: re-encode failed for $f (see $work/session_${i}.log)" >&2
            return 1
        fi
        printf "file '%s'\n" "$(readlink -f "$seg")" >>"$list"

        if [ "$i" -lt "${#gaps[@]}" ] && awk -v g="${gaps[$i]}" 'BEGIN { exit !(g < 0.5) }'; then
            # below the 1s dead-air threshold and too short for a readable
            # slate; ffmpeg also misbehaves with near-zero -t
            echo "compose_timeline: skipping negligible gap[$i]=${gaps[$i]}s (< 0.5s)" >&2
        elif [ "$i" -lt "${#gaps[@]}" ]; then
            local gap="${gaps[$i]}"
            local slate="$work/slate_${i}.mp4"
            local ft=""
            if [ -n "$DRAWTEXT_FONT" ]; then ft=":fontfile=${DRAWTEXT_FONT}"; fi
            if ! ffmpeg -nostdin -hide_banner -y \
                    -f lavfi -i "color=c=black:s=1920x1080:r=30" \
                    -f lavfi -i "anullsrc=r=48000:cl=stereo" \
                    -t "$gap" \
                    -vf "drawtext=text='signal lost (reconnecting)':fontcolor=white:fontsize=48:box=1:boxcolor=black@0.6:x=(w-text_w)/2:y=(h-text_h)/2${ft}" \
                    -c:v libx264 -preset veryfast -pix_fmt yuv420p \
                    -c:a aac -ar 48000 -ac 2 \
                    "$slate" >"$work/slate_${i}.log" 2>&1; then
                echo "compose_timeline: slate encode failed for gap $i (${gap}s, see $work/slate_${i}.log)" >&2
                return 1
            fi
            printf "file '%s'\n" "$(readlink -f "$slate")" >>"$list"
        fi
        i=$((i + 1))
    done

    if ! ffmpeg -nostdin -hide_banner -y -f concat -safe 0 -i "$list" -c copy "$out" \
            >"$work/concat.log" 2>&1; then
        echo "compose_timeline: concat failed (see $work/concat.log)" >&2
        return 1
    fi
    echo "compose_timeline: $cell -> $out (${flv_count} sessions, ${#gaps[@]} gaps: ${gaps[*]:-none})"
    return 0
}

# run_freezedetect <timeline.mp4> — prints freeze seconds (slates count as
# freeze intentionally: a viewer experiences dead air as a freeze). The
# ffmpeg call is wrapped with `|| true` so a decode error still lets awk
# read to EOF and print whatever partial sum it saw, instead of tripping
# pipefail on the assignment at the call site. Note: freezedetect only
# emits freeze_duration on THAW, so a freeze still in progress at EOF is
# undercounted (missing from the sum entirely). This is bounded, not
# unbounded, because the timeline's last segment is always a session
# (compose_timeline never ends on a slate), so any freeze open at EOF is at
# most that last session's own trailing freeze, not an entire missed gap.
run_freezedetect() {
    local timeline="$1"
    { ffmpeg -nostdin -hide_banner -i "$timeline" \
        -vf "freezedetect=n=-60dB:d=2" -an -f null - 2>&1 || true; } \
        | awk '/lavfi\.freezedetect\.freeze_duration/ { sum += $NF } END { printf "%.1f", sum + 0 }'
}

# render_sbs <left.mp4> <right.mp4> <out.mp4> — hstack, each side scaled to
# 960x540, labelled. Audio: both arms publish the SAME looped source clip,
# so left's (direct-a's) audio track stands in for the pair rather than
# mixing two near-duplicate tracks (which would just phase/echo); `0:a?`
# keeps this optional so a left segment with no audio doesn't hard-fail.
render_sbs() {
    local left="$1" right="$2" out="$3"
    local ft=""
    if [ -n "$DRAWTEXT_FONT" ]; then ft=":fontfile=${DRAWTEXT_FONT}"; fi
    ffmpeg -nostdin -hide_banner -y -i "$left" -i "$right" -filter_complex \
        "[0:v]scale=960:540,drawtext=text='direct (single link)':fontcolor=white:fontsize=28:box=1:boxcolor=black@0.6:x=10:y=10${ft}[l];[1:v]scale=960:540,drawtext=text='mqvpn (bonded)':fontcolor=white:fontsize=28:box=1:boxcolor=black@0.6:x=10:y=10${ft}[r];[l][r]hstack=inputs=2[v]" \
        -map "[v]" -map 0:a? \
        -c:v libx264 -preset veryfast -pix_fmt yuv420p -c:a aac -ar 48000 -ac 2 \
        "$out" >"${out}.log" 2>&1
}

# ---- main ----------------------------------------------------------------

setup_netns
setup_ingest_alias
generate_cert
write_rtmp_inis

declare -A ROW_SESSIONS ROW_DEADAIR ROW_FREEZE ROW_TIMELINE SBS
failed=0

for spec in "${CONDS[@]}"; do
    IFS='|' read -r cond rate_a netem_a rate_b netem_b dur flap <<<"$spec"
    echo "=== $cond  A:${rate_a}/${netem_a}  B:${rate_b}/${netem_b}  dur=${dur}s flap=${flap:-none} ==="
    apply_tc_full "$rate_a" "$netem_a" "$rate_b" "$netem_b"

    for arm in "${ARMS[@]}"; do
        key="$cond,$arm"
        cell="$OUT_DIR/${cond}_${arm}"
        # wipe stale artifacts from a prior attempt at this cell (a reused
        # RTMP_BENCH_OUT must not let old DVR/lag files corrupt this run)
        rm -rf "$cell"
        mkdir -p "$cell"
        echo "  [$key] ..."
        ok=1
        reason=""
        start_ingest "$cell" || { ok=0; reason="ingest failed to start"; }
        if [ "$ok" -eq 1 ] && [ "$arm" != "direct-a" ]; then
            run_vpn_rtmp "$arm" bench-a0 bench-b0 || { ok=0; reason="vpn setup failed"; }
        fi
        if [ "$ok" -eq 1 ]; then
            start_flv_sampler "$cell/dvr" "$cell/flv_samples.csv"
            if [ -n "$flap" ]; then
                schedule_flap "${flap%%:*}" "${flap##*:}" "$cell/flap.log"
            fi
            run_publisher "$cell" \
                "rtmp://$(arm_target "$arm"):${RTMP_PORT}/live/bench" \
                "$dur" -- -re -stream_loop -1 -i "$CLIP"
            wait_flap
            stop_flv_sampler
        fi
        kill_vpn
        stop_ingest
        # restore path A state in case a failed run aborted mid-flap
        ip netns exec "$NS_CLIENT" ip link set bench-a0 up 2>/dev/null || true
        ip netns exec "$NS_CLIENT" ip addr replace "${PATH_A_CLIENT_IP}/24" dev bench-a0 2>/dev/null || true

        row=""
        if [ "$ok" -eq 1 ]; then
            if ! row=$(python3 "$(dirname "$0")/../benchmarks/rtmp_analyze.py" \
                    cell --cell-dir "$cell" --cond "$cond" --arm "$arm" --rep 1 --duration "$dur"); then
                ok=0; reason="rtmp_analyze.py cell exited nonzero (see stderr)"
            fi
        fi

        timeline="$cell/timeline.mp4"
        if [ "$ok" -eq 1 ] && ! compose_timeline "$cell" "$timeline"; then
            ok=0; reason="compose_timeline failed"
        fi

        freeze_s="-"
        if [ "$ok" -eq 1 ]; then
            freeze_s=$(run_freezedetect "$timeline")
        fi

        if [ "$ok" -eq 1 ]; then
            sessions=$(echo "$row" | awk -F, '{print $4}')
            dead_air=$(echo "$row" | awk -F, '{print $6}')
            echo "    -> OK sessions=$sessions dead_air_s=$dead_air freeze_s=$freeze_s"
            ROW_SESSIONS["$key"]="$sessions"
            ROW_DEADAIR["$key"]="$dead_air"
            ROW_FREEZE["$key"]="$freeze_s"
            ROW_TIMELINE["$key"]="$timeline"
        else
            echo "    -> FAILED ($reason) — artifacts kept in $cell"
            failed=$((failed + 1))
            ROW_SESSIONS["$key"]="FAILED"
            ROW_DEADAIR["$key"]="FAILED"
            ROW_FREEZE["$key"]="FAILED ($reason)"
            ROW_TIMELINE["$key"]="-"
        fi
    done

    sbs="$OUT_DIR/${cond}_sbs.mp4"
    # Clear any stale sbs (and its log) up front — a reused RTMP_BENCH_OUT
    # must not let a PRIOR run's side-by-side masquerade as this run's,
    # whether this run regenerates it below or skips it because an arm
    # FAILED.
    rm -f "$sbs" "${sbs}.log"
    if [ "${ROW_TIMELINE[$cond,direct-a]:--}" != "-" ] && [ "${ROW_TIMELINE[$cond,mqvpn-hybrid]:--}" != "-" ]; then
        if render_sbs "${ROW_TIMELINE[$cond,direct-a]}" "${ROW_TIMELINE[$cond,mqvpn-hybrid]}" "$sbs"; then
            echo "  sbs: $sbs"
            SBS["$cond"]="$sbs"
        else
            echo "  WARNING: render_sbs failed for $cond (see ${sbs}.log) — artifacts kept"
            failed=$((failed + 1))
            SBS["$cond"]="-"
        fi
    else
        echo "  skipping sbs for $cond (one or both arms FAILED)"
        SBS["$cond"]="-"
    fi
done
clear_tc

SUMMARY="$OUT_DIR/summary.md"
{
    echo "# RTMP bench — tier 2 (real video) summary"
    echo ""
    echo "- date: $(date '+%Y-%m-%d %H:%M')  kernel: $(uname -r)"
    echo "- ffmpeg: $(ffmpeg -version 2>/dev/null | awk 'NR==1{print; exit}')"
    echo "- clip: $(basename "$CLIP") ($CLIP_DIR), sha256=$(sha256sum "$CLIP" | cut -c1-16)"
    echo ""
    for spec in "${CONDS[@]}"; do
        cond="${spec%%|*}"
        echo "## $cond"
        echo ""
        echo "| arm | sessions | dead_air_s | freeze_s | timeline | sbs |"
        echo "|---|---|---|---|---|---|"
        for arm in "${ARMS[@]}"; do
            key="$cond,$arm"
            echo "| $arm | ${ROW_SESSIONS[$key]:-?} | ${ROW_DEADAIR[$key]:-?} | ${ROW_FREEZE[$key]:-?} | ${ROW_TIMELINE[$key]:--} | ${SBS[$cond]:--} |"
        done
        echo ""
    done
} >"$SUMMARY"

echo "Results in: $OUT_DIR"
echo "Summary: $SUMMARY"
if [ "$failed" -gt 0 ]; then
    echo "WARNING: $failed cell(s)/render(s) FAILED — see $SUMMARY and per-cell artifacts in $OUT_DIR"
    exit 1
fi
