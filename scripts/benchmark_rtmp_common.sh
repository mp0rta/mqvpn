# scripts/benchmark_rtmp_common.sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# shellcheck shell=bash
# RTMP bench helpers layered on the SRT bench netns foundation.
# Source this file; do not execute. Caller must set: MQVPN, WORK_DIR, PSK.
# See docs: RTMP arms use product-default scheduler/CC (no --scheduler/--cc
# overrides): the hybrid stream lane is MinRTT by construction, and the
# datagram arm deliberately shows default WLB flow-pinning behaviour.

# shellcheck source=scripts/benchmark_srt_common.sh
. "$(dirname "${BASH_SOURCE[0]}")/benchmark_srt_common.sh"

RTMP_PORT=1935
# Single source of truth for the module path — used by write_nginx_conf's
# load_module AND both drivers' preflight checks (they source this file
# first), so the two can never drift.
NGINX_RTMP_MODULE=/usr/lib/nginx/modules/ngx_rtmp_module.so
# Stream-lane egress target for the mqvpn arms. MUST be outside the tunnel
# subnet: the server egress ACL rejects tunnel-subnet targets BEFORE
# EgressAllow is consulted (src/hybrid/tcp_egress.c,
# svr_tcp_egress_acl_decide — same constraint, and same 10.222 lo-alias
# pattern, as tests/test_e2e_hybrid_h2.sh). Both mqvpn arms publish to this
# alias for target parity; direct-a publishes to the raw path-A address.
RTMP_TARGET_IP=10.222.0.1
TUN_DEV=mqvpn0
INGEST_PID=""
SAMPLER_PID=""
FLAP_PID=""

# write_rtmp_inis — one INI per mqvpn arm, passed to BOTH sides (EgressAllow
# is only meaningful on the server; harmless on the client). Format mirrors
# tests/test_e2e_hybrid_h2.sh (keys cross-checked against src/config.c).
# NOTE: EgressAllow's subnet below must stay in sync with RTMP_TARGET_IP.
write_rtmp_inis() {
    cat >"${WORK_DIR}/hybrid-stream.conf" <<EOF
[Hybrid]
Enabled = true
Tcp = stream
EgressAllow = 10.222.0.0/24
EOF
    cat >"${WORK_DIR}/hybrid-raw.conf" <<EOF
[Hybrid]
Enabled = true
Tcp = raw
EOF
}

# setup_ingest_alias — lo alias in NS_SERVER for the egress target
# (idempotent; call once after setup_netns)
setup_ingest_alias() {
    ip netns exec "$NS_SERVER" ip addr replace ${RTMP_TARGET_IP}/32 dev lo
}

# arm_ini <arm> — echoes the INI path for an mqvpn arm ("" for direct-a)
arm_ini() {
    case "$1" in
        mqvpn-hybrid)   echo "${WORK_DIR}/hybrid-stream.conf" ;;
        mqvpn-datagram) echo "${WORK_DIR}/hybrid-raw.conf" ;;
        direct-a)       echo "" ;;
        *)              echo "arm_ini: unknown arm: $1" >&2; return 1 ;;
    esac
}

# arm_target <arm> — RTMP URL host the publisher connects to
arm_target() {
    case "$1" in
        direct-a) echo "$PATH_A_SERVER_IP" ;;
        mqvpn-*)  echo "$RTMP_TARGET_IP" ;;
        *)        echo "arm_target: unknown arm: $1" >&2; return 1 ;;
    esac
}

# run_vpn_rtmp <arm> <path-iface>...
# Same shape as the SRT run_vpn() but injects the per-arm [Hybrid] INI.
# Uses SERVER_PID/CLIENT_PID so the SRT kill_vpn() is reused as-is.
run_vpn_rtmp() {
    local arm="$1"; shift
    local conf
    conf="$(arm_ini "$arm")" || return 1
    if [ -z "$conf" ]; then
        echo "run_vpn_rtmp: direct arm needs no VPN" >&2
        return 1
    fi
    local path_args=()
    local ifc
    for ifc in "$@"; do
        path_args+=(--path "$ifc")
    done

    ip netns exec "$NS_SERVER" "$MQVPN" \
        --mode server \
        --listen 0.0.0.0:4433 \
        --subnet 10.0.0.0/24 \
        --cert "${WORK_DIR}/server.crt" \
        --key "${WORK_DIR}/server.key" \
        --auth-key "$PSK" \
        --config "$conf" \
        --log-level info >"${WORK_DIR}/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 2
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "    ERROR: server died (see ${WORK_DIR}/server.log)"
        return 1
    fi

    ip netns exec "$NS_CLIENT" "$MQVPN" \
        --mode client \
        --server ${PATH_A_SERVER_IP}:4433 \
        "${path_args[@]}" \
        --auth-key "$PSK" \
        --insecure \
        --config "$conf" \
        --log-level info >"${WORK_DIR}/client.log" 2>&1 &
    CLIENT_PID=$!
    sleep 5
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "    ERROR: client died (see ${WORK_DIR}/client.log)"
        return 1
    fi

    if ! ip netns exec "$NS_CLIENT" ping -c 2 -W 2 "$TUN_SERVER_IP" >/dev/null 2>&1; then
        echo "    ERROR: tunnel not established"
        return 1
    fi

    # Route the egress target into the tunnel: the bench client installs no
    # default route, so without this the flow never reaches the lane
    # classifier at all (e2e adds the same /32 via the tun device).
    ip netns exec "$NS_CLIENT" ip route replace ${RTMP_TARGET_IP}/32 dev "$TUN_DEV"
    if ! ip netns exec "$NS_CLIENT" ping -c 1 -W 2 "$RTMP_TARGET_IP" >/dev/null 2>&1; then
        echo "    ERROR: egress target ${RTMP_TARGET_IP} unreachable through tunnel"
        return 1
    fi
    return 0
}

# ---- RTMP ingest (nginx-rtmp) ------------------------------------------

# write_nginx_conf <cell-dir>
write_nginx_conf() {
    local dir="$1"
    mkdir -p "$dir/dvr" "$dir/nginx-logs" "$dir/nginx-prefix"
    cat >"$dir/nginx.conf" <<EOF
load_module ${NGINX_RTMP_MODULE};
# Workers must stay root: they default to an unprivileged user (nobody
# with this build — no --user configure flag; www-data only when the
# distro conf sets it), which cannot traverse into ~/... (Ubuntu ships
# /home/USER as 750), so the record module fails with "record: failed to
# open file ... (13: Permission denied)" even when the dvr dir itself is
# 0777 (observed). Bench-only conf inside the bench netns; the usual
# privilege-drop rationale does not apply — never reuse this conf outside.
user root;
error_log "$dir/nginx-logs/error.log" info;
pid "$dir/nginx.pid";
worker_processes 1;
events { worker_connections 128; }
rtmp {
    server {
        listen ${RTMP_PORT};
        chunk_size 4096;
        application live {
            live on;
            record all;
            record_path "$dir/dvr";
            record_unique on;
        }
    }
}
EOF
}

# start_ingest <cell-dir> — nginx in NS_SERVER, waits for the listen socket
start_ingest() {
    local dir
    # absolute path required: nginx resolves a relative -c against the -p
    # prefix (observed: prefix + relative conf path concatenated → ENOENT)
    dir="$(readlink -f "$1")"
    write_nginx_conf "$dir"
    ip netns exec "$NS_SERVER" nginx -c "$dir/nginx.conf" -p "$dir/nginx-prefix" \
        -g "daemon off;" >"$dir/nginx-logs/stdout.log" 2>&1 &
    INGEST_PID=$!
    local i
    # shellcheck disable=SC2034  # loop counter only; the bound (40 tries) is the point
    for i in $(seq 1 40); do
        # awk reads ss output to EOF — safe under pipefail (G19)
        if ip netns exec "$NS_SERVER" ss -ltn 2>/dev/null \
            | awk -v p=":${RTMP_PORT}\$" '$4 ~ p {found=1} END {exit !found}'; then
            return 0
        fi
        if ! kill -0 "$INGEST_PID" 2>/dev/null; then
            echo "    ERROR: nginx died (see $dir/nginx-logs/)"
            return 1
        fi
        sleep 0.25
    done
    echo "    ERROR: nginx-rtmp never listened on :${RTMP_PORT}"
    return 1
}

stop_ingest() {
    if [ -n "$INGEST_PID" ]; then
        kill "$INGEST_PID" 2>/dev/null || true
        wait "$INGEST_PID" 2>/dev/null || true
    fi
    INGEST_PID=""
}

# ---- ingest byte-timeline sampler --------------------------------------
# Polls ALL *.flv in the DVR dir every 250 ms; logs epoch, summed bytes,
# newest file (by mtime). record_unique creates one FLV per publish session,
# so a disconnect/re-publish cycle switches files mid-scenario; dead air is
# computed downstream by rtmp_analyze.py on the summed-size timeline.

# start_flv_sampler <dvr-dir> <out-csv>
start_flv_sampler() {
    local dvr="$1" out="$2"
    echo "ts,total_bytes,newest" >"$out"
    (
        while :; do
            total=0; newest=""; newest_m=0
            for f in "$dvr"/*.flv; do
                [ -e "$f" ] || continue
                sz=$(stat -c %s "$f" 2>/dev/null) || continue
                m=$(stat -c %Y "$f" 2>/dev/null) || m=0
                total=$((total + sz))
                if [ "$m" -ge "$newest_m" ]; then newest_m=$m; newest="${f##*/}"; fi
            done
            printf '%s,%s,%s\n' "$(date +%s.%3N)" "$total" "$newest" >>"$out"
            sleep 0.25
        done
    ) &
    SAMPLER_PID=$!
}

stop_flv_sampler() {
    if [ -n "$SAMPLER_PID" ]; then
        kill "$SAMPLER_PID" 2>/dev/null || true
        wait "$SAMPLER_PID" 2>/dev/null || true
    fi
    SAMPLER_PID=""
}

# ---- link flap (R3) -----------------------------------------------------
# Recipe from scripts/ci_e2e/run_admin_down_test.sh: admin down + addr flush
# (platform treats as immediate path drop), restore = up + addr re-add.
# netem qdisc survives down/up (attached to the device).
# NOTE: the subshell inherits set -e — if the down half fails, the up half
# is skipped and bench-a0 stays down. The tier-1 driver's post-cell restore
# (ip link set up + ip addr replace) is the recovery for that case; keep it.

# schedule_flap <down-at-s> <up-at-s> <flap-log>
schedule_flap() {
    local down_at="$1" up_at="$2" log="$3"
    if ! [ "$up_at" -gt "$down_at" ]; then
        echo "schedule_flap: up_at ($up_at) must be > down_at ($down_at)" >&2
        return 1
    fi
    (
        sleep "$down_at"
        ip netns exec "$NS_CLIENT" ip link set bench-a0 down
        ip netns exec "$NS_CLIENT" ip addr flush dev bench-a0
        printf '%s flap-down\n' "$(date +%s.%3N)" >>"$log"
        sleep $((up_at - down_at))
        ip netns exec "$NS_CLIENT" ip link set bench-a0 up
        ip netns exec "$NS_CLIENT" ip addr add ${PATH_A_CLIENT_IP}/24 dev bench-a0
        printf '%s flap-up\n' "$(date +%s.%3N)" >>"$log"
    ) &
    FLAP_PID=$!
}

wait_flap() {
    if [ -n "$FLAP_PID" ]; then
        wait "$FLAP_PID" 2>/dev/null || true
    fi
    FLAP_PID=""
}

# stop_flap — kill + wait + reset FLAP_PID (symmetric with stop_ingest /
# stop_flv_sampler), for snappy abort cleanup instead of waiting out the
# scheduled up-time.
stop_flap() {
    if [ -n "$FLAP_PID" ]; then
        kill "$FLAP_PID" 2>/dev/null || true
        wait "$FLAP_PID" 2>/dev/null || true
    fi
    FLAP_PID=""
}

# ---- publisher: ffmpeg + OBS-like reconnect wrapper ---------------------

WATCHDOG_STALL_S=10
RECONNECT_DELAY_S=2
RECONNECT_CONFIRM_S=3
# Exposed for a driver EXIT trap to kill an orphaned ffmpeg deterministically
# (set next to fpid in run_publisher, cleared after wait).
# shellcheck disable=SC2034  # read by driver scripts, not within this file
PUBLISHER_FFMPEG_PID=""

ev_log() { # <file> <text...>
    local f="$1"; shift
    printf '%s %s\n' "$(date +%s.%3N)" "$*" >>"$f"
}

# progress_out_time_us <progress-file> — last out_time_us, 0 if none yet.
# The `|| printf '0'` fallback keeps this safe under set -e when the file
# is missing or unreadable (awk exits non-zero on open failure).
progress_out_time_us() {
    awk -F= '$1 == "out_time_us" { v = $2 } END { printf "%d", v + 0 }' "$1" 2>/dev/null \
        || printf '0'
}

# run_publisher <cell-dir> <rtmp-url> <scenario-s> -- <ffmpeg input args...>
# Blocks for the whole scenario. Artifacts in <cell-dir>:
#   publisher.events                 connect/stall-kill/exit/reconnect-ok
#   progress.N / ffmpeg.N.log        per publish session
#   lag.N.csv                        ts,out_time_us samples (per session)
run_publisher() {
    local cell="$1" url="$2" scenario_s="$3"; shift 3
    [ "${1:-}" = "--" ] && shift
    local ev="$cell/publisher.events"
    : >"$ev"
    local t0=$SECONDS
    local end=$((SECONDS + scenario_s))
    local session=0
    while [ "$SECONDS" -lt "$end" ]; do
        session=$((session + 1))
        local prog="$cell/progress.$session"
        local lagcsv="$cell/lag.$session.csv"
        : >"$prog"
        echo "ts,out_time_us" >"$lagcsv"
        ip netns exec "$NS_CLIENT" ffmpeg -nostdin -hide_banner -loglevel warning \
            "$@" \
            -c:v libx264 -preset veryfast -b:v 8M -maxrate 8M -bufsize 16M \
            -g 60 -keyint_min 60 -pix_fmt yuv420p \
            -c:a aac -b:a 160k \
            -f flv -progress "$prog" \
            "$url" >"$cell/ffmpeg.$session.log" 2>&1 &
        local fpid=$!
        PUBLISHER_FFMPEG_PID=$fpid
        ev_log "$ev" "connect session=$session"
        local last_out=0 last_change=$SECONDS ok_since=-1 confirmed=0
        while kill -0 "$fpid" 2>/dev/null && [ "$SECONDS" -lt "$end" ]; do
            sleep 0.5
            local cur
            cur=$(progress_out_time_us "$prog")
            printf '%s,%s\n' "$(date +%s.%3N)" "$cur" >>"$lagcsv"
            if [ "$cur" -gt "$last_out" ]; then
                # ok_since = FIRST advance; deliberately not reset on later
                # stalls ("advanced ≥3s after first advance"). Against the
                # 10 s watchdog at 0.5 s polling this cannot materially
                # miscount; keep the definition in sync with rtmp_analyze.py.
                if [ "$ok_since" -lt 0 ]; then ok_since=$SECONDS; fi
                if [ "$session" -gt 1 ] && [ "$confirmed" -eq 0 ] \
                   && [ $((SECONDS - ok_since)) -ge "$RECONNECT_CONFIRM_S" ]; then
                    ev_log "$ev" "reconnect-ok session=$session"
                    confirmed=1
                fi
                last_out=$cur
                last_change=$SECONDS
            else
                if [ $((SECONDS - last_change)) -ge "$WATCHDOG_STALL_S" ]; then
                    ev_log "$ev" "stall-kill session=$session"
                    kill -9 "$fpid" 2>/dev/null || true
                    break
                fi
            fi
        done
        if [ "$SECONDS" -ge "$end" ] && kill -0 "$fpid" 2>/dev/null; then
            # TERM, poll up to 5s, then KILL — ffmpeg blocked in a socket
            # write can ignore TERM; unbounded wait hangs the whole matrix
            # (same pattern as kill_vpn in benchmark_srt_common.sh:158-176).
            kill "$fpid" 2>/dev/null || true
            local deadline=$((SECONDS + 5))
            while kill -0 "$fpid" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do
                sleep 0.2
            done
            kill -9 "$fpid" 2>/dev/null || true
        fi
        set +e
        wait "$fpid" 2>/dev/null
        local rc=$?
        set -e
        # shellcheck disable=SC2034  # cleared for the driver's EXIT trap, not read in this file
        PUBLISHER_FFMPEG_PID=""
        ev_log "$ev" "exit session=$session rc=$rc"
        if [ "$SECONDS" -lt "$end" ]; then
            sleep "$RECONNECT_DELAY_S"
        fi
    done
    ev_log "$ev" "scenario-end sessions=$session elapsed=$((SECONDS - t0))"
}

# tier-1 synthetic source args (1080p30 + tone), infinite; killed at scenario
# end. -re per input (canonical form); tier 2 passes its own
# (-re -stream_loop -1 -i clip) instead.
# shellcheck disable=SC2034  # consumed by driver scripts via "${TIER1_SRC[@]}"
TIER1_SRC=(-re -f lavfi -i "testsrc2=size=1920x1080:rate=30" -re -f lavfi -i "sine=frequency=440:sample_rate=48000")
