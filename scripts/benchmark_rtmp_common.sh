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
load_module /usr/lib/nginx/modules/ngx_rtmp_module.so;
error_log $dir/nginx-logs/error.log info;
pid $dir/nginx.pid;
worker_processes 1;
events { worker_connections 128; }
rtmp {
    server {
        listen ${RTMP_PORT};
        chunk_size 4096;
        application live {
            live on;
            record all;
            record_path $dir/dvr;
            record_unique on;
        }
    }
}
EOF
}

# start_ingest <cell-dir> — nginx in NS_SERVER, waits for the listen socket
start_ingest() {
    local dir="$1"
    write_nginx_conf "$dir"
    ip netns exec "$NS_SERVER" nginx -c "$dir/nginx.conf" -p "$dir/nginx-prefix" \
        -g "daemon off;" >"$dir/nginx-logs/stdout.log" 2>&1 &
    INGEST_PID=$!
    local i
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
