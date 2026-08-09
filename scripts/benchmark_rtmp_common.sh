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
