# scripts/benchmark_srt_common.sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# shellcheck shell=bash
# Shared netns/tc/VPN helpers + stats CSV parsers for the SRT benchmarks.
# Source this file; do not execute. Caller must set: MQVPN, WORK_DIR, PSK.

NS_CLIENT=bench-client
NS_SERVER=bench-server
PATH_A_CLIENT_IP=192.168.10.1
PATH_A_SERVER_IP=192.168.10.2
PATH_B_CLIENT_IP=192.168.20.1
PATH_B_SERVER_IP=192.168.20.2
TUN_SERVER_IP=10.0.0.1

# C3 burst-loss shaping — single source of truth for BOTH tiers (drift
# between tier 1 and tier 2 would silently corrupt the C3 comparison).
# Default: p=2% good→bad, r=40% bad→good, 70% loss in bad state, 0.1% in
# good → mean loss ≈ 3.3%, expected burst length 2.5 pkts (see spec).
# SRT_BENCH_GEMODEL overrides the four gemodel parameters for severity
# sweeps, e.g. SRT_BENCH_GEMODEL="4% 30% 80% 0.5%" (mean ≈ 10%).
GEMODEL="loss gemodel ${SRT_BENCH_GEMODEL:-2% 40% 70% 0.1%}"

SERVER_PID=""
CLIENT_PID=""

setup_netns() {
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del bench-a0 2>/dev/null || true
    ip link del bench-b0 2>/dev/null || true

    ip netns add "$NS_SERVER"
    ip netns add "$NS_CLIENT"

    ip link add bench-a0 type veth peer name bench-a1
    ip link set bench-a0 netns "$NS_CLIENT"
    ip link set bench-a1 netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add ${PATH_A_CLIENT_IP}/24 dev bench-a0
    ip netns exec "$NS_SERVER" ip addr add ${PATH_A_SERVER_IP}/24 dev bench-a1
    ip netns exec "$NS_CLIENT" ip link set bench-a0 up
    ip netns exec "$NS_SERVER" ip link set bench-a1 up

    ip link add bench-b0 type veth peer name bench-b1
    ip link set bench-b0 netns "$NS_CLIENT"
    ip link set bench-b1 netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add ${PATH_B_CLIENT_IP}/24 dev bench-b0
    ip netns exec "$NS_SERVER" ip addr add ${PATH_B_SERVER_IP}/24 dev bench-b1
    ip netns exec "$NS_CLIENT" ip link set bench-b0 up
    ip netns exec "$NS_SERVER" ip link set bench-b1 up

    ip netns exec "$NS_CLIENT" ip link set lo up
    ip netns exec "$NS_SERVER" ip link set lo up
    ip netns exec "$NS_SERVER" sysctl -w net.ipv4.ip_forward=1 >/dev/null

    ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$PATH_A_SERVER_IP" >/dev/null
    ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$PATH_B_SERVER_IP" >/dev/null
}

teardown_netns() {
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del bench-a0 2>/dev/null || true
    ip link del bench-b0 2>/dev/null || true
}

apply_tc_full() {
    local rate_a="$1" netem_a="$2" rate_b="$3" netem_b="$4"
    clear_tc
    # shellcheck disable=SC2086  # netem args are intentionally word-split
    ip netns exec "$NS_CLIENT" tc qdisc add dev bench-a0 root netem $netem_a rate "$rate_a"
    # shellcheck disable=SC2086
    ip netns exec "$NS_SERVER" tc qdisc add dev bench-a1 root netem $netem_a rate "$rate_a"
    # shellcheck disable=SC2086
    ip netns exec "$NS_CLIENT" tc qdisc add dev bench-b0 root netem $netem_b rate "$rate_b"
    # shellcheck disable=SC2086
    ip netns exec "$NS_SERVER" tc qdisc add dev bench-b1 root netem $netem_b rate "$rate_b"
}

clear_tc() {
    ip netns exec "$NS_CLIENT" tc qdisc del dev bench-a0 root 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc del dev bench-a1 root 2>/dev/null || true
    ip netns exec "$NS_CLIENT" tc qdisc del dev bench-b0 root 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc del dev bench-b1 root 2>/dev/null || true
}

generate_cert() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
        -days 365 -nodes -subj "/CN=mqvpn-bench" 2>/dev/null
}

# run_vpn <scheduler> <path-iface>...
# Starts server+client, waits for the tunnel, pings through it.
# SRT_BENCH_REORDER=on enables the tunnel reorder shim on both sides.
# Default OFF: under sustained real loss the shim head-of-line blocks on
# gaps that will never fill (measured 87-93% stream loss vs ~1% without);
# SRT-layer reordering tolerance (lossmaxttl) covers the multipath
# reordering instead, inside SRT's existing latency buffer.
run_vpn() {
    local scheduler="$1"; shift
    local path_args=()
    local ifc
    for ifc in "$@"; do
        path_args+=(--path "$ifc")
    done

    local extra_args=()
    if [ "${SRT_BENCH_REORDER:-off}" = "on" ]; then
        printf '[Reorder]\nEnabled = on\n' > "${WORK_DIR}/reorder.conf"
        extra_args=(--config "${WORK_DIR}/reorder.conf")
    fi
    # SRT_BENCH_CC selects the QUIC congestion controller (default bbr2).
    # Diagnostic knob: C3 burst loss collapses the datagram path under bbr2;
    # bbr/cubic/none isolate how much of that is the CC's loss response.
    extra_args+=(--cc "${SRT_BENCH_CC:-bbr2}")

    ip netns exec "$NS_SERVER" "$MQVPN" \
        --mode server \
        --listen 0.0.0.0:4433 \
        --subnet 10.0.0.0/24 \
        --cert "${WORK_DIR}/server.crt" \
        --key "${WORK_DIR}/server.key" \
        --auth-key "$PSK" \
        --scheduler "$scheduler" \
        "${extra_args[@]}" \
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
        --scheduler "$scheduler" \
        "${extra_args[@]}" \
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
    return 0
}

kill_vpn() {
    # TERM, poll up to 5s, then KILL and reap — a fixed sleep does not
    # guarantee port 4433 / netns resources are released before the next run.
    local pid
    for pid in "$CLIENT_PID" "$SERVER_PID"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    local deadline=$((SECONDS + 5))
    for pid in "$CLIENT_PID" "$SERVER_PID"; do
        [ -n "$pid" ] || continue
        while kill -0 "$pid" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do
            sleep 0.2
        done
        kill -9 "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    CLIENT_PID=""
    SERVER_PID=""
}

# ---- stats CSV helpers -------------------------------------------------
# srt-xtransmit stats CSVs differ across versions: some expose cumulative
# "<col>Total" columns, some only per-interval "<col>".  csv_metric prefers
# the Total column's last value and falls back to summing the interval
# column.  Reads to EOF (no grep -q / head early-exit: avoids SIGPIPE
# false failures under pipefail).
# usage: csv_metric <file> <column>   e.g. csv_metric rcv.csv pktRcvDrop
csv_metric() {
    local file="$1" col="$2"
    [ -s "$file" ] || { echo "NA"; return 0; }   # missing CSV must not abort under set -e
    awk -F, -v col="$col" '
        NR == 1 {
            for (i = 1; i <= NF; i++) {
                gsub(/^[ \t]+|[ \t\r]+$/, "", $i)
                if ($i == col "Total") tc = i
                else if ($i == col)    ic = i
            }
            next
        }
        tc { last = $tc }
        !tc && ic { sum += $ic }
        END {
            if (tc)      printf "%d", last + 0
            else if (ic) printf "%d", sum + 0
            else         print "NA"
        }' "$file"
}

# Mean of a numeric column (for msRTT etc.)
csv_mean() {
    local file="$1" col="$2"
    [ -s "$file" ] || { echo "NA"; return 0; }
    awk -F, -v col="$col" '
        NR == 1 {
            for (i = 1; i <= NF; i++) {
                gsub(/^[ \t]+|[ \t\r]+$/, "", $i)
                if ($i == col) c = i
            }
            next
        }
        c { sum += $c; n++ }
        END { if (n) printf "%.2f", sum / n; else print "NA" }' "$file"
}
