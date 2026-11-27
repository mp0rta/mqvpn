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

# shape_dev <netns> <dev> <rate> <netem> — netem under a tbf root. netem counts
# its limit in skbs, and a UDP GSO send is one skb carrying many packets, so on
# its own a "limit 600" queue held ~3.5x the intended bytes (measured). The tbf
# root only splits GSO skbs into wire packets (burst 2000 is below any
# multi-packet GSO skb); its 10gbit rate never shapes. Path rate, delay, loss
# and limit stay on netem.
shape_dev() {
    local ns="$1" dev="$2" rate="$3" netem="$4"
    # shellcheck disable=SC2086  # netem args are intentionally word-split
    ip netns exec "$ns" tc qdisc add dev "$dev" root handle 1: tbf rate 10gbit burst 2000 latency 1ms &&
        ip netns exec "$ns" tc qdisc add dev "$dev" parent 1:1 handle 10: netem $netem rate "$rate"
}

apply_tc_full() {
    local rate_a="$1" netem_a="$2" rate_b="$3" netem_b="$4"
    clear_tc
    shape_dev "$NS_CLIENT" bench-a0 "$rate_a" "$netem_a"
    shape_dev "$NS_SERVER" bench-a1 "$rate_a" "$netem_a"
    shape_dev "$NS_CLIENT" bench-b0 "$rate_b" "$netem_b"
    shape_dev "$NS_SERVER" bench-b1 "$rate_b" "$netem_b"
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
# VPN_SERVER_SCHED overrides the server's scheduler (default: <scheduler>).
# SRT_BENCH_CLIENT_LOG sets the client's --log-level (default info; debug
# exposes xquic's per-path state, e.g. path_bw, at a cost in log volume).
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

    local server_conf="" client_conf=""
    if [ "${SRT_BENCH_REORDER:-off}" = "on" ]; then
        server_conf+=$'[Reorder]\nEnabled = true\n'
        client_conf+=$'[Reorder]\nEnabled = true\n'
    fi
    # VPN_REINJ=<mode> sets [Multipath] Reinjection on the client only (no CLI
    # flag exists): the client is the SRT sender, and a phone would enable it
    # in its own config while the shared server keeps the default.
    # VPN_REINJ=redundant sets Redundant = true instead (RedundantPorts from
    # SRT_BENCH_RED_PORTS when set).
    local reinj="${VPN_REINJ:-off}"
    if [ "$reinj" = "redundant" ]; then
        client_conf+=$'[Multipath]\nRedundant = true\n'
        if [ -n "${SRT_BENCH_RED_PORTS:-}" ]; then
            client_conf+="RedundantPorts = ${SRT_BENCH_RED_PORTS}"$'\n'
        fi
    elif [ "$reinj" != "off" ]; then
        client_conf+=$'[Multipath]\nReinjection = '"${reinj}"$'\n'
    fi
    # SRT_BENCH_CC selects the QUIC congestion controller (default bbr2).
    # Diagnostic knob: C3 burst loss collapses the datagram path under bbr2;
    # bbr/cubic/none isolate how much of that is the CC's loss response.
    local server_args=(--cc "${SRT_BENCH_CC:-bbr2}") client_args=(--cc "${SRT_BENCH_CC:-bbr2}")
    if [ -n "$server_conf" ]; then
        printf '%s' "$server_conf" > "${WORK_DIR}/server.conf"
        server_args+=(--config "${WORK_DIR}/server.conf")
    fi
    if [ -n "$client_conf" ]; then
        printf '%s' "$client_conf" > "${WORK_DIR}/client.conf"
        client_args+=(--config "${WORK_DIR}/client.conf")
    fi

    ip netns exec "$NS_SERVER" "$MQVPN" \
        --mode server \
        --listen 0.0.0.0:4433 \
        --subnet 10.0.0.0/24 \
        --cert "${WORK_DIR}/server.crt" \
        --key "${WORK_DIR}/server.key" \
        --auth-key "$PSK" \
        --scheduler "${VPN_SERVER_SCHED:-$scheduler}" \
        "${server_args[@]}" \
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
        "${client_args[@]}" \
        --log-level "${SRT_BENCH_CLIENT_LOG:-info}" >"${WORK_DIR}/client.log" 2>&1 &
    CLIENT_PID=$!
    sleep 5
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "    ERROR: client died (see this run's client log in ${WORK_DIR})"
        return 1
    fi

    if ! ip netns exec "$NS_CLIENT" ping -c 2 -W 2 "$TUN_SERVER_IP" >/dev/null 2>&1; then
        echo "    ERROR: tunnel not established"
        return 1
    fi
    # An unknown Reinjection value is a WARN + fallback to off, which would
    # silently turn a redundant arm into a plain one.
    local marker="reinjection enabled: mode=${reinj}"
    if [ "$reinj" = "redundant" ]; then
        marker="redundant mode enabled:"
    fi
    if [ "$reinj" != "off" ] && \
       ! grep -q "$marker" "${WORK_DIR}/client.log"; then
        echo "    ERROR: client did not log '${marker}' (see this run's client log in ${WORK_DIR})"
        return 1
    fi
    return 0
}

# rx_bytes <server-iface> — bytes the server received on one path: per-path
# uplink wire volume, which shows whether a redundant arm really duplicated.
rx_bytes() {
    ip netns exec "$NS_SERVER" cat "/sys/class/net/$1/statistics/rx_bytes"
}

# set_path_a <rate> <netem> — replace path A's shaping in both directions.
# Returns nonzero if either side fails: callers run where errexit is off.
set_path_a() {
    local rate="$1" netem="$2"
    # shellcheck disable=SC2086  # netem args are intentionally word-split
    ip netns exec "$NS_CLIENT" tc qdisc change dev bench-a0 parent 1:1 handle 10: netem $netem rate "$rate" \
        || return 1
    # shellcheck disable=SC2086
    ip netns exec "$NS_SERVER" tc qdisc change dev bench-a1 parent 1:1 handle 10: netem $netem rate "$rate"
}

# flap_path_a <down-s> <period-s> <duration-s> <rate> <netem> — blackhole
# path A for <down-s> out of every <period-s> (a carrier dropout / handover),
# first outage <period-s minus down-s> in, for as many whole periods as fit
# in <duration-s>. Returns with path A restored, so the caller waits for it
# instead of killing it: a kill would orphan an in-flight tc that could
# re-apply the outage after the caller's restore. Nonzero on any tc failure,
# possibly mid-outage.
flap_path_a() {
    local down="$1" period="$2" duration="$3" rate="$4" netem="$5" t
    for (( t = period; t <= duration; t += period )); do
        sleep $((period - down))
        set_path_a "$rate" "loss 100%" || return 1
        sleep "$down"
        set_path_a "$rate" "$netem" || return 1
    done
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
