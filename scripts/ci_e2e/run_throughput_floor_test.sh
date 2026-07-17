#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_throughput_floor_test.sh — multipath throughput regression smoke.
#
# Runs the WLB scheduler over a 2-path netem topology and asserts:
#   1. single-path throughput is sane    (catches gross tunnel breakage)
#   2. multipath >= 0.8 × single-path    (catches the class of bugs where
#                                          multi tanks below single — e.g.
#                                          the get_interest stability-timer
#                                          extend bug that pinned the
#                                          libevent tick 30 seconds out)
#
# Topology:
#   Path A:  300 Mbps / 10 ms one-way
#   Path B:   80 Mbps / 30 ms one-way
#   Sum cap ≈ 380 Mbps; healthy multi gain ~+5..+15% over single.
#   Regression signature: multi at ~0.3 × single (3-4x throughput drop).
#
# The ratio assertion is build-type invariant: ASan/UBSan slow single and
# multi uniformly, so the regression ratio is preserved. The absolute
# floor (60 Mbps) is generous enough that even a sanitizer build clears
# it on a healthy binary, while a regressed build (~25 Mbps multi under
# ASan) trips it. CI nevertheless runs this only in the release netns-tests
# job to keep the assertion margins wide.
#
# Runtime: ~35 seconds (netns/cert setup + one 10s iperf3 single + one
# 10s iperf3 multi + teardown).
#
# Usage: sudo ./run_throughput_floor_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]

set -e

source "$(dirname "$0")/sanitizer_check.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN=""
LOG_LEVEL="error"  # data-plane bench: keep logging minimal

while [ $# -gt 0 ]; do
    case "$1" in
        --log-level) LOG_LEVEL="$2"; shift 2 ;;
        *) [ -z "$MQVPN" ] && MQVPN="$1"; shift ;;
    esac
done

MQVPN="${MQVPN:-${SCRIPT_DIR}/../../build/mqvpn}"

if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN"
    echo "Build first: mkdir build && cd build && cmake .. && make"
    exit 1
fi

for cmd in iperf3 openssl python3 tc; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "error: required dependency $cmd not on PATH"
        exit 2
    fi
done

MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"

# Unique names so this test can run alongside other e2e tests that use
# `veth-a0` / `vpn-server` etc.
NS_SERVER="vpn-server-tput"
NS_CLIENT="vpn-client-tput"
VETH_A0="veth-a0-tput"
VETH_A1="veth-a1-tput"
VETH_B0="veth-b0-tput"
VETH_B1="veth-b1-tput"

IP_A_CLIENT="10.100.0.2/24"
IP_A_SERVER="10.100.0.1/24"
IP_B_CLIENT="10.200.0.2/24"
IP_B_SERVER="10.200.0.1/24"
SERVER_ADDR="10.100.0.1"
TUNNEL_IP="10.0.0.1"
VPN_PORT="4433"

NETEM_A="delay 10ms rate 300mbit"
NETEM_B="delay 30ms rate 80mbit"

IPERF_DURATION=10
IPERF_STREAMS=4

# Floor thresholds. Healthy on this machine sees single ~260 Mbps and
# multi ~280 Mbps. The regression we are guarding against produced
# multi ~84 Mbps (single unchanged). The ratio assertion is what
# actually catches the regression class (healthy ~1.08 vs regressed
# ~0.32 — wide margin against either floor). The absolute floors are
# only a sanity check; relax them to ~30 if a noisy CI runner trips
# them on a healthy build.
FLOOR_SINGLE_MBPS=60
FLOOR_MULTI_MBPS=60
FLOOR_MULTI_OVER_SINGLE_RATIO=0.8

SERVER_PID=""
CLIENT_PID=""
SANITIZER_FAIL=0

stop_client() {
    stop_and_check_sanitizer "$CLIENT_PID" "client" \
        "${WORK_DIR}/client.log" || SANITIZER_FAIL=1
    CLIENT_PID=""
    sleep 1
}

stop_all() {
    stop_client
    stop_and_check_sanitizer "$SERVER_PID" "server" \
        "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
    SERVER_PID=""
    sleep 1
}

cleanup() {
    echo ""
    echo "Cleaning up..."
    stop_all
    ip netns exec "$NS_SERVER" pkill -f iperf3 2>/dev/null || true
    ip netns exec "$NS_CLIENT" pkill -f iperf3 2>/dev/null || true
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del "$VETH_A0" 2>/dev/null || true
    ip link del "$VETH_B0" 2>/dev/null || true
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

# Clean leftovers from a prior failed run
ip netns del "$NS_SERVER" 2>/dev/null || true
ip netns del "$NS_CLIENT" 2>/dev/null || true
ip link del "$VETH_A0" 2>/dev/null || true
ip link del "$VETH_B0" 2>/dev/null || true

PSK=$("$MQVPN" --genkey 2>/dev/null)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-throughput-floor-test" 2>/dev/null

setup_topology() {
    ip netns add "$NS_SERVER"
    ip netns add "$NS_CLIENT"

    ip link add "$VETH_A0" type veth peer name "$VETH_A1"
    ip link set "$VETH_A0" netns "$NS_CLIENT"
    ip link set "$VETH_A1" netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add "$IP_A_CLIENT" dev "$VETH_A0"
    ip netns exec "$NS_SERVER" ip addr add "$IP_A_SERVER" dev "$VETH_A1"
    ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" up
    ip netns exec "$NS_SERVER" ip link set "$VETH_A1" up

    ip link add "$VETH_B0" type veth peer name "$VETH_B1"
    ip link set "$VETH_B0" netns "$NS_CLIENT"
    ip link set "$VETH_B1" netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add "$IP_B_CLIENT" dev "$VETH_B0"
    ip netns exec "$NS_SERVER" ip addr add "$IP_B_SERVER" dev "$VETH_B1"
    ip netns exec "$NS_CLIENT" ip link set "$VETH_B0" up
    ip netns exec "$NS_SERVER" ip link set "$VETH_B1" up

    ip netns exec "$NS_CLIENT" ip link set lo up
    ip netns exec "$NS_SERVER" ip link set lo up

    # Same rp_filter relaxation + lo /32 pattern as ci_bench_aggregate.sh, so
    # Path B traffic destined to SERVER_ADDR (owned by veth-a1) is accepted
    # when it arrives on veth-b1. See scripts/ci_benchmarks/ci_bench_env.sh
    # for the long-form rationale.
    ip netns exec "$NS_SERVER" sysctl -w net.ipv4.ip_forward=1 >/dev/null
    for iface in all default lo "$VETH_A1" "$VETH_B1"; do
        ip netns exec "$NS_SERVER" \
            sysctl -w "net.ipv4.conf.${iface}.rp_filter=0" >/dev/null
    done
    for iface in all default lo "$VETH_A0" "$VETH_B0"; do
        ip netns exec "$NS_CLIENT" \
            sysctl -w "net.ipv4.conf.${iface}.rp_filter=0" >/dev/null
    done
    ip netns exec "$NS_SERVER" ip addr add "${SERVER_ADDR}/32" dev lo
    ip netns exec "$NS_CLIENT" ip route add 10.100.0.0/24 via 10.200.0.1 \
        dev "$VETH_B0" metric 200

    # netem on both ends of each pair (RTT = 2 × delay)
    ip netns exec "$NS_CLIENT" tc qdisc add dev "$VETH_A0" root netem ${NETEM_A}
    ip netns exec "$NS_SERVER" tc qdisc add dev "$VETH_A1" root netem ${NETEM_A}
    ip netns exec "$NS_CLIENT" tc qdisc add dev "$VETH_B0" root netem ${NETEM_B}
    ip netns exec "$NS_SERVER" tc qdisc add dev "$VETH_B1" root netem ${NETEM_B}

    ip netns exec "$NS_CLIENT" ping -c 1 -W 2 "$SERVER_ADDR" >/dev/null
    ip netns exec "$NS_CLIENT" ping -c 1 -W 2 10.200.0.1 >/dev/null
}

start_server() {
    ip netns exec "$NS_SERVER" "$MQVPN" \
        --mode server \
        --listen "0.0.0.0:${VPN_PORT}" \
        --subnet 10.0.0.0/24 \
        --cert "${WORK_DIR}/server.crt" \
        --key "${WORK_DIR}/server.key" \
        --auth-key "$PSK" \
        --scheduler wlb \
        --log-level "$LOG_LEVEL" >"${WORK_DIR}/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 2
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "  server died"
        cat "${WORK_DIR}/server.log"
        return 1
    fi
}

# $1: space-separated --path args (e.g. "$VETH_A0" or "$VETH_A0 $VETH_B0")
start_client() {
    local paths_args=""
    for iface in $1; do
        paths_args="$paths_args --path $iface"
    done
    ip netns exec "$NS_CLIENT" "$MQVPN" \
        --mode client \
        --server "${SERVER_ADDR}:${VPN_PORT}" \
        ${paths_args} \
        --auth-key "$PSK" \
        --insecure \
        --scheduler wlb \
        --log-level "$LOG_LEVEL" >"${WORK_DIR}/client.log" 2>&1 &
    CLIENT_PID=$!
    sleep 3
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "  client died"
        cat "${WORK_DIR}/client.log"
        return 1
    fi
}

wait_tunnel() {
    local timeout="${1:-15}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_IP" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# Run one iperf3 TCP DL run and print Mbps as a single number to stdout.
# The `|| true` on the client and the silenced `wait` are intentional:
# garbage JSON or a torn-down server feed into the python parser which
# returns 0.0, letting the throughput-floor assert step fail cleanly
# rather than the script aborting under `set -e`.
run_iperf3_mbps() {
    local json_file
    json_file="$(mktemp)"

    ip netns exec "$NS_SERVER" iperf3 -s -B "$TUNNEL_IP" -1 >/dev/null 2>&1 &
    local srv_pid=$!
    sleep 1

    ip netns exec "$NS_CLIENT" iperf3 \
        -c "$TUNNEL_IP" \
        -t "$IPERF_DURATION" \
        -P "$IPERF_STREAMS" \
        -R \
        --json >"$json_file" 2>&1 || true

    wait "$srv_pid" 2>/dev/null || true

    python3 -c "
import json
try:
    with open('${json_file}') as f:
        data = json.load(f)
    end = data.get('end', {})
    if 'sum_received' in end:
        print(f\"{end['sum_received']['bits_per_second'] / 1e6:.1f}\")
    elif 'sum' in end:
        print(f\"{end['sum']['bits_per_second'] / 1e6:.1f}\")
    else:
        print('0.0')
except Exception:
    print('0.0')
"
    rm -f "$json_file"
}

# ----- Run -----

echo "================================================================"
echo "  mqvpn throughput-floor regression smoke"
echo "  Binary:   $MQVPN"
echo "  Topology: A=300mbit/10ms, B=80mbit/30ms, theoretical sum=380mbit"
echo "  Probe:    WLB, $IPERF_STREAMS streams, ${IPERF_DURATION}s iperf3 TCP DL"
echo "  Coverage: WLB only. Stability/Recovery timer is scheduler-agnostic,"
echo "            but a future scheduler-specific pacing bug could slip past"
echo "            this test. Extend to minrtt if that ever happens."
echo "================================================================"

setup_topology
echo "OK: netns + netem configured"
start_server
echo "OK: VPN server up"

# Single-path probe (Path A only) — fast lane, regression-insensitive
echo ""
echo "[1/2] single-path (Path A only)..."
start_client "$VETH_A0"
if ! wait_tunnel 15; then
    echo "FAIL: single-path tunnel did not come up within 15s"
    exit 1
fi
SINGLE_MBPS="$(run_iperf3_mbps)"
echo "      single-path throughput: ${SINGLE_MBPS} Mbps"
stop_client  # only the single-path client; server stays up for the multi probe
sleep 2      # match ci_bench_aggregate.sh's inter-iteration grace period

# Multipath probe (Path A + Path B) — the cell that catches the regression
echo ""
echo "[2/2] multipath (Path A + Path B)..."
start_client "$VETH_A0 $VETH_B0"
if ! wait_tunnel 15; then
    echo "FAIL: multipath tunnel did not come up within 15s"
    exit 1
fi
MULTI_MBPS="$(run_iperf3_mbps)"
echo "      multipath throughput:   ${MULTI_MBPS} Mbps"

# ----- Assert -----

python3 - <<EOF
import sys

single = float("$SINGLE_MBPS")
multi  = float("$MULTI_MBPS")
floor_single = float("$FLOOR_SINGLE_MBPS")
floor_multi  = float("$FLOOR_MULTI_MBPS")
ratio_floor  = float("$FLOOR_MULTI_OVER_SINGLE_RATIO")

ratio = (multi / single) if single > 0 else 0.0

print()
print("Throughput floor check:")
print(f"  single = {single:.1f} Mbps  (floor = {floor_single:.0f})")
print(f"  multi  = {multi:.1f} Mbps  (floor = {floor_multi:.0f})")
print(f"  multi / single = {ratio:.2f}  (floor = {ratio_floor:.2f})")

failures = []
if single < floor_single:
    failures.append(f"single-path throughput {single:.1f} < {floor_single:.0f} Mbps")
if multi < floor_multi:
    failures.append(f"multipath throughput {multi:.1f} < {floor_multi:.0f} Mbps")
if single > 0 and ratio < ratio_floor:
    failures.append(
        f"multi/single ratio {ratio:.2f} < {ratio_floor:.2f} "
        "(multipath is tanking — likely a tick/pacing regression)"
    )

if failures:
    print()
    print("FAIL:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)

print()
print("PASS: throughput within floors")
EOF

echo ""
echo "================================================================"
echo "  Result: PASS"
echo "================================================================"
