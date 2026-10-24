#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_pmtud_multipath_test.sh — E2E test for PMTUD = true with two paths.
#
# client --A-- server and client --B-- server, both 1500 at first. The
# server side of each link is where the MTU shrinks: larger frames are
# dropped there without any ICMP error. During one transfer:
#   1. both paths carry 1500: the TUN MTU grows to what that fits;
#   2. path B shrinks to 1400: the connection uses the smaller size;
#   3. path B shrinks to 1340, below the start size: the size goes down to
#      what B still carries and the transfer keeps going on both paths.
#
# Usage: sudo ./run_pmtud_multipath_test.sh [path-to-mqvpn] [--log-level LEVEL]

set -e

source "$(dirname "$0")/sanitizer_check.sh"
source "$(dirname "$0")/e2e_lib.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN=""
LOG_LEVEL="info"

while [ $# -gt 0 ]; do
    case "$1" in
        --log-level) LOG_LEVEL="$2"; shift 2 ;;
        *) [ -z "$MQVPN" ] && MQVPN="$1"; shift ;;
    esac
done

MQVPN="${MQVPN:-${SCRIPT_DIR}/../../build/mqvpn}"

if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN"
    exit 1
fi
for tool in tc iperf3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: $tool not found"
        exit 1
    fi
done

MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"

NS_CLIENT="vpn-client-pmm"
NS_SERVER="vpn-server-pmm"
TUNNEL_IP="10.0.0.1"
# IPv4 20 + UDP 8 + tag 16 + ACK room 16 + QUIC/DATAGRAM/MASQUE 18
OVERHEAD=78
# a veth takes frames up to 4 bytes over its MTU (room for a VLAN tag), so
# the size found can be that much above the MTU set
SLACK=4

SERVER_PID=""
CLIENT_PID=""
IPERF_PID=""
SANITIZER_FAIL=0
FAIL=0

cleanup() {
    echo ""
    echo "Cleaning up..."
    [ -n "$IPERF_PID" ] && kill "$IPERF_PID" 2>/dev/null || true
    stop_and_check_sanitizer "$CLIENT_PID" "client" \
        "${WORK_DIR}/client.log" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$SERVER_PID" "server" \
        "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
    sleep 1
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip netns del "$NS_SERVER" 2>/dev/null || true
    if [ -n "${MQVPN_E2E_LOG_DIR:-}" ]; then
        mkdir -p "$MQVPN_E2E_LOG_DIR"
        cp "${WORK_DIR}/client.log" "${MQVPN_E2E_LOG_DIR}/pmtud-mp-client.log" 2>/dev/null || true
        cp "${WORK_DIR}/server.log" "${MQVPN_E2E_LOG_DIR}/pmtud-mp-server.log" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

ip netns del "$NS_CLIENT" 2>/dev/null || true
ip netns del "$NS_SERVER" 2>/dev/null || true

PSK=$("$MQVPN" --genkey 2>/dev/null)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-pmtud-mp-test" 2>/dev/null

ip netns add "$NS_CLIENT"
ip netns add "$NS_SERVER"
ip netns exec "$NS_CLIENT" ip link set lo up
ip netns exec "$NS_SERVER" ip link set lo up

# path A: 10.110.1.0/24, path B: 10.110.2.0/24
for p in a:1 b:2; do
    n=${p%:*} i=${p#*:}
    ip link add "pmm-${n}c" type veth peer name "pmm-${n}s"
    ip link set "pmm-${n}c" netns "$NS_CLIENT"
    ip link set "pmm-${n}s" netns "$NS_SERVER"
    ip netns exec "$NS_CLIENT" ip addr add "10.110.${i}.1/24" dev "pmm-${n}c"
    ip netns exec "$NS_SERVER" ip addr add "10.110.${i}.2/24" dev "pmm-${n}s"
    ip netns exec "$NS_CLIENT" ip link set "pmm-${n}c" up
    ip netns exec "$NS_SERVER" ip link set "pmm-${n}s" up
    # no offloads: packets must reach the peer at the size they were sent
    ip netns exec "$NS_CLIENT" ethtool -K "pmm-${n}c" tso off gso off gro off \
        tx-udp-segmentation off >/dev/null 2>&1 || true
    ip netns exec "$NS_SERVER" ethtool -K "pmm-${n}s" tso off gso off gro off \
        tx-udp-segmentation off >/dev/null 2>&1 || true
    ip netns exec "$NS_CLIENT" tc qdisc add dev "pmm-${n}c" root netem rate 50mbit delay 10ms
    ip netns exec "$NS_SERVER" tc qdisc add dev "pmm-${n}s" root netem rate 50mbit delay 10ms
done

ip netns exec "$NS_CLIENT" ping -c 1 -W 2 10.110.1.2 >/dev/null
ip netns exec "$NS_CLIENT" ping -c 1 -W 2 10.110.2.2 >/dev/null

ip netns exec "$NS_SERVER" "$MQVPN" \
    --mode server \
    --listen 0.0.0.0:4433 \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --pmtud \
    --log-level "$LOG_LEVEL" >"${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: server did not start"
    cat "${WORK_DIR}/server.log"
    exit 1
fi

ip netns exec "$NS_CLIENT" "$MQVPN" \
    --mode client \
    --server 10.110.1.2:4433 \
    --path pmm-ac --path pmm-bc \
    --auth-key "$PSK" \
    --insecure \
    --pmtud \
    --log-level "$LOG_LEVEL" >"${WORK_DIR}/client.log" 2>&1 &
CLIENT_PID=$!

tun_mtu() {
    ip netns exec "$NS_CLIENT" ip link show mqvpn0 2>/dev/null \
        | sed -n 's/.* mtu \([0-9]*\) .*/\1/p'
}

# bytes the server received on a path's link
rx_bytes() {
    ip netns exec "$NS_SERVER" cat "/sys/class/net/pmm-${1}s/statistics/rx_bytes"
}

for _ in $(seq 30); do
    ip netns exec "$NS_CLIENT" ip addr show mqvpn0 2>/dev/null | grep -q "inet " && break
    sleep 0.5
done
if ! ip netns exec "$NS_CLIENT" ping -c 2 -W 2 "$TUNNEL_IP" >/dev/null; then
    echo "FAIL: tunnel did not come up"
    exit 1
fi
echo "PASS: tunnel up"

ip netns exec "$NS_SERVER" iperf3 -s -1 -B "$TUNNEL_IP" -p 5201 >/dev/null 2>&1 &
for _ in $(seq 20); do
    ip netns exec "$NS_SERVER" ss -ltn "sport = :5201" | grep -q LISTEN && break
    sleep 0.2
done
timeout 40 ip netns exec "$NS_CLIENT" iperf3 -c "$TUNNEL_IP" -p 5201 -t 18 -i 1 \
    >"${WORK_DIR}/iperf.txt" 2>&1 &
IPERF_PID=$!

# ── 1. both paths at 1500 ──
sleep 5
max_mtu=$((1500 - OVERHEAD))
mtu=$(tun_mtu)
if [ "$mtu" -gt 1300 ] && [ "$mtu" -le "$max_mtu" ]; then
    echo "PASS: TUN MTU grew to $mtu with both paths at 1500 (up to $max_mtu)"
else
    echo "FAIL: TUN MTU $mtu with both paths at 1500, expected 1301..$max_mtu"
    FAIL=1
fi

# ── 2. path B shrinks to 1400 ──
ip netns exec "$NS_SERVER" ip link set pmm-bs mtu 1400
sleep 5
max_mtu=$((1400 + SLACK - OVERHEAD))
mtu=$(tun_mtu)
if [ "$mtu" -ge 1280 ] && [ "$mtu" -le "$max_mtu" ]; then
    echo "PASS: TUN MTU went down to $mtu with path B at 1400 (up to $max_mtu)"
else
    echo "FAIL: TUN MTU $mtu with path B at 1400, expected 1280..$max_mtu"
    FAIL=1
fi

# ── 3. path B shrinks below the start size ──
ip netns exec "$NS_SERVER" ip link set pmm-bs mtu 1340
sleep 3
a0=$(rx_bytes a)
b0=$(rx_bytes b)
sleep 3
a1=$(rx_bytes a)
b1=$(rx_bytes b)
max_mtu=$((1340 + SLACK - OVERHEAD))
mtu=$(tun_mtu)
if [ "$mtu" -ge 1150 ] && [ "$mtu" -le "$max_mtu" ]; then
    echo "PASS: TUN MTU went down to $mtu with path B at 1340 (up to $max_mtu)"
else
    echo "FAIL: TUN MTU $mtu with path B at 1340, expected 1150..$max_mtu"
    FAIL=1
fi
# data keeps flowing, and path B is still used: how much it gets is up to
# the scheduler, but more than its probes and ACKs
if [ $((a1 - a0)) -gt 1000000 ] && [ $((b1 - b0)) -gt 50000 ]; then
    echo "PASS: both paths carry data below the start size" \
        "(A $(((a1 - a0) / 1000)) kB, B $(((b1 - b0) / 1000)) kB in 3 s)"
else
    echo "FAIL: a path carries no data below the start size" \
        "(A $(((a1 - a0) / 1000)) kB, B $(((b1 - b0) / 1000)) kB in 3 s)"
    FAIL=1
fi

if wait "$IPERF_PID"; then
    echo "PASS: TCP transfer survived both shrinks"
else
    echo "FAIL: TCP transfer across the shrinks"
    cat "${WORK_DIR}/iperf.txt"
    FAIL=1
fi
IPERF_PID=""

if [ "$FAIL" -ne 0 ]; then
    echo "=== PMTUD multipath test FAILED ==="
    exit 1
fi
echo "=== PMTUD multipath test PASSED ==="
