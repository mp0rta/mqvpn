#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_failover_test.sh — E2E netns coverage for the failover scheduler.
#
# The client runs --scheduler failover with --path A --path B (B a backup by
# default) and asks the server, which runs wlb, to use failover for its
# download direction too. One connection goes through:
#   1. A healthy: B carries only the standby probes, upload and download.
#   2. A loses every packet, link up: the tunnel keeps working over B.
#   3. A delivers again: traffic goes back to it, B is idle again.
#   4. A's link goes down and up (the path is closed and added again): A comes
#      back as the primary, not as a second backup, and B is idle again.
# Path bytes are the server-side veth counters.
#
# Topology: standard dual-path veth (-fo suffix).
#
# Usage: sudo ./run_failover_test.sh [mqvpn-binary] [--log-level LEVEL]

set -e

source "$(dirname "$0")/sanitizer_check.sh"

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
[ -f "$MQVPN" ] || { echo "error: mqvpn binary not found at $MQVPN"; exit 1; }
MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"

NS_SERVER="vpn-server-fo"
NS_CLIENT="vpn-client-fo"
VETH_A0="veth-a0-fo"
VETH_A1="veth-a1-fo"
VETH_B0="veth-b0-fo"
VETH_B1="veth-b1-fo"

IP_A_CLIENT="10.116.0.2/24"
IP_A_SERVER="10.116.0.1/24"
IP_B_CLIENT="10.216.0.2/24"
IP_B_SERVER="10.216.0.1/24"
SERVER_ADDR="10.116.0.1"
TUNNEL_IP="10.0.0.1"
IPERF_PORT=5216

# B may carry standby probes and their ACKs while A works: a few hundred
# bytes a second. Anything near the iperf3 rate means B carried data.
B_IDLE_MAX=65536
A_BUSY_MIN=1000000

SERVER_PID=""
CLIENT_PID=""
SANITIZER_FAIL=0
PASS=0
FAIL=0

cleanup_processes() {
    stop_and_check_sanitizer "$CLIENT_PID" "client" "${WORK_DIR}/client.log" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$SERVER_PID" "server" "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
    SERVER_PID=""
    CLIENT_PID=""
    sleep 1
}

cleanup() {
    echo ""
    echo "Cleaning up..."
    cleanup_processes
    pkill -f "iperf3 -s -B ${TUNNEL_IP} -p ${IPERF_PORT}" 2>/dev/null || true
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

pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }

# rx+tx bytes of a server-side veth
srv_bytes() {
    local d="$1"
    echo $(( $(ip netns exec "$NS_SERVER" cat "/sys/class/net/$d/statistics/rx_bytes") +
             $(ip netns exec "$NS_SERVER" cat "/sys/class/net/$d/statistics/tx_bytes") ))
}

# iperf3 through the tunnel for $2 seconds ($1 = "" upload, "-R" download)
run_iperf() {
    ip netns exec "$NS_CLIENT" iperf3 -c "$TUNNEL_IP" -p "$IPERF_PORT" -t "$2" ${1:+"$1"} \
        > "${WORK_DIR}/iperf.log" 2>&1
}

# B idle and A busy while iperf3 runs: $1 label, $2 iperf3 flag
check_primary_only() {
    local a0 b0 a1 b1
    a0=$(srv_bytes "$VETH_A1"); b0=$(srv_bytes "$VETH_B1")
    if ! run_iperf "$2" 4; then
        fail "$1: iperf3 failed"; tail -5 "${WORK_DIR}/iperf.log"; return
    fi
    a1=$(srv_bytes "$VETH_A1"); b1=$(srv_bytes "$VETH_B1")
    local da=$((a1 - a0)) db=$((b1 - b0))
    if [ "$da" -ge "$A_BUSY_MIN" ] && [ "$db" -le "$B_IDLE_MAX" ]; then
        pass "$1: A carried $da bytes, B $db"
    else
        fail "$1: A carried $da bytes, B $db (want A >= $A_BUSY_MIN, B <= $B_IDLE_MAX)"
    fi
}

ip netns del "$NS_SERVER" 2>/dev/null || true
ip netns del "$NS_CLIENT" 2>/dev/null || true
ip link del "$VETH_A0" 2>/dev/null || true
ip link del "$VETH_B0" 2>/dev/null || true

PSK=$("$MQVPN" --genkey 2>/dev/null)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-fo-test" 2>/dev/null

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
ip netns exec "$NS_SERVER" sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "$NS_SERVER" ip addr add "${SERVER_ADDR}/32" dev lo
ip netns exec "$NS_CLIENT" ip route add 10.116.0.0/24 via 10.216.0.1 dev "$VETH_B0" metric 200
# Both paths get a rate and a delay, A the faster one; the loss rule of phase
# 2 changes A's qdisc in place.
NETEM_A=(delay 5ms rate 100mbit)
NETEM_B=(delay 20ms rate 50mbit)
for d in "$VETH_A0:$NS_CLIENT" "$VETH_A1:$NS_SERVER"; do
    ip netns exec "${d#*:}" tc qdisc add dev "${d%%:*}" root netem "${NETEM_A[@]}"
done
for d in "$VETH_B0:$NS_CLIENT" "$VETH_B1:$NS_SERVER"; do
    ip netns exec "${d#*:}" tc qdisc add dev "${d%%:*}" root netem "${NETEM_B[@]}"
done

ip netns exec "$NS_SERVER" "$MQVPN" \
    --mode server \
    --listen "0.0.0.0:4433" \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --scheduler wlb --allow-client-scheduler \
    --log-level "$LOG_LEVEL" > "${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    fail "server died"; cat "${WORK_DIR}/server.log"
    exit 1
fi

ip netns exec "$NS_CLIENT" "$MQVPN" \
    --mode client \
    --server "${SERVER_ADDR}:4433" \
    --path "$VETH_A0" --path "$VETH_B0" \
    --auth-key "$PSK" \
    --insecure \
    --scheduler failover --request-server-scheduler \
    --log-level "$LOG_LEVEL" > "${WORK_DIR}/client.log" 2>&1 &
CLIENT_PID=$!

TUNNEL_OK=0
for _ in $(seq 1 30); do
    if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_IP" >/dev/null 2>&1; then
        TUNNEL_OK=1; break
    fi
    sleep 1
done
if [ "$TUNNEL_OK" -ne 1 ]; then
    fail "tunnel never reachable"; tail -40 "${WORK_DIR}/client.log"
    exit 1
fi
# let the backup path validate and settle as STANDBY
for _ in $(seq 1 10); do
    grep -q "iface=${VETH_B0} state=STANDBY" "${WORK_DIR}/client.log" && break
    sleep 1
done

ip netns exec "$NS_SERVER" iperf3 -s -B "$TUNNEL_IP" -p "$IPERF_PORT" -D
sleep 1

echo "=== Test 1: scheduler and path roles ==="
if grep -q "client requested scheduler failover: applied" "${WORK_DIR}/server.log"; then
    pass "server runs failover for this client"
else
    fail "server did not apply the failover request"
    grep -i "scheduler" "${WORK_DIR}/server.log" | tail -5
fi
if grep -q "iface=${VETH_B0} state=STANDBY" "${WORK_DIR}/client.log"; then
    pass "B is STANDBY"
else
    fail "B is not STANDBY"; grep -E "activated|-> " "${WORK_DIR}/client.log" | tail -5
fi

echo "=== Test 2: A healthy, B idle ==="
check_primary_only "upload" ""
check_primary_only "download" "-R"

echo "=== Test 3: A loses every packet, the tunnel moves to B ==="
for d in "$VETH_A0:$NS_CLIENT" "$VETH_A1:$NS_SERVER"; do
    ip netns exec "${d#*:}" tc qdisc change dev "${d%%:*}" root netem "${NETEM_A[@]}" loss 100%
done
# 6 s of 20 pings a second; the first 2 s are for detecting the outage
ip netns exec "$NS_CLIENT" ping -D -n -i 0.05 -w 6 "$TUNNEL_IP" > "${WORK_DIR}/ping.log" 2>&1 || true
for d in "$VETH_A0:$NS_CLIENT" "$VETH_A1:$NS_SERVER"; do
    ip netns exec "${d#*:}" tc qdisc change dev "${d%%:*}" root netem "${NETEM_A[@]}"
done
T0=$(grep -m1 -oE '^\[[0-9.]+\]' "${WORK_DIR}/ping.log" | tr -d '[]' || true)
LATE=0
if [ -n "$T0" ]; then
    LATE=$(awk -v t0="$T0" '/bytes from/ { t = substr($1, 2, length($1) - 2); if (t - t0 >= 2) n++ } END { print n + 0 }' \
        "${WORK_DIR}/ping.log")
fi
# 4 s at 20/s = 80 pings; want most of them answered
if [ "$LATE" -ge 60 ]; then
    pass "tunnel worked over B during the outage ($LATE of ~80 late pings answered)"
else
    fail "tunnel did not move to B: $LATE of ~80 late pings answered"
    tail -5 "${WORK_DIR}/ping.log"
fi

echo "=== Test 4: A delivers again, traffic goes back to it ==="
sleep 8
check_primary_only "download after the outage" "-R"

echo "=== Test 5: A's link goes down and up, A is the primary again ==="
ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" down
sleep 4
ip netns exec "$NS_CLIENT" ip link set "$VETH_A0" up
READD_OK=0
for _ in $(seq 1 15); do
    if awk '/re-added/ { s = 1 } s' "${WORK_DIR}/client.log" |
            grep -q "iface=${VETH_A0} state=ACTIVE"; then
        READD_OK=1; break
    fi
    sleep 1
done
if [ "$READD_OK" -eq 1 ]; then
    pass "A was added again as ACTIVE"
else
    fail "A was not added again as ACTIVE"
    grep -E "re-added|activated|-> " "${WORK_DIR}/client.log" | tail -8
fi
sleep 3
check_primary_only "download after A's link came back" "-R"

if ! kill -0 "$CLIENT_PID" 2>/dev/null; then fail "client died"; fi
if ! kill -0 "$SERVER_PID" 2>/dev/null; then fail "server died"; fi

echo ""
echo "================================================="
echo " Results: PASS=$PASS  FAIL=$FAIL"
echo "================================================="
[ "$FAIL" -eq 0 ]
