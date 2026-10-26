#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_multiclient_isolation_test.sh — one client's backpressure must not stall
# the others (mp0rta/mqvpn#446)
#
# 1 server + 2 client netns, one path each, shaped with netem both ways:
#   client 1: 10 Mbit, 40 ms; receives a 30 Mbit UDP flood, so its QUIC send
#             queue on the server fills up
#   client 2: 20 Mbit, 10 ms; only pings the server's tunnel address
# Client 2's pings sent during the flood must keep getting answered, with
# little loss and no large delay: the server must drop client 1's excess,
# not stop reading the TUN they share.
#
# Usage: sudo ./run_multiclient_isolation_test.sh [path-to-mqvpn-binary]

set -e

source "$(dirname "$0")/sanitizer_check.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="${1:-${SCRIPT_DIR}/../../build/mqvpn}"

if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN"
    echo "Build first: mkdir build && cd build && cmake .. && make"
    exit 1
fi
for tool in iperf3 ping tc; do
    command -v "$tool" >/dev/null || { echo "error: $tool not found"; exit 1; }
done

MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"
NS_LIST="mi-server mi-client1 mi-client2"

# Pass criteria for client 2's pings sent during the flood (base RTT 20 ms).
MAX_LOSS_PCT=10
MAX_P95_MS=150

PSK=$("$MQVPN" --genkey 2>/dev/null)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-test" 2>/dev/null

SERVER_PID=""
CLIENT1_PID=""
CLIENT2_PID=""
IPERF_S_PID=""
SANITIZER_FAIL=0

cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ -n "$IPERF_S_PID" ]; then
        kill "$IPERF_S_PID" 2>/dev/null || true
    fi
    stop_and_check_sanitizer "$CLIENT2_PID" "client2" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$CLIENT1_PID" "client1" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$SERVER_PID" "server" || SANITIZER_FAIL=1
    sleep 1
    for ns in $NS_LIST; do
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

for ns in $NS_LIST; do
    ip netns del "$ns" 2>/dev/null || true
done

echo "=== Setting up network namespaces (1 server + 2 clients) ==="
for ns in $NS_LIST; do
    ip netns add "$ns"
    ip netns exec "$ns" ip link set lo up
done
for i in 1 2; do
    ip link add "mi-veth-c${i}" type veth peer name "mi-veth-s${i}"
    ip link set "mi-veth-c${i}" netns "mi-client${i}"
    ip link set "mi-veth-s${i}" netns mi-server
    ip netns exec "mi-client${i}" ip addr add "192.168.${i}1.1/24" dev "mi-veth-c${i}"
    ip netns exec mi-server ip addr add "192.168.${i}1.2/24" dev "mi-veth-s${i}"
    ip netns exec "mi-client${i}" ip link set "mi-veth-c${i}" up
    ip netns exec mi-server ip link set "mi-veth-s${i}" up
done
shape() { # <client index> <netem args...>
    local i="$1"
    shift
    ip netns exec "mi-client${i}" tc qdisc add dev "mi-veth-c${i}" root netem "$@"
    ip netns exec mi-server tc qdisc add dev "mi-veth-s${i}" root netem "$@"
}
shape 1 delay 20ms rate 10mbit
shape 2 delay 5ms rate 20mbit

echo "=== Starting VPN server ==="
ip netns exec mi-server "$MQVPN" \
    --mode server \
    --listen 0.0.0.0:4433 \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --log-level info > "${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "=== FAIL: Server process died ==="
    cat "${WORK_DIR}/server.log"
    exit 1
fi

echo "=== Starting 2 clients ==="
for i in 1 2; do
    ip netns exec "mi-client${i}" "$MQVPN" \
        --mode client \
        --server "192.168.${i}1.2:4433" \
        --auth-key "$PSK" \
        --insecure \
        --log-level info > "${WORK_DIR}/client${i}.log" 2>&1 &
    eval "CLIENT${i}_PID=$!"
done
for i in 1 2; do
    ok=0
    for _ in $(seq 30); do
        if ip netns exec "mi-client${i}" ip addr show dev mqvpn0 2>/dev/null | grep -q "inet "; then
            ok=1
            break
        fi
        sleep 1
    done
    if [ "$ok" -ne 1 ]; then
        echo "=== FAIL: client ${i} got no tunnel address ==="
        cat "${WORK_DIR}/client${i}.log"
        exit 1
    fi
    echo "OK: client ${i} connected"
done
for i in 1 2; do
    if ! ip netns exec "mi-client${i}" ping -c 3 -W 2 10.0.0.1 >/dev/null 2>&1; then
        echo "=== FAIL: client ${i} cannot ping 10.0.0.1 ==="
        exit 1
    fi
done

echo ""
echo "=== Client 1 receives a 30 Mbit UDP flood, client 2 pings ==="
ip netns exec mi-server iperf3 -s -B 10.0.0.1 > "${WORK_DIR}/iperf_s.log" 2>&1 &
IPERF_S_PID=$!
sleep 1

# 50 pings per second for 14 s; the flood runs from t=2 s to t=12 s.
ip netns exec mi-client2 ping -D -n -i 0.02 -s 100 -w 14 10.0.0.1 \
    > "${WORK_DIR}/ping.log" 2>&1 &
PING_PID=$!
T0=$(date +%s.%N)
sleep 2
timeout -k 2 16 ip netns exec mi-client1 iperf3 -c 10.0.0.1 -u -b 30M -l 1200 -R -t 10 \
    > "${WORK_DIR}/iperf_c.log" 2>&1 || true
wait "$PING_PID" || true

# Client 2's pings sent between t=4 s and t=11 s, while the flood is running.
RESULT=$(python3 - "${WORK_DIR}/ping.log" "$T0" <<'PY'
import re, sys
log, t0 = sys.argv[1], float(sys.argv[2])
rtts = []
for line in open(log):
    m = re.match(r'\[(\d+\.\d+)\].*time=([\d.]+) ms', line)
    if m:
        sent = float(m.group(1)) - float(m.group(2)) / 1000 - t0
        if 4 <= sent < 11:
            rtts.append(float(m.group(2)))
expected = 7 * 50
rtts.sort()
loss = 100.0 * max(0, expected - len(rtts)) / expected
p95 = rtts[int(len(rtts) * 0.95)] if rtts else 1e9
print(f"{loss:.1f} {p95:.0f} {len(rtts)} {expected}")
PY
)
read -r LOSS P95 GOT EXPECTED <<< "$RESULT"
echo "client 2 during the flood: ${GOT}/${EXPECTED} answered, loss ${LOSS}%, p95 RTT ${P95} ms"
grep -E "receiver|sender" "${WORK_DIR}/iperf_c.log" | tail -1 || true

FAIL=0
if ! awk -v l="$LOSS" -v m="$MAX_LOSS_PCT" 'BEGIN { exit !(l <= m) }'; then
    echo "FAIL: client 2 lost ${LOSS}% of its pings (max ${MAX_LOSS_PCT}%)"
    FAIL=1
fi
if [ "$P95" -gt "$MAX_P95_MS" ]; then
    echo "FAIL: client 2 p95 RTT ${P95} ms (max ${MAX_P95_MS} ms)"
    FAIL=1
fi
if [ "$FAIL" -ne 0 ]; then
    echo "=== FAIL: one client's flood stalled another client ==="
    tail -20 "${WORK_DIR}/server.log"
    exit 1
fi
echo "=== PASS: client 2 unaffected by client 1's flood ==="
