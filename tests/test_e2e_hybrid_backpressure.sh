#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# test_e2e_hybrid_backpressure.sh — netns end-to-end test for receive-side
# backpressure on the hybrid TCP lane, with the real client and the real
# server (tests/test_tcp_egress.c covers the server against a test client).
#
#   Test 1 (downlink): an application in the client netns connects and does
#     not read; the source behind the server offers 256 MiB. The source must
#     stop after a bounded amount and neither mqvpn process may grow by the
#     offered amount. Once the application reads, every byte arrives intact.
#   Test 2 (uplink): the same with a destination behind the server that does
#     not read and a sender in the client netns.
#   Test 3 (RecvRateLimit): with three downloads stalled, a fourth one still
#     completes; then the three complete intact. Without the per-connection
#     share the first stalled download takes the whole connection window.
#
# The bounds are loose on purpose: besides the QUIC stream window (16 MiB at
# most) the kernel socket buffers of four TCP sockets hold data. What is
# ruled out is "the sender never stops" (all 256 MiB accepted).
#
# Requires: root, netns support, python3 (3.9+), ss.
# Usage:    sudo ./test_e2e_hybrid_backpressure.sh [mqvpn-binary]

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="${MQVPN:-${SCRIPT_DIR}/../build-debug/mqvpn}"
# shellcheck source=../benchmarks/bench_env_setup.sh
source "${SCRIPT_DIR}/../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN}}"
N_PATHS=1
CTRL_PORT=9099   # h1 9095, h2 9096, benchmarks 9097, mixed 9098

# Same addressing as test_e2e_hybrid_h2.sh: a /32 loopback alias in the
# server netns that the client reaches only through the TCP lane's egress.
TARGET_IP="10.222.0.1"
PORT_BASE=8100
PEER="${SCRIPT_DIR}/hybrid_bp_peer.py"

MIB=$((1024 * 1024))
OFFERED=$((256 * MIB))        # per stalled connection in Tests 1 and 2
SENT_BOUND=$((96 * MIB))      # the sender must stop below this
RSS_BOUND_KB=$((96 * 1024))   # growth allowed per mqvpn process
HOL_STALLED=$((32 * MIB))     # per stalled connection in Test 3
HOL_PROBE=$((4 * MIB))
RECV_RATE=$((16 * MIB))       # bytes/s; a quarter of it per connection

WORK="$(mktemp -d)"
PEER_PIDS=""
trap 'for p in $PEER_PIDS; do kill "$p" 2>/dev/null || true; done;
      ip netns exec "$NS_SERVER" ip addr del "${TARGET_IP}/32" dev lo 2>/dev/null || true;
      bench_cleanup; rm -rf "$WORK"' EXIT

fail=0
echo "[hybrid-bp] binary=$MQVPN target=${TARGET_IP}"
bench_check_test_deps python3 ss

cat >"$WORK/stream.ini" <<EOF
[Hybrid]
Enabled = true
Tcp = stream
EgressAllow = 10.222.0.0/24
EOF
cat >"$WORK/ratelimit.ini" <<EOF
[Hybrid]
Enabled = true
Tcp = stream
EgressAllow = 10.222.0.0/24

[Advanced]
RecvRateLimit = ${RECV_RATE}
EOF

bench_setup_netns_n "$N_PATHS"
bench_add_server_host_routes "$N_PATHS"
ip netns exec "$NS_SERVER" ip addr add "${TARGET_IP}/32" dev lo

vpn_run() {   # $1 = ini, $2 = log tag
    bench_start_vpn_server "--control-port ${CTRL_PORT} --config $1" "$WORK/$2.server.log"
    bench_start_vpn_client "--path $(bench_path_veth_client 0) --config $1" "$WORK/$2.client.log"
    bench_wait_tunnel 25
}

# peer <netns> <args for hybrid_bp_peer.py...>
peer() {
    local ns="$1"; shift
    ip netns exec "$ns" python3 "$PEER" "$@" &
    PEER_PIDS="$PEER_PIDS $!"
}

wait_listening() {   # $1 = port
    local i
    for (( i=0; i<40; i++ )); do
        ip netns exec "$NS_SERVER" ss -ltn 2>/dev/null | grep -q ":$1 " && return 0
        sleep 0.25
    done
    echo "FAIL: nothing listens on port $1"; fail=1; return 1
}

first_field() { cut -d' ' -f1 "$1" 2>/dev/null || echo 0; }
rss_kb() { awk '/^VmRSS:/ {print $2}' "/proc/$1/status"; }

# Wait until the byte count in file $1 is non-zero and unchanged for 3 s
# (max $2 s). Prints the count.
wait_plateau() {
    local f="$1" timeout="$2" prev=-1 same=0 cur i
    for (( i=0; i<timeout; i++ )); do
        cur="$(first_field "$f")"; [ -n "$cur" ] || cur=0
        if [ "$cur" -gt 0 ] && [ "$cur" = "$prev" ]; then
            same=$((same + 1))
            [ "$same" -ge 3 ] && { echo "$cur"; return 0; }
        else
            same=0
        fi
        prev="$cur"
        sleep 1
    done
    echo "$cur"
    return 1
}

wait_file() {   # $1 = file, $2 = timeout s
    local i
    for (( i=0; i<$2*4; i++ )); do
        [ -s "$1" ] && return 0
        sleep 0.25
    done
    return 1
}

# The receiver's "<bytes> <sha256>" must equal the sender's.
check_intact() {   # $1 = label, $2 = sender progress file, $3 = receiver result file, $4 = timeout s
    if ! wait_file "$3" "$4"; then
        echo "FAIL: [$1] the receiver did not finish within $4 s (sender at $(first_field "$2") bytes)"
        fail=1
    elif [ "$(cat "$2")" = "$(cat "$3")" ]; then
        echo "PASS: [$1] $(first_field "$3") bytes arrived intact"
    else
        echo "FAIL: [$1] sender '$(cat "$2")' != receiver '$(cat "$3")'"
        fail=1
    fi
}

# The lane must have carried the connections: kernel TCP end to end (RAW
# lane) has its own backpressure and would pass every check here.
check_lane_flows() {   # $1 = client log, $2 = expected connections
    local i tot=0
    for (( i=0; i<40; i++ )); do
        tot="$(grep -oE 'flows act/tot/rej=[0-9]+/[0-9]+/[0-9]+' "$1" | tail -1 | cut -d/ -f4)"
        [ "${tot:-0}" -ge "$2" ] && { echo "PASS: $tot connections went through the TCP lane"; return 0; }
        sleep 1
    done
    echo "FAIL: the client reports ${tot:-0} TCP-lane connections, expected $2"
    fail=1
}

# One stalled transfer. $1 = label, $2 = port, $3 = netns of the sender.
# The listener is always behind the server; the client netns connects.
stalled_transfer() {
    local label="$1" port="$2" tx_ns="$3"
    local prog="$WORK/$label.progress" res="$WORK/$label.result" go="$WORK/$label.go"
    local rss_s0 rss_c0 rss_s1 rss_c1 sent

    rss_s0="$(rss_kb "$_BENCH_SERVER_PID")"; rss_c0="$(rss_kb "$_BENCH_CLIENT_PID")"
    if [ "$tx_ns" = "$NS_SERVER" ]; then
        peer "$NS_SERVER" listen "$TARGET_IP" "$port" tx "$OFFERED" "$prog"
        wait_listening "$port" || return 0
        peer "$NS_CLIENT" connect "$TARGET_IP" "$port" rx "$go" "$res"
    else
        peer "$NS_SERVER" listen "$TARGET_IP" "$port" rx "$go" "$res"
        wait_listening "$port" || return 0
        peer "$NS_CLIENT" connect "$TARGET_IP" "$port" tx "$OFFERED" "$prog"
    fi

    if ! sent="$(wait_plateau "$prog" 90)"; then
        echo "FAIL: [$label] the sender neither stopped nor finished within 90 s (at $sent bytes)"
        fail=1
    elif [ "$sent" -ge "$SENT_BOUND" ]; then
        echo "FAIL: [$label] the sender was not stopped: $sent of $OFFERED bytes accepted while the receiver reads nothing"
        fail=1
    else
        echo "PASS: [$label] the sender stopped at $sent of $OFFERED bytes"
    fi

    rss_s1="$(rss_kb "$_BENCH_SERVER_PID")"; rss_c1="$(rss_kb "$_BENCH_CLIENT_PID")"
    echo "  resident memory while stalled: server ${rss_s0} -> ${rss_s1} kB, client ${rss_c0} -> ${rss_c1} kB"
    if [ $((rss_s1 - rss_s0)) -ge "$RSS_BOUND_KB" ] || [ $((rss_c1 - rss_c0)) -ge "$RSS_BOUND_KB" ]; then
        echo "FAIL: [$label] an mqvpn process grew by ${RSS_BOUND_KB} kB or more"
        fail=1
    else
        echo "PASS: [$label] both mqvpn processes grew by less than ${RSS_BOUND_KB} kB"
    fi

    touch "$go"
    check_intact "$label" "$prog" "$res" 180
}

echo ""
echo "=== Test 1: downlink, the application on the client side does not read ==="
vpn_run "$WORK/stream.ini" t12
stalled_transfer downlink $((PORT_BASE + 1)) "$NS_SERVER"

echo ""
echo "=== Test 2: uplink, the destination behind the server does not read ==="
stalled_transfer uplink $((PORT_BASE + 2)) "$NS_CLIENT"
check_lane_flows "$WORK/t12.client.log" 2
bench_stop_vpn

echo ""
echo "=== Test 3: RecvRateLimit, three stalled downloads do not stop a fourth ==="
vpn_run "$WORK/ratelimit.ini" t3
for n in 1 2 3; do
    port=$((PORT_BASE + 10 + n))
    peer "$NS_SERVER" listen "$TARGET_IP" "$port" tx "$HOL_STALLED" "$WORK/hol$n.progress"
    wait_listening "$port" || true
    peer "$NS_CLIENT" connect "$TARGET_IP" "$port" rx "$WORK/hol$n.go" "$WORK/hol$n.result"
done
for n in 1 2 3; do
    if sent="$(wait_plateau "$WORK/hol$n.progress" 60)" && [ "$sent" -lt "$HOL_STALLED" ]; then
        echo "PASS: [stalled $n] the sender stopped at $sent of $HOL_STALLED bytes"
    else
        echo "FAIL: [stalled $n] the sender is at $sent of $HOL_STALLED bytes, expected a stop below the total"
        fail=1
    fi
done

port=$((PORT_BASE + 20))
touch "$WORK/probe.go"
peer "$NS_SERVER" listen "$TARGET_IP" "$port" tx "$HOL_PROBE" "$WORK/probe.progress"
wait_listening "$port" || true
peer "$NS_CLIENT" connect "$TARGET_IP" "$port" rx "$WORK/probe.go" "$WORK/probe.result"
check_intact "fourth download" "$WORK/probe.progress" "$WORK/probe.result" 30

for n in 1 2 3; do
    if [ "$(first_field "$WORK/hol$n.progress")" -ge "$HOL_STALLED" ]; then
        echo "FAIL: [stalled $n] finished sending although its receiver never read"
        fail=1
    fi
    touch "$WORK/hol$n.go"
done
for n in 1 2 3; do
    check_intact "stalled $n" "$WORK/hol$n.progress" "$WORK/hol$n.result" 120
done
check_lane_flows "$WORK/t3.client.log" 4
bench_stop_vpn

if [ "$fail" -ne 0 ]; then
    for f in "$WORK"/*.log; do echo "--- $f (tail)"; tail -n 30 "$f"; done
    echo "FAILED"
    exit 1
fi
echo "ALL PASSED"
