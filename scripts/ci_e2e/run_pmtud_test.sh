#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_pmtud_test.sh — E2E test for PMTUD = true (--pmtud).
#
# client (link MTU 1500) -> router -> server (link MTU 1450), and the router
# sends no ICMP errors, so the only way to learn the path MTU is the probes
# inside the tunnel:
#   1. the tunnel comes up at the start size (TUN MTU 1280) and the client
#      TUN MTU then grows to what the 1450-byte link carries, no more;
#   2. a DF ping of that inner size gets through, and a TCP transfer
#      completes with nothing fragmented by the router;
#   3. the link shrinks to 1400 during a transfer: the client TUN MTU goes
#      down to what fits, and the transfer keeps going;
#   4. it shrinks again, below the start size: the tunnel (IPv4 only) goes
#      down to QUIC's minimum packet size, finds what fits and keeps going.
#
# With --ipv6 the underlay between client and server is IPv6.
#
# Usage: sudo ./run_pmtud_test.sh [path-to-mqvpn] [--ipv6] [--log-level LEVEL]

set -e

source "$(dirname "$0")/sanitizer_check.sh"
source "$(dirname "$0")/e2e_lib.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN=""
LOG_LEVEL="info"
IPV6=0

while [ $# -gt 0 ]; do
    case "$1" in
        --log-level) LOG_LEVEL="$2"; shift 2 ;;
        --ipv6) IPV6=1; shift ;;
        *) [ -z "$MQVPN" ] && MQVPN="$1"; shift ;;
    esac
done

MQVPN="${MQVPN:-${SCRIPT_DIR}/../../build/mqvpn}"

if [ ! -f "$MQVPN" ]; then
    echo "error: mqvpn binary not found at $MQVPN"
    exit 1
fi
for tool in tc nft iperf3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: $tool not found"
        exit 1
    fi
done

MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"

NS_CLIENT="vpn-client-pm"
NS_ROUTER="vpn-router-pm"
NS_SERVER="vpn-server-pm"
SERVER_ADDR="10.101.0.1"
SERVER_EP="${SERVER_ADDR}:4433"
# IPv4 20 + UDP 8 + tag 16 + ACK room 16 + QUIC/DATAGRAM/MASQUE 18
OVERHEAD=78
if [ "$IPV6" -eq 1 ]; then
    SERVER_ADDR="fd00:101::1"
    SERVER_EP="[${SERVER_ADDR}]:4433"
    OVERHEAD=98 # IPv6 header is 20 bytes larger
fi
TUNNEL_IP="10.0.0.1"
MID_MTU=1450
SHRUNK_MTU=1400
SMALL_MTU=$((1340 + OVERHEAD - 78)) # below the start size (1358 / 1378)

SERVER_PID=""
CLIENT_PID=""
SANITIZER_FAIL=0
FAIL=0

cleanup() {
    echo ""
    echo "Cleaning up..."
    stop_and_check_sanitizer "$CLIENT_PID" "client" \
        "${WORK_DIR}/client.log" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$SERVER_PID" "server" \
        "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
    sleep 1
    for ns in "$NS_CLIENT" "$NS_ROUTER" "$NS_SERVER"; do
        ip netns del "$ns" 2>/dev/null || true
    done
    if [ -n "${MQVPN_E2E_LOG_DIR:-}" ]; then
        mkdir -p "$MQVPN_E2E_LOG_DIR"
        cp "${WORK_DIR}/client.log" "${MQVPN_E2E_LOG_DIR}/pmtud-client.log" 2>/dev/null || true
        cp "${WORK_DIR}/server.log" "${MQVPN_E2E_LOG_DIR}/pmtud-server.log" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

for ns in "$NS_CLIENT" "$NS_ROUTER" "$NS_SERVER"; do
    ip netns del "$ns" 2>/dev/null || true
done

PSK=$("$MQVPN" --genkey 2>/dev/null)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-pmtud-test" 2>/dev/null

for ns in "$NS_CLIENT" "$NS_ROUTER" "$NS_SERVER"; do
    ip netns add "$ns"
    ip netns exec "$ns" ip link set lo up
done

# client <-> router: 1500
ip link add pm-c0 type veth peer name pm-r0
ip link set pm-c0 netns "$NS_CLIENT"
ip link set pm-r0 netns "$NS_ROUTER"
ip netns exec "$NS_CLIENT" ip addr add 10.100.0.2/24 dev pm-c0
ip netns exec "$NS_ROUTER" ip addr add 10.100.0.1/24 dev pm-r0
if [ "$IPV6" -eq 1 ]; then
    ip netns exec "$NS_CLIENT" ip addr add fd00:100::2/64 dev pm-c0 nodad
    ip netns exec "$NS_ROUTER" ip addr add fd00:100::1/64 dev pm-r0 nodad
fi
ip netns exec "$NS_CLIENT" ip link set pm-c0 up
ip netns exec "$NS_ROUTER" ip link set pm-r0 up

# router <-> server: MID_MTU
ip link add pm-r1 type veth peer name pm-s0
ip link set pm-r1 netns "$NS_ROUTER"
ip link set pm-s0 netns "$NS_SERVER"
ip netns exec "$NS_ROUTER" ip addr add 10.101.0.254/24 dev pm-r1
ip netns exec "$NS_SERVER" ip addr add 10.101.0.1/24 dev pm-s0
if [ "$IPV6" -eq 1 ]; then
    ip netns exec "$NS_ROUTER" ip addr add fd00:101::fe/64 dev pm-r1 nodad
    ip netns exec "$NS_SERVER" ip addr add "${SERVER_ADDR}/64" dev pm-s0 nodad
fi
ip netns exec "$NS_ROUTER" ip link set pm-r1 mtu "$MID_MTU" up
ip netns exec "$NS_SERVER" ip link set pm-s0 mtu "$MID_MTU" up

# no offloads: packets must reach the router at the size they were sent
for d in "$NS_CLIENT pm-c0" "$NS_ROUTER pm-r0" "$NS_ROUTER pm-r1" "$NS_SERVER pm-s0"; do
    set -- $d
    ip netns exec "$1" ethtool -K "$2" tso off gso off gro off tx-udp-segmentation off \
        >/dev/null 2>&1 || true
done

ip netns exec "$NS_CLIENT" ip route add default via 10.100.0.1
ip netns exec "$NS_SERVER" ip route add default via 10.101.0.254
ip netns exec "$NS_ROUTER" sysctl -qw net.ipv4.ip_forward=1
if [ "$IPV6" -eq 1 ]; then
    ip netns exec "$NS_CLIENT" ip -6 route add default via fd00:100::1
    ip netns exec "$NS_SERVER" ip -6 route add default via fd00:101::fe
    ip netns exec "$NS_ROUTER" sysctl -qw net.ipv6.conf.all.forwarding=1
fi
ip netns exec "$NS_ROUTER" tc qdisc add dev pm-r0 root netem rate 100mbit delay 10ms
ip netns exec "$NS_ROUTER" tc qdisc add dev pm-r1 root netem rate 100mbit delay 10ms

# the router sends no Fragmentation Needed / Packet Too Big
ip netns exec "$NS_ROUTER" nft -f - <<EOF
table inet pmtud_test {
    chain out {
        type filter hook output priority -500;
        icmp type destination-unreachable drop
        icmpv6 type packet-too-big drop
    }
}
EOF

# IPv6 link-local addresses finish DAD before the router forwards
for _ in $(seq 10); do
    ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$SERVER_ADDR" >/dev/null && break
done
ip netns exec "$NS_CLIENT" ping -c 1 -W 2 "$SERVER_ADDR" >/dev/null

ip netns exec "$NS_SERVER" "$MQVPN" \
    --mode server \
    --listen "$SERVER_EP" \
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
    --server "$SERVER_EP" \
    --path pm-c0 \
    --auth-key "$PSK" \
    --insecure \
    --pmtud \
    --log-level "$LOG_LEVEL" >"${WORK_DIR}/client.log" 2>&1 &
CLIENT_PID=$!

# start a one-shot iperf3 server on port $1 and wait until it listens
iperf_server() {
    ip netns exec "$NS_SERVER" iperf3 -s -1 -B "$TUNNEL_IP" -p "$1" >/dev/null 2>&1 &
    for _ in $(seq 20); do
        ip netns exec "$NS_SERVER" ss -ltn "sport = :$1" | grep -q LISTEN && return 0
        sleep 0.2
    done
    return 1
}

tun_mtu() {
    ip netns exec "$NS_CLIENT" ip link show mqvpn0 2>/dev/null \
        | sed -n 's/.* mtu \([0-9]*\) .*/\1/p'
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

# ── 1. the TUN MTU grows to what the 1450-byte link carries ──
max_mtu=$((MID_MTU - OVERHEAD))
mtu=0
for _ in $(seq 20); do
    mtu=$(tun_mtu)
    [ -n "$mtu" ] && [ "$mtu" -gt 1300 ] && break
    sleep 0.5
done
sleep 3 # let the search finish
mtu=$(tun_mtu)
if [ "$mtu" -gt 1300 ] && [ "$mtu" -le "$max_mtu" ]; then
    echo "PASS: TUN MTU grew to $mtu (link carries up to $max_mtu)"
else
    echo "FAIL: TUN MTU $mtu, expected 1301..$max_mtu"
    FAIL=1
fi

# ── 2. a DF ping of that size and a TCP transfer, nothing fragmented ──
if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 -M do -s $((mtu - 28)) "$TUNNEL_IP" >/dev/null; then
    echo "PASS: DF ping of $mtu bytes through the tunnel"
else
    echo "FAIL: DF ping of $mtu bytes through the tunnel"
    FAIL=1
fi

iperf_server 5201
if ip netns exec "$NS_CLIENT" iperf3 -c "$TUNNEL_IP" -p 5201 -t 3 >"${WORK_DIR}/iperf1.txt" 2>&1; then
    echo "PASS: TCP transfer at the discovered size"
else
    echo "FAIL: TCP transfer at the discovered size"
    cat "${WORK_DIR}/iperf1.txt"
    FAIL=1
fi
# an IPv6 router never fragments: an oversize packet would just be dropped
frags=$(ip netns exec "$NS_ROUTER" nstat -az IpFragCreates | awk 'NR > 1 { print $2 }')
if [ "${frags:-0}" -eq 0 ]; then
    echo "PASS: router fragmented nothing"
else
    echo "FAIL: router created $frags fragments"
    FAIL=1
fi

# ── 3. the link shrinks during a transfer ──
iperf_server 5202
timeout 30 ip netns exec "$NS_CLIENT" iperf3 -c "$TUNNEL_IP" -p 5202 -t 10 -i 1 >"${WORK_DIR}/iperf2.txt" 2>&1 &
IPERF_PID=$!
sleep 3
ip netns exec "$NS_ROUTER" ip link set pm-r1 mtu "$SHRUNK_MTU"
ip netns exec "$NS_SERVER" ip link set pm-s0 mtu "$SHRUNK_MTU"
if wait "$IPERF_PID"; then
    echo "PASS: TCP transfer survived the link shrinking to $SHRUNK_MTU"
else
    echo "FAIL: TCP transfer across the link shrinking to $SHRUNK_MTU"
    cat "${WORK_DIR}/iperf2.txt"
    FAIL=1
fi
# the last seconds of the transfer carried data
late=$(grep -E "^\[ *[0-9]+\] +(8|9)\.00-" "${WORK_DIR}/iperf2.txt" \
    | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /bits\/sec/) print $(i - 1) }' | head -1)
if [ -n "$late" ] && awk -v v="$late" 'BEGIN { exit !(v > 0) }'; then
    echo "PASS: data still flowing after the shrink ($late)"
else
    echo "FAIL: no data after the shrink"
    cat "${WORK_DIR}/iperf2.txt"
    FAIL=1
fi
max_mtu=$((SHRUNK_MTU - OVERHEAD))
mtu=$(tun_mtu)
if [ "$mtu" -ge 1280 ] && [ "$mtu" -le "$max_mtu" ]; then
    echo "PASS: TUN MTU went down to $mtu (link carries up to $max_mtu)"
else
    echo "FAIL: TUN MTU $mtu after the shrink, expected 1280..$max_mtu"
    FAIL=1
fi

# ── 4. the link shrinks below the start size ──
iperf_server 5203
timeout 30 ip netns exec "$NS_CLIENT" iperf3 -c "$TUNNEL_IP" -p 5203 -t 10 -i 1 >"${WORK_DIR}/iperf3.txt" 2>&1 &
IPERF_PID=$!
sleep 3
ip netns exec "$NS_ROUTER" ip link set pm-r1 mtu "$SMALL_MTU"
ip netns exec "$NS_SERVER" ip link set pm-s0 mtu "$SMALL_MTU"
if wait "$IPERF_PID"; then
    echo "PASS: TCP transfer survived the link shrinking to $SMALL_MTU"
else
    echo "FAIL: TCP transfer across the link shrinking to $SMALL_MTU"
    cat "${WORK_DIR}/iperf3.txt"
    FAIL=1
fi
late=$(grep -E "^\[ *[0-9]+\] +(8|9)\.00-" "${WORK_DIR}/iperf3.txt" \
    | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /bits\/sec/) print $(i - 1) }' | head -1)
if [ -n "$late" ] && awk -v v="$late" 'BEGIN { exit !(v > 0) }'; then
    echo "PASS: data still flowing below the start size ($late)"
else
    echo "FAIL: no data after the shrink below the start size"
    cat "${WORK_DIR}/iperf3.txt"
    FAIL=1
fi
max_mtu=$((SMALL_MTU - OVERHEAD))
mtu=$(tun_mtu)
if [ "$mtu" -ge 1150 ] && [ "$mtu" -le "$max_mtu" ]; then
    echo "PASS: TUN MTU went down to $mtu (link carries up to $max_mtu)"
else
    echo "FAIL: TUN MTU $mtu below the start size, expected 1150..$max_mtu"
    FAIL=1
fi
if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 -M do -s $((mtu - 28)) "$TUNNEL_IP" >/dev/null; then
    echo "PASS: DF ping of $mtu bytes through the tunnel"
else
    echo "FAIL: DF ping of $mtu bytes through the tunnel"
    FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
    echo "=== PMTUD test FAILED ==="
    exit 1
fi
echo "=== PMTUD test PASSED ($([ "$IPV6" -eq 1 ] && echo IPv6 || echo IPv4) underlay) ==="
