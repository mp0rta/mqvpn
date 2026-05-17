#!/bin/bash
# run_d1_port_only_retain_test.sh — D1 §9.4 ¶1 MAY retain on port-only change.
#
# Negative-side of run_d1_ip_change_rebind_test.sh: when ONLY the source port
# changes (same src IP), the rebinding probe still validates the new 5-tuple
# but the D1 reset MUST NOT fire (xqc_frame.c port_only_retain branch).
#
# Topology mirrors run_d1_ip_change_rebind_test.sh but the SNAT src IP stays
# constant; only the source port is forced to rotate via SNAT --to-source
# 10.61.0.10:<rangeA> -> :<rangeB> + conntrack flush.
#
# Assertions on server.log:
#   - REBINDING|validate NAT rebinding addr   (probe was issued)
#   - REBINDING|port_only_retain|spec:9.4_p1_MAY   (retain branch taken)
#   - NO occurrence of MIGRATION|cwnd_rtt_reset (reset must NOT fire)
#
# Usage: sudo ./run_d1_port_only_retain_test.sh [mqvpn-binary] [--log-level LEVEL]

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

if ! command -v iptables >/dev/null 2>&1; then
    echo "SKIP: iptables not available (required for SNAT scenario)"
    exit 0
fi

WORK_DIR="$(mktemp -d)"

NS_SERVER="vpn-server-d1pt"
NS_MIDDLE="vpn-middle-d1pt"
NS_CLIENT="vpn-client-d1pt"

VETH_C0="veth-c0-d1pt"
VETH_C1="veth-c1-d1pt"
VETH_M1="veth-m1-d1pt"
VETH_S0="veth-s0-d1pt"

IP_CLIENT="10.52.0.2/24"
IP_MIDDLE_IN="10.52.0.1/24"
IP_MIDDLE_OUT="10.62.0.1/24"
IP_SERVER="10.62.0.100/24"
SNAT_IP="10.62.0.10"

SERVER_ADDR="10.62.0.100"
TUNNEL_IP="10.0.0.1"

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
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_MIDDLE" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del "$VETH_C0" 2>/dev/null || true
    ip link del "$VETH_M1" 2>/dev/null || true
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

ip netns del "$NS_SERVER" 2>/dev/null || true
ip netns del "$NS_MIDDLE" 2>/dev/null || true
ip netns del "$NS_CLIENT" 2>/dev/null || true
ip link del "$VETH_C0" 2>/dev/null || true
ip link del "$VETH_M1" 2>/dev/null || true

PSK=$("$MQVPN" --genkey 2>/dev/null)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-d1pt-test" 2>/dev/null

ip netns add "$NS_SERVER"
ip netns add "$NS_MIDDLE"
ip netns add "$NS_CLIENT"

ip link add "$VETH_C0" type veth peer name "$VETH_C1"
ip link set "$VETH_C0" netns "$NS_CLIENT"
ip link set "$VETH_C1" netns "$NS_MIDDLE"
ip netns exec "$NS_CLIENT" ip addr add "$IP_CLIENT" dev "$VETH_C0"
ip netns exec "$NS_MIDDLE" ip addr add "$IP_MIDDLE_IN" dev "$VETH_C1"
ip netns exec "$NS_CLIENT" ip link set "$VETH_C0" up
ip netns exec "$NS_MIDDLE" ip link set "$VETH_C1" up

ip link add "$VETH_M1" type veth peer name "$VETH_S0"
ip link set "$VETH_M1" netns "$NS_MIDDLE"
ip link set "$VETH_S0" netns "$NS_SERVER"
ip netns exec "$NS_MIDDLE" ip addr add "$IP_MIDDLE_OUT" dev "$VETH_M1"
ip netns exec "$NS_SERVER" ip addr add "$IP_SERVER" dev "$VETH_S0"
ip netns exec "$NS_MIDDLE" ip link set "$VETH_M1" up
ip netns exec "$NS_SERVER" ip link set "$VETH_S0" up

ip netns exec "$NS_CLIENT" ip link set lo up
ip netns exec "$NS_MIDDLE" ip link set lo up
ip netns exec "$NS_SERVER" ip link set lo up

ip netns exec "$NS_MIDDLE" sysctl -w net.ipv4.ip_forward=1 >/dev/null

ip netns exec "$NS_CLIENT" ip route add default via 10.52.0.1
ip netns exec "$NS_SERVER" ip route add 10.62.0.0/24 dev "$VETH_S0" || true
ip netns exec "$NS_MIDDLE" ip addr add "${SNAT_IP}/24" dev "$VETH_M1" || true

# Initial SNAT — narrow port range to force renumbering on rule swap.
ip netns exec "$NS_MIDDLE" iptables -t nat -A POSTROUTING -o "$VETH_M1" \
    -s 10.52.0.0/24 -p udp -j SNAT --to-source "${SNAT_IP}:40000-40050"

ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$SERVER_ADDR" >/dev/null || {
    echo "SKIP: pre-flight ping via NAT failed"
    exit 0
}

ip netns exec "$NS_SERVER" "$MQVPN" \
    --mode server \
    --listen "0.0.0.0:4433" \
    --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" \
    --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" \
    --scheduler min_srtt \
    --log-level "$LOG_LEVEL" > "${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "  FAIL: server died"; cat "${WORK_DIR}/server.log"; FAIL=$((FAIL + 1))
else
    ip netns exec "$NS_CLIENT" "$MQVPN" \
        --mode client \
        --server "${SERVER_ADDR}:4433" \
        --path "$VETH_C0" \
        --auth-key "$PSK" \
        --insecure \
        --scheduler min_srtt \
        --log-level "$LOG_LEVEL" > "${WORK_DIR}/client.log" 2>&1 &
    CLIENT_PID=$!
    sleep 3

    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        echo "  FAIL: client died"; cat "${WORK_DIR}/client.log"; FAIL=$((FAIL + 1))
    else
        TUNNEL_OK=0
        for i in $(seq 1 15); do
            if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_IP" >/dev/null 2>&1; then
                TUNNEL_OK=1; break
            fi
            sleep 1
        done

        if [ "$TUNNEL_OK" -ne 1 ]; then
            echo "  FAIL: tunnel never reachable"
            tail -40 "${WORK_DIR}/client.log"
            FAIL=$((FAIL + 1))
        else
            echo "=== Test: D1 §9.4 ¶1 port-only retain (no reset) ==="

            # Rotate SNAT source port range — same IP, different ports.
            ip netns exec "$NS_MIDDLE" iptables -t nat -F
            ip netns exec "$NS_MIDDLE" iptables -t nat -A POSTROUTING -o "$VETH_M1" \
                -s 10.52.0.0/24 -p udp -j SNAT --to-source "${SNAT_IP}:50000-50050"
            command -v conntrack >/dev/null 2>&1 && \
                ip netns exec "$NS_MIDDLE" conntrack -F 2>/dev/null || true

            ( for i in $(seq 1 10); do
                ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_IP" >/dev/null 2>&1 || true
                sleep 1
              done ) &
            POKER=$!

            PROBE_OK=0
            RETAIN_OK=0
            for i in $(seq 1 10); do
                if grep -qE "REBINDING\|validate NAT rebinding addr" "${WORK_DIR}/server.log"; then
                    PROBE_OK=1
                fi
                if grep -qE "REBINDING\|port_only_retain\|spec:9.4_p1_MAY" "${WORK_DIR}/server.log"; then
                    RETAIN_OK=1
                fi
                [ "$PROBE_OK" -eq 1 ] && [ "$RETAIN_OK" -eq 1 ] && break
                sleep 1
            done
            kill "$POKER" 2>/dev/null || true
            wait "$POKER" 2>/dev/null || true

            # Reset MUST NOT have fired (port-only is the MAY-retain branch).
            RESET_PRESENT=0
            if grep -qE "MIGRATION\|cwnd_rtt_reset" "${WORK_DIR}/server.log"; then
                RESET_PRESENT=1
            fi

            if [ "$PROBE_OK" -eq 1 ] && [ "$RETAIN_OK" -eq 1 ] && [ "$RESET_PRESENT" -eq 0 ]; then
                echo "  PASS: port-only retain (probe validated, retain logged, no reset)"
                PASS=$((PASS + 1))
            else
                echo "  FAIL: probe=$PROBE_OK retain=$RETAIN_OK reset_present=$RESET_PRESENT"
                echo "  --- server.log (last 100 lines) ---"
                tail -100 "${WORK_DIR}/server.log"
                FAIL=$((FAIL + 1))
            fi
        fi
    fi
fi

echo ""
echo "================================================="
echo " Results: PASS=$PASS  FAIL=$FAIL"
echo "================================================="
[ "$FAIL" -eq 0 ]
