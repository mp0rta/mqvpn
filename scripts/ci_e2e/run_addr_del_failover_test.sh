#!/bin/bash
# run_addr_del_failover_test.sh — E2E test for path failover on ADDRESS-ONLY
# removal (RTM_DELADDR with the link staying admin-UP), i.e. the NetworkManager
# `nmcli dev disconnect` / DHCP-lease-loss case.
#
# Companion to run_admin_down_test.sh and run_carrier_flap_test.sh:
#   - carrier_flap : peer down  -> RTM_NEWLINK, IFF_UP set, operstate DOWN
#                    (is_carrier_loss() catches it)
#   - admin_down   : ip link set <local> down + addr flush
#                    -> RTM_NEWLINK IFF_UP=0 (+ RTM_DELADDR); sends fail with
#                    write errors so the path degrades via the write-error path
#   - addr_del     : THIS TEST. `ip addr del` only, link stays admin-UP.
#                    The kernel emits ONLY RTM_DELADDR; IFF_UP and carrier stay
#                    set. This mirrors `nmcli dev disconnect` and DHCP lease
#                    expiry on a real box, which do NOT toggle the link.
#
# Reproduces the real-network finding (v0.8.1-beta1, 2026-07-06): with wlb and
# an actively-used path, removing that path's source address caused the whole
# tunnel to stall for the full outage because the path was never dropped —
# RTM_DELADDR has no handler in platform_linux.c's netlink switch and the
# carrier-loss gate requires IFF_UP to be *cleared*... which nmcli/DHCP do not do.
#
# Expected once fixed: within a couple of seconds of the address disappearing,
# the path is dropped/degraded and traffic continues on the surviving path.
#
# Topology (dual-path multipath):
#   vpn-client-da                 vpn-server-da
#     veth-a0-da ───────────────── veth-a1-da    Path A (10.100.0.0/24)
#     veth-b0-da ───────────────── veth-b1-da    Path B (10.200.0.0/24)
#
# Usage: sudo ./run_addr_del_failover_test.sh [path-to-mqvpn-binary] [--log-level LEVEL]
#        (use --log-level debug: FSM transition logs are DEBUG level)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/sanitizer_check.sh"
MQVPN=""
LOG_LEVEL="debug"

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
MQVPN="$(realpath "$MQVPN")"
WORK_DIR="$(mktemp -d)"

NS_SERVER="vpn-server-da"
NS_CLIENT="vpn-client-da"
VETH_A0="veth-a0-da"
VETH_A1="veth-a1-da"
VETH_B0="veth-b0-da"
VETH_B1="veth-b1-da"

IP_A_CLIENT="10.100.0.2/24"
IP_A_SERVER="10.100.0.1/24"
IP_B_CLIENT="10.200.0.2/24"
IP_B_SERVER="10.200.0.1/24"
SERVER_ADDR="10.100.0.1"
TUNNEL_IP="10.0.0.1"

SERVER_PID=""
CLIENT_PID=""
SANITIZER_FAIL=0

cleanup() {
    echo ""
    echo "Cleaning up..."
    stop_and_check_sanitizer "$CLIENT_PID" "client" \
        "${WORK_DIR}/client.log" || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$SERVER_PID" "server" \
        "${WORK_DIR}/server.log" || SANITIZER_FAIL=1
    sleep 1
    ip netns del "$NS_SERVER" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip link del "$VETH_A0" 2>/dev/null || true
    ip link del "$VETH_B0" 2>/dev/null || true
    if [ -n "${MQVPN_E2E_LOG_DIR:-}" ]; then
        mkdir -p "$MQVPN_E2E_LOG_DIR"
        cp "${WORK_DIR}/client.log" "${WORK_DIR}/server.log" \
            "$MQVPN_E2E_LOG_DIR/" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
    if [ "$SANITIZER_FAIL" -ne 0 ]; then
        echo "FAIL: sanitizer errors detected"
        exit 1
    fi
}
trap cleanup EXIT

ip netns del "$NS_SERVER" 2>/dev/null || true
ip netns del "$NS_CLIENT" 2>/dev/null || true
ip link del "$VETH_A0" 2>/dev/null || true
ip link del "$VETH_B0" 2>/dev/null || true

wait_for_log() {
    local log_file="$1" pattern="$2" timeout="${3:-15}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        grep -qE "$pattern" "$log_file" 2>/dev/null && return 0
        sleep 1; elapsed=$((elapsed + 1))
    done
    return 1
}

# Like wait_for_log but only considers lines AFTER $3 — needed to
# distinguish a post-restore activation from the initial connect-time one.
wait_for_log_after() {
    local log_file="$1" pattern="$2" start_line="$3" timeout="${4:-15}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        tail -n "+$((start_line + 1))" "$log_file" 2>/dev/null | grep -qE "$pattern" && return 0
        sleep 1; elapsed=$((elapsed + 1))
    done
    return 1
}

# ─── Setup ───
PSK=$("$MQVPN" --genkey 2>/dev/null)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${WORK_DIR}/server.key" -out "${WORK_DIR}/server.crt" \
    -days 365 -nodes -subj "/CN=mqvpn-addr-del-test" 2>/dev/null

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
# Reach the server (Path A subnet) via Path B too, so the QUIC connection
# survives on Path B while Path A's address is gone.
ip netns exec "$NS_CLIENT" ip route add 10.100.0.0/24 via 10.200.0.1 dev "$VETH_B0" metric 200

ip netns exec "$NS_CLIENT" ping -c 1 -W 2 "$SERVER_ADDR" >/dev/null
ip netns exec "$NS_CLIENT" ping -c 1 -W 2 10.200.0.1 >/dev/null

# ─── Server ───
ip netns exec "$NS_SERVER" "$MQVPN" \
    --mode server --listen "0.0.0.0:4433" --subnet 10.0.0.0/24 \
    --cert "${WORK_DIR}/server.crt" --key "${WORK_DIR}/server.key" \
    --auth-key "$PSK" --scheduler wlb \
    --log-level "$LOG_LEVEL" >"${WORK_DIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 2
kill -0 "$SERVER_PID" 2>/dev/null || { echo "server died"; cat "${WORK_DIR}/server.log"; exit 1; }

# ─── Client ───
ip netns exec "$NS_CLIENT" "$MQVPN" \
    --mode client --server "${SERVER_ADDR}:4433" \
    --path "$VETH_A0" --path "$VETH_B0" \
    --auth-key "$PSK" --insecure --scheduler wlb \
    --log-level "$LOG_LEVEL" >"${WORK_DIR}/client.log" 2>&1 &
CLIENT_PID=$!
sleep 3
kill -0 "$CLIENT_PID" 2>/dev/null || { echo "client died"; cat "${WORK_DIR}/client.log"; exit 1; }

# Wait for tunnel up
ELAPSED=0
while [ "$ELAPSED" -lt 15 ]; do
    ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_IP" >/dev/null 2>&1 && break
    sleep 1; ELAPSED=$((ELAPSED + 1))
done
[ "$ELAPSED" -ge 15 ] && { echo "FAIL: tunnel not up"; cat "${WORK_DIR}/client.log"; exit 1; }
echo "OK: tunnel up (${ELAPSED}s)"

# Require BOTH paths ACTIVE by name — a bare "path.*activated" is satisfied
# by Path A's connect-time activation alone, letting the test proceed while
# Path B is still VALIDATING on a slow runner.
for IFACE in "$VETH_A0" "$VETH_B0"; do
    wait_for_log "${WORK_DIR}/client.log" \
        "activated:.*iface=${IFACE}.*state=ACTIVE|name=${IFACE}\].*-> ACTIVE" 15 \
        || { echo "FAIL: path ${IFACE} not active"; cat "${WORK_DIR}/client.log"; exit 1; }
done
echo "OK: dual-path active"

# =================================================================
#  Address-only removal (link stays admin-UP) — nmcli/DHCP mirror
# =================================================================
echo ""
echo "=== Removing Path A source address ONLY (link stays UP) — nmcli/DHCP mirror ==="
LINE_BEFORE=$(wc -l <"${WORK_DIR}/client.log")

# Sanity: prove the link stays admin-up (IFF_UP) after the address goes.
ip netns exec "$NS_CLIENT" ip addr del "$IP_A_CLIENT" dev "$VETH_A0"
echo "--- ${VETH_A0} state right after addr del (expect UP,LOWER_UP; no inet) ---"
ip netns exec "$NS_CLIENT" ip -br addr show "$VETH_A0"

# --- Functional assertion: tunnel keeps flowing on Path B (fast failover) ---
# 20 pings over ~10s spanning the outage. With the fix, Path A is dropped
# promptly and every ping rides Path B (≈0 loss). Without it, the path lingers
# and traffic stalls until the address returns.
echo "--- tunnel ping continuity over ~10s (Path B must carry) ---"
PING_OUT=$(ip netns exec "$NS_CLIENT" ping -c 20 -i 0.5 -W 2 "$TUNNEL_IP" 2>&1 || true)
echo "$PING_OUT" | tail -3
LOSS=$(echo "$PING_OUT" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+' | head -1)
LOSS="${LOSS:-100}"

# --- Diagnostic dump: what did the client actually do on RTM_DELADDR? ---
echo ""
echo "=== DIAGNOSTIC: client-side reaction to addr removal (post addr-del lines) ==="
tail -n "+$((LINE_BEFORE + 1))" "${WORK_DIR}/client.log" \
    | grep -iE "closing path|carrier lost|address removed|DELADDR|${VETH_A0}\].*->|DEGRADED|CLOSED|write.*error|write_socket|ENETUNREACH|ENETDOWN|EADDRNOTAVAIL|sendmsg|sendto|no route|stuck in PENDING" \
    | head -40 || echo "(no matching diagnostic lines)"
echo "=== END DIAGNOSTIC ==="
echo ""

# --- Pass/fail: path dropped AND traffic continuity ---
DROPPED=0
tail -n "+$((LINE_BEFORE + 1))" "${WORK_DIR}/client.log" \
    | grep -qE "interface ${VETH_A0} .*closing path|name=${VETH_A0}\].*-> (DEGRADED|CLOSED|CREATE_WAIT)" \
    && DROPPED=1

echo "RESULT (removal): ping_loss=${LOSS}%  path_A_dropped_or_degraded=${DROPPED}"
if [ "$LOSS" -gt 10 ] || [ "$DROPPED" -ne 1 ]; then
    echo "=== FAIL: RTM_DELADDR failover gap reproduced ==="
    echo "    (loss=${LOSS}% > 10%  and/or  Path A not dropped)"
    exit 1
fi
echo "OK: Path A dropped, traffic continued on Path B"

# =================================================================
#  Recovery: address comes back (mirrors `nmcli dev connect` / DHCP renew)
#  -> Path A must return to ACTIVE, not sit stuck in PENDING/VALIDATING.
# =================================================================
echo ""
echo "=== Re-adding Path A source address (nmcli connect / DHCP renew mirror) ==="
READD_MARK=$(wc -l <"${WORK_DIR}/client.log")
ip netns exec "$NS_CLIENT" ip addr add "$IP_A_CLIENT" dev "$VETH_A0"

# Path A must reactivate within 45s (search only lines after the re-add).
ACT_PATTERN="activated:.*iface=${VETH_A0}.*state=(ACTIVE|STANDBY)|name=${VETH_A0}\].*-> (ACTIVE|STANDBY)"
if wait_for_log_after "${WORK_DIR}/client.log" "$ACT_PATTERN" "$READD_MARK" 45; then
    echo "OK: Path A returned to ACTIVE after address restore"
else
    echo "=== FAIL: Path A did not return to ACTIVE within 45s of address restore ==="
    grep -E "stuck in PENDING" "${WORK_DIR}/client.log" && echo "(path stuck in PENDING)"
    echo "--- post-restore client log ---"
    tail -n "+$((READD_MARK + 1))" "${WORK_DIR}/client.log" \
        | grep -iE "${VETH_A0}\]|path [0-9]|re-added|reactivat|VALIDATING|ACTIVE|PENDING|stuck" | tail -25
    exit 1
fi

# Final: both paths carry traffic again.
if ip netns exec "$NS_CLIENT" ping -c 3 -W 2 "$TUNNEL_IP" >/dev/null 2>&1; then
    echo "OK: tunnel ping works after recovery"
else
    echo "=== FAIL: tunnel ping failed after recovery ==="
    exit 1
fi

echo ""
echo "=== All addr-del failover tests PASSED ==="
exit 0
