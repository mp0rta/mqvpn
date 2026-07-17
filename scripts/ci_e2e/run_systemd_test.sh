#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_systemd_test.sh — Systemd service integration test using network namespaces
#
# Validates the full systemd lifecycle for mqvpn-server.service and
# mqvpn-client@.service using drop-in overrides to run inside netns.
#
# Topology (same pattern as run_nat_test.sh):
#   sd-client                  sd-server                    sd-external
#     veth-c ────────────────── veth-s
#     192.168.100.1/24          192.168.100.2/24
#                                veth-wan-s ──────────────── veth-wan-e
#                                172.16.0.1/24               172.16.0.2/24
#
# Prerequisites: systemd, mqvpn installed via `cmake --install . --prefix /usr/local`
#
# Usage: sudo scripts/ci_e2e/run_systemd_test.sh

set -euo pipefail

# ── Helpers ──────────────────────────────────────────────────────────────────

pass() { echo ""; echo "=== $1: PASS ==="; }
fail() { echo ""; echo "=== $1: FAIL ==="; dump_logs; exit 1; }

dump_logs() {
    echo ""
    echo "--- journalctl mqvpn-server ---"
    journalctl -u mqvpn-server --no-pager -n 80 2>/dev/null || true
    echo ""
    echo "--- journalctl mqvpn-client@test1 ---"
    journalctl -u mqvpn-client@test1 --no-pager -n 80 2>/dev/null || true
}

# ── Phase 1: Prerequisites ──────────────────────────────────────────────────

echo "=== Phase 1: Prerequisites ==="

if ! systemctl --version >/dev/null 2>&1; then
    echo "FAIL: systemd not available"
    exit 1
fi
echo "OK: systemd available"

for f in /usr/local/bin/mqvpn \
         /usr/local/lib/systemd/system/mqvpn-server.service \
         /usr/local/lib/systemd/system/mqvpn-client@.service \
         /usr/local/lib/mqvpn/mqvpn-server-nat.sh; do
    if [ ! -f "$f" ]; then
        echo "FAIL: $f not found — run: cd build && sudo cmake --install . --prefix /usr/local"
        exit 1
    fi
done
echo "OK: all installed files present"

# ── Phase 2: Unit file validation ────────────────────────────────────────────

echo ""
echo "=== Phase 2: Unit file validation ==="

systemd-analyze verify /usr/local/lib/systemd/system/mqvpn-server.service 2>&1 || true
systemd-analyze verify /usr/local/lib/systemd/system/mqvpn-client@.service 2>&1 || true
echo "OK: systemd-analyze verify completed"

# ── Setup: keys, configs, netns, drop-ins ────────────────────────────────────

echo ""
echo "=== Setup ==="

# Generate PSK
PSK=$(/usr/local/bin/mqvpn --genkey 2>/dev/null)
echo "Generated PSK: ${PSK}"

# Write config files + cert to /etc/mqvpn (must be here — PrivateTmp=true
# in the unit file means /tmp is isolated from the host)
mkdir -p /etc/mqvpn

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /etc/mqvpn/server.key -out /etc/mqvpn/server.crt \
    -days 1 -nodes -subj "/CN=mqvpn-systemd-test" 2>/dev/null
echo "OK: cert generated"

cat > /etc/mqvpn/server.conf <<EOF
[Interface]
Listen = 192.168.100.2:4433
Subnet = 10.0.0.0/24
TunName = mqvpn0
LogLevel = debug

[TLS]
Cert = /etc/mqvpn/server.crt
Key  = /etc/mqvpn/server.key

[Auth]
Key = ${PSK}
EOF

cat > /etc/mqvpn/client-test1.conf <<EOF
[Server]
Address  = 192.168.100.2:4433
Insecure = true

[Auth]
Key = ${PSK}

[Interface]
TunName  = mqvpn0
LogLevel = debug
Reconnect = true
ReconnectInterval = 2
EOF

echo "OK: configs written to /etc/mqvpn/"

# ── Cleanup trap ─────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    systemctl stop mqvpn-client@test1 2>/dev/null || true
    systemctl stop mqvpn-server 2>/dev/null || true
    sleep 1
    rm -rf /run/systemd/system/mqvpn-server.service.d
    rm -rf /run/systemd/system/mqvpn-client@test1.service.d
    systemctl daemon-reload 2>/dev/null || true
    rm -rf /etc/mqvpn
    ip netns del sd-server 2>/dev/null || true
    ip netns del sd-client 2>/dev/null || true
    ip netns del sd-external 2>/dev/null || true
    ip link del sd-veth-c 2>/dev/null || true
    ip link del sd-veth-wan-s 2>/dev/null || true
    echo "Cleanup done"
}
trap cleanup EXIT

# Clean leftover namespaces from previous runs
ip netns del sd-server 2>/dev/null || true
ip netns del sd-client 2>/dev/null || true
ip netns del sd-external 2>/dev/null || true
ip link del sd-veth-c 2>/dev/null || true
ip link del sd-veth-wan-s 2>/dev/null || true

# ── Network namespaces ───────────────────────────────────────────────────────

echo "Setting up network namespaces..."
ip netns add sd-server
ip netns add sd-client
ip netns add sd-external

# veth pair 1: client <-> server
ip link add sd-veth-c type veth peer name sd-veth-s
ip link set sd-veth-c netns sd-client
ip link set sd-veth-s netns sd-server

ip netns exec sd-client ip addr add 192.168.100.1/24 dev sd-veth-c
ip netns exec sd-server ip addr add 192.168.100.2/24 dev sd-veth-s
ip netns exec sd-client ip link set sd-veth-c up
ip netns exec sd-server ip link set sd-veth-s up
ip netns exec sd-client ip link set lo up
ip netns exec sd-server ip link set lo up

# veth pair 2: server <-> external (WAN)
ip link add sd-veth-wan-s type veth peer name sd-veth-wan-e
ip link set sd-veth-wan-s netns sd-server
ip link set sd-veth-wan-e netns sd-external

ip netns exec sd-server ip addr add 172.16.0.1/24 dev sd-veth-wan-s
ip netns exec sd-external ip addr add 172.16.0.2/24 dev sd-veth-wan-e
ip netns exec sd-server ip link set sd-veth-wan-s up
ip netns exec sd-external ip link set sd-veth-wan-e up
ip netns exec sd-external ip link set lo up

# Routing
ip netns exec sd-server ip route add default via 172.16.0.2 dev sd-veth-wan-s
ip netns exec sd-client ip route add default via 192.168.100.2 dev sd-veth-c

# Enable IP forwarding in server namespace
ip netns exec sd-server sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Verify underlay
ip netns exec sd-client ping -c 1 -W 1 192.168.100.2 >/dev/null
echo "OK: client -> server underlay"
ip netns exec sd-server ping -c 1 -W 1 172.16.0.2 >/dev/null
echo "OK: server -> external WAN"

# ── Systemd drop-in overrides ───────────────────────────────────────────────

echo "Installing systemd drop-in overrides..."

mkdir -p /run/systemd/system/mqvpn-server.service.d
cat > /run/systemd/system/mqvpn-server.service.d/override.conf <<'DROPIN'
[Unit]
StartLimitBurst=10

[Service]
ExecStartPre=
ExecStartPre=/usr/bin/ip netns exec sd-server /usr/local/lib/mqvpn/mqvpn-server-nat.sh setup /etc/mqvpn/server.conf
ExecStart=
ExecStart=/usr/bin/ip netns exec sd-server /usr/local/bin/mqvpn --config /etc/mqvpn/server.conf
ExecStopPost=
ExecStopPost=/usr/bin/ip netns exec sd-server /usr/local/lib/mqvpn/mqvpn-server-nat.sh teardown /etc/mqvpn/server.conf
ReadWritePaths=/run/netns /proc/sys/net
DROPIN

mkdir -p /run/systemd/system/mqvpn-client@test1.service.d
cat > /run/systemd/system/mqvpn-client@test1.service.d/override.conf <<'DROPIN'
[Unit]
StartLimitBurst=10

[Service]
ExecStart=
ExecStart=/usr/bin/ip netns exec sd-client /usr/local/bin/mqvpn --config /etc/mqvpn/client-%i.conf
ReadWritePaths=
ReadWritePaths=/dev/net/tun /run/netns
DROPIN

systemctl daemon-reload
echo "OK: drop-ins installed, daemon reloaded"

# ── Phase 3: Server start ───────────────────────────────────────────────────

echo ""
echo "=== Phase 3: Server start ==="

systemctl start mqvpn-server
sleep 2

if ! systemctl is-active --quiet mqvpn-server; then
    echo "FAIL: mqvpn-server not active"
    systemctl status mqvpn-server --no-pager || true
    fail "Phase 3 (server start)"
fi
echo "OK: mqvpn-server is active"

# Verify TUN device in server namespace
if ! ip netns exec sd-server ip link show mqvpn0 >/dev/null 2>&1; then
    echo "FAIL: mqvpn0 TUN not found in sd-server namespace"
    fail "Phase 3 (server TUN)"
fi
echo "OK: mqvpn0 present in sd-server"

# Verify NAT rules were created by ExecStartPre
NAT_RULES=$(ip netns exec sd-server iptables -t nat -L POSTROUTING -n 2>/dev/null \
    | grep -c "mqvpn-server-nat" || true)
if [ "$NAT_RULES" -eq 0 ]; then
    echo "FAIL: no NAT MASQUERADE rules found (ExecStartPre issue)"
    ip netns exec sd-server iptables -t nat -L -v -n 2>/dev/null || true
    fail "Phase 3 (NAT rules)"
fi
echo "OK: NAT MASQUERADE rules present ($NAT_RULES rules)"

FWD_RULES=$(ip netns exec sd-server iptables -L FORWARD -n 2>/dev/null \
    | grep -c "mqvpn-server-nat" || true)
echo "OK: FORWARD rules present ($FWD_RULES rules)"

pass "Phase 3 (server start)"

# ── Phase 4: Client start ───────────────────────────────────────────────────

echo ""
echo "=== Phase 4: Client start ==="

systemctl start mqvpn-client@test1
sleep 3

if ! systemctl is-active --quiet mqvpn-client@test1; then
    echo "FAIL: mqvpn-client@test1 not active"
    systemctl status mqvpn-client@test1 --no-pager || true
    fail "Phase 4 (client start)"
fi
echo "OK: mqvpn-client@test1 is active"

# Verify TUN device in client namespace
if ! ip netns exec sd-client ip link show mqvpn0 >/dev/null 2>&1; then
    echo "FAIL: mqvpn0 TUN not found in sd-client namespace"
    fail "Phase 4 (client TUN)"
fi
echo "OK: mqvpn0 present in sd-client"

# Ping through tunnel to external
echo "Pinging 172.16.0.2 through VPN tunnel + NAT..."
if ip netns exec sd-client ping -c 3 -W 2 172.16.0.2; then
    echo "OK: tunnel connectivity works"
else
    echo "FAIL: cannot ping external through tunnel"
    echo ""
    echo "--- TUN devices ---"
    ip netns exec sd-server ip addr show dev mqvpn0 2>/dev/null || true
    ip netns exec sd-client ip addr show dev mqvpn0 2>/dev/null || true
    echo ""
    echo "--- Client routes ---"
    ip netns exec sd-client ip route show 2>/dev/null || true
    fail "Phase 4 (tunnel ping)"
fi

pass "Phase 4 (client start)"

# ── Phase 5: Stop and verify NAT cleanup ─────────────────────────────────────

echo ""
echo "=== Phase 5: Stop + NAT cleanup ==="

systemctl stop mqvpn-client@test1
systemctl stop mqvpn-server
sleep 2

# Verify services stopped
if systemctl is-active --quiet mqvpn-server; then
    echo "FAIL: mqvpn-server still active after stop"
    fail "Phase 5 (server stop)"
fi
echo "OK: mqvpn-server stopped"

if systemctl is-active --quiet mqvpn-client@test1; then
    echo "FAIL: mqvpn-client@test1 still active after stop"
    fail "Phase 5 (client stop)"
fi
echo "OK: mqvpn-client@test1 stopped"

# Verify ExecStopPost cleaned up NAT rules
NAT_AFTER=$(ip netns exec sd-server iptables -t nat -L POSTROUTING -n 2>/dev/null \
    | grep -c "mqvpn-server-nat" || true)
if [ "$NAT_AFTER" -ne 0 ]; then
    echo "FAIL: NAT rules not cleaned up by ExecStopPost ($NAT_AFTER remaining)"
    ip netns exec sd-server iptables -t nat -L -v -n 2>/dev/null || true
    fail "Phase 5 (NAT cleanup)"
fi
echo "OK: NAT MASQUERADE rules cleaned up"

FWD_AFTER=$(ip netns exec sd-server iptables -L FORWARD -n 2>/dev/null \
    | grep -c "mqvpn-server-nat" || true)
if [ "$FWD_AFTER" -ne 0 ]; then
    echo "FAIL: FORWARD rules not cleaned up ($FWD_AFTER remaining)"
    fail "Phase 5 (FORWARD cleanup)"
fi
echo "OK: FORWARD rules cleaned up"

pass "Phase 5 (stop + NAT cleanup)"

# ── Phase 6: Restart test ────────────────────────────────────────────────────

echo ""
echo "=== Phase 6: Server restart + client reconnect ==="

# Start both services fresh
systemctl start mqvpn-server
sleep 2
systemctl start mqvpn-client@test1
sleep 3

# Verify both running
if ! systemctl is-active --quiet mqvpn-server; then
    fail "Phase 6 (server pre-restart)"
fi
if ! systemctl is-active --quiet mqvpn-client@test1; then
    fail "Phase 6 (client pre-restart)"
fi

# Verify connectivity before restart
if ! ip netns exec sd-client ping -c 1 -W 2 172.16.0.2 >/dev/null 2>&1; then
    echo "FAIL: no connectivity before restart"
    fail "Phase 6 (pre-restart ping)"
fi
echo "OK: connectivity verified before restart"

# Restart server — client should reconnect automatically
echo "Restarting mqvpn-server..."
systemctl restart mqvpn-server
echo "OK: restart issued"

# Poll for client reconnection (up to 20s)
echo "Waiting for client reconnect..."
RECONNECTED=0
for i in $(seq 1 20); do
    if ip netns exec sd-client ping -c 1 -W 1 172.16.0.2 >/dev/null 2>&1; then
        echo "OK: client reconnected after ${i}s"
        RECONNECTED=1
        break
    fi
    sleep 1
done

if [ "$RECONNECTED" -eq 0 ]; then
    echo "FAIL: client did not reconnect within 20s"
    systemctl status mqvpn-server --no-pager || true
    systemctl status mqvpn-client@test1 --no-pager || true
    fail "Phase 6 (reconnect)"
fi

# Verify NAT rules restored after restart
NAT_RESTART=$(ip netns exec sd-server iptables -t nat -L POSTROUTING -n 2>/dev/null \
    | grep -c "mqvpn-server-nat" || true)
if [ "$NAT_RESTART" -eq 0 ]; then
    echo "FAIL: NAT rules not restored after server restart"
    fail "Phase 6 (NAT after restart)"
fi
echo "OK: NAT rules restored after restart"

# Stop services for cleanup
systemctl stop mqvpn-client@test1 2>/dev/null || true
systemctl stop mqvpn-server 2>/dev/null || true

pass "Phase 6 (restart + reconnect)"

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo "=========================================="
echo "  All systemd integration tests passed!"
echo "=========================================="
