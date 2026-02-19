#!/bin/bash
# scripts/vps_setup.sh — Run on VPS to start mqvpn server
set -e

PORT=${1:-10020}
SUBNET="10.0.0.0/24"
CERT_DIR="/root/mqvpn/certs"
BUILD_DIR="/root/mqvpn/build"

# Generate certs if missing
if [ ! -f "$CERT_DIR/server.crt" ]; then
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
        -days 365 -nodes -subj "/CN=mqvpn-test"
    echo "Generated TLS certificates"
fi

# Enable forwarding + NAT
sysctl -w net.ipv4.ip_forward=1
IFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+')
iptables -C INPUT -s $SUBNET -j ACCEPT 2>/dev/null || \
    iptables -I INPUT -s $SUBNET -j ACCEPT
iptables -C INPUT -p udp --dport $PORT -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p udp --dport $PORT -j ACCEPT
iptables -t nat -C POSTROUTING -s $SUBNET -o $IFACE -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s $SUBNET -o $IFACE -j MASQUERADE
iptables -C FORWARD -i mqvpn0 -s $SUBNET -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD -i mqvpn0 -s $SUBNET -j ACCEPT
iptables -C FORWARD -o mqvpn0 -d $SUBNET -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD -o mqvpn0 -d $SUBNET -j ACCEPT

echo "NAT configured: $SUBNET → $IFACE"

# Start server
echo "Starting mqvpn server on port $PORT..."
$BUILD_DIR/mqvpn --mode server \
    --listen 0.0.0.0:$PORT \
    --subnet $SUBNET \
    --cert "$CERT_DIR/server.crt" \
    --key "$CERT_DIR/server.key" \
    --log-level debug 2>&1 | tee /root/mqvpn-server.log
