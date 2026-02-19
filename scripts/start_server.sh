#!/bin/bash
# start_server.sh — Generate certs, configure NAT, and start mqvpn server
#
# Usage: sudo ./scripts/start_server.sh [options]
#   --listen ADDR:PORT   Listen address (default: 0.0.0.0:443)
#   --subnet CIDR        Client IP pool (default: 10.0.0.0/24)
#   --cert PATH          TLS certificate (default: certs/server.crt)
#   --key PATH           TLS private key (default: certs/server.key)
#   --skip-nat           Skip NAT/forwarding setup

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

LISTEN="0.0.0.0:443"
SUBNET="10.0.0.0/24"
CERT="$PROJECT_DIR/certs/server.crt"
KEY="$PROJECT_DIR/certs/server.key"
SKIP_NAT=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --listen)  LISTEN="$2"; shift 2 ;;
        --subnet)  SUBNET="$2"; shift 2 ;;
        --cert)    CERT="$2"; shift 2 ;;
        --key)     KEY="$2"; shift 2 ;;
        --skip-nat) SKIP_NAT=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

MQVPN="$PROJECT_DIR/build/mqvpn"
if [ ! -x "$MQVPN" ]; then
    echo "Error: $MQVPN not found. Run 'make' in build/ first."
    exit 1
fi

# --- Generate self-signed certificate if missing ---
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "Generating self-signed certificate..."
    mkdir -p "$(dirname "$CERT")"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$KEY" -out "$CERT" \
        -days 365 -nodes -subj "/CN=mqvpn" 2>/dev/null
    echo "  cert: $CERT"
    echo "  key:  $KEY"
fi

# --- NAT setup ---
if [ "$SKIP_NAT" -eq 0 ]; then
    echo "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    IFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || true)
    if [ -z "$IFACE" ]; then
        echo "Warning: could not detect default interface, skipping NAT"
    else
        echo "Setting up NAT: $SUBNET → $IFACE"
        iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$IFACE" -j MASQUERADE 2>/dev/null \
            || iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$IFACE" -j MASQUERADE
        iptables -C FORWARD -i mqvpn0 -s "$SUBNET" -j ACCEPT 2>/dev/null \
            || iptables -I FORWARD -i mqvpn0 -s "$SUBNET" -j ACCEPT
        iptables -C FORWARD -o mqvpn0 -d "$SUBNET" -j ACCEPT 2>/dev/null \
            || iptables -I FORWARD -o mqvpn0 -d "$SUBNET" -j ACCEPT
    fi
fi

# --- Start server ---
echo "Starting mqvpn server (listen=$LISTEN, subnet=$SUBNET)..."
exec "$MQVPN" --mode server --listen "$LISTEN" \
    --subnet "$SUBNET" --cert "$CERT" --key "$KEY"
