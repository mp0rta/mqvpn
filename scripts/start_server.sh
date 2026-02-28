#!/bin/bash
# start_server.sh — Generate certs, configure NAT, and start mqvpn server
#
# Usage: sudo ./scripts/start_server.sh [options]
#   --config PATH        mqvpn config file (all settings read from config)
#   --skip-nat           Skip NAT/forwarding setup (can be used with --config)
#
# Without --config:
#   --listen ADDR:PORT   Listen address (default: 0.0.0.0:443)
#   --subnet CIDR        Client IP pool (default: 10.0.0.0/24)
#   --cert PATH          TLS certificate (default: certs/server.crt)
#   --key PATH           TLS private key (default: certs/server.key)
#   --auth-key KEY       Pre-shared key for client auth (default: auto-generated)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

LISTEN="0.0.0.0:443"
SUBNET="10.0.0.0/24"
TUN_NAME="mqvpn0"
CERT="$PROJECT_DIR/certs/server.crt"
KEY="$PROJECT_DIR/certs/server.key"
AUTH_KEY=""
CONFIG=""
SKIP_NAT=0
HAS_LISTEN=0
HAS_SUBNET=0
HAS_CERT=0
HAS_KEY=0
HAS_AUTH_KEY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --listen)  LISTEN="$2"; HAS_LISTEN=1; shift 2 ;;
        --subnet)  SUBNET="$2"; HAS_SUBNET=1; shift 2 ;;
        --cert)    CERT="$2"; HAS_CERT=1; shift 2 ;;
        --key)     KEY="$2"; HAS_KEY=1; shift 2 ;;
        --auth-key) AUTH_KEY="$2"; HAS_AUTH_KEY=1; shift 2 ;;
        --config)  CONFIG="$2"; shift 2 ;;
        --skip-nat) SKIP_NAT=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Validate flag combinations ---
if [ -n "$CONFIG" ]; then
    CONFLICT=""
    [ "$HAS_LISTEN" -eq 1 ] && CONFLICT="$CONFLICT --listen"
    [ "$HAS_SUBNET" -eq 1 ] && CONFLICT="$CONFLICT --subnet"
    [ "$HAS_CERT" -eq 1 ] && CONFLICT="$CONFLICT --cert"
    [ "$HAS_KEY" -eq 1 ] && CONFLICT="$CONFLICT --key"
    [ "$HAS_AUTH_KEY" -eq 1 ] && CONFLICT="$CONFLICT --auth-key"
    if [ -n "$CONFLICT" ]; then
        echo "Error: --config cannot be combined with:$CONFLICT"
        echo "Only --skip-nat can be used with --config."
        exit 1
    fi
fi

MQVPN="$PROJECT_DIR/build/mqvpn"
if [ ! -x "$MQVPN" ]; then
    echo "Error: $MQVPN not found. Run './build.sh' first."
    exit 1
fi

# --- Read values from config file if provided ---
if [ -n "$CONFIG" ]; then
    if [ ! -f "$CONFIG" ]; then
        echo "Error: config file not found: $CONFIG"
        exit 1
    fi
    # Extract Subnet from config (used for NAT setup)
    cfg_subnet=$(sed -n 's/^[[:space:]]*Subnet[[:space:]]*=[[:space:]]*\(.*\)/\1/p' "$CONFIG" | tail -1 | tr -d '[:space:]')
    if [ -n "$cfg_subnet" ]; then
        SUBNET="$cfg_subnet"
    fi
    # Extract TunName from config (used for FORWARD rules)
    cfg_tun=$(sed -n 's/^[[:space:]]*TunName[[:space:]]*=[[:space:]]*\(.*\)/\1/p' "$CONFIG" | tail -1 | tr -d '[:space:]')
    if [ -n "$cfg_tun" ]; then
        TUN_NAME="$cfg_tun"
    fi
fi

# --- Lock file (prevent concurrent instances) ---
LOCKFILE="/var/run/mqvpn-start-server.lock"
exec 9>"$LOCKFILE"
if ! flock -n 9; then
    echo "Error: another start_server.sh is already running (lock: $LOCKFILE)"
    exit 1
fi
echo $$ >&9

# --- Cleanup state (set early so partial setup is always cleaned up) ---
ORIG_IP_FORWARD=""
NAT_IFACE=""
MQVPN_PID=""
IPTABLES_COMMENT="mqvpn-start-server:$$"

cleanup() {
    echo ""
    echo "Cleaning up..."

    # Stop mqvpn server
    if [ -n "$MQVPN_PID" ] && kill -0 "$MQVPN_PID" 2>/dev/null; then
        kill "$MQVPN_PID" 2>/dev/null || true
        wait "$MQVPN_PID" 2>/dev/null || true
        echo "  mqvpn server stopped"
    fi

    # Remove all iptables rules tagged with our comment (handles duplicates)
    if [ "$SKIP_NAT" -eq 0 ] && [ -n "$NAT_IFACE" ]; then
        while iptables -t nat -D POSTROUTING -s "$SUBNET" -o "$NAT_IFACE" -j MASQUERADE \
            -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null; do :; done
        while iptables -D FORWARD -i "$TUN_NAME" -s "$SUBNET" -j ACCEPT \
            -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null; do :; done
        while iptables -D FORWARD -o "$TUN_NAME" -d "$SUBNET" -j ACCEPT \
            -m comment --comment "$IPTABLES_COMMENT" 2>/dev/null; do :; done
        echo "  iptables rules removed"
    fi

    # Restore ip_forward
    if [ -n "$ORIG_IP_FORWARD" ]; then
        sysctl -w net.ipv4.ip_forward="$ORIG_IP_FORWARD" >/dev/null
        echo "  ip_forward restored to $ORIG_IP_FORWARD"
    fi

    echo "Done."
}

trap cleanup EXIT

# --- Generate self-signed certificate if missing (skip if --config) ---
if [ -z "$CONFIG" ]; then
    if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
        echo "Generating self-signed certificate..."
        mkdir -p "$(dirname "$CERT")"
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "$KEY" -out "$CERT" \
            -days 365 -nodes -subj "/CN=mqvpn" 2>/dev/null
        echo "  cert: $CERT"
        echo "  key:  $KEY"
    fi
fi

# --- NAT setup ---
if [ "$SKIP_NAT" -eq 0 ]; then
    ORIG_IP_FORWARD=$(sysctl -n net.ipv4.ip_forward)

    echo "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    NAT_IFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || true)
    if [ -z "$NAT_IFACE" ]; then
        echo "Warning: could not detect default interface, skipping NAT"
    else
        echo "Setting up NAT: $SUBNET → $NAT_IFACE"
        iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$NAT_IFACE" -j MASQUERADE \
            -m comment --comment "$IPTABLES_COMMENT"
        iptables -I FORWARD -i "$TUN_NAME" -s "$SUBNET" -j ACCEPT \
            -m comment --comment "$IPTABLES_COMMENT"
        iptables -I FORWARD -o "$TUN_NAME" -d "$SUBNET" -j ACCEPT \
            -m comment --comment "$IPTABLES_COMMENT"
    fi
fi

# --- Generate PSK if not provided (skip if --config) ---
if [ -z "$CONFIG" ] && [ -z "$AUTH_KEY" ]; then
    AUTH_KEY=$("$MQVPN" --genkey 2>/dev/null)
    echo "Generated auth key: $AUTH_KEY"
    echo "Use this key on the client with: --auth-key \"$AUTH_KEY\""
fi

# --- Start server ---
if [ -n "$CONFIG" ]; then
    echo "Starting mqvpn server (config=$CONFIG, subnet=$SUBNET)..."
    "$MQVPN" --config "$CONFIG" &
else
    echo "Starting mqvpn server (listen=$LISTEN, subnet=$SUBNET)..."
    "$MQVPN" --mode server --listen "$LISTEN" \
        --subnet "$SUBNET" --cert "$CERT" --key "$KEY" \
        --auth-key "$AUTH_KEY" &
fi
MQVPN_PID=$!
wait $MQVPN_PID 2>/dev/null || true
