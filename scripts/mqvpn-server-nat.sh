#!/bin/bash
# mqvpn-server-nat.sh — NAT setup/teardown helper for mqvpn-server.service
#
# Usage:
#   mqvpn-server-nat.sh setup   CONFIG_PATH
#   mqvpn-server-nat.sh teardown CONFIG_PATH
#
# Reads Subnet from the config file and manages:
#   - net.ipv4.ip_forward = 1
#   - iptables MASQUERADE + FORWARD rules

set -e

ACTION="$1"
CONFIG="$2"

if [ -z "$ACTION" ] || [ -z "$CONFIG" ]; then
    echo "Usage: $0 setup|teardown CONFIG_PATH" >&2
    exit 1
fi

if [ ! -f "$CONFIG" ]; then
    echo "Error: config file not found: $CONFIG" >&2
    exit 1
fi

# Read Subnet from config (fallback: 10.0.0.0/24)
SUBNET=$(sed -n 's/^[[:space:]]*Subnet[[:space:]]*=[[:space:]]*\(.*\)/\1/p' "$CONFIG" | head -1 | tr -d '[:space:]')
SUBNET="${SUBNET:-10.0.0.0/24}"

# Read TunName from config (fallback: mqvpn0)
TUN_NAME=$(sed -n 's/^[[:space:]]*TunName[[:space:]]*=[[:space:]]*\(.*\)/\1/p' "$CONFIG" | head -1 | tr -d '[:space:]')
TUN_NAME="${TUN_NAME:-mqvpn0}"

COMMENT="mqvpn-server-nat"

# Detect default outbound interface
detect_iface() {
    ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || true
}

setup() {
    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    NAT_IFACE=$(detect_iface)
    if [ -z "$NAT_IFACE" ]; then
        echo "Warning: could not detect default interface, skipping NAT rules" >&2
        return 0
    fi

    echo "mqvpn-server-nat: setup subnet=$SUBNET iface=$NAT_IFACE tun=$TUN_NAME"

    iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$NAT_IFACE" -j MASQUERADE \
        -m comment --comment "$COMMENT"
    iptables -I FORWARD -i "$TUN_NAME" -s "$SUBNET" -j ACCEPT \
        -m comment --comment "$COMMENT"
    iptables -I FORWARD -o "$TUN_NAME" -d "$SUBNET" -j ACCEPT \
        -m comment --comment "$COMMENT"
}

teardown() {
    echo "mqvpn-server-nat: teardown"

    # Remove rules by line number (reverse order to avoid index shift)
    # This handles any rule shape as long as it has our comment tag
    delete_by_comment() {
        local table="$1" chain="$2"
        while true; do
            local line
            line=$(iptables -t "$table" -L "$chain" --line-numbers -n 2>/dev/null \
                | grep "$COMMENT" | head -1 | awk '{print $1}')
            [ -z "$line" ] && break
            iptables -t "$table" -D "$chain" "$line" 2>/dev/null || break
        done
    }

    delete_by_comment nat POSTROUTING
    delete_by_comment filter FORWARD
}

case "$ACTION" in
    setup)    setup ;;
    teardown) teardown ;;
    *)
        echo "Unknown action: $ACTION (use setup or teardown)" >&2
        exit 1
        ;;
esac
