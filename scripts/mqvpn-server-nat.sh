#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# mqvpn-server-nat.sh — NAT setup/teardown helper for mqvpn-server.service
#
# Usage:
#   mqvpn-server-nat.sh setup   CONFIG_PATH
#   mqvpn-server-nat.sh teardown CONFIG_PATH
#
# Reads Subnet/Subnet6 from the config file and manages:
#   - net.ipv4.ip_forward = 1 (+ net.ipv6.conf.all.forwarding if Subnet6 set)
#   - iptables MASQUERADE + FORWARD rules
#   - ip6tables FORWARD + NAT66 (MASQUERADE) rules

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
SUBNET=$(sed -n 's/^[[:space:]]*Subnet[[:space:]]*=[[:space:]]*\(.*\)/\1/p' "$CONFIG" | tail -1 | tr -d '[:space:]')
SUBNET="${SUBNET:-10.0.0.0/24}"

# Read Subnet6 from config (optional, empty if not set)
SUBNET6=$(sed -n 's/^[[:space:]]*Subnet6[[:space:]]*=[[:space:]]*\(.*\)/\1/p' "$CONFIG" | tail -1 | tr -d '[:space:]')
SUBNET6="${SUBNET6:-}"

# Read TunName from config (fallback: mqvpn0)
TUN_NAME=$(sed -n 's/^[[:space:]]*TunName[[:space:]]*=[[:space:]]*\(.*\)/\1/p' "$CONFIG" | tail -1 | tr -d '[:space:]')
TUN_NAME="${TUN_NAME:-mqvpn0}"

COMMENT="mqvpn-server-nat"
STATE_DIR="/run/mqvpn"

# Detect default outbound interface
detect_iface() {
    ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' || true
}

setup() {
    mkdir -p "$STATE_DIR"

    # Save and enable IP forwarding
    sysctl -n net.ipv4.ip_forward > "$STATE_DIR/orig_ip_forward.$TUN_NAME"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    NAT_IFACE=$(detect_iface)
    if [ -z "$NAT_IFACE" ]; then
        echo "Warning: could not detect default interface, skipping IPv4 NAT rules" >&2
    else
        echo "mqvpn-server-nat: setup subnet=$SUBNET iface=$NAT_IFACE tun=$TUN_NAME"

        iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$NAT_IFACE" -j MASQUERADE \
            -m comment --comment "$COMMENT"
        iptables -I FORWARD -i "$TUN_NAME" -s "$SUBNET" -j ACCEPT \
            -m comment --comment "$COMMENT"
        iptables -I FORWARD -o "$TUN_NAME" -d "$SUBNET" -j ACCEPT \
            -m comment --comment "$COMMENT"
    fi

    # IPv6 forwarding + FORWARD + NAT66 rules
    if [ -n "$SUBNET6" ]; then
        sysctl -n net.ipv6.conf.all.forwarding > "$STATE_DIR/orig_ip6_forward.$TUN_NAME"
        sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
        ip6tables -I FORWARD -i "$TUN_NAME" -s "$SUBNET6" -j ACCEPT \
            -m comment --comment "$COMMENT"
        ip6tables -I FORWARD -o "$TUN_NAME" -d "$SUBNET6" -j ACCEPT \
            -m comment --comment "$COMMENT"
        NAT6_IFACE=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | grep -oP 'dev \K\S+' || true)
        if [ -n "$NAT6_IFACE" ]; then
            ip6tables -t nat -A POSTROUTING -s "$SUBNET6" -o "$NAT6_IFACE" -j MASQUERADE \
                -m comment --comment "$COMMENT"
            echo "mqvpn-server-nat: IPv6 NAT66 $SUBNET6 → $NAT6_IFACE"
        fi
        echo "mqvpn-server-nat: IPv6 FORWARD rules added for $SUBNET6"
    fi
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

    # Remove IPv6 FORWARD rules (unconditional — handles config changes between setup/teardown)
    delete_by_comment_v6() {
        local table="$1" chain="$2"
        while true; do
            local line
            line=$(ip6tables -t "$table" -L "$chain" --line-numbers -n 2>/dev/null \
                | grep "$COMMENT" | head -1 | awk '{print $1}')
            [ -z "$line" ] && break
            ip6tables -t "$table" -D "$chain" "$line" 2>/dev/null || break
        done
    }
    delete_by_comment_v6 nat POSTROUTING
    delete_by_comment_v6 filter FORWARD

    # Restore forwarding settings
    if [ -f "$STATE_DIR/orig_ip_forward.$TUN_NAME" ]; then
        sysctl -w net.ipv4.ip_forward="$(cat "$STATE_DIR/orig_ip_forward.$TUN_NAME")" >/dev/null
        rm -f "$STATE_DIR/orig_ip_forward.$TUN_NAME"
    fi
    if [ -f "$STATE_DIR/orig_ip6_forward.$TUN_NAME" ]; then
        sysctl -w net.ipv6.conf.all.forwarding="$(cat "$STATE_DIR/orig_ip6_forward.$TUN_NAME")" >/dev/null
        rm -f "$STATE_DIR/orig_ip6_forward.$TUN_NAME"
    fi
}

case "$ACTION" in
    setup)    setup ;;
    teardown) teardown ;;
    *)
        echo "Unknown action: $ACTION (use setup or teardown)" >&2
        exit 1
        ;;
esac
