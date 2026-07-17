#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# setup_server_nat.sh — Configure NAT for mqvpn server
# Run on the VPN server after mqvpn-server starts.
#
# Usage: sudo ./setup_server_nat.sh [SUBNET] [IFACE] [SUBNET6]

set -e

SUBNET="${1:-10.0.0.0/24}"
IFACE="${2:-eth0}"
SUBNET6="${3:-}"

echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1

echo "Setting up NAT: $SUBNET → $IFACE"
iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$IFACE" -j MASQUERADE
iptables -A FORWARD -s "$SUBNET" -j ACCEPT
iptables -A FORWARD -d "$SUBNET" -j ACCEPT

if [ -n "$SUBNET6" ]; then
    echo "Enabling IPv6 forwarding..."
    sysctl -w net.ipv6.conf.all.forwarding=1
    echo "Setting up IPv6 FORWARD + NAT66: $SUBNET6"
    ip6tables -I FORWARD -s "$SUBNET6" -j ACCEPT
    ip6tables -I FORWARD -d "$SUBNET6" -j ACCEPT
    NAT6_IFACE=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | grep -oP 'dev \K\S+' || true)
    NAT6_IFACE="${NAT6_IFACE:-$IFACE}"
    ip6tables -t nat -A POSTROUTING -s "$SUBNET6" -o "$NAT6_IFACE" -j MASQUERADE
    echo "  IPv6 NAT66: $SUBNET6 → $NAT6_IFACE"
fi

echo "NAT configured successfully."
echo ""
echo "To remove these rules later:"
echo "  iptables -t nat -D POSTROUTING -s $SUBNET -o $IFACE -j MASQUERADE"
echo "  iptables -D FORWARD -s $SUBNET -j ACCEPT"
echo "  iptables -D FORWARD -d $SUBNET -j ACCEPT"
if [ -n "$SUBNET6" ]; then
    echo "  ip6tables -t nat -D POSTROUTING -s $SUBNET6 -o $NAT6_IFACE -j MASQUERADE"
    echo "  ip6tables -D FORWARD -s $SUBNET6 -j ACCEPT"
    echo "  ip6tables -D FORWARD -d $SUBNET6 -j ACCEPT"
fi
