#!/bin/bash
# setup_server_nat.sh — Configure NAT for mpvpn server
# Run on the VPN server after mpvpn-server starts.
#
# Usage: sudo ./setup_server_nat.sh [SUBNET] [IFACE]

set -e

SUBNET="${1:-10.0.0.0/24}"
IFACE="${2:-eth0}"

echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1

echo "Setting up NAT: $SUBNET → $IFACE"
iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$IFACE" -j MASQUERADE
iptables -A FORWARD -s "$SUBNET" -j ACCEPT
iptables -A FORWARD -d "$SUBNET" -j ACCEPT

echo "NAT configured successfully."
echo ""
echo "To remove these rules later:"
echo "  iptables -t nat -D POSTROUTING -s $SUBNET -o $IFACE -j MASQUERADE"
echo "  iptables -D FORWARD -s $SUBNET -j ACCEPT"
echo "  iptables -D FORWARD -d $SUBNET -j ACCEPT"
