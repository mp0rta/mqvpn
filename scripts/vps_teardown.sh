#!/bin/bash
# scripts/vps_teardown.sh — Stop mqvpn server and clean up
set -e

SUBNET="10.0.0.0/24"

pkill -f "mqvpn --mode server" || true
pkill iperf3 || true

IFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+')
iptables -D INPUT -s $SUBNET -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -s $SUBNET -o $IFACE -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -s $SUBNET -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -d $SUBNET -j ACCEPT 2>/dev/null || true

ip link del mqvpn0 2>/dev/null || true
ip link del mpvpn0 2>/dev/null || true

echo "Cleaned up"
