#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# mqvpn-server-info — print the mqvpn-server summary: status, auth key, port
# and subnets.
#
# Usage:
#   sudo mqvpn-server-info

set -euo pipefail

CONF=/etc/mqvpn/server.conf

err() { echo "mqvpn-server-info: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || err "run as root (use sudo): $CONF is readable only by root"
[ -f "$CONF" ] || err "$CONF not found. Run: sudo dpkg-reconfigure mqvpn-server"

conf_value() { # $1 = section, $2 = key
    sed -n "/^\\[$1\\]/,/^\\[/ s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*\\([^[:space:]#]*\\).*/\\1/p" "$CONF" | head -n 1
}

# [TLS] also has a Key line, so the section matters.
AUTH_KEY=$(conf_value Auth Key)
LISTEN=$(conf_value Interface Listen)
PORT=${LISTEN##*:}
SUBNET=$(conf_value Interface Subnet)
SUBNET6=$(conf_value Interface Subnet6)
PORT=${PORT:-443}
SUBNET=${SUBNET:-10.0.0.0/24}

STATUS=$(systemctl is-active mqvpn-server 2>/dev/null) || true

echo ""
echo "  mqvpn-server: ${STATUS:-unknown}"
echo ""
echo "  Config:    $CONF"
echo "  Auth key:  $AUTH_KEY"
echo "  Port:      ${PORT}/udp"
echo "  Subnet:    $SUBNET"
if [ -n "$SUBNET6" ]; then echo "  Subnet6:   $SUBNET6"; fi
echo ""
echo "  Show this again: sudo mqvpn-server-info"
echo ""
