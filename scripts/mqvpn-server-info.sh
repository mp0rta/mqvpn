#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# mqvpn-server-info — print the mqvpn-server connection summary: auth key,
# port, subnets, server address and a client command to paste.
#
# Usage:
#   sudo mqvpn-server-info

set -euo pipefail

CONF=/etc/mqvpn/server.conf
GENERATED_LIST=/var/lib/mqvpn-server/generated.list

err() { echo "mqvpn-server-info: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || err "run as root (use sudo): $CONF is readable only by root"
[ -f "$CONF" ] || err "$CONF not found. Run: sudo /usr/lib/mqvpn/mqvpn-server-setup"

conf_value() { # $1 = section, $2 = key
    sed -n "/^\\[$1\\]/,/^\\[/ s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*\\([^[:space:]#]*\\).*/\\1/p" "$CONF" | head -n 1
}

# [TLS] also has a Key line, so the section matters.
AUTH_KEY=$(conf_value Auth Key)
LISTEN=$(conf_value Interface Listen)
PORT=${LISTEN##*:}
SUBNET=$(conf_value Interface Subnet)
SUBNET6=$(conf_value Interface Subnet6)
CERT=$(conf_value TLS Cert)
PORT=${PORT:-443}
SUBNET=${SUBNET:-10.0.0.0/24}
CERT=${CERT:-/etc/mqvpn/server.crt}

# A certificate name other than the default "mqvpn" is the public hostname
# that mqvpn-server-setup got (--hostname, debconf or MQVPN_HOSTNAME).
SERVER=
if [ -r "$CERT" ]; then
    SERVER=$(openssl x509 -in "$CERT" -noout -subject -nameopt multiline 2>/dev/null \
        | sed -n 's/^[[:space:]]*commonName[[:space:]]*=[[:space:]]*//p' | head -n 1) || SERVER=
    [ "$SERVER" = mqvpn ] && SERVER=
fi
if [ -z "$SERVER" ] && command -v curl >/dev/null 2>&1; then
    SERVER=$(curl -fsS -4 --max-time 5 ifconfig.me 2>/dev/null) || SERVER=
fi
if [ -z "$SERVER" ]; then
    SERVER=$(hostname -I 2>/dev/null | awk '{ print $1 }') || SERVER=
fi
SERVER=${SERVER:-<server-address>}
case "$SERVER" in
    *:*) SERVER="[$SERVER]" ;;
esac

# The client must skip certificate verification only for the self-signed
# certificate that mqvpn-server-setup created.
INSECURE=
if [ -f "$GENERATED_LIST" ] && grep -qxF "$CERT" "$GENERATED_LIST"; then
    INSECURE=" --insecure"
fi

STATUS=$(systemctl is-active mqvpn-server 2>/dev/null) || true

echo ""
echo "  mqvpn-server: ${STATUS:-unknown}"
echo ""
echo "  Config:    $CONF"
echo "  Auth key:  $AUTH_KEY"
echo "  Port:      ${PORT}/udp"
echo "  Subnet:    $SUBNET"
[ -n "$SUBNET6" ] && echo "  Subnet6:   $SUBNET6"
echo ""
echo "  Client:"
echo "    sudo mqvpn --mode client --server ${SERVER}:${PORT} \\"
echo "        --auth-key \"$AUTH_KEY\"${INSECURE}"
echo ""
echo "  Show this again: sudo mqvpn-server-info"
echo ""
