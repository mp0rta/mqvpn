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

is_ipv4() {
    local octet
    [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for octet in "${BASH_REMATCH[@]:1:4}"; do
        (( 10#$octet <= 255 )) || return 1
    done
}
# Admins paste the client command into a root shell, so a value from the
# certificate or the network goes into it only if it is a plain name or address.
is_host_name() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; }
is_ipv6() { [[ "$1" =~ ^[0-9A-Fa-f:]{2,39}$ && "$1" == *:* ]]; }

# A certificate name other than the default "mqvpn" is the public hostname
# that mqvpn-server-setup got (--hostname, debconf or MQVPN_HOSTNAME).
SERVER=
NOTE=
if [ -r "$CERT" ]; then
    cn=$(openssl x509 -in "$CERT" -noout -subject -nameopt multiline 2>/dev/null \
        | sed -n 's/^[[:space:]]*commonName[[:space:]]*=[[:space:]]*//p' | head -n 1) || cn=
    # A CA certificate can have its names only in subjectAltName, with no CN.
    mapfile -t dns < <(openssl x509 -in "$CERT" -noout -ext subjectAltName 2>/dev/null \
        | tr ',' '\n' | sed -n 's/^[[:space:]]*DNS://p')
    for name in "$cn" "${dns[@]}"; do
        if [ "$name" != mqvpn ] && { is_host_name "$name" || is_ipv6 "$name"; }; then
            SERVER=$name
            break
        fi
    done
fi
if [ -z "$SERVER" ] && command -v curl >/dev/null 2>&1; then
    public=$(curl -fsS -4 --max-time 5 https://ifconfig.me 2>/dev/null) || public=
    if is_ipv4 "$public"; then
        SERVER=$public
    fi
fi
if [ -z "$SERVER" ]; then
    local_addr=$(hostname -I 2>/dev/null | awk '{ print $1 }') || local_addr=
    if is_ipv4 "$local_addr"; then
        SERVER=$local_addr
        NOTE="The public address lookup failed. $local_addr is an address of this host: if clients reach the server through NAT, use its public address."
    fi
fi
SERVER=${SERVER:-<server-address>}
case "$SERVER" in
    *:*) SERVER="[$SERVER]" ;;
esac

# Only a self-signed certificate needs --insecure on the client. A certificate
# that replaced the generated one at the same path (certbot) does not.
INSECURE=
if [ -r "$CERT" ]; then
    subject=$(openssl x509 -in "$CERT" -noout -subject -nameopt RFC2253 2>/dev/null) || subject=
    issuer=$(openssl x509 -in "$CERT" -noout -issuer -nameopt RFC2253 2>/dev/null) || issuer=
    if [ -n "$subject" ] && [ "${subject#subject=}" = "${issuer#issuer=}" ]; then
        INSECURE=" --insecure"
    fi
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
if [ -n "$INSECURE" ]; then
    echo ""
    echo "  Note: --insecure turns off the certificate check. Omit it if the client trusts this certificate."
fi
if [ -n "$NOTE" ]; then
    echo ""
    echo "  Note: $NOTE"
fi
echo ""
echo "  Show this again: sudo mqvpn-server-info"
echo ""
