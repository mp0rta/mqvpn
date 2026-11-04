#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# mqvpn-server-setup — create the TLS certificate and /etc/mqvpn/server.conf
# for mqvpn-server.service. The mqvpn-server deb runs it from postinst, and
# admins can run it again at any time.
#
# Usage:
#   mqvpn-server-setup [--port N] [--subnet CIDR] [--subnet6 CIDR6]
#                      [--hostname NAME] [--enable-control [PORT]] [--start]
#
# It never replaces an existing PSK, certificate, key or server.conf. On an
# existing server.conf, only --enable-control makes a change.

set -euo pipefail

CONF_DIR=/etc/mqvpn
CONF=$CONF_DIR/server.conf
CRT=$CONF_DIR/server.crt
KEY=$CONF_DIR/server.key
DEFAULTS_FILE=/etc/default/mqvpn-server
STATE_DIR=/var/lib/mqvpn-server
GENERATED_LIST=$STATE_DIR/generated.list
# Installed as <prefix>/lib/mqvpn/mqvpn-server-setup.
PREFIX=$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)
MQVPN=$PREFIX/bin/mqvpn
SERVER_INFO=$PREFIX/bin/mqvpn-server-info

info() { echo "[*] $*"; }
ok()   { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }
err()  { echo "[!] $*" >&2; exit 1; }

usage() {
    echo "Usage: mqvpn-server-setup [--port N] [--subnet CIDR] [--subnet6 CIDR6] [--hostname NAME] [--enable-control [PORT]] [--start]"
}

is_true() {
    case "${1,,}" in
        yes|true|on|1) return 0 ;;
        *) return 1 ;;
    esac
}

# --- Settings (precedence, lowest first: defaults, debconf, $DEFAULTS_FILE, environment, flags) ---
SETTINGS=(MQVPN_PORT MQVPN_SUBNET MQVPN_SUBNET6 MQVPN_HOSTNAME
          MQVPN_ENABLE_CONTROL MQVPN_CONTROL_PORT MQVPN_SERVER_AUTOSTART)

# Save the environment values first: sourcing $DEFAULTS_FILE overwrites them.
declare -A env_values=()
for name in "${SETTINGS[@]}"; do
    if [ -n "${!name+x}" ]; then
        env_values[$name]=${!name}
    fi
done

declare -A flag_values=()
FROM_POSTINST=0
PRINT_AUTOSTART=0
START=0
require_arg() { [ "$1" -ge 2 ] || err "$2 requires an argument"; }
while [ $# -gt 0 ]; do
    case "$1" in
        --port)     require_arg "$#" --port;     flag_values[MQVPN_PORT]=$2;     shift 2 ;;
        --subnet)   require_arg "$#" --subnet;   flag_values[MQVPN_SUBNET]=$2;   shift 2 ;;
        --subnet6)  require_arg "$#" --subnet6;  flag_values[MQVPN_SUBNET6]=$2;  shift 2 ;;
        --hostname) require_arg "$#" --hostname; flag_values[MQVPN_HOSTNAME]=$2; shift 2 ;;
        --enable-control)
            flag_values[MQVPN_ENABLE_CONTROL]=yes
            if [ $# -ge 2 ] && [[ "$2" =~ ^[0-9]+$ ]]; then
                flag_values[MQVPN_CONTROL_PORT]=$2
                shift 2
            else
                shift
            fi
            ;;
        --start) START=1; shift ;;
        --from-postinst) FROM_POSTINST=1; shift ;;
        --print-autostart) PRINT_AUTOSTART=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; err "Unknown option: $1" ;;
    esac
done

MQVPN_PORT=443
MQVPN_SUBNET=10.0.0.0/24
MQVPN_SUBNET6=
MQVPN_HOSTNAME=
MQVPN_ENABLE_CONTROL=no
MQVPN_CONTROL_PORT=9090
MQVPN_SERVER_AUTOSTART=yes

# postinst passes the debconf answers as MQVPN_DEBCONF_<NAME>.
for name in "${SETTINGS[@]}"; do
    debconf_name=MQVPN_DEBCONF_${name#MQVPN_}
    if [ -n "${!debconf_name:-}" ]; then
        printf -v "$name" '%s' "${!debconf_name}"
    fi
done
if [ -r "$DEFAULTS_FILE" ]; then
    # shellcheck source=/dev/null
    . "$DEFAULTS_FILE"
fi
for name in "${!env_values[@]}"; do
    printf -v "$name" '%s' "${env_values[$name]}"
done
for name in "${!flag_values[@]}"; do
    printf -v "$name" '%s' "${flag_values[$name]}"
done

if [ "$PRINT_AUTOSTART" -eq 1 ]; then
    if is_true "$MQVPN_SERVER_AUTOSTART"; then echo yes; else echo no; fi
    exit 0
fi

# The values go into server.conf and the openssl subject, so reject anything
# that is not plainly a port, a CIDR or a host name.
valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
# Prefix ranges: the address pool accepts only these (src/addr_pool.c).
valid_subnet4() {
    local octet
    # No leading zeros: inet_pton rejects them.
    [[ "$1" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})/([0-9]{1,2})$ ]] || return 1
    for octet in "${BASH_REMATCH[@]:1:4}"; do
        (( 10#$octet <= 255 )) || return 1
    done
    (( 10#${BASH_REMATCH[5]} >= 16 && 10#${BASH_REMATCH[5]} <= 30 ))
}
valid_subnet6() {
    local addr=${1%/*} group
    local -a groups
    [[ "$1" =~ ^[0-9A-Fa-f:]+/([0-9]{1,3})$ ]] || return 1
    (( 10#${BASH_REMATCH[1]} >= 96 && 10#${BASH_REMATCH[1]} <= 126 )) || return 1
    [[ "$addr" != *::*::* && "$addr" != *:::* ]] || return 1
    IFS=: read -ra groups <<< "$addr"
    (( ${#groups[@]} <= 8 )) || return 1
    for group in "${groups[@]}"; do
        (( ${#group} <= 4 )) || return 1
    done
}
valid_port "$MQVPN_PORT" || err "Invalid port: $MQVPN_PORT"
valid_port "$MQVPN_CONTROL_PORT" || err "Invalid control port: $MQVPN_CONTROL_PORT"
valid_subnet4 "$MQVPN_SUBNET" || err "Invalid subnet (an IPv4 CIDR from /16 to /30): $MQVPN_SUBNET"
[ -z "$MQVPN_SUBNET6" ] || valid_subnet6 "$MQVPN_SUBNET6" \
    || err "Invalid subnet6 (an IPv6 CIDR from /96 to /126): $MQVPN_SUBNET6"
[ -z "$MQVPN_HOSTNAME" ] || [[ "$MQVPN_HOSTNAME" =~ ^[A-Za-z0-9.:-]{1,253}$ ]] \
    || err "Invalid hostname: $MQVPN_HOSTNAME"

[ "$(id -u)" -eq 0 ] || err "mqvpn-server-setup must run as root (use sudo)"
[ -x "$MQVPN" ] || err "$MQVPN not found (install the mqvpn package)"

# Per-install RFC 4193 ULA prefix: fd + 40 random bits, /112. /112 keeps the
# 16-bit host pool (matches IPv4 /24) and stays within the [96,126] range
# required by mqvpn_addr_pool_init6.
gen_subnet6() {
    local hex
    hex=$(openssl rand -hex 5)
    printf 'fd%s:%s:%s::/112' "${hex:0:2}" "${hex:2:4}" "${hex:6:4}"
}

# Skip Subnet6 when the kernel has IPv6 disabled (ipv6.disable=1) or
# ip6tables does not work: mqvpn-server-nat.sh runs sysctl and ip6tables
# under set -e and would fail ExecStartPre.
probe_ipv6() {
    [ -d /proc/sys/net/ipv6 ] || return 1
    [ -w /proc/sys/net/ipv6/conf/all/forwarding ] || return 1
    ip6tables -L FORWARD >/dev/null 2>&1 || return 1
    return 0
}

# purge deletes only the paths in this list (postrm, D7).
record_generated() {
    mkdir -p "$STATE_DIR"
    touch "$GENERATED_LIST"
    grep -qxF "$1" "$GENERATED_LIST" || echo "$1" >> "$GENERATED_LIST"
}
is_generated() { [ -f "$GENERATED_LIST" ] && grep -qxF "$1" "$GENERATED_LIST"; }

umask 077
mkdir -p "$CONF_DIR"

# --- TLS certificate ---
# `-e` so that symlinks to certbot/letsencrypt count as present.
# - both present: the admin set them up (own CA, certbot, ...) — skip
# - neither present: create a self-signed pair
# - only one present: the admin is mid-setup — change nothing, only warn
crt_exists=0; key_exists=0
[ -e "$CRT" ] && crt_exists=1
[ -e "$KEY" ] && key_exists=1
# One file of a pair that this script listed is left from an interrupted run.
if [ "$crt_exists" -ne "$key_exists" ]; then
    present=$CRT
    [ "$key_exists" -eq 1 ] && present=$KEY
    if [ ! -L "$present" ] && is_generated "$present"; then
        warn "$present is left from an interrupted run; creating the certificate again"
        rm -f "$present"
        crt_exists=0; key_exists=0
    fi
fi
if [ "$crt_exists" -eq 1 ] && [ "$key_exists" -eq 1 ]; then
    ok "Certificate already in place, skipping (managed by admin / certbot / etc.)"
elif [ "$crt_exists" -eq 0 ] && [ "$key_exists" -eq 0 ]; then
    san_args=()
    if [ -n "$MQVPN_HOSTNAME" ]; then
        if [[ "$MQVPN_HOSTNAME" =~ ^[0-9.]+$ || "$MQVPN_HOSTNAME" == *:* ]]; then
            san_args=(-addext "subjectAltName=IP:$MQVPN_HOSTNAME")
        else
            san_args=(-addext "subjectAltName=DNS:$MQVPN_HOSTNAME")
        fi
    fi
    tmp_key=$(mktemp "$CONF_DIR/.server.key.XXXXXX")
    tmp_crt=$(mktemp "$CONF_DIR/.server.crt.XXXXXX")
    trap 'rm -f "$tmp_key" "$tmp_crt"' EXIT
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$tmp_key" -out "$tmp_crt" -days 365 -nodes \
        -subj "/CN=${MQVPN_HOSTNAME:-mqvpn}" "${san_args[@]}" 2>/dev/null \
        || err "Failed to generate the self-signed certificate"
    chmod 600 "$tmp_key" "$tmp_crt"
    # List the paths before the files appear, so that an interrupted run is recoverable.
    record_generated "$CRT"
    record_generated "$KEY"
    mv "$tmp_key" "$KEY"
    mv "$tmp_crt" "$CRT"
    trap - EXIT
    ok "Generated self-signed certificate (CN=${MQVPN_HOSTNAME:-mqvpn})"
else
    missing=$([ "$crt_exists" -eq 0 ] && echo server.crt || echo server.key)
    warn "Only one of $CONF_DIR/server.{crt,key} is present ($missing missing); leaving as-is. Place the missing file before starting mqvpn-server."
fi

# --- server.conf ---
if [ ! -f "$CONF" ]; then
    AUTH_KEY=$("$MQVPN" --genkey) || err "Failed to generate auth key"
    [ -n "$AUTH_KEY" ] || err "Empty auth key generated"

    # Generate Subnet6 only when IPv6 works. An explicit value is used as-is.
    SUBNET6=$MQVPN_SUBNET6
    if [ -z "$SUBNET6" ]; then
        if probe_ipv6; then
            SUBNET6=$(gen_subnet6)
        else
            warn "IPv6 unavailable (kernel disabled or ip6tables missing); skipping Subnet6"
        fi
    fi

    # A temporary file and mv: a failure never leaves a partial server.conf.
    tmp=$(mktemp "$CONF_DIR/.server.conf.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    {
        echo "[Interface]"
        echo "Listen = 0.0.0.0:$MQVPN_PORT"
        echo "Subnet = $MQVPN_SUBNET"
        [ -n "$SUBNET6" ] && echo "Subnet6 = $SUBNET6"
        echo "TunName = mqvpn0"
        echo "LogLevel = info"
        echo
        echo "[TLS]"
        echo "Cert = $CRT"
        echo "Key = $KEY"
        echo
        echo "[Auth]"
        echo "Key = $AUTH_KEY"
        echo "MaxClients = 64"
        echo
        echo "[Multipath]"
        echo "Scheduler = wlb"
        echo "AllowClientScheduler = true"
        echo
        # Server side only offers these; each takes effect for a client that
        # also enables it.
        echo "[Hybrid]"
        echo "Enabled = true"
        echo
        echo "[Reorder]"
        echo "Enabled = true"
        echo
        if is_true "$MQVPN_ENABLE_CONTROL"; then
            echo "[Control]"
            echo "Listen = 127.0.0.1:$MQVPN_CONTROL_PORT"
        else
            echo "# [Control]"
            echo "# Listen = 127.0.0.1:9090"
        fi
    } > "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$CONF"
    trap - EXIT
    record_generated "$CONF"
    ok "Generated $CONF"
else
    ok "Config already exists, skipping"

    # Only the --enable-control flag changes an existing config, not the
    # debconf answers or $DEFAULTS_FILE.
    if [ -n "${flag_values[MQVPN_ENABLE_CONTROL]:-}" ]; then
        CONTROL_PORT=$MQVPN_CONTROL_PORT
        if grep -qE '^[[:space:]]*\[Control\][[:space:]]*$' "$CONF"; then
            warn "[Control] section is already active in $CONF — not modified."

        elif awk -v port="$CONTROL_PORT" '
            BEGIN { replaced = 0 }
            {
                if (!replaced && prev == "# [Control]" \
                    && $0 == "# Listen = 127.0.0.1:9090") {
                    print "[Control]"
                    print "Listen = 127.0.0.1:" port
                    replaced = 1
                    prev = ""
                    next
                }
                if (NR > 1) print prev
                prev = $0
            }
            END {
                if (prev != "") print prev
                exit (replaced ? 0 : 1)
            }
        ' "$CONF" > "$CONF.new"; then
            chmod --reference="$CONF" "$CONF.new"
            chown --reference="$CONF" "$CONF.new"
            mv "$CONF.new" "$CONF"
            ok "Uncommented [Control] stub in $CONF (port $CONTROL_PORT)."

        else
            rm -f "$CONF.new"
            if grep -qE '^[[:space:]]*#[[:space:]]*\[Control\]' "$CONF"; then
                warn "Found admin-edited commented [Control] in $CONF — not modified."
                warn "Edit it manually: uncomment '[Control]' and 'Listen = ...'."
            else
                {
                    echo
                    echo "[Control]"
                    echo "Listen = 127.0.0.1:$CONTROL_PORT"
                } >> "$CONF"
                ok "Appended [Control] block to $CONF."
            fi
        fi
    fi
fi

# postinst runs daemon-reload, the start and the summary itself.
if [ "$FROM_POSTINST" -eq 1 ]; then
    exit 0
fi

systemctl daemon-reload
if [ "$START" -eq 1 ]; then
    info "Starting mqvpn-server..."
    systemctl enable --now mqvpn-server
fi
"$SERVER_INFO"
