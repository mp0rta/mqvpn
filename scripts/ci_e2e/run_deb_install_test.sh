#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_deb_install_test.sh — install, upgrade, remove and purge tests of the
# mqvpn, mqvpn-server and mqvpn-dev debs
#
# Run only on a disposable host with systemd (a CI runner): the test installs
# and purges packages, starts mqvpn-server on UDP 10443, changes iptables and
# sysctls, and adds a dummy interface. The numbers in the phase names are the
# assertion numbers of the packaging plan.
#
# Usage: sudo scripts/ci_e2e/run_deb_install_test.sh DEB_DIR OLD_MQVPN_DEB
#   DEB_DIR        the three debs of this build
#   OLD_MQVPN_DEB  the mqvpn deb of the last release before the split, which
#                  still contains the server and development files

set -euo pipefail

DEB_DIR=$(readlink -f "${1:?usage: run_deb_install_test.sh DEB_DIR OLD_MQVPN_DEB}")
OLD_DEB=$(readlink -f "${2:?usage: run_deb_install_test.sh DEB_DIR OLD_MQVPN_DEB}")
RT=$(echo "$DEB_DIR"/mqvpn_*.deb)
SRV=$(echo "$DEB_DIR"/mqvpn-server_*.deb)
DEV=$(echo "$DEB_DIR"/mqvpn-dev_*.deb)
VERSION=$(dpkg-deb -f "$RT" Version)

CONF=/etc/mqvpn/server.conf
CRT=/etc/mqvpn/server.crt
KEY=/etc/mqvpn/server.key
DEFAULTS=/etc/default/mqvpn-server
UNIT=mqvpn-server.service
WORK=$(mktemp -d)
LOG=$WORK/apt.log
# Not under /tmp: the unit has PrivateTmp=true and would not see it.
CERT_DIR=/etc/mqvpn-ci-certs

export DEBIAN_FRONTEND=noninteractive

# ── Helpers ──────────────────────────────────────────────────────────────────

pass() { echo "OK: $1"; }
fail() {
    echo ""
    echo "=== FAIL: $1 ==="
    echo "--- last apt output ---"
    tail -n 60 "$LOG" 2>/dev/null || true
    echo "--- journalctl $UNIT ---"
    journalctl -u "$UNIT" --no-pager -n 60 2>/dev/null || true
    exit 1
}
phase() { echo ""; echo "=== $1 ==="; }
check() { # $1 = description, $2... = command
    local what=$1
    shift
    if "$@"; then pass "$what"; else fail "$what"; fi
}

cleanup() {
    rm -f /usr/sbin/policy-rc.d
    ip link del mqvpnci0 2>/dev/null || true
    ip addr del 10.0.0.1/24 dev lo 2>/dev/null || true
    rm -rf "$WORK" "$CERT_DIR"
}
trap cleanup EXIT

# A prompt reads stdin, so </dev/null turns a hidden prompt into a failure,
# and timeout turns a hang into a failure.
apt_run() { # [VAR=value...] apt-get arguments...
    local envs=()
    while [ $# -gt 0 ] && [[ "$1" == *=* ]]; do
        envs+=("$1")
        shift
    done
    timeout 300 env "${envs[@]}" apt-get -y -o Dpkg::Use-Pty=0 "$@" </dev/null > "$LOG" 2>&1
}

purge_all() {
    dpkg --purge mqvpn-dev mqvpn-server mqvpn > "$LOG" 2>&1 || fail "dpkg --purge of all packages"
}

wait_active() {
    local _
    for _ in $(seq 1 30); do
        systemctl --quiet is-active "$UNIT" && return 0
        sleep 0.5
    done
    return 1
}
is_inactive() { ! systemctl --quiet is-active "$UNIT"; }
is_enabled() { [ "$(systemctl is-enabled "$UNIT" 2>/dev/null)" = enabled ]; }
mode_is() { [ "$(stat -c %a "$1")" = "$2" ]; }
conf_has() { grep -qxF "$1" "$CONF"; }
auth_key() { sed -n '/^\[Auth\]/,/^\[/ s/^Key = //p' "$CONF"; }
cert_fp() { openssl x509 -in "$CRT" -noout -fingerprint -sha256; }
nat_rule_count() {
    local rules
    rules=$(iptables -t nat -S POSTROUTING) || return 1
    grep -c mqvpn-server-nat <<< "$rules" || true
}
nat_rule_present() { local n; n=$(nat_rule_count) && [ "$n" -gt 0 ]; }
nat_rule_absent() { local n; n=$(nat_rule_count) && [ "$n" -eq 0 ]; }
log_has() { grep -qF "$1" "$LOG"; }
main_pid() { systemctl show -p MainPID --value "$UNIT"; }
make_admin_cert() { # $1 = CN
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout "$CERT_DIR/key.pem" \
        -out "$CERT_DIR/cert.pem" -days 1 -nodes -subj "/CN=$1" 2>/dev/null
}
write_admin_conf() {
    cat > "$CONF" <<EOF
[Interface]
Listen = 0.0.0.0:10443
Subnet = 10.79.0.0/24

[TLS]
Cert = $CRT
Key = $KEY

[Auth]
Key = $(mqvpn --genkey)
EOF
    chmod 600 "$CONF"
}
# debconf code 10: the question does not exist, so purge deleted the answers.
debconf_purged() { echo 'GET mqvpn-server/subnet' | debconf-communicate 2>/dev/null | grep -q '^10 '; }

# ── Prerequisites ────────────────────────────────────────────────────────────

phase "Prerequisites"
[ "$(id -u)" -eq 0 ] || { echo "FAIL: run as root"; exit 1; }
for f in "$RT" "$SRV" "$DEV" "$OLD_DEB"; do
    [ -f "$f" ] || { echo "FAIL: $f not found"; exit 1; }
done
[ -d /run/systemd/system ] || { echo "FAIL: systemd is not running"; exit 1; }
if dpkg-query -W mqvpn >/dev/null 2>&1; then
    echo "FAIL: mqvpn is already installed on this host"
    exit 1
fi
pass "debs: ${RT##*/} ${SRV##*/} ${DEV##*/}; old: ${OLD_DEB##*/}"

# ── 1-4, 9: first install with environment overrides ─────────────────────────

phase "1-4, 9: install all three debs (MQVPN_PORT=10443 MQVPN_SUBNET=10.77.0.0/24)"
apt_run MQVPN_PORT=10443 MQVPN_SUBNET=10.77.0.0/24 install "$RT" "$SRV" "$DEV" || fail "apt-get install of the three debs"
check "1: server.conf has mode 600" mode_is "$CONF" 600
check "1: server.conf has Listen = 0.0.0.0:10443" conf_has "Listen = 0.0.0.0:10443"
check "1: server.conf has Subnet = 10.77.0.0/24" conf_has "Subnet = 10.77.0.0/24"
PSK=$(auth_key)
check "1: [Auth] Key is set" test -n "$PSK"
check "2: server.crt has mode 600" mode_is "$CRT" 600
check "2: server.key has mode 600" mode_is "$KEY" 600
check "3: $UNIT is enabled" is_enabled
check "3: $UNIT is active" wait_active
check "3: the NAT rule is present" nat_rule_present
check "4: postinst printed the summary with the PSK" log_has "Auth key:  $PSK"
check "4: mqvpn-server-info prints the PSK" bash -c "mqvpn-server-info | grep -qF 'Auth key:  $PSK'"
for pair in "mqvpn mqvpn-server" "mqvpn mqvpn-dev" "mqvpn-server mqvpn-dev"; do
    read -r a b <<< "$pair"
    shared=$(comm -12 <(dpkg -L "$a" | sort) <(dpkg -L "$b" | sort) | while read -r p; do [ -d "$p" ] || echo "$p"; done)
    check "9: $a and $b share no file" test -z "$shared"
done

# ── 5, 19.2: reinstall keeps the PSK, the certificate and a conffile edit ─────

phase "5, 19.2: apt-get install --reinstall mqvpn-server"
FP=$(cert_fp)
sed -i 's/^#MQVPN_SUBNET6=$/MQVPN_SUBNET6=/' "$DEFAULTS"
check "19.2: the edit is in $DEFAULTS" grep -qx 'MQVPN_SUBNET6=' "$DEFAULTS"
apt_run install --reinstall "$SRV" || fail "apt-get install --reinstall (a conffile prompt also fails here)"
check "5: the PSK did not change" test "$(auth_key)" = "$PSK"
check "5: the certificate did not change" test "$(cert_fp)" = "$FP"
check "19.2: the conffile edit stays" grep -qx 'MQVPN_SUBNET6=' "$DEFAULTS"
check "19.2: dpkg wrote no .dpkg-dist or .dpkg-old file" bash -c "! ls $DEFAULTS.dpkg-* 2>/dev/null"
check "5: $UNIT is active after the reinstall" wait_active

# ── 18: mqvpn-dev builds a program against libmqvpn ──────────────────────────

phase "18: compile and link against libmqvpn"
cat > "$WORK/devtest.c" <<'EOF'
#include <stdio.h>
#include <libmqvpn.h>
int main(void) { puts(mqvpn_version_string()); return 0; }
EOF
check "18: gcc -lmqvpn links" gcc -o "$WORK/devtest" "$WORK/devtest.c" -lmqvpn
check "18: the program prints $VERSION" test "$("$WORK/devtest")" = "$VERSION"
apt_run remove mqvpn-dev || fail "apt-get remove mqvpn-dev"
check "18: libmqvpn.so.4 stays after the removal of mqvpn-dev" test -e /usr/lib/libmqvpn.so.4
check "18: the program still runs" "$WORK/devtest"

# ── 7: remove keeps the configuration; a reinstall starts the server again ──

phase "7, 19.4: apt-get remove mqvpn-server"
apt_run remove mqvpn-server || fail "apt-get remove mqvpn-server"
check "7: $UNIT is not active" is_inactive
check "7: the NAT rule is gone" nat_rule_absent
check "7: server.conf stays" test -f "$CONF"
check "7: postrm printed the purge note" log_has "mqvpn-server: removed. A purge deletes the generated server.conf"
check "19.4: remove keeps $DEFAULTS" test -f "$DEFAULTS"
apt_run install "$SRV" || fail "apt-get install after remove"
check "7: a reinstall starts the server that remove stopped" wait_active
check "7: the reinstall keeps the PSK" test "$(auth_key)" = "$PSK"

# ── 8, 13, 19.4: purge deletes the generated files only ──────────────────────

phase "8, 13, 19.4: apt-get purge mqvpn-server"
apt_run purge mqvpn-server || fail "apt-get purge mqvpn-server"
for f in "$CONF" "$CRT" "$KEY"; do
    check "13: purge deleted $f" test ! -e "$f"
done
check "8: purge deleted /var/lib/mqvpn-server" test ! -e /var/lib/mqvpn-server
check "8: purge listed the deleted server.conf once" test "$(grep -cxF "mqvpn-server: deleted $CONF" "$LOG")" = 1
check "8: /etc/mqvpn/client.conf.example of mqvpn stays" test -f /etc/mqvpn/client.conf.example
check "19.4: purge deleted $DEFAULTS" test ! -e "$DEFAULTS"
check "8: purge deleted the debconf answers" debconf_purged

# ── 13b: purge keeps a symlink that replaced a generated certificate ────────

phase "13b: a certbot-style symlink over the generated certificate survives purge"
apt_run MQVPN_PORT=10443 install "$SRV" || fail "apt-get install mqvpn-server"
make_admin_cert certbot.ci.example
ln -sf "$CERT_DIR/cert.pem" "$CRT"
ln -sf "$CERT_DIR/key.pem" "$KEY"
apt_run purge mqvpn-server || fail "apt-get purge mqvpn-server"
check "13b: the certificate symlink stays" test -L "$CRT"
check "13b: the key symlink stays" test -L "$KEY"
check "13b: the generated server.conf is gone" test ! -e "$CONF"
rm -f "$CRT" "$KEY"

# ── 6: MQVPN_SERVER_AUTOSTART=no ─────────────────────────────────────────────

phase "6: install with MQVPN_SERVER_AUTOSTART=no"
apt_run MQVPN_SERVER_AUTOSTART=no MQVPN_PORT=10443 install "$SRV" || fail "apt-get install with MQVPN_SERVER_AUTOSTART=no"
check "6: $UNIT is not active" is_inactive
check "6: $UNIT is not enabled" bash -c "[ \"\$(systemctl is-enabled $UNIT 2>/dev/null)\" != enabled ]"
check "6: server.conf exists" test -f "$CONF"
apt_run purge mqvpn-server || fail "apt-get purge mqvpn-server"

# ── 6b: setup fails on a first install ───────────────────────────────────────

phase "6b: install with an invalid MQVPN_SUBNET"
apt_run MQVPN_SUBNET=10.77.0.0/8 MQVPN_PORT=10443 install "$SRV" || fail "postinst failed after a failed setup"
check "6b: postinst reported the failed setup" log_has "mqvpn-server: setup failed"
check "6b: $UNIT is not active" is_inactive
check "6b: $UNIT is not enabled" bash -c "[ \"\$(systemctl is-enabled $UNIT 2>/dev/null)\" != enabled ]"
check "6b: no server.conf" test ! -e "$CONF"
apt_run purge mqvpn-server || fail "apt-get purge mqvpn-server"

# ── 10: policy-rc.d refuses the start ────────────────────────────────────────

phase "10: install under a policy-rc.d that returns 101"
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
apt_run MQVPN_PORT=10443 install "$SRV" || fail "postinst failed under policy-rc.d"
check "10: $UNIT is not active" is_inactive
rm -f /usr/sbin/policy-rc.d
apt_run purge mqvpn-server || fail "apt-get purge mqvpn-server"

# ── 11: debconf preseed ──────────────────────────────────────────────────────

phase "11: preseed the subnet and the hostname"
debconf-set-selections <<'EOF'
mqvpn-server mqvpn-server/subnet string 10.88.0.0/24
mqvpn-server mqvpn-server/hostname string vpn.ci.example
mqvpn-server mqvpn-server/port string 10443
EOF
apt_run install "$SRV" || fail "apt-get install with preseeded answers"
check "11: server.conf uses the preseeded subnet" conf_has "Subnet = 10.88.0.0/24"
check "11: server.conf uses the preseeded port" conf_has "Listen = 0.0.0.0:10443"
check "11: the certificate CN is the hostname" bash -c "openssl x509 -in $CRT -noout -subject | grep -q 'CN *= *vpn.ci.example'"
check "11: the certificate SAN is the hostname" bash -c "openssl x509 -in $CRT -noout -ext subjectAltName | grep -q 'DNS:vpn.ci.example'"
check "11: the client command uses the hostname" bash -c "mqvpn-server-info | grep -q -- '--server vpn.ci.example:10443'"
apt_run purge mqvpn-server || fail "apt-get purge mqvpn-server"

# ── 12: subnet collision detection ───────────────────────────────────────────

phase "12: the default subnet overlaps a host address"
if ip link add mqvpnci0 type dummy 2>/dev/null; then
    collide_dev=mqvpnci0
    ip link set mqvpnci0 up
else
    collide_dev=lo
fi
ip addr add 10.0.0.1/24 dev "$collide_dev"
apt_run MQVPN_PORT=10443 install "$SRV" || fail "apt-get install with a subnet collision (a prompt or a hang also fails here)"
subnet=$(sed -n 's/^Subnet = //p' "$CONF")
check "12: the selected subnet $subnet is not 10.0.0.0/24" test "$subnet" != 10.0.0.0/24
check "12: the selected subnet $subnet is a 10.x.0.0/24 candidate" bash -c "[[ '$subnet' =~ ^10\\.[1-9][0-9]*\\.0\\.0/24$ ]]"
apt_run purge mqvpn-server || fail "apt-get purge mqvpn-server"
ip addr del 10.0.0.1/24 dev "$collide_dev"
ip link del mqvpnci0 2>/dev/null || true

# ── 14: purge never deletes admin files ──────────────────────────────────────

phase "14: admin-written server.conf and a certbot-style symlink survive purge"
mkdir -p /etc/mqvpn
make_admin_cert admin.ci.example
ln -s "$CERT_DIR/cert.pem" "$CRT"
ln -s "$CERT_DIR/key.pem" "$KEY"
write_admin_conf
ADMIN_SUM=$(sha256sum "$CONF")
apt_run install "$SRV" || fail "apt-get install over an admin configuration"
check "14: the install did not change server.conf" test "$(sha256sum "$CONF")" = "$ADMIN_SUM"
check "14: setup generated no file" test ! -s /var/lib/mqvpn-server/generated.list
apt_run purge mqvpn-server || fail "apt-get purge mqvpn-server"
check "14: server.conf survives purge" test -f "$CONF"
check "14: the certificate symlink survives purge" test -L "$CRT"
check "14: the key symlink survives purge" test -L "$KEY"
rm -f "$CONF" "$CRT" "$KEY"

# ── 19.3: conffile upgrade with --force-confdef --force-confold ──────────────

phase "19.3: upgrade to a server deb with a changed conffile"
apt_run MQVPN_PORT=10443 install "$SRV" || fail "apt-get install mqvpn-server"
sed -i 's/^#MQVPN_PORT=443$/MQVPN_PORT=10443/' "$DEFAULTS"
dpkg-deb -R "$SRV" "$WORK/srv2"
sed -i "s/^Version: .*/Version: $VERSION+ci1/" "$WORK/srv2/DEBIAN/control"
echo "# packaged change for the conffile test" >> "$WORK/srv2/etc/default/mqvpn-server"
(cd "$WORK/srv2" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' | xargs -0 md5sum > DEBIAN/md5sums)
dpkg-deb --root-owner-group -b "$WORK/srv2" "$WORK/srv2.deb" >/dev/null
apt_run -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install "$WORK/srv2.deb" \
    || fail "upgrade with --force-confdef --force-confold"
check "19.3: the admin edit stays" grep -qx 'MQVPN_PORT=10443' "$DEFAULTS"
check "19.3: dpkg wrote the package version as .dpkg-dist" grep -q 'packaged change for the conffile test' "$DEFAULTS.dpkg-dist"
apt_run purge mqvpn-server || fail "apt-get purge mqvpn-server"
check "19.3: purge deleted $DEFAULTS" test ! -e "$DEFAULTS"

# ── 17: upgrade from the last pre-split mqvpn deb ────────────────────────────

phase "17.1-17.4: upgrade from ${OLD_DEB##*/} with a running server, mqvpn first"
purge_all
apt_run install "$OLD_DEB" || fail "apt-get install of the old deb"
check "17.1: the old mqvpn owns the server unit" bash -c "dpkg -S /usr/lib/systemd/system/$UNIT | grep -q '^mqvpn:'"
mkdir -p /etc/mqvpn
make_admin_cert old.ci.example
cp "$CERT_DIR/cert.pem" "$CRT"
cp "$CERT_DIR/key.pem" "$KEY"
chmod 600 "$CRT" "$KEY"
write_admin_conf
systemctl daemon-reload
systemctl enable --now "$UNIT" >/dev/null 2>&1
check "17.2: $UNIT is enabled from the old deb" is_enabled
check "17.2: $UNIT runs from the old deb" wait_active
OLD_PID=$(main_pid)
apt_run install "$RT" || fail "17.3: upgrade of mqvpn alone"
check "17.3: the mqvpn postinst printed the warning" log_has "mqvpn: WARNING: mqvpn-server.service is enabled or running"
apt_run MQVPN_PORT=10443 install "$SRV" || fail "17.4: install of mqvpn-server"
check "17.4: mqvpn-server owns the unit" bash -c "dpkg -S /usr/lib/systemd/system/$UNIT | grep -q '^mqvpn-server:'"
check "17.4: $UNIT is enabled" is_enabled
check "17.4: $UNIT is active" wait_active
check "17.4: the install restarted the old server process" test "$(main_pid)" != "$OLD_PID"
check "17.4: the install kept the admin server.conf" grep -q 'Subnet = 10.79.0.0/24' "$CONF"

phase "17.5: upgrade from ${OLD_DEB##*/}, all three debs in one transaction"
purge_all
apt_run install "$OLD_DEB" || fail "apt-get install of the old deb"
apt_run MQVPN_PORT=10443 install "$RT" "$SRV" "$DEV" || fail "17.5: one-transaction upgrade"
check "17.5: dpkg reported no file conflict" bash -c "! grep -q 'trying to overwrite' $LOG"
check "17.5: mqvpn-dev owns libmqvpn.h" bash -c "dpkg -S /usr/include/libmqvpn.h | grep -q '^mqvpn-dev:'"
check "17.5: libmqvpn.a is gone" test ! -e /usr/lib/libmqvpn.a
check "17.5: the unit that was disabled in the old deb stays disabled" bash -c "[ \"\$(systemctl is-enabled $UNIT 2>/dev/null)\" != enabled ]"
check "17.5: the unit that was disabled in the old deb does not start" is_inactive
check "17.5: postinst said why the unit stays disabled" log_has "was disabled before this install, so it stays disabled"
check "17.5: postinst deleted the keep-disabled marker" test ! -e /var/lib/mqvpn-server/keep-disabled
purge_all
rm -f "$CONF" "$CRT" "$KEY"

echo ""
echo "=== run_deb_install_test: PASS ==="
