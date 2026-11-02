#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# check_deb_contents.sh — static checks of the three CPack debs
#
# Checks, without installing anything:
#   - cpack made exactly the mqvpn, mqvpn-server and mqvpn-dev debs
#   - each file from `cmake --install` is in exactly one deb, so no install()
#     rule lacks a COMPONENT
#   - the server files and the development files are in their new packages
#   - the control fields of the split (Depends, Breaks, Replaces, conffiles)
#
# Usage: scripts/ci_e2e/check_deb_contents.sh BUILD_DIR
#   BUILD_DIR must be configured with -DCMAKE_INSTALL_PREFIX=/usr, built, and
#   contain the output of `cpack -G DEB`.

set -euo pipefail

BUILD_DIR=${1:?usage: check_deb_contents.sh BUILD_DIR}
failures=0

pass() { echo "OK: $1"; }
fail() { echo "FAIL: $1"; failures=$((failures + 1)); }

shopt -s nullglob
debs=("$BUILD_DIR"/*.deb)
rt=("$BUILD_DIR"/mqvpn_*.deb)
srv=("$BUILD_DIR"/mqvpn-server_*.deb)
dev=("$BUILD_DIR"/mqvpn-dev_*.deb)
shopt -u nullglob
if [ "${#debs[@]}" -eq 3 ] && [ "${#rt[@]}" -eq 1 ] && [ "${#srv[@]}" -eq 1 ] && [ "${#dev[@]}" -eq 1 ]; then
    pass "cpack made exactly three debs: ${debs[*]##*/}"
else
    echo "FAIL: expected mqvpn, mqvpn-server and mqvpn-dev debs, found: ${debs[*]##*/}"
    exit 1
fi
RT=${rt[0]} SRV=${srv[0]} DEV=${dev[0]}
VERSION=$(dpkg-deb -f "$RT" Version)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Files and symlinks only: directories are shared on purpose.
payload() { dpkg-deb --fsys-tarfile "$1" | tar -t | sed 's|^\./|/|' | grep -v '/$' | sort; }
payload "$RT" > "$work/rt"
payload "$SRV" > "$work/srv"
payload "$DEV" > "$work/dev"

# ── Manifest coverage: an untagged install() rule lands in no deb ───────────
DESTDIR="$work/root" cmake --install "$BUILD_DIR" >/dev/null
(cd "$work/root" && find . \( -type f -o -type l \) | sed 's|^\./|/|' | sort) > "$work/installed"
sort "$work/rt" "$work/srv" "$work/dev" > "$work/packaged"
if diff -u "$work/installed" "$work/packaged" > "$work/manifest.diff"; then
    pass "each installed file is in exactly one deb ($(wc -l < "$work/installed") files)"
else
    fail "cmake --install output and deb contents differ (- installed only, + duplicate or deb only):"
    cat "$work/manifest.diff"
fi

# ── File placement (D2, D9) ──────────────────────────────────────────────────
expect_in() { # $1 = package list file, $2 = package name, $3... = paths
    local list=$1 name=$2 path
    shift 2
    for path in "$@"; do
        if grep -qxF "$path" "$work/$list"; then pass "$path is in $name"; else fail "$path is not in $name"; fi
    done
}
expect_not_in() {
    local list=$1 name=$2 path
    shift 2
    for path in "$@"; do
        if grep -qxF "$path" "$work/$list"; then fail "$path is still in $name"; else pass "$path is not in $name"; fi
    done
}
SERVER_FILES=(/usr/lib/systemd/system/mqvpn-server.service /usr/lib/mqvpn/mqvpn-server-nat.sh
              /usr/lib/mqvpn/mqvpn-nat-config /etc/mqvpn/server.conf.example /etc/mqvpn/server.json.example)
DEV_FILES=(/usr/include/libmqvpn.h /usr/include/mqvpn_bind_posix.h /usr/lib/libmqvpn.so)
expect_in srv mqvpn-server "${SERVER_FILES[@]}" /usr/lib/mqvpn/mqvpn-server-setup /usr/bin/mqvpn-server-info \
    /etc/default/mqvpn-server /usr/share/doc/mqvpn-server/README.Debian \
    /usr/share/doc/mqvpn-server/LICENSE /usr/share/doc/mqvpn-server/NOTICE
expect_not_in rt mqvpn "${SERVER_FILES[@]}" "${DEV_FILES[@]}"
expect_in dev mqvpn-dev "${DEV_FILES[@]}" /usr/share/doc/mqvpn-dev/LICENSE /usr/share/doc/mqvpn-dev/NOTICE
expect_in rt mqvpn /usr/bin/mqvpn /usr/lib/libmqvpn.so.4 /usr/lib/libxquic.so \
    /usr/lib/systemd/system/mqvpn-client@.service /etc/mqvpn/client.conf.example \
    /etc/mqvpn/client.json.example /usr/share/doc/mqvpn/LICENSE /usr/share/doc/mqvpn/NOTICE \
    /usr/share/doc/mqvpn/NEWS.Debian.gz
for list in rt srv dev; do
    expect_not_in "$list" "$list deb" /usr/lib/libmqvpn.a
done
link=$(dpkg-deb -c "$DEV" | awk '$6 == "./usr/lib/libmqvpn.so" { print $8 }')
if [ "$link" = libmqvpn.so.4 ]; then pass "libmqvpn.so -> libmqvpn.so.4"; else fail "libmqvpn.so points to '$link'"; fi

# ── Control fields ──────────────────────────────────────────────────────────
expect_field() { # $1 = deb, $2 = field, $3 = expected substring
    local value
    value=$(dpkg-deb -f "$1" "$2")
    if [[ "$value" == *"$3"* ]]; then pass "${1##*/} $2 has '$3'"; else fail "${1##*/} $2 is '$value', expected '$3'"; fi
}
expect_field "$SRV" Depends "mqvpn (>= $VERSION)"
expect_field "$SRV" Pre-Depends "debconf"
expect_field "$SRV" Breaks "mqvpn (<< "
expect_field "$SRV" Replaces "mqvpn (<< "
expect_field "$DEV" Depends "mqvpn (= $VERSION)"
expect_field "$DEV" Breaks "mqvpn (<< "
expect_field "$DEV" Replaces "mqvpn (<< "
expect_field "$RT" Suggests "mqvpn-server"
split=$(dpkg-deb -f "$SRV" Breaks | sed -n 's/.*mqvpn (<< \([^~)]*\)~).*/\1/p')
if dpkg --compare-versions "$VERSION" ge "$split"; then
    pass "version $VERSION is at or above the split version $split"
else
    fail "version $VERSION is below the split version $split: the new debs break the mqvpn deb of the same build"
fi

# ── conffiles (D5, R14) ─────────────────────────────────────────────────────
conffiles() { dpkg-deb --ctrl-tarfile "$1" | tar -xO ./conffiles 2>/dev/null || true; }
if [ "$(conffiles "$SRV")" = /etc/default/mqvpn-server ]; then
    pass "mqvpn-server conffiles lists only /etc/default/mqvpn-server"
else
    fail "mqvpn-server conffiles is: $(conffiles "$SRV")"
fi
for deb in "$RT" "$DEV"; do
    if [ -z "$(conffiles "$deb")" ]; then pass "${deb##*/} has no conffiles"; else fail "${deb##*/} has conffiles"; fi
done

echo ""
if [ "$failures" -ne 0 ]; then
    echo "=== check_deb_contents: $failures FAILURE(S) ==="
    exit 1
fi
echo "=== check_deb_contents: PASS ==="
