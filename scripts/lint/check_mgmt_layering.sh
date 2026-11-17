#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# scripts/lint/check_mgmt_layering.sh
#
# The client management IPC is layered; this gate keeps the include
# directions that make the layers testable on their own:
#
#  1. src/mgmt/*.[ch] and src/common/ipc/*.[ch] (protocol core) include no
#     event2/, no platform/, no mqvpn_internal.h, no <sys/socket.h>, no
#     <winsock2.h>.
#  2. src/platform/common/mgmt_conn.c (connection layer) includes none of
#     sys/un.h, afunix.h, sys/stat.h, unistd.h, windows.h, aclapi.h, sddl.h:
#     it never creates, chmods or unlinks a listener. The socket header it
#     needs for shutdown() and send() is allowed.
#  3. Every #include "..." in src/cli/*.[ch] that resolves to a file under
#     src/ lives in src/cli/, src/common/ipc/ or is src/json_util.h.
#     (libmqvpn.h is outside src/ and allowed.) yyjson.h is reached only
#     through json_util.h, here and in the protocol core.
#  4. The mqvpnctl source list in CMakeLists.txt names nothing from
#     src/mgmt/, src/platform/ or mqvpn_lib.
#
# Token gate: comments match too, and an include reached through a macro is
# invisible. A run that scans zero files is "cannot run", never a pass.
#
# Exit status: 0 clean, 1 violation(s) reported, 2 cannot run.
set -euo pipefail

# grep with its exit status inspected (see check_sansio_core.sh): an I/O error
# must not read as "no match". Sets GREP_OUT; returns 0 on match, 1 on none.
GREP_OUT=
grep_checked() {
    local file=$1
    shift
    local st
    set +e
    GREP_OUT=$(grep "$@" -- "$file")
    st=$?
    set -e
    if [ "$st" -ge 2 ]; then
        echo "mgmt-layering: cannot scan $file (grep exited $st) - refusing to report clean"
        exit 2
    fi
    return "$st"
}

REPO_ROOT=$(cd -- "$(dirname -- "$0")/../.." && pwd -P) || {
    echo "mgmt-layering: cannot resolve the repository root from $0"
    exit 2
}
cd "$REPO_ROOT"
if [ ! -f include/libmqvpn.h ] || [ ! -f CMakeLists.txt ]; then
    echo "mgmt-layering: $REPO_ROOT does not look like an mqvpn checkout"
    exit 2
fi

rc=0
checked=0

# scan_files <label> <extended-regexp> <file>...
scan_files() {
    local label=$1 pat=$2 f
    shift 2
    for f in "$@"; do
        [ -f "$f" ] || continue
        checked=$((checked + 1))
        if grep_checked "$f" -nE "$pat"; then
            echo "mgmt-layering: $label in $f:"
            printf '%s\n' "$GREP_OUT" | sed 's/^/    /'
            rc=1
        fi
    done
}

INC='^[[:space:]]*#[[:space:]]*include[[:space:]]*[<"]([^>"]*/)?'

# 1. protocol core
scan_files "forbidden include (protocol core)" \
    "${INC}(event2/|platform/|mqvpn_internal\\.h|sys/socket\\.h|winsock2\\.h|yyjson\\.h)" \
    src/mgmt/*.[ch] src/common/ipc/*.[ch]

# 2. connection layer
scan_files "OS-specific include (connection layer)" \
    "${INC}(un\\.h|afunix\\.h|stat\\.h|unistd\\.h|windows\\.h|aclapi\\.h|sddl\\.h)[>\"]" \
    src/platform/common/mgmt_conn.c

# 3. CLI quoted includes
for f in src/cli/*.[ch]; do
    [ -f "$f" ] || continue
    checked=$((checked + 1))
    grep_checked "$f" -E '^[[:space:]]*#[[:space:]]*include[[:space:]]*"' || continue
    while IFS= read -r line; do
        inc=${line#*\"}
        inc=${inc%%\"*}
        case "$inc" in
            json_util.h) continue ;;
            yyjson.h)
                echo "mgmt-layering: $f includes \"yyjson.h\" directly; include json_util.h"
                rc=1
                continue
                ;;
        esac
        # A relative path can step out of src/cli/ into any other layer.
        case "$inc" in
            *..*)
                echo "mgmt-layering: $f includes \"$inc\": '..' in a CLI include is not allowed"
                rc=1
                continue
                ;;
        esac
        if [ -f "src/cli/$inc" ] || [ -f "src/common/ipc/$inc" ]; then continue; fi
        hit=$(find src -type f -name "$(basename -- "$inc")" -print)
        if [ -n "$hit" ]; then
            echo "mgmt-layering: $f includes \"$inc\", which resolves to:"
            printf '%s\n' "$hit" | sed 's/^/    /'
            rc=1
        fi
    done <<<"$GREP_OUT"
done

# 4. mqvpnctl source list in CMakeLists.txt (from add_executable(mqvpnctl to
# the first closing parenthesis)
ctl_list=$(awk '/add_executable\(mqvpnctl/ {f=1} f {print} f && /\)/ {exit}' CMakeLists.txt)
if [ -z "$ctl_list" ]; then
    echo "mgmt-layering: no add_executable(mqvpnctl ...) found in CMakeLists.txt"
    exit 2
fi
checked=$((checked + 1))
bad=$(printf '%s\n' "$ctl_list" | grep -nE 'src/mgmt/|src/platform/|mqvpn_lib' || true)
if [ -n "$bad" ]; then
    echo "mgmt-layering: the mqvpnctl source list names a forbidden source:"
    printf '%s\n' "$bad" | sed 's/^/    /'
    rc=1
fi

if [ "$checked" -eq 0 ]; then
    echo "mgmt-layering: no files were scanned"
    exit 2
fi
if [ "$rc" -eq 0 ]; then
    echo "mgmt-layering: OK ($checked files checked)"
else
    echo "mgmt-layering: FAILED ($checked files checked)"
fi
exit "$rc"
