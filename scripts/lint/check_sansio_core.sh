#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# scripts/lint/check_sansio_core.sh [build-dir]        (default build-dir: build)
#
# libmqvpn's core is sans-I/O: it never issues a socket syscall, never holds
# an fd or SOCKET, and never sees UDP_SEGMENT/UDP_GRO. Every send goes out
# through a transport ops table (include/libmqvpn.h, ABI 3); every receive is
# pushed in by the platform. This gate keeps it that way.
#
# What it enforces, exactly:
#
#  1. Core sources - the RESOLVED source list of the mqvpn_lib target, which
#     CMake writes to <build-dir>/mqvpn_lib_sources.txt at configure time so
#     that the conditional appends (the hybrid lane files) are included - must
#     contain none of:
#       * sendto|sendmsg|sendmmsg|recvfrom|recvmsg|recvmmsg|
#         setsockopt|getsockopt|socket|close   immediately followed by `(`
#       * the bare token SOCKET, UDP_SEGMENT or UDP_GRO
#       * an #include of a bind header (udp_offload.h, bind/posix_offload.h,
#         mqvpn_bind_posix.h) in either delimiter, "..." or <...> - the core
#         is bind-agnostic
#     Exclusions, these two and no others:
#       src/bind/*                the bundled transport implementations
#       src/hybrid/tcp_egress.c   the server egress lane owns its TCP sockets
#                                 (out of scope by design; see AGENTS.md)
#     The other hybrid files are NOT excluded, so a regression there is caught.
#     A listed source that is missing, or an entry with a stray CR, is itself
#     a failure: the list has to describe the tree it is scanned against.
#
#  2. Public header - include/libmqvpn.h must not contain the token SOCKET,
#     and no `int fd` / `int tun_fd` parameter unless one of
#     egress_fd_register, egress_fd_unregister,
#     mqvpn_server_on_egress_fd_ready or mqvpn_client_set_tun_active appears
#     on that line or within the two lines above it. The first three are the
#     hybrid egress API (out of scope); tun_fd is a platform-owned TUN
#     descriptor the core discards. The lookback exists because these are
#     real declarations that clang-format wraps at ColumnLimit: a parameter
#     can legitimately sit on a continuation line, away from its function
#     name.
#
# The subject of the scan is the source tree the BUILD DIR was configured
# from (CMAKE_HOME_DIRECTORY in its CMakeCache.txt), not whatever repository
# the caller happens to stand in; `git rev-parse --show-toplevel` and then
# the script's own location are only fallbacks. The tree actually scanned is
# printed on every run.
#
# Deliberate limits, so the header claim stays exactly as large as the check:
#   * Comments match too. A comment is where the next sendto() starts.
#   * Word-boundary regexes, so XQC_SOCKET_EAGAIN, cb_write_socket( and
#     xqc_conn_close( do NOT match.
#   * It is a token gate, not a semantic one: I/O reached through a macro or
#     a function pointer is invisible to it.
#   * The subject is the library target only. Files that belong to the CLI
#     targets - e.g. src/path_mgr.c, the platform's socket factory, and
#     src/config.c - are outside "core" by construction and are not scanned.
#     This is not a whole-src/ sweep.
#   * The header check matches the literal spellings `int fd` and `int tun_fd`.
#     A descriptor smuggled in as `int *fd`, `int sock` or inside a struct is
#     not caught; only review is.
#   * The two-line lookback trades a little strictness for not going red on a
#     reflow: a NEW fd parameter added within two lines of an allow-listed
#     declaration would be accepted. Widening it would trade the other way.
#   * A run that scans zero files, or that cannot read a file it was told to
#     scan, is "cannot run" - never a pass.
#
# Exit status: 0 clean, 1 violation(s) reported, 2 cannot run.
set -euo pipefail

HDR_FD_LOOKBACK=2

# grep with its exit status inspected. `if grep ...; then` folds "no match"
# (1) and "cannot read the file" (>= 2) into the same false, which would
# score an unreadable core source as clean; that is a vacuous pass, so an
# I/O error is fatal instead. Sets GREP_OUT; returns 0 on match, 1 on none.
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
        echo "sansio-gate: cannot scan $file (grep exited $st) - refusing to report clean"
        exit 2
    fi
    return "$st"
}

BUILD_DIR=${1:-build}
LIST="$BUILD_DIR/mqvpn_lib_sources.txt"

# -f before -r: a directory is readable but is not a source list, and an
# unreadable file must not fall through to the redirect below, where `set -e`
# would turn it into a bare rc=1 outside the documented exit contract.
if [ ! -f "$LIST" ]; then
    echo "sansio-gate: source list not found: $LIST (cwd $PWD)"
    echo "sansio-gate: configure the build first, e.g. cmake -S . -B $BUILD_DIR"
    exit 2
fi
if [ ! -r "$LIST" ]; then
    echo "sansio-gate: source list not readable: $LIST"
    exit 2
fi

# Absolutise the list before the cd below, so a relative <build-dir> keeps
# meaning what it meant on the command line no matter where we are invoked
# from.
list_dir=$(cd -- "$(dirname -- "$LIST")" && pwd -P) || {
    echo "sansio-gate: cannot resolve the directory of $LIST"
    exit 2
}
LIST="$list_dir/$(basename -- "$LIST")"

# Which tree to scan. The build dir knows: CMake records the source dir it
# was configured from, and that is the tree whose file list we are holding.
# Deriving it from the caller's cwd instead would scan a different checkout
# than the one the list describes.
CACHE="$list_dir/CMakeCache.txt"
REPO_ROOT=
root_from=
if [ -r "$CACHE" ]; then
    REPO_ROOT=$(sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' "$CACHE" | tail -n 1)
    if [ -n "$REPO_ROOT" ]; then
        root_from="CMAKE_HOME_DIRECTORY in $CACHE"
    fi
fi
# Fallback 1: the caller's repository. Checked rather than interpolated bare -
# unchecked it either aborts with git's own 128 (outside the documented 0/1/2)
# or, wrapped in a `cd`, silently makes the cwd the "repo root".
if [ -z "$REPO_ROOT" ]; then
    REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
    if [ -n "$REPO_ROOT" ]; then
        root_from="git rev-parse --show-toplevel"
    fi
fi
# Fallback 2: scripts/lint/ -> repo root, for an invocation by absolute path
# from outside any checkout.
if [ -z "$REPO_ROOT" ]; then
    REPO_ROOT=$(dirname -- "$(dirname -- "$(dirname -- "$0")")")
    root_from="the location of $0"
fi
REPO_ROOT=$(cd -- "$REPO_ROOT" && pwd -P) || {
    echo "sansio-gate: cannot enter the repository root (from $root_from)"
    exit 2
}
cd "$REPO_ROOT"

HDR=include/libmqvpn.h

# Validate the root before scanning, so a wrong one is one clear line rather
# than a listed-source-missing report per core file.
if [ ! -f "$HDR" ]; then
    echo "sansio-gate: $REPO_ROOT does not look like an mqvpn checkout ($HDR missing)"
    echo "sansio-gate: root came from $root_from"
    exit 2
fi

echo "sansio-gate: scanning $REPO_ROOT (root from $root_from)"
echo "sansio-gate: source list $LIST"

PATTERNS='\b(sendto|sendmsg|sendmmsg|recvfrom|recvmsg|recvmmsg|setsockopt|getsockopt|socket|close)\(|\bSOCKET\b|\bUDP_SEGMENT\b|\bUDP_GRO\b|#[[:space:]]*include[[:space:]]*["<](udp_offload|bind/posix_offload|mqvpn_bind_posix)\.h[">]'
HDR_FD_ALLOW='egress_fd_register|egress_fd_unregister|mqvpn_server_on_egress_fd_ready|mqvpn_client_set_tun_active'

rc=0
checked=0
excluded=0

# `|| [ -n "$src" ]`: read returns false on a final line with no terminating
# newline, and the body must still run for it - otherwise the last entry of a
# list written without a trailing newline is silently never scanned.
while IFS= read -r src || [ -n "$src" ]; do
    [ -n "$src" ] || continue
    case "$src" in
        *$'\r')
            echo "sansio-gate: stray CR at the end of a list entry (CRLF list?): '${src%$'\r'}'"
            echo "    from $LIST"
            rc=1
            continue
            ;;
    esac
    case "$src" in
        /*) abs=$src ;;
        *) abs="$REPO_ROOT/$src" ;;
    esac
    # Fall back to the unresolved path when realpath is absent or the entry
    # does not exist; the existence check below then reports it.
    abs=$(realpath -- "$abs" 2>/dev/null || printf '%s' "$abs")
    rel=${abs#"$REPO_ROOT"/}
    # Both spellings of every exclusion: `rel` is repo-relative when the
    # strip above succeeded, and still absolute when it could not.
    case "$rel" in
        src/bind/* | */src/bind/* | src/hybrid/tcp_egress.c | */src/hybrid/tcp_egress.c)
            excluded=$((excluded + 1))
            continue
            ;;
    esac
    if [ ! -f "$abs" ]; then
        echo "sansio-gate: listed source is missing: $rel"
        echo "    listed in $LIST as: '$src'"
        rc=1
        continue
    fi
    checked=$((checked + 1))
    if grep_checked "$abs" -nE "$PATTERNS"; then
        echo "sansio-gate: forbidden socket I/O in core file $rel:"
        printf '%s\n' "$GREP_OUT" | sed 's/^/    /'
        rc=1
    fi
done < "$LIST"

# A gate that scanned nothing must not report success.
if [ "$checked" -eq 0 ]; then
    echo "sansio-gate: no core files were scanned - $LIST holds $(wc -l <"$LIST") line(s),"
    echo "sansio-gate: all of them excluded, missing or malformed; re-configure $BUILD_DIR"
    exit 2
fi

if grep_checked "$HDR" -nE '\bSOCKET\b'; then
    echo "sansio-gate: SOCKET token in $HDR:"
    printf '%s\n' "$GREP_OUT" | sed 's/^/    /'
    rc=1
fi

fd_matches=
if grep_checked "$HDR" -nE '\bint (fd|tun_fd)\b'; then
    fd_matches=$GREP_OUT
fi
if [ -n "$fd_matches" ]; then
    # A window per hit rather than `grep | grep -v` over single lines: the
    # allow-listed declarations are wrapped at ColumnLimit, so the function
    # name can sit up to HDR_FD_LOOKBACK lines above its own parameter.
    while IFS= read -r m; do
        ln=${m%%:*}
        start=$((ln > HDR_FD_LOOKBACK ? ln - HDR_FD_LOOKBACK : 1))
        window=$(awk -v a="$start" -v b="$ln" 'NR >= a && NR <= b {printf "%d:%s\n", NR, $0}' "$HDR")
        if [ -z "$window" ]; then
            echo "sansio-gate: cannot read lines $start-$ln of $HDR - refusing to report"
            exit 2
        fi
        if [[ ! $window =~ $HDR_FD_ALLOW ]]; then
            echo "sansio-gate: unexpected fd parameter in $HDR:"
            printf '%s\n' "$window" | sed 's/^/    /'
            echo "    none of these appears in the ${HDR_FD_LOOKBACK}-line window above it:"
            echo "    $HDR_FD_ALLOW"
            rc=1
        fi
    done <<<"$fd_matches"
fi

if [ "$rc" -eq 0 ]; then
    echo "sansio-gate: OK ($checked core files checked, $excluded excluded)"
else
    echo "sansio-gate: FAILED ($checked core files checked, $excluded excluded)"
    echo "sansio-gate: see the report(s) above - the core reaches the network"
    echo "sansio-gate: only through the ABI 3 transport ops, never directly"
fi
exit "$rc"
