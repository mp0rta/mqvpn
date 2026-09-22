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
#         mqvpn_bind_posix.h) - the core is bind-agnostic
#     Exclusions, these two and no others:
#       src/bind/*                the bundled transport implementations
#       src/hybrid/tcp_egress.c   the server egress lane owns its TCP sockets
#                                 (out of scope by design; see AGENTS.md)
#     The other hybrid files are NOT excluded, so a regression there is caught.
#     A listed source that does not exist is itself a failure: the list has to
#     describe the tree it is scanned against.
#
#  2. Public header - include/libmqvpn.h must not contain the token SOCKET,
#     and no `int fd` / `int tun_fd` parameter except on a line that also
#     names egress_fd_register, egress_fd_unregister,
#     mqvpn_server_on_egress_fd_ready or mqvpn_client_set_tun_active. The
#     first three are the hybrid egress API (out of scope); tun_fd is a
#     platform-owned TUN descriptor the core discards. The allow-list is
#     line-scoped on purpose: a new fd parameter - or a reflow that separates
#     one from its function name - makes a human look.
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
#   * A run that scans zero files is "cannot run", never a pass.
#
# Exit status: 0 clean, 1 violation(s) reported, 2 cannot run.
set -euo pipefail

BUILD_DIR=${1:-build}
LIST="$BUILD_DIR/mqvpn_lib_sources.txt"

if [ ! -f "$LIST" ]; then
    echo "sansio-gate: source list not found: $LIST (cwd $PWD)"
    echo "sansio-gate: configure the build first, e.g. cmake -S . -B $BUILD_DIR"
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

# pwd -P on both sides, and realpath on each entry below: the generated list
# mixes relative entries (from set()) with absolute ones (from
# list(APPEND ${CMAKE_SOURCE_DIR}/...)), and a checkout reached through a
# symlink spells ${CMAKE_SOURCE_DIR} differently from
# `git rev-parse --show-toplevel`. Without the normalisation the prefix strip
# below would leave those entries absolute and the exclusions would silently
# not apply.
#
# The git query is checked rather than interpolated bare: it fails when the
# gate is invoked by absolute path from outside the checkout, and `cd ""` is
# a silent no-op that would make the cwd the "repo root". Fall back to the
# script's own location (scripts/lint/ -> root) in that case.
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [ -z "$REPO_ROOT" ]; then
    REPO_ROOT=$(dirname -- "$(dirname -- "$(dirname -- "$0")")")
fi
REPO_ROOT=$(cd -- "$REPO_ROOT" && pwd -P) || {
    echo "sansio-gate: cannot enter the repository root"
    exit 2
}
cd "$REPO_ROOT"

HDR=include/libmqvpn.h

# Validate the root before scanning, so a wrong one is one clear line rather
# than a listed-source-missing report per core file.
if [ ! -f "$HDR" ]; then
    echo "sansio-gate: $REPO_ROOT does not look like an mqvpn checkout ($HDR missing)"
    exit 2
fi

PATTERNS='\b(sendto|sendmsg|sendmmsg|recvfrom|recvmsg|recvmmsg|setsockopt|getsockopt|socket|close)\(|\bSOCKET\b|\bUDP_SEGMENT\b|\bUDP_GRO\b|#[[:space:]]*include[[:space:]]*"(udp_offload|bind/posix_offload|mqvpn_bind_posix)\.h"'
HDR_FD_ALLOW='egress_fd_register|egress_fd_unregister|mqvpn_server_on_egress_fd_ready|mqvpn_client_set_tun_active'

rc=0
checked=0
excluded=0

while IFS= read -r src; do
    [ -n "$src" ] || continue
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
        echo "    listed in $LIST as: $src"
        rc=1
        continue
    fi
    checked=$((checked + 1))
    if hits=$(grep -nE "$PATTERNS" "$abs"); then
        echo "sansio-gate: forbidden socket I/O in core file $rel:"
        printf '%s\n' "$hits" | sed 's/^/    /'
        rc=1
    fi
done < "$LIST"

# A gate that scanned nothing must not report success.
if [ "$checked" -eq 0 ]; then
    echo "sansio-gate: no core files were scanned - $LIST holds $(wc -l <"$LIST") line(s),"
    echo "sansio-gate: all of them excluded or missing; re-configure $BUILD_DIR"
    exit 2
fi

if hdr_hits=$(grep -nE '\bSOCKET\b' "$HDR"); then
    echo "sansio-gate: SOCKET token in $HDR:"
    printf '%s\n' "$hdr_hits" | sed 's/^/    /'
    rc=1
fi

# Two steps with a here-string rather than `grep | grep -v`: under pipefail a
# second grep that filters every line out is indistinguishable from a first
# grep that found nothing, and the unfiltered hits would be lost from the
# report.
fd_hits=$(grep -nE '\bint (fd|tun_fd)\b' "$HDR" || true)
if [ -n "$fd_hits" ]; then
    fd_hits=$(grep -vE "$HDR_FD_ALLOW" <<<"$fd_hits" || true)
fi
if [ -n "$fd_hits" ]; then
    echo "sansio-gate: unexpected fd parameter in $HDR"
    echo "    allow-listed on the same line only: $HDR_FD_ALLOW"
    printf '%s\n' "$fd_hits" | sed 's/^/    /'
    rc=1
fi

if [ "$rc" -eq 0 ]; then
    echo "sansio-gate: OK ($checked core files checked, $excluded excluded)"
else
    echo "sansio-gate: FAILED ($checked core files checked, $excluded excluded)"
    echo "sansio-gate: see the report(s) above - the core reaches the network"
    echo "sansio-gate: only through the ABI 3 transport ops, never directly"
fi
exit "$rc"
