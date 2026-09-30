#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# formal/cbmc/run.sh — prove the path_on_event harnesses (formal/README.md).
# This flag set is normative. Extra arguments are passed to every cbmc run.
#
# Requires cbmc >= 5.95 on PATH (Ubuntu: `apt install cbmc`; without root:
# `apt-get download cbmc minisat && dpkg -x <deb> <dir>` and export
# LD_LIBRARY_PATH=<dir>/usr/lib PATH=<dir>/usr/bin:$PATH).
#
# NDEBUG must NOT be defined: path_invariant_check()'s assert()s are proof
# obligations here (they vanish under NDEBUG, silently gutting the check).
# The unwind bound covers the longest loop, the PRE_SET membership scan
# (PATH_SLOT_ORACLE_N_PRE iterations); --unwinding-assertions proves it is
# enough.

set -eu
cd "$(dirname "$0")/../.."

SRC="formal/cbmc/harness_path_on_event.c src/path_state_machine.c"
INC="-I src -I include -I formal/oracle"

# Canary: the invariant's assertions are among the properties (an NDEBUG
# slipped into the flags would remove them and still verify "successfully").
# shellcheck disable=SC2086
n=$(cbmc $SRC $INC --function harness --show-properties "$@" 2>/dev/null |
    grep -c 'path_invariant_check\.assertion' || true)
if [ "$n" -eq 0 ]; then
    echo "run.sh: no path_invariant_check assertion among the properties" >&2
    exit 1
fi
echo "run.sh: $n path_invariant_check assertions are proof obligations"

for fn in harness harness_null_ctx; do
    echo "== cbmc --function $fn"
    # shellcheck disable=SC2086
    cbmc $SRC $INC \
        --function "$fn" \
        --bounds-check --pointer-check --signed-overflow-check \
        --undefined-shift-check --div-by-zero-check \
        --unwind 200 --unwinding-assertions \
        "$@"
done
