#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# formal/cbmc/run.sh — prove the path_on_event harnesses (formal/README.md).
# This flag set is normative. Extra arguments are passed to every cbmc run;
# one that skips the verification (--show-properties, say) fails the run.
#
# Needs cbmc on PATH. Tested with cbmc 5.95.1, Ubuntu 24.04's package, which
# CI installs (`apt install cbmc`; without root: `apt-get download cbmc
# minisat && dpkg -x <deb> <dir>` and export LD_LIBRARY_PATH=<dir>/usr/lib
# PATH=<dir>/usr/bin:$PATH). CBMC 6 enables more checks by default, so its
# property count differs.
#
# NDEBUG must NOT be defined: it removes every assert(), those of
# path_invariant_check() and the harnesses' own, and they are the proof
# obligations here.
# The unwind bound covers the longest loop, the PRE_SET membership scan
# (PATH_SLOT_ORACLE_N_PRE iterations, 196 today); --unwinding-assertions
# proves it is enough. When the table grows, raise --unwind above
# PATH_SLOT_ORACLE_N_PRE.

set -eu
cd "$(dirname "$0")/../.."

SRC="formal/cbmc/harness_path_on_event.c src/path_state_machine.c"
INC="-I src -I include -I formal/oracle"

LOGS=$(mktemp -d)
trap 'rm -rf "$LOGS"' EXIT
# dash runs the EXIT trap on exit, not on a fatal signal.
trap 'exit 130' INT
trap 'exit 143' TERM

# Canary: the invariant's assertions are among the properties. An NDEBUG
# slipped into the flags would remove every assert(), the harnesses' own
# included, and the runs below would still verify "successfully". CBMC
# reports errors on stderr, left visible here; the property list (stdout) is
# only counted.
rc=0
# shellcheck disable=SC2086
cbmc $SRC $INC --function harness --show-properties "$@" \
    >"$LOGS/properties.log" || rc=$?
if [ "$rc" -ne 0 ]; then
    echo "run.sh: cbmc --show-properties exited with $rc" >&2
    exit "$rc"
fi
n=$(grep -c 'path_invariant_check\.assertion' "$LOGS/properties.log" || true)
if [ "$n" -eq 0 ]; then
    echo "run.sh: no path_invariant_check assertion among the properties" >&2
    exit 1
fi
echo "run.sh: $n path_invariant_check assertions are proof obligations"

# A called function without a body fails the run. CBMC only warns (on
# stderr), treats the call as returning an arbitrary value with no other
# effect and can still verify "successfully", so an accessor
# path_state_machine.c starts calling that the harness does not stub would
# go unnoticed.
for fn in harness harness_null_ctx; do
    echo "== cbmc --function $fn"
    log=$LOGS/$fn.log
    rc=0
    # shellcheck disable=SC2086
    cbmc $SRC $INC \
        --function "$fn" \
        --bounds-check --pointer-check --signed-overflow-check \
        --undefined-shift-check --div-by-zero-check \
        --unwind 200 --unwinding-assertions \
        "$@" >"$log" 2>&1 || rc=$?
    cat "$log"
    if grep 'no body for function' "$log" >&2; then
        echo "run.sh: cbmc --function $fn called a function without a body" \
            "(cbmc exited with $rc): stub it in" \
            "formal/cbmc/harness_path_on_event.c" >&2
        exit 1
    fi
    if [ "$rc" -ne 0 ]; then
        echo "run.sh: cbmc --function $fn exited with $rc" >&2
        exit "$rc"
    fi
    # An option that only inspects the program (--show-properties, say)
    # makes cbmc exit 0 without proving anything.
    if ! grep -qx 'VERIFICATION SUCCESSFUL' "$log"; then
        echo "run.sh: cbmc --function $fn did not report VERIFICATION" \
            "SUCCESSFUL (an option that skips verification?)" >&2
        exit 1
    fi
done
