#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# formal/cbmc/run.sh — prove the path_on_event harnesses (formal/README.md).
# This flag set is normative. The only extra argument it accepts is --trace
# (a counterexample trace for a failed property), passed to every cbmc run.
# For any other cbmc option, run cbmc directly with the command lines below.
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

# Only --trace passes: any other option could select or weaken the proof
# obligations (--property, --unwind, --no-*-check, ...) and still end in
# VERIFICATION SUCCESSFUL.
for arg in "$@"; do
    case $arg in
    --trace) ;;
    *)
        echo "run.sh: unsupported argument '$arg': run.sh runs the normative" \
            "proof and accepts only --trace; call cbmc directly for other" \
            "options" >&2
        exit 2
        ;;
    esac
done

LOGS=$(mktemp -d)
trap 'rm -rf "$LOGS"' EXIT
# dash runs the EXIT trap on exit, not on a fatal signal.
trap 'exit 130' INT
trap 'exit 143' TERM

# Canary: the invariant's assertions are among the properties. With the
# arguments restricted to --trace, NDEBUG can reach the cbmc command line
# only through this script's own flags, and the canary guards against that:
# NDEBUG would remove every assert(), the harnesses' own included, and the
# runs below would still verify "successfully". CBMC reports errors on
# stderr, left visible here; the property list (stdout) is only counted.
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
    # cbmc can exit 0 without a verdict (an option that only inspects the
    # program, such as --show-properties, does): require the verdict line.
    if ! grep -qx 'VERIFICATION SUCCESSFUL' "$log"; then
        echo "run.sh: cbmc --function $fn exited 0 without reporting" \
            "VERIFICATION SUCCESSFUL" >&2
        exit 1
    fi
done
