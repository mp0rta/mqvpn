#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# formal/run_tlc.sh — check the TLA+ models and regenerate the transition
# oracle (formal/README.md).
#
#   formal/run_tlc.sh sany     parse and check every module
#   formal/run_tlc.sh safety   MqvpnPathSlot.cfg (invariants, action properties)
#   formal/run_tlc.sh live     MqvpnPathSlot_live.cfg (liveness under fairness)
#   formal/run_tlc.sh oracle   regenerate formal/oracle/path_slot_oracle.inc
#   formal/run_tlc.sh all      all of the above (the default)
#
# Needs Java 11+, python3 and TLA2TOOLS_JAR = the tla2tools.jar of the
# tlaplus v1.7.4 release (TLC 2.19); the hash is checked because the oracle
# is generated from TLC's state dump, whose format is not a stable interface.

set -eu

JAR=${TLA2TOOLS_JAR:?set TLA2TOOLS_JAR to the tla2tools.jar of tlaplus v1.7.4}
case $JAR in
/*) ;;
*) JAR=$PWD/$JAR ;;
esac
cd "$(dirname "$0")"
JAR_SHA256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
actual=$(sha256sum "$JAR" | cut -d' ' -f1)
if [ "$actual" != "$JAR_SHA256" ]; then
    echo "run_tlc.sh: $JAR is not tlaplus v1.7.4 (sha256 $actual)" >&2
    exit 1
fi

META=$(mktemp -d)
trap 'rm -rf "$META"' EXIT
# dash runs the EXIT trap on exit, not on a fatal signal.
trap 'exit 130' INT
trap 'exit 143' TERM

# A TLC warning fails the run: TLC only warns, and exits 0, when an EXCEPT
# names a field the record does not have (a misspelt field), leaving the
# record unchanged.
tlc() {
    name=$1
    shift
    log=$META/$name.log
    rc=0
    java -XX:+UseParallelGC -DTLA-Library="$PWD" -cp "$JAR" tlc2.TLC \
        -deadlock -metadir "$META/$name" "$@" >"$log" 2>&1 || rc=$?
    cat "$log"
    if [ "$rc" -ne 0 ]; then
        echo "run_tlc.sh: TLC ($name) exited with $rc" >&2
        exit "$rc"
    fi
    if grep '^Warning:' "$log" >&2; then
        echo "run_tlc.sh: TLC ($name) printed warnings" >&2
        exit 1
    fi
}

# SANY exits 0 on semantic errors (only a parse error is non-zero), so its
# report is checked too.
sany() {
    out=$(java -DTLA-Library="$PWD" -cp "$JAR" tla2sany.SANY \
        PathSlotFsm.tla MqvpnPathSlot.tla oracle/PathSlotOracle.tla) || {
        echo "$out"
        exit 1
    }
    echo "$out"
    case $out in
    *"Semantic errors:"* | *"*** Errors:"*)
        echo "run_tlc.sh: SANY reported errors" >&2
        exit 1
        ;;
    esac
}

safety() {
    tlc safety -workers auto -config MqvpnPathSlot.cfg MqvpnPathSlot.tla
}

live() {
    tlc live -workers auto -config MqvpnPathSlot_live.cfg MqvpnPathSlot.tla
}

# The table does not depend on the dump's order (the generator sorts the
# rows); one worker keeps that order the same from run to run, so two dumps
# can be diffed when debugging the generator.
oracle() {
    tlc oracle -workers 1 -dump "$META/oracle" \
        -config oracle/PathSlotOracle.cfg oracle/PathSlotOracle.tla
    python3 oracle/gen_oracle.py "$META/oracle.dump" oracle/path_slot_oracle.inc
    echo "run_tlc.sh: wrote formal/oracle/path_slot_oracle.inc"
}

case ${1:-all} in
sany) sany ;;
safety) safety ;;
live) live ;;
oracle) oracle ;;
all)
    sany
    safety
    live
    oracle
    ;;
*)
    echo "usage: $0 [sany|safety|live|oracle|all]" >&2
    exit 2
    ;;
esac
