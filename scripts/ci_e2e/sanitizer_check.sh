#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# sanitizer_check.sh — Check if a process exited cleanly (no sanitizer errors)
#
# Usage: source sanitizer_check.sh
#        stop_and_check_sanitizer PID "description" [log_file]
#
# Sends SIGTERM, waits, checks exit code. ASan/UBSan cause non-zero exit.
# Exit code 1 = sanitizer error detected.
#
# If log_file is given and the sanitizer trips, the log is dumped to stderr
# so CI output captures the actual ASan/UBSan diagnostic instead of just
# "exited with code 1".

_dump_sanitizer_log() {
    local desc="$1" log_file="$2"
    [ -z "$log_file" ] && return
    [ ! -f "$log_file" ] && return
    echo "--- ${desc} log: ${log_file} (last 200 lines) ---" >&2
    tail -200 "$log_file" >&2
    echo "--- end ${desc} log ---" >&2
}

# Residence-warning postcondition: a path stuck in PENDING (or a retry
# overdue) at the end of ANY e2e test is a recovery bug the test body
# didn't assert on. The library already warns — make CI listen.
# Opt out per-test with MQVPN_E2E_ALLOW_RESIDENCE_WARN=1 (e.g. for a
# future test that deliberately parks a path).
_check_residence_warnings() {
    local desc="$1" log_file="$2"

    if [ -n "$log_file" ] && [ -f "$log_file" ] \
        && [ -z "${MQVPN_E2E_ALLOW_RESIDENCE_WARN:-}" ]; then
        if grep -qE "stuck in PENDING|DEGRADED retry overdue" "$log_file"; then
            echo "RESIDENCE FAIL: $desc log contains a path-residence warning" >&2
            grep -nE "stuck in PENDING|DEGRADED retry overdue" "$log_file" | tail -5 >&2
            return 1
        fi
    fi
    return 0
}

stop_and_check_sanitizer() {
    local pid="$1"
    local desc="${2:-process}"
    local log_file="${3:-}"
    local rc=0

    if [ -z "$pid" ]; then return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then
        # Already dead — check if it died from sanitizer
        wait "$pid" 2>/dev/null
        rc=$?
        if [ $rc -ne 0 ]; then
            echo "SANITIZER FAIL: $desc (PID $pid) exited with code $rc"
            _dump_sanitizer_log "$desc" "$log_file"
            return 1
        fi
        _check_residence_warnings "$desc" "$log_file" || return 1
        return 0
    fi

    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null
    rc=$?

    # SIGTERM causes exit code 143 (128+15) which is normal
    if [ $rc -ne 0 ] && [ $rc -ne 143 ]; then
        echo "SANITIZER FAIL: $desc (PID $pid) exited with code $rc"
        _dump_sanitizer_log "$desc" "$log_file"
        return 1
    fi
    _check_residence_warnings "$desc" "$log_file" || return 1
    return 0
}
