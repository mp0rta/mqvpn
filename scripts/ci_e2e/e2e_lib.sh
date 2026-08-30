#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# e2e_lib.sh — shared helpers for the netns e2e drivers. Sourced (not
# executed): `source "$(dirname "$0")/e2e_lib.sh"` — same idiom as
# sanitizer_check.sh.
#
# Consumers are the ci_e2e drivers whose wait helpers were byte-identical
# copies (one pair had already drifted cosmetically before extraction).
# Deliberate NON-consumers, left with their local definitions:
#   - run_dellink_test.sh: case-insensitive grep (-qiE) variant;
#   - tests/test_e2e_*.sh: different default timeouts (40s/10s) and, in
#     test_e2e_dellink.sh, a different signature (global $CLIENT_LOG).
# Fold those in only by preserving their exact semantics.

# wait_for_log <log_file> <extended-regex> [timeout_sec=15]
# Polls once per second until the pattern appears anywhere in the file.
# Returns 0 on match, 1 on timeout.
wait_for_log() {
    local log_file="$1" pattern="$2" timeout="${3:-15}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if grep -qE "$pattern" "$log_file" 2>/dev/null; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# wait_for_log_after <log_file> <extended-regex> <start_line> [timeout_sec=15]
# Like wait_for_log, but only matches in lines AFTER line number
# <start_line> — for asserting that an event re-occurs after a marker
# (e.g. a second re-add after a second flap) rather than matching the
# first occurrence again.
# G19 note: `tail | grep -q` is safe here because no consumer runs under
# `set -o pipefail` (they use set -e/-eu); under pipefail an early-exiting
# grep can SIGPIPE the writer and turn a match into a spurious timeout —
# if a pipefail script ever adopts this lib, rework the pipe first.
wait_for_log_after() {
    local log_file="$1" pattern="$2" start_line="$3" timeout="${4:-15}"
    local elapsed=0
    while [ "$elapsed" -lt "$timeout" ]; do
        if tail -n "+$((start_line + 1))" "$log_file" 2>/dev/null \
                | grep -qE "$pattern"; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}
