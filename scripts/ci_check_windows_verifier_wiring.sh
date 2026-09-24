#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# Weak deletion/ordering tripwire for the Windows certificate verifier wiring.
# The Windows platform layer has no unit harness (client construction lives
# inside the libevent run loop), so this only asserts that a non-comment line
# in platform_windows.c calls mqvpn_config_set_cert_verifier( before the line
# that calls mqvpn_client_new(. It does not check the arguments or the
# conditions around the call — review does.
set -euo pipefail
f="$(dirname "$0")/../src/platform/windows/platform_windows.c"

# First code line containing $1; single-line comments are stripped first
# (both calls sit on code lines). awk reads to EOF: no early-exit reader.
first_line() {
    awk -v pat="$1" '
        { line = $0; sub(/\/\/.*$/, "", line); gsub(/\/\*.*\*\//, "", line) }
        !found && index(line, pat) { found = NR }
        END { if (found) print found }' "$f"
}

install_line=$(first_line "mqvpn_config_set_cert_verifier(")
new_line=$(first_line "mqvpn_client_new(")
echo "set_cert_verifier at line ${install_line:-none}, mqvpn_client_new at line ${new_line:-none}"
if [[ -z "$install_line" || -z "$new_line" ]]; then
    echo "FAIL: call missing"
    exit 1
fi
if ((install_line >= new_line)); then
    echo "FAIL: verifier installed after client creation"
    exit 1
fi
echo "PASS: Windows verifier wiring present and ordered"
