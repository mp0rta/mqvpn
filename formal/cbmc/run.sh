#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# formal/cbmc/run.sh — run the path_on_event conformance harness.
# This flag set is normative; see formal/README.md for what is verified.
#
# Requires cbmc >= 5.95 on PATH (Ubuntu: `apt install cbmc`; without root:
# `apt-get download cbmc minisat && dpkg -x <deb> <dir>` and export
# LD_LIBRARY_PATH=<dir>/usr/lib PATH=<dir>/usr/bin:$PATH).
#
# NDEBUG must NOT be defined: path_invariant_check()'s assert()s are proof
# obligations here (they vanish under NDEBUG, silently gutting the check).

set -eu
cd "$(dirname "$0")/../.."

exec cbmc formal/cbmc/harness_path_on_event.c formal/cbmc/stubs.c \
    src/path_state_machine.c \
    -I src -I include \
    --function harness \
    --bounds-check --pointer-check --signed-overflow-check \
    --undefined-shift-check --div-by-zero-check \
    --unwind 10 --unwinding-assertions \
    "$@"
