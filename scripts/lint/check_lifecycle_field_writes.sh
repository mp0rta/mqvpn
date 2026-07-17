#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# scripts/lint/check_lifecycle_field_writes.sh
#
# Enforce spec §3.3 / §7.1: direct assignment to path_entry_t lifecycle
# fields is only allowed inside src/path_state_machine.c (path_on_event
# body + helpers) and at lines tagged with a trailing /* LINT-ALLOW */
# comment.
#
# Fields (spec §3.3, also see path_entry_internal.h):
#   state | platform_attached | xquic_path_live | xqc_path_id
#   recreate_after_us | recreate_retries | path_stable_since_us
#
# Pointer-name anchor (avoids `c->state` collision with mqvpn_client_t
# connection state):
#   p | pp | entry | path | primary
#
# Rollout:
#   LINT_MODE=warning (default) - exit 0 with stderr report
#   LINT_MODE=fail              - exit 1 on any violation
#
set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)
LINT_MODE=${LINT_MODE:-warning}

FIELDS='state|platform_attached|xquic_path_live|xqc_path_id|recreate_after_us|recreate_retries|path_stable_since_us'
POINTERS='p|pp|entry|path|primary'
# Match `PTR->FIELD <optional ws> = <NOT another =>` - rejects `==` comparisons.
PATTERN="($POINTERS)->($FIELDS)[[:space:]]*=[^=]"

# Files / scopes exempt because they use a different struct (mqvpn_path_t
# in path_mgr / platform layers, xqc_path_metrics_t in server) or are the
# FSM module itself.
EXCLUDED_FILES='
src/path_state_machine.c
src/path_entry_internal.h
src/path_mgr.c
src/path_mgr.h
src/mqvpn_server.c
src/platform/linux/platform_linux.c
src/platform/linux/netlink_mon.c
src/platform/windows/platform_windows.c
src/platform/windows/net_mon.c
src/platform/darwin/platform_darwin.c
src/platform/darwin/route_mon.c
'

cd "$REPO_ROOT"

# Build the list of candidate files via `git ls-files`. Need BOTH top-level
# (`src/*.c`) AND subtree (`src/**/*.c`) globs - git ls-files does not
# expand `**` to match the parent directory itself.
files=$(git ls-files \
        'src/*.c' 'src/*.h' 'src/**/*.c' 'src/**/*.h' \
        'tests/*.c' 'tests/*.h' 'tests/**/*.c' 'tests/**/*.h' \
        | grep -vxF -f <(printf '%s\n' $EXCLUDED_FILES))

violations=$(printf '%s\n' "$files" \
    | xargs -r grep -nHE "$PATTERN" 2>/dev/null \
    | grep -vF "LINT-ALLOW" \
    || true)

if [ -z "$violations" ]; then
    echo "lint: check_lifecycle_field_writes: clean"
    exit 0
fi

echo "lint: check_lifecycle_field_writes - violation(s):"
printf '%s\n' "$violations" | sed 's/^/  /'

if [ "$LINT_MODE" = "fail" ]; then
    exit 1
fi
echo "lint: warning mode (LINT_MODE=warning), not failing build"
exit 0
