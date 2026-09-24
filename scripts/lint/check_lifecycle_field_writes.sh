#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# scripts/lint/check_lifecycle_field_writes.sh
#
# Two checks guard the path_entry_t lifecycle fields; both always run.
#
# Check 1 - field writes.
# Enforce spec §3.3 / §7.1: direct assignment to path_entry_t lifecycle
# fields is only allowed inside src/path_state_machine.c (path_on_event
# body + helpers) and at lines tagged with a trailing /* LINT-ALLOW */
# comment.
#
# Fields (spec §3.3, also see path_entry_internal.h):
#   state | transport_attached | transport_released | xquic_path_live
#   xqc_path_id | recreate_after_us | recreate_retries | path_stable_since_us
#
# Pointer-name anchor (avoids `c->state` collision with mqvpn_client_t
# connection state):
#   p | pp | entry | path | primary
#
# Check 2 - include policy.
# path_entry_t is defined only in src/path_entry_internal.h, and
# src/path_state_machine.h includes that header, re-exporting it. A file
# that cannot see path_entry_t cannot write its fields under any pointer
# name, so only these files may #include the two headers directly
# (INCLUDE_ALLOWLIST below):
#   path_entry_internal.h  src/mqvpn_client.c, src/path_state_machine.h,
#                          tests/test_path_state_machine.c
#   path_state_machine.h   src/mqvpn_client.c, src/path_state_machine.c,
#                          tests/test_path_state_machine.c
# Every file the table names is guarded the same way, by basename, and may
# be #included only where the table allows it. So #including any of those
# .c files as a translation unit, which would smuggle the definition in, is
# allowed nowhere, and a header added as an includer needs rows of its own.
# An allowlist entry that is not a tracked file is itself a violation: the
# allowlist has to describe the tree. So is a guarded basename that no
# tracked file bears, or renaming a guarded file would switch its guard off
# without a word.
#
# Scanned: every tracked *.c *.h *.cc *.cpp *.m *.mm file. An include is a
# line starting with #include, #include_next or #import (blanks allowed
# around the `#`) that names a guarded basename in "..." or <...>, with or
# without a directory prefix such as ../src/. A comment line such as
# ` * #include "x.h"` does not start with `#`, so it is not one. The check
# is line-based, not a preprocessor: an include spelled through a macro, a
# compiler -include flag, a copied struct definition, a backslash-separated
# path ("..\src\path_entry_internal.h") or a case-variant spelling - the
# last two compile only on Windows or a case-insensitive filesystem - gets
# past it, and an include line inside #if 0 or a block comment still
# counts.
#
# Rollout (the combined result of both checks):
#   LINT_MODE=warning (default) - exit 0 with the report on stdout
#   LINT_MODE=fail              - exit 1 on any violation of either check
#
set -eu

REPO_ROOT=$(git rev-parse --show-toplevel)
LINT_MODE=${LINT_MODE:-warning}

FIELDS='state|transport_attached|transport_released|xquic_path_live|xqc_path_id|recreate_after_us|recreate_retries|path_stable_since_us'
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
src/platform/windows/platform_windows.c
src/platform/windows/net_mon.c
src/platform/darwin/platform_darwin.c
src/platform/posix/netmon_common.c
'

# Check 2: a guarded header, then one file allowed to #include it directly,
# per line. This table is the only source: every file it names is guarded,
# by basename (column 1 is only ever read as a basename, however it is
# written), so the .c files (never listed first) may be #included nowhere.
INCLUDE_ALLOWLIST='
path_entry_internal.h src/mqvpn_client.c
path_entry_internal.h src/path_state_machine.h
path_entry_internal.h tests/test_path_state_machine.c
path_state_machine.h src/mqvpn_client.c
path_state_machine.h src/path_state_machine.c
path_state_machine.h tests/test_path_state_machine.c
'
# Every basename the table names, once each; then as one ERE alternation,
# dots escaped.
GUARDED_NAMES=$(awk '{ for (i = 1; i <= NF; i++) { n = split($i, part, "/"); print part[n] } }' \
    <<<"$INCLUDE_ALLOWLIST" | sort -u)
GUARDED=$(awk '{ gsub(/\./, "\\."); print }' <<<"$GUARDED_NAMES" | paste -s -d '|' -)
INCLUDE_PATTERN="^[[:space:]]*#[[:space:]]*(include|include_next|import)[[:space:]]*[\"<]([^\">]*/)?($GUARDED)[\">]"

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

# Check 2. -o prints just the matched `#include "dir/name"`, so the guarded
# basename is what follows the last /, " or < once the closing delimiter is
# dropped. The allowed list a report prints is the list the file is checked
# against; column 1 is compared by basename, as GUARDED reads it.
include_violations=
hits=$(git ls-files -z '*.c' '*.h' '*.cc' '*.cpp' '*.m' '*.mm' \
    | xargs -0 -r grep -nHoE "$INCLUDE_PATTERN" \
    || true)
while IFS=: read -r file line inc; do
    [ -n "$file" ] || continue
    inc=${inc%?}
    guarded=${inc##*[/\"<]}
    allowed=$(awk -v g="$guarded" '
        { n = split($1, part, "/") }
        part[n] == g { printf "%s%s", sep, $2; sep = ", " }' <<<"$INCLUDE_ALLOWLIST")
    case ", $allowed, " in
        *", $file, "*) continue ;;
    esac
    include_violations+="$file:$line: #includes $guarded; allowed only in: ${allowed:-nowhere}"$'\n'
done <<<"$hits"

tracked=$(git ls-files)
while read -r guarded file; do
    [ -n "$guarded" ] || continue
    if ! grep -qxF -- "$file" <<<"$tracked"; then
        include_violations+="allowlist entry $file for $guarded is not a tracked file"$'\n'
    fi
done <<<"$INCLUDE_ALLOWLIST"

# A guarded basename must still be borne by a tracked file, or renaming a
# guarded file would switch its guard off silently.
tracked_names=$(awk -F/ '{ print $NF }' <<<"$tracked")
while read -r name; do
    [ -n "$name" ] || continue
    if ! grep -qxF -- "$name" <<<"$tracked_names"; then
        include_violations+="guarded file $name is not the basename of any tracked file"$'\n'
    fi
done <<<"$GUARDED_NAMES"

if [ -z "$violations" ] && [ -z "$include_violations" ]; then
    echo "lint: check_lifecycle_field_writes: clean"
    exit 0
fi

if [ -n "$violations" ]; then
    echo "lint: check_lifecycle_field_writes - violation(s):"
    printf '%s\n' "$violations" | sed 's/^/  /'
fi
if [ -n "$include_violations" ]; then
    echo "lint: check_lifecycle_field_writes - include-policy violation(s):"
    printf '%s' "$include_violations" | sed 's/^/  /'
fi

if [ "$LINT_MODE" = "fail" ]; then
    exit 1
fi
echo "lint: warning mode (LINT_MODE=warning), not failing build"
exit 0
