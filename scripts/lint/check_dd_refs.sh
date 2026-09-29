#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# scripts/lint/check_dd_refs.sh
#
# Every "DD §<n>" reference in a tracked file must name a section of
# docs/design-decisions.md, whose sections are headed "## §<n> <title>".
# The numbers are positional: inserting or removing a section re-points every
# later reference without any error, so this check makes that loud. It also
# fails on a section number that appears twice.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
dd=docs/design-decisions.md

declare -A have=()
dups=()
while IFS= read -r n; do
    if [[ -n "${have[$n]:-}" ]]; then dups+=("$n"); fi
    have[$n]=1
done < <(sed -nE 's/^## §([0-9]+) .*/\1/p' "$dd")

if [[ ${#have[@]} -eq 0 ]]; then
    echo "check_dd_refs: no '## §<n> ' headings found in $dd" >&2
    exit 1
fi

bad=0
for n in "${dups[@]}"; do
    echo "$dd: section §$n is defined more than once" >&2
    bad=1
done

# git grep exits 1 when nothing matches; a tree without references passes.
refs=$(git grep -nIoE 'DD §[0-9]+' || true)
total=0
while IFS= read -r ref; do
    [[ -z "$ref" ]] && continue
    total=$((total + 1))
    n=${ref##*§}
    if [[ -z "${have[$n]:-}" ]]; then
        echo "${ref%:DD §*}: 'DD §$n' names no section of $dd" >&2
        bad=1
    fi
done <<< "$refs"

if [[ $bad -ne 0 ]]; then
    echo "check_dd_refs: FAIL (sections: $(printf '%s\n' "${!have[@]}" | sort -n | tr '\n' ' '))" >&2
    exit 1
fi
echo "check_dd_refs: OK ($total references, ${#have[@]} sections)"
