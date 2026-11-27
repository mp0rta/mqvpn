#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# scripts/lint/check_config_docs.sh
#
# Every key in the config descriptor table (src/config.c) must appear in both
# configuration pages of the website: the INI name as `Name` or in an
# `Name = ...` example line, the JSON name as `name` or "name".
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
pages=(website/guide/configuration.md website/ja/guide/configuration.md)
# Deprecated JSON-only spelling, kept working but no longer documented.
skip_json=" server_auth_key "

table=$(sed -n '/^static const cfg_key_desc_t cfg_keys\[\] = {/,/^};/p' src/config.c | tr '\n' ' ')
rows=$(grep -oE '(CFG_[A-Z0-9_]+\(|\{)SEC_[A-Z]+, *("[A-Za-z0-9]+"|NULL), *("[a-z0-9_]+"|NULL)' \
    <<<"$table" || true)
if [[ -z "$rows" ]]; then
    echo "check_config_docs: no rows found in the src/config.c descriptor table" >&2
    exit 1
fi

bad=0
while IFS= read -r row; do
    ini=$(sed -E 's/.*SEC_[A-Z]+, *("([A-Za-z0-9]+)"|NULL).*/\2/' <<<"$row")
    json=$(sed -E 's/.*, *("([a-z0-9_]+)"|NULL)$/\2/' <<<"$row")
    for page in "${pages[@]}"; do
        if [[ -n "$ini" ]] && ! grep -qF "\`$ini\`" "$page" &&
            ! grep -qE "^[[:space:]]*${ini}[[:space:]]*=" "$page"; then
            echo "$page: INI key $ini is not documented" >&2
            bad=1
        fi
        if [[ -n "$json" && "$skip_json" != *" $json "* ]] &&
            ! grep -qF "\`$json\`" "$page" && ! grep -qF "\"$json\"" "$page"; then
            echo "$page: JSON key $json is not documented" >&2
            bad=1
        fi
    done
done <<<"$rows"

if [[ $bad -ne 0 ]]; then
    echo "check_config_docs: document the keys above (see CONTRIBUTING.md, adding a config key)" >&2
    exit 1
fi
echo "check_config_docs: OK ($(wc -l <<<"$rows") keys)"
