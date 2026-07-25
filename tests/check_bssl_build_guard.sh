#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# scripts/bssl_build_guard.sh behaviour, including the case that broke the
# Android reproducible-build gate: the guard reads the pin with `git rev-parse`
# and every consumer runs under `set -e`, so a source tree WITHOUT git metadata
# (release tarball, or android-repro.yml's `tar --exclude=.git` copies) aborted
# the whole build with "fatal: not a git repository".
#
# Uses throwaway git repos in a temp dir — no submodules, no network, no
# BoringSSL build. Runs the functions the way the consumers do, i.e. under
# `set -e`, because "returns nonzero" and "aborts the build" are the same thing
# there and only the second one is observable to a user.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/bssl_build_guard.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0

note() { printf '  %s\n' "$1"; }
ok() { printf 'PASS: %s\n' "$1"; }
bad() {
    printf 'FAIL: %s\n' "$1"
    fail=1
}

# A git repo with one commit; echoes its path.
make_repo() {
    local d="$WORK/$1"
    mkdir -p "$d"
    git -C "$d" init -q
    git -C "$d" -c user.email=t@t -c user.name=t commit -q --allow-empty -m x
    echo "$d"
}

# Run a guard call exactly as a consumer does: sourced, under `set -e`.
# Echoes the exit status; stderr/stdout go to $WORK/out.
run_guarded() {
    (
        set -euo pipefail
        # shellcheck source=/dev/null
        source "$GUARD"
        "$@"
    ) > "$WORK/out" 2>&1
    echo $?
}

# ── 1. no git metadata: must not abort, must not leave a bogus stamp ───────
src="$WORK/nogit-src"
bdir="$WORK/nogit-build"
mkdir -p "$src" "$bdir"
touch "$bdir/libssl.a"

rc="$(run_guarded bssl_guard_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ]; then
    bad "guard aborts on a tree without git metadata (rc=$rc)"
    sed 's/^/      /' "$WORK/out"
elif [ -d "$bdir" ]; then
    bad "guard left an unattributable build dir in place"
else
    ok "guard wipes an unattributable build dir instead of aborting"
fi

mkdir -p "$bdir"
rc="$(run_guarded bssl_stamp_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ]; then
    bad "stamp aborts on a tree without git metadata (rc=$rc)"
    sed 's/^/      /' "$WORK/out"
elif [ -e "$bdir/.mqvpn-boringssl-commit" ]; then
    bad "stamp wrote a stamp it cannot attribute (an empty stamp reads as a real one)"
else
    ok "stamp records nothing when the pin is undeterminable"
fi

rc="$(run_guarded bssl_verify_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ]; then
    bad "verify aborts on a tree without git metadata (rc=$rc)"
    sed 's/^/      /' "$WORK/out"
elif ! grep -q "WARNING" "$WORK/out"; then
    bad "verify skipped silently; the skip must be visible in the build log"
else
    ok "verify skips (loudly) when the pin is undeterminable"
fi

# ── 2. real repo: the provenance contract itself still holds ──────────────
src="$(make_repo repo)"
bdir="$WORK/repo-build"
mkdir -p "$bdir"
touch "$bdir/libssl.a"

run_guarded bssl_stamp_build_dir "$src" "$bdir" > /dev/null
pin="$(git -C "$src" rev-parse HEAD)"
if [ "$(cat "$bdir/.mqvpn-boringssl-commit")" != "$pin" ]; then
    bad "stamp did not record the pin"
else
    ok "stamp records the pin"
fi

rc="$(run_guarded bssl_guard_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ] || [ ! -f "$bdir/libssl.a" ]; then
    bad "guard wiped a build dir whose stamp matches the pin (rc=$rc)"
else
    ok "guard keeps a build dir whose stamp matches the pin"
fi

rc="$(run_guarded bssl_verify_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ]; then
    bad "verify rejected a matching stamp (rc=$rc)"
else
    ok "verify accepts a matching stamp"
fi

# Pin bump → the dir must go.
git -C "$src" -c user.email=t@t -c user.name=t commit -q --allow-empty -m y
rc="$(run_guarded bssl_guard_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ]; then
    bad "guard aborted on a pin bump instead of wiping (rc=$rc)"
elif [ -d "$bdir" ]; then
    bad "guard kept a build dir built from the previous pin"
else
    ok "guard wipes a build dir built from the previous pin"
fi

# Consume-only path: no rebuild available, so a mismatch must fail loudly.
mkdir -p "$bdir"
echo "0000000000000000000000000000000000000000" > "$bdir/.mqvpn-boringssl-commit"
rc="$(run_guarded bssl_verify_build_dir "$src" "$bdir")"
if [ "$rc" -eq 0 ]; then
    bad "verify accepted a stamp from another revision"
elif ! grep -q "ERROR" "$WORK/out"; then
    bad "verify failed without saying why"
else
    ok "verify rejects a stamp from another revision"
fi

# Unstamped dir (pre-stamp build): unknown provenance, treated as stale.
rm -f "$bdir/.mqvpn-boringssl-commit"
rc="$(run_guarded bssl_guard_build_dir "$src" "$bdir")"
if [ "$rc" -ne 0 ] || [ -d "$bdir" ]; then
    bad "guard did not wipe an unstamped build dir (rc=$rc)"
else
    ok "guard wipes an unstamped build dir"
fi

if [ "$fail" -ne 0 ]; then
    echo "RESULT: FAIL"
    exit 1
fi
echo "RESULT: PASS"
