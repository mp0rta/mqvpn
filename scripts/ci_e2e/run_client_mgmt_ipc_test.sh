#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# scripts/ci_e2e/run_client_mgmt_ipc_test.sh [build-dir]      (default: build)
#
# Client management IPC integration test: mqvpnctl and a raw line client
# against mgmt_endpoint_host. No root, no netns, no VPN; runs on Linux, macOS
# and Windows (Git Bash). Every case prints PASS / FAIL / SKIP; the exit status
# is non-zero iff a case failed.
set -uo pipefail

BUILD_DIR=${1:-build}
PY=${PYTHON:-python3}
EXE=
HOST=$BUILD_DIR/tests/mgmt_endpoint_host
RAW=$BUILD_DIR/tests/mgmt_raw_client
CTL=$BUILD_DIR/mqvpnctl
IS_WIN=0
case "$(uname -s)" in
    MINGW* | MSYS*)
        IS_WIN=1
        EXE=.exe
        PY=${PYTHON:-python}
        HOST=$BUILD_DIR/tests/Release/mgmt_endpoint_host$EXE
        RAW=$BUILD_DIR/tests/Release/mgmt_raw_client$EXE
        CTL=$BUILD_DIR/Release/mqvpnctl$EXE
        ;;
esac
for b in "$HOST" "$RAW" "$CTL"; do
    if [ ! -x "$b" ]; then
        echo "missing binary: $b (build mqvpnctl mgmt_endpoint_host mgmt_raw_client first)"
        exit 2
    fi
done

# Short path: AF_UNIX sun_path is 104 bytes on macOS.
# T13 (root) also needs the build dir to be world-traversable so that
# $CTL is executable by nobody.
OWN_BASE=
if [ -n "${RUNNER_TEMP:-}" ]; then
    BASE=$RUNNER_TEMP
else
    BASE=$(mktemp -d)
    OWN_BASE=1
fi
if [ "${#BASE}" -gt 50 ]; then
    BASE=$(mktemp -d /tmp/mgmt.XXXXXX)
    OWN_BASE=1
fi
[ -z "$OWN_BASE" ] || chmod 755 "$BASE"
TMPD=$BASE/mgmt-$$
mkdir -p "$TMPD" && chmod 755 "$TMPD"

PASS=0
FAIL=0
SKIP=0
PIDS=()

cleanup() {
    local p
    touch "$TMPD/t18.stop" 2>/dev/null
    for p in ${PIDS[@]+"${PIDS[@]}"}; do kill -KILL "$p" 2>/dev/null; done
    wait 2>/dev/null
    rm -rf "$TMPD"
    if [ -n "$OWN_BASE" ]; then rmdir "$BASE" 2>/dev/null; fi
}
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); echo "PASS: $1"; }
fail() {
    FAIL=$((FAIL + 1))
    echo "FAIL: $1"
    shift
    local l
    for l in "$@"; do echo "      $l"; done
}
skip() { SKIP=$((SKIP + 1)); echo "SKIP: $1 ($2)"; }

USE_PY_CLOCK=
_t=$(date +%s%N 2>/dev/null || true)
case "$_t" in '' | *[!0-9]*) USE_PY_CLOCK=1 ;; esac
now_ms() {
    if [ -n "$USE_PY_CLOCK" ]; then
        "$PY" -c 'import time;print(int(time.time()*1000))'
    else
        local t
        t=$(date +%s%N)
        echo $((t / 1000000))
    fi
}

# start_host NAME ARGS... : background host, stdout/stderr in $TMPD/NAME.{out,err}.
# Sets HPID. Returns 0 once "listening on" is in the file, 1 if it exited or
# never printed it within 10 s.
HPID=
start_host() {
    local name=$1 i
    shift
    "$HOST" "$@" >"$TMPD/$name.out" 2>"$TMPD/$name.err" &
    HPID=$!
    PIDS+=("$HPID")
    for i in $(seq 1 100); do
        if grep -q 'listening on' "$TMPD/$name.out"; then return 0; fi
        kill -0 "$HPID" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

# wait_exit PID SECS : sets WRC to the exit status, or 999 after killing it.
WRC=
wait_exit() {
    local pid=$1 i
    for i in $(seq 1 $(($2 * 10))); do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
            WRC=$?
            return 0
        fi
        sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    WRC=999
    return 1
}

stop_host() { kill -TERM "$1" 2>/dev/null; wait_exit "$1" 10; }

# start_bind NAME ARGS... : background mgmt_raw_client --bind-only.
start_bind() {
    local name=$1 i
    shift
    "$RAW" --bind-only "$@" >"$TMPD/$name.out" 2>"$TMPD/$name.err" &
    HPID=$!
    PIDS+=("$HPID")
    for i in $(seq 1 100); do
        if grep -q '^bound ' "$TMPD/$name.out"; then return 0; fi
        kill -0 "$HPID" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

HELLO='{"jsonrpc":"2.0","id":1,"method":"system.hello","params":{"cmp_versions":["1.0"]}}'
PING='{"jsonrpc":"2.0","id":%d,"method":"system.ping"}'
S=$TMPD/a.sock

# ---- T1: host up, socket and lock exist
if start_host h1 "$S" && [ -S "$S" ] && [ -e "$S.lock" ]; then
    pass "T1  host listens, socket and lock file exist"
    H1=$HPID
else
    fail "T1  host start" "stdout: $(cat "$TMPD/h1.out")" "stderr: $(cat "$TMPD/h1.err")"
    H1=$HPID
fi

# ---- T2: version, text
out=$("$CTL" --endpoint "$S" version 2>"$TMPD/err")
rc=$?
n=$(printf '%s\n' "$out" | wc -l)
if [ "$rc" -eq 0 ] && [ "$((n + 0))" -eq 3 ]; then
    pass "T2  mqvpnctl version (text): exit 0, 3 lines"
else
    fail "T2  mqvpnctl version (text)" "exit=$rc lines=$n" "stdout: $out" "stderr: $(cat "$TMPD/err")"
fi

# ---- T2b: --help / -h
out=$("$CTL" --help 2>"$TMPD/err")
rc=$?
if [ "$rc" -eq 0 ] && [ -n "$out" ]; then
    pass "T2b mqvpnctl --help: exit 0, non-empty stdout"
else
    fail "T2b mqvpnctl --help" "exit=$rc" "stdout: $out" "stderr: $(cat "$TMPD/err")"
fi
"$CTL" -h >/dev/null 2>"$TMPD/err"
rc=$?
if [ "$rc" -eq 0 ]; then
    pass "T2b mqvpnctl -h: exit 0"
else
    fail "T2b mqvpnctl -h" "exit=$rc" "stderr: $(cat "$TMPD/err")"
fi

# ---- T3: version, --json
out=$("$CTL" --endpoint "$S" --json version 2>"$TMPD/err")
rc=$?
if [ "$rc" -eq 0 ] && "$PY" -c '
import json, sys
d = json.load(sys.stdin)
assert d["schema_version"]
assert d["endpoint"]["role"] == "admin"
' <<<"$out"; then
    pass "T3  mqvpnctl --json version: schema_version and endpoint.role"
else
    fail "T3  mqvpnctl --json version" "exit=$rc" "stdout: $out" "stderr: $(cat "$TMPD/err")"
fi

# ---- T4: no socket -> exit 5, JSON UNAVAILABLE, empty stderr
out=$("$CTL" --endpoint "$TMPD/none.sock" --json version 2>"$TMPD/err")
rc=$?
if [ "$rc" -eq 5 ] && [[ $out == *UNAVAILABLE* ]] && [ ! -s "$TMPD/err" ]; then
    pass "T4  no endpoint: exit 5, UNAVAILABLE in JSON, stderr empty"
else
    fail "T4  no endpoint" "exit=$rc" "stdout: $out" "stderr: $(cat "$TMPD/err")"
fi

# ---- T5: malformed line -> -32700, same connection still handshakes
out=$("$RAW" "$S" --lines 2 --payload "$(printf '{bad\n%s' "$HELLO")"$'\n' 2>"$TMPD/err")
rc=$?
l1=$(sed -n 1p <<<"$out")
l2=$(sed -n 2p <<<"$out")
if [ "$rc" -eq 0 ] && [[ $l1 == *-32700* ]] && [[ $l2 == *'"result"'* ]]; then
    pass "T5  malformed -> -32700, hello still works on the connection"
else
    fail "T5  malformed line" "exit=$rc" "stdout: $out" "stderr: $(cat "$TMPD/err")"
fi

# ---- T6: oversized line -> INVALID_REQUEST then EOF
out=$("$RAW" "$S" --lines 2 --fill 70000 2>"$TMPD/err")
rc=$?
if [ "$rc" -eq 3 ] && [[ $out == *INVALID_REQUEST* ]]; then
    pass "T6  70000-byte line: INVALID_REQUEST then EOF (exit 3)"
else
    fail "T6  oversized line" "exit=$rc" "stdout: $out" "stderr: $(cat "$TMPD/err")"
fi

# ---- T7: 4 requests in one payload, replies in order
p=$HELLO$'\n'
for i in 2 3 4; do p+=$(printf "$PING" "$i")$'\n'; done
out=$("$RAW" "$S" --lines 4 --payload "$p" 2>"$TMPD/err")
rc=$?
ids=$("$PY" -c '
import json, sys
print([json.loads(l)["id"] for l in sys.stdin if l.strip()])
' <<<"$out" 2>&1)
if [ "$rc" -eq 0 ] && [ "$ids" = "[1, 2, 3, 4]" ]; then
    pass "T7  4 requests in one payload: ids 1..4 in order"
else
    fail "T7  pipelined requests" "exit=$rc ids=$ids" "stdout: $out" "stderr: $(cat "$TMPD/err")"
fi

# ---- T8a: unsupported version -> -32002 with details.supported
out=$("$RAW" "$S" --lines 1 --payload '{"jsonrpc":"2.0","id":1,"method":"system.hello","params":{"cmp_versions":["9.9"]}}'$'\n' 2>"$TMPD/err")
rc=$?
if [ "$rc" -eq 0 ] && [[ $out == *-32002* ]] && [[ $out == *'"supported":["1.0"]'* ]]; then
    pass "T8a hello cmp_versions [9.9]: -32002, details.supported [1.0]"
else
    fail "T8a hello with an unsupported version" "exit=$rc" "stdout: $out" "stderr: $(cat "$TMPD/err")"
fi

# ---- T8c: reply followed by a junk line, both readable
out=$("$RAW" "$S" --lines 2 --payload "$HELLO"$'\njunk\n' 2>"$TMPD/err")
rc=$?
n=$(printf '%s\n' "$out" | wc -l)
if [ "$rc" -eq 0 ] && [ "$((n + 0))" -eq 2 ]; then
    pass "T8c reply + trailing junk line: both lines read"
else
    fail "T8c trailing junk" "exit=$rc lines=$n" "stdout: $out" "stderr: $(cat "$TMPD/err")"
fi

# ---- T9: mqvpnctl links no libmqvpn / xquic / libevent
case "$(uname -s)" in
    Linux)
        deps=$(ldd "$CTL" 2>&1)
        syms=$(nm -u "$CTL" 2>&1)
        ;;
    Darwin)
        deps=$(otool -L "$CTL" 2>&1)
        syms=$(nm -u "$CTL" 2>&1)
        ;;
    *) deps= syms= ;;
esac
if [ "$IS_WIN" -eq 1 ]; then
    skip "T9  link check" "Windows: dumpbin step in the workflow"
elif [ -z "$deps" ] || [ -z "$syms" ]; then
    fail "T9  link check" "ldd/otool or nm produced no output"
elif [[ $deps == *libmqvpn* || $deps == *xquic* || $deps == *libevent* ]] ||
    [[ $syms == *xqc_* || $syms == *mqvpn_client* || $syms == *mqvpn_server* || $syms == *event_base* ]]; then
    fail "T9  link check" "deps: $deps" "undefined symbols: $syms"
else
    pass "T9  mqvpnctl links no libmqvpn, xquic or libevent"
fi

# ---- T10: 4 concurrent versions
for i in 1 2 3 4; do
    "$CTL" --endpoint "$S" version >"$TMPD/t10.$i.out" 2>&1 &
    PIDS+=("$!")
    T10[i]=$!
done
bad=
for i in 1 2 3 4; do
    wait "${T10[i]}"
    r=$?
    [ "$r" -eq 0 ] || bad+=" #$i=$r($(cat "$TMPD/t10.$i.out"))"
done
if [ -z "$bad" ]; then pass "T10 4 concurrent mqvpnctl version: all exit 0"; else fail "T10 concurrent versions" "$bad"; fi

# ---- T11: silent host, --timeout 1 -> exit 8 within 3 s
SS=$TMPD/silent.sock
if start_host h11 "$SS" --silent; then
    t0=$(now_ms)
    out=$("$CTL" --endpoint "$SS" --timeout 1 version 2>&1)
    rc=$?
    dt=$(($(now_ms) - t0))
    if [ "$rc" -eq 8 ] && [ "$dt" -le 3000 ]; then
        pass "T11 silent host: --timeout 1 -> exit 8 in ${dt} ms"
    else
        fail "T11 silent host" "exit=$rc elapsed=${dt}ms" "output: $out"
    fi
    stop_host "$HPID"
else
    fail "T11 silent host start" "stderr: $(cat "$TMPD/h11.err")"
fi

# ---- T12 / T12b: socket mode (POSIX)
if [ "$IS_WIN" -eq 1 ]; then
    skip "T12 SocketMode 0640" "Windows"
    skip "T12b default socket mode" "Windows"
else
    M=$TMPD/mode.sock
    if start_host h12 "$M" --mode 0640; then
        ls_out=$(ls -l "$M")
        if [ "${ls_out:0:10}" = "srw-r-----" ]; then
            pass "T12 --mode 0640 -> srw-r-----"
        else
            fail "T12 --mode 0640" "ls -l: $ls_out"
        fi
        stop_host "$HPID"
    else
        fail "T12 host start" "stderr: $(cat "$TMPD/h12.err")"
    fi
    ls_out=$(ls -l "$S")
    if [ "${ls_out:0:10}" = "srw-rw----" ]; then
        pass "T12b default socket mode -> srw-rw----"
    else
        fail "T12b default socket mode" "ls -l: $ls_out"
    fi
fi

# ---- T13: permission boundary (root + nobody only)
if [ "$IS_WIN" -eq 0 ] && [ "$(id -u)" -eq 0 ] && id nobody >/dev/null 2>&1; then
    AS_NOBODY='import os, pwd, sys
p = pwd.getpwnam("nobody")
os.setgroups([]); os.setgid(p.pw_gid); os.setuid(p.pw_uid)
os.execv(sys.argv[1], sys.argv[1:])'
    # nobody must traverse every parent of the binary and the socket: a runner
    # checkout or RUNNER_TEMP may sit under a 0750 home, so use a fresh /tmp dir
    # and a copy of the CLI there (absolute path, no cwd dependence).
    T13D=$(mktemp -d /tmp/mgmt13.XXXXXX)
    chmod 755 "$T13D"
    cp "$CTL" "$T13D/mqvpnctl" && chmod 755 "$T13D/mqvpnctl"
    CTL13=$T13D/mqvpnctl
    P13=$T13D/perm.sock
    ok=1
    detail=
    for m in 0600 0666; do
        if ! start_host h13 "$P13" --mode "$m"; then
            ok=0
            detail+=" host($m) failed: $(cat "$TMPD/h13.err");"
            continue
        fi
        out=$("$PY" -c "$AS_NOBODY" "$CTL13" --endpoint "$P13" version 2>&1)
        rc=$?
        if [ "$m" = 0600 ] && [ "$rc" -eq 0 ]; then ok=0; detail+=" mode 0600: nobody got in (rc=0: $out);"; fi
        if [ "$m" = 0666 ] && [ "$rc" -ne 0 ]; then ok=0; detail+=" mode 0666: nobody denied (rc=$rc: $out);"; fi
        stop_host "$HPID"
    done
    rm -rf "$T13D"
    if [ "$ok" -eq 1 ]; then
        pass "T13 nobody is denied on 0600 and allowed on 0666"
    else
        fail "T13 permission boundary" "$detail"
    fi
else
    skip "T13 permission boundary" "needs root and a nobody user"
fi

# ---- T14: kill -9, restart replaces the socket
K=$TMPD/k.sock
if start_host h14a "$K"; then
    kill -KILL "$HPID" 2>/dev/null
    wait "$HPID" 2>/dev/null
    if start_host h14b "$K"; then
        out=$("$CTL" --endpoint "$K" version 2>&1)
        rc=$?
        if [ "$rc" -eq 0 ]; then
            pass "T14 restart after kill -9 replaces the stale socket"
        else
            fail "T14 restart after kill -9" "mqvpnctl exit=$rc: $out"
        fi
        stop_host "$HPID"
    else
        fail "T14 restart after kill -9" "host B failed: $(cat "$TMPD/h14b.err")"
    fi
else
    fail "T14 host start" "stderr: $(cat "$TMPD/h14a.err")"
fi

# ---- T15: a regular file on the path -> host exit 1, file untouched
F=$TMPD/file.sock
printf 'precious\n' >"$F"
start_host h15 "$F" >/dev/null
wait_exit "$HPID" 5
if [ "$WRC" -eq 1 ] && [ "$(cat "$F")" = "precious" ]; then
    pass "T15 regular file on the path: host exit 1, file intact"
else
    fail "T15 regular file on the path" "host exit=$WRC" "file: $(cat "$F" 2>&1)" "stderr: $(cat "$TMPD/h15.err")"
fi

# ---- T16: second host on the same path -> exit 1, first keeps answering
start_host h16 "$S" >/dev/null
wait_exit "$HPID" 5
rc2=$WRC
out=$("$CTL" --endpoint "$S" version 2>&1)
rc=$?
if [ "$rc2" -eq 1 ] && [ "$rc" -eq 0 ]; then
    pass "T16 second host on the same path: exit 1, first still answers"
else
    fail "T16 second host" "host B exit=$rc2" "mqvpnctl exit=$rc: $out" "stderr: $(cat "$TMPD/h16.err")"
fi

# ---- T17: silent connection is dropped by the handshake deadline
HS=$TMPD/hs.sock
if start_host h17 "$HS" --handshake-ms 300; then
    t0=$(now_ms)
    out=$("$RAW" "$HS" --lines 0 --timeout-ms 5000 2>&1)
    rc=$?
    dt=$(($(now_ms) - t0))
    if [ "$rc" -eq 0 ] && [ "$dt" -le 1000 ]; then
        pass "T17 --handshake-ms 300: silent connection gets EOF in ${dt} ms"
    else
        fail "T17 handshake deadline" "exit=$rc elapsed=${dt}ms" "output: $out"
    fi
    stop_host "$HPID"
else
    fail "T17 host start" "stderr: $(cat "$TMPD/h17.err")"
fi

# ---- T18: ping flood from 24 clients must not starve mqvpnctl
: >"$TMPD/pings.ndjson"
for i in $(seq 1 1000); do printf '{"jsonrpc":"2.0","id":%d,"method":"system.ping"}\n' "$i"; done >"$TMPD/pings.ndjson"
total_lines() { cat "$TMPD"/t18.*.out | wc -l; }
LPIDS=()
for i in $(seq 1 24); do
    : >"$TMPD/t18.$i.out"
    (
        while [ ! -e "$TMPD/t18.stop" ]; do
            "$RAW" "$S" --lines 1000 --timeout-ms 8000 --payload-file "$TMPD/pings.ndjson" \
                >>"$TMPD/t18.$i.out" 2>>"$TMPD/t18.$i.err"
            echo $? >>"$TMPD/t18.$i.rc"
        done
    ) &
    LPIDS+=("$!")
    PIDS+=("$!")
done
t_start=$(now_ms)
sleep 1
bad=
info=
for r in 1 2 3; do
    b=$(($(total_lines) + 0))
    t0=$(now_ms)
    "$CTL" --endpoint "$S" version >"$TMPD/t18ctl.txt" 2>&1
    rc=$?
    dt=$(($(now_ms) - t0))
    a=$(($(total_lines) + 0))
    info+=" run$r:exit=$rc,${dt}ms,+$((a - b))lines"
    [ "$rc" -eq 0 ] || bad+=" run$r exit=$rc ($(cat "$TMPD/t18ctl.txt"));"
    [ "$dt" -le 2000 ] || bad+=" run$r took ${dt} ms;"
    [ "$((a - b))" -gt 0 ] || bad+=" run$r: load did not grow ($b -> $a lines);"
done
while [ $(($(now_ms) - t_start)) -lt 5500 ]; do sleep 0.2; done
touch "$TMPD/t18.stop"
for p in "${LPIDS[@]}"; do wait "$p" 2>/dev/null; done
lines=$(($(total_lines) + 0))
rcs=$(cat "$TMPD"/t18.*.rc | sort | uniq -c | tr '\n' ' ')
if grep -qv '^0$' "$TMPD"/t18.*.rc; then
    bad+=" raw client exit codes: $rcs;"
fi
if [ -z "$bad" ]; then
    pass "T18 24 clients flooding: mqvpnctl stays prompt ($info; total $lines lines; raw exits: $rcs)"
else
    fail "T18 flood" "$bad" "$info" "raw exits: $rcs"
fi

# ---- T19: a foreign socket on the path -> host exit 1, socket survives
if [ "$IS_WIN" -eq 1 ]; then
    skip "T19 foreign socket" "Windows: --bind-only lands with the Windows port"
else
    FP=$TMPD/foreign.sock
    if start_bind b19 "$FP" --stop-file "$TMPD/b19.stop"; then
        BPID=$HPID
        start_host h19 "$FP" >/dev/null
        wait_exit "$HPID" 5
        hrc=$WRC
        "$RAW" "$FP" --timeout-ms 500 >/dev/null 2>&1
        crc=$? # 8 = connected, nobody answers
        if [ "$hrc" -eq 1 ] && [ -S "$FP" ] && [ "$crc" -eq 8 ]; then
            pass "T19 foreign socket on the path: host exit 1, socket intact and connectable"
        else
            fail "T19 foreign socket" "host exit=$hrc connect exit=$crc" "stderr: $(cat "$TMPD/h19.err")"
        fi
        touch "$TMPD/b19.stop"
        wait_exit "$BPID" 5
    else
        fail "T19 --bind-only start" "stderr: $(cat "$TMPD/b19.err")"
    fi
fi

# ---- T20: path replaced under a running host -> host leaves the replacement alone
if [ "$IS_WIN" -eq 1 ]; then
    skip "T20 replaced socket" "Windows: --bind-only lands with the Windows port"
else
    RP=$TMPD/repl.sock
    if start_host h20 "$RP"; then
        H20=$HPID
        rm -f "$RP"
        if start_bind b20 "$RP" --stop-file "$TMPD/b20.stop"; then
            BPID=$HPID
            stop_host "$H20"
            hrc=$WRC
            "$RAW" "$RP" --timeout-ms 500 >/dev/null 2>&1
            crc=$?
            if [ "$hrc" -eq 0 ] && [ -S "$RP" ] && [ "$crc" -eq 8 ]; then
                pass "T20 replaced socket survives the host's shutdown"
            else
                fail "T20 replaced socket" "host exit=$hrc connect exit=$crc socket=$([ -S "$RP" ] && echo present || echo gone)"
            fi
            touch "$TMPD/b20.stop"
            wait_exit "$BPID" 5
        else
            fail "T20 --bind-only start" "stderr: $(cat "$TMPD/b20.err")"
            stop_host "$H20"
        fi
    else
        fail "T20 host start" "stderr: $(cat "$TMPD/h20.err")"
    fi
fi

# ---- T21: Windows ProgramData DACL (the Windows job covers it)
skip "T21 ProgramData DACL" "Windows only"

# ---- T22: full backlog owner -> second host refuses, owner unlinks on stop
BP=$TMPD/backlog.sock
if start_host h22a "$BP" --no-accept; then
    A=$HPID
    CP=()
    for i in $(seq 1 24); do
        "$RAW" "$BP" --timeout-ms 1500 >/dev/null 2>&1 &
        CP+=("$!")
        PIDS+=("$!")
    done
    sleep 0.3
    start_host h22b "$BP" >/dev/null
    wait_exit "$HPID" 5
    brc=$WRC
    stop_host "$A"
    arc=$WRC
    for p in "${CP[@]}"; do wait "$p" 2>/dev/null; done
    if [ "$brc" -eq 1 ] && [ "$arc" -eq 0 ] && [ ! -e "$BP" ]; then
        pass "T22 full backlog: second host exit 1, owner exits 0 and unlinks its socket"
    else
        fail "T22 full backlog" "host B exit=$brc owner exit=$arc" "path: $(ls -l "$BP" 2>&1)" "stderr B: $(cat "$TMPD/h22b.err")"
    fi
else
    fail "T22 host start" "stderr: $(cat "$TMPD/h22a.err")"
fi

# ---- T23: owner stalled between bind and listen
if [ "$IS_WIN" -eq 1 ]; then
    skip "T23 stalled owner" "Windows: --bind-only lands with the Windows port"
else
    SP=$TMPD/stall.sock
    if start_bind b23 "$SP" --hold-lock; then
        BPID=$HPID
        start_host h23a "$SP" >/dev/null
        wait_exit "$HPID" 5
        r1=$WRC
        kill -KILL "$BPID" 2>/dev/null
        wait "$BPID" 2>/dev/null
        if [ "$r1" -eq 1 ] && [ -S "$SP" ] && start_host h23b "$SP"; then
            out=$("$CTL" --endpoint "$SP" version 2>&1)
            rc=$?
            if [ "$rc" -eq 0 ]; then
                pass "T23 stalled owner: refused while it lives; after kill -9 the stale socket is replaced"
            else
                fail "T23 after kill -9" "mqvpnctl exit=$rc: $out"
            fi
            stop_host "$HPID"
        else
            fail "T23 stalled owner" "first host exit=$r1 socket=$([ -S "$SP" ] && echo present || echo gone)" \
                "stderr A: $(cat "$TMPD/h23a.err")" "stderr B: $(cat "$TMPD/h23b.err" 2>&1)"
        fi
    else
        fail "T23 --bind-only --hold-lock start" "stderr: $(cat "$TMPD/b23.err")"
    fi
fi

# ---- last: the main host stops on SIGTERM and unlinks its socket
stop_host "$H1"
if [ "$WRC" -eq 0 ] && [ ! -e "$S" ]; then
    pass "T1b host stops on SIGTERM (exit 0) and removes its socket"
else
    fail "T1b host shutdown" "exit=$WRC" "path: $(ls -l "$S" 2>&1)" "stderr: $(cat "$TMPD/h1.err")"
fi

echo "=== Results: PASS=$PASS FAIL=$FAIL ==="
echo "(SKIP=$SKIP)"
[ "$FAIL" -eq 0 ]
