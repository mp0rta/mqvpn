#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# run_reinjection_test.sh — E2E netns coverage for [Multipath] Reinjection.
#
# Reinjection (speculative multipath duplication of unacked data,
# MQVPN_REINJ_* in include/libmqvpn.h) has no CLI flag — config file/JSON
# only (see the reinjection block in main.c) — so every non-"off" scenario here drives
# both endpoints via --config.
#
# Traffic direction is server -> client in every scenario, so the SERVER
# (the sender of the data that can go unacked / get duplicated) is where
# the control API's per-path "reinject_tx_bytes" (control_socket.c
# ctrl_cmd_get_status) accrues.
#
# Scenarios (all 2-path netns):
#   1. off       — default config (no [Multipath] Reinjection key). Asserts
#                  every "reinject_tx_bytes" in the server's get_status stays
#                  0, and that the "reinjection enabled: mode=" log marker
#                  never appears on either end.
#   2. deadline  — [Multipath] Reinjection = deadline on BOTH sides, with
#                  [Hybrid] Enabled=true / Tcp=stream so the stream lane is
#                  live (the post-build_conn_settings log blocks in mqvpn_client.c / mqvpn_server.c both warn
#                  that deadline mode "protects only stream traffic" without
#                  the hybrid lane enabled). A file is downloaded from the
#                  server's egress target over the hybrid TCP lane (the HTTP
#                  response body — i.e. the bulk bytes — flows server ->
#                  client by construction of a GET). Midway through the
#                  transfer, the ACTIVE path (the lower-RTT one under the
#                  MinRTT fallback the stream lane uses — see AGENTS.md's
#                  "hybrid TCP lane is scheduled by MinRTT" note) is
#                  degraded with netem so its in-flight data goes late,
#                  arming the deadline reinjection path. Asserts the
#                  transfer still completes byte-identical and that at
#                  least one server-side path shows reinject_tx_bytes > 0,
#                  sampled while the client is still connected (closed
#                  paths drop out of the get_status snapshot). Retry
#                  rationale: see _deadline_body.
#   3. dgram_unrecognized — [Multipath] Reinjection = dgram on BOTH sides.
#                  The mode was removed: config files that still carry it
#                  warn "Reinjection 'dgram' not recognized" and run with
#                  reinjection off. Asserts the tunnel comes up, both logs
#                  carry the warning and neither logs "reinjection enabled:".
#   4. redundant — client-only [Multipath] Redundant = on (server default).
#                  Asserts the client logs "redundant mode enabled:
#                  ports=all", then sends an inner UDP flow client -> server
#                  and compares the server-side veth rx_bytes of both paths:
#                  each must carry at least 1.4 MB and min/max >= 0.8.
#
# Every scenario ends with a sanitizer exit-code check (stop_and_check_sanitizer,
# same as 22/25 sibling e2e scripts) on both the client and server PID —
# without it, ASAN_OPTIONS=detect_leaks=1 in CI can never fail this step.
# Sanitizer failures are tracked separately from functional PASS/FAIL (mirrors
# run_backup_fec_test.sh's SANITIZER_FAIL) and force exit 1 at the very end
# regardless of the scenario tally.
#
# REQUIRES: root, GNU/OpenBSD netcat (`nc -q`), python3, iperf3, curl.
#
# Run manually:
#   sudo bash scripts/ci_e2e/run_reinjection_test.sh [path/to/mqvpn]
#
# Exit code: 0 if all scenarios pass and no sanitizer error fired, 1 otherwise.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/sanitizer_check.sh"
source "${SCRIPT_DIR}/../../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN:-${SCRIPT_DIR}/../../build/mqvpn}}"
LOG_DIR="$(mktemp -d)"
CTRL_PORT=9099
SANITIZER_FAIL=0

# Track scratch dirs created per-scenario (HTTP docroots) for cleanup —
# separate from bench_cleanup, which only knows about netns/veth/procs.
SCENARIO_TMP_DIRS=()

# Global HTTP test-server state (scenario "deadline" only), so a mid-run
# operator abort (SIGINT/SIGTERM before the scenario's own teardown runs)
# still gets reaped by the EXIT trap — mirrors tests/test_e2e_hybrid_h2.sh's
# HTTP_PID + cleanup_http_server pattern exactly.
HTTP_PID=""
HTTP_TARGET_IP=""
cleanup_http_server() {
    if [ -n "$HTTP_PID" ] && kill -0 "$HTTP_PID" 2>/dev/null; then
        kill "$HTTP_PID" 2>/dev/null || true
        wait "$HTTP_PID" 2>/dev/null || true
    fi
    HTTP_PID=""
    if [ -n "$HTTP_TARGET_IP" ]; then
        ip netns exec "$NS_SERVER" ip addr del "${HTTP_TARGET_IP}/32" dev lo 2>/dev/null || true
    fi
}

# Named-function trap (same shape as run_backup_fec_test.sh's cleanup() +
# `trap cleanup EXIT`, not an inline string) so a mid-run operator abort
# still reaps the HTTP server / netns / scratch dirs and the SANITIZER_FAIL
# verdict is checked exactly once, regardless of which scenario was live.
cleanup() {
    local _rc=$?
    cleanup_http_server
    bench_cleanup
    local d
    for d in "${SCENARIO_TMP_DIRS[@]:-}"; do
        [[ -n "$d" ]] && rm -rf "$d"
    done
    if (( _rc != 0 )); then
        echo "Logs preserved at: $LOG_DIR" >&2
    else
        rm -rf "$LOG_DIR"
    fi
    if (( SANITIZER_FAIL != 0 )); then
        echo "FAIL: sanitizer errors detected" >&2
        exit 1
    fi
}
trap cleanup EXIT
echo "Logs: $LOG_DIR"

# --- Preflight ---

if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: must run as root (sudo)" >&2
    exit 2
fi
if ! command -v nc >/dev/null 2>&1; then
    echo "ERROR: nc (netcat) not on PATH" >&2
    exit 2
fi
if ! nc -h 2>&1 | grep -q '\-q'; then
    echo "ERROR: nc lacks the '-q' flag — install GNU netcat (apt: netcat-openbsd works too if it ships -q)" >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not on PATH" >&2
    exit 2
fi
if ! command -v iperf3 >/dev/null 2>&1; then
    echo "ERROR: iperf3 not on PATH" >&2
    exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl not on PATH" >&2
    exit 2
fi
if [[ -z "$MQVPN" || ! -x "$MQVPN" ]]; then
    echo "ERROR: mqvpn binary not found (pass path as argv[1] or set MQVPN env)" >&2
    exit 2
fi

bench_check_deps

PASS=0
FAIL=0

# --- Control-API helpers (copied from run_control_api_test.sh — same
# socat/nc idiom, same JSON grep style; no jq / new deps added). ---

ctrl_send() {
    local ns="$1" addr="$2" port="$3" json="$4"
    if [[ -n "$ns" ]]; then
        printf '%s' "$json" | ip netns exec "$ns" nc -q1 "$addr" "$port" 2>/dev/null \
            | head -c 16384
    else
        printf '%s' "$json" | nc -q1 "$addr" "$port" 2>/dev/null | head -c 16384
    fi
}

assert_json_field() {
    python3 - "$1" "$2" "$3" <<'PY'
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(1)
try:
    expected = json.loads(sys.argv[3])
except Exception:
    sys.exit(1)
sys.exit(0 if d.get(sys.argv[2]) == expected else 1)
PY
}

# wait_for <secs> <bash-cmd>  → polls every 0.2s up to <secs>
wait_for() {
    local secs="$1"; shift
    local deadline=$(( $(date +%s) + secs ))
    while (( $(date +%s) < deadline )); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

ctrl_local() {
    local r
    r=$(ctrl_send "$NS_SERVER" 127.0.0.1 "$CTRL_PORT" "$1")
    if [[ -z "$r" ]]; then
        echo "  ctrl_local: empty response (server may be dead)" >&2
        return 1
    fi
    printf '%s' "$r"
}

# --- Server / client launchers (copied from run_control_api_test.sh) ---

start_server_with_flags() {
    local server_log="$1"
    shift
    if ! bench_start_vpn_server >"${server_log}.bringup" 2>&1; then
        echo "  bench_start_vpn_server failed; tail of bringup log:" >&2
        tail -20 "${server_log}.bringup" >&2
        return 1
    fi
    kill "$_BENCH_SERVER_PID" 2>/dev/null || true
    wait "$_BENCH_SERVER_PID" 2>/dev/null || true

    # --auth-key is NOT taken from the caller's argv: bench_start_vpn_server
    # re-rolls $_BENCH_PSK on every call (--genkey internally), so a
    # caller-supplied value would expand before the re-roll and pass either
    # the empty initial value or a stale PSK. Always use the freshly-rolled
    # $_BENCH_PSK here, after the re-roll above.
    ip netns exec "$NS_SERVER" "$MQVPN" --mode server \
        --listen "0.0.0.0:${VPN_LISTEN_PORT}" \
        --subnet 10.0.0.0/24 \
        --cert "$_BENCH_WORK_DIR/server.crt" \
        --key "$_BENCH_WORK_DIR/server.key" \
        --log-level "$BENCH_LOG_LEVEL" \
        --auth-key "$_BENCH_PSK" \
        "$@" \
        >"$server_log" 2>&1 &
    _BENCH_SERVER_PID=$!
    sleep 1

    if ! kill -0 "$_BENCH_SERVER_PID" 2>/dev/null; then
        echo "  ERROR: server failed to start; tail of $server_log:" >&2
        tail -20 "$server_log" >&2
        return 1
    fi
    return 0
}

start_client_with_auth_key() {
    local auth_key="$1"
    local client_log="$2"
    local extra_flags="$3"

    if [[ -n "$_BENCH_CLIENT_PID" ]]; then
        kill "$_BENCH_CLIENT_PID" 2>/dev/null || true
        wait "$_BENCH_CLIENT_PID" 2>/dev/null || true
        _BENCH_CLIENT_PID=""
    fi

    # shellcheck disable=SC2086
    ip netns exec "$NS_CLIENT" "$MQVPN" --mode client \
        --server "${IP_A_SERVER_ADDR}:${VPN_LISTEN_PORT}" \
        --auth-key "$auth_key" \
        --insecure \
        --path "$VETH_A0" --path "$VETH_B0" \
        --log-level "$BENCH_LOG_LEVEL" \
        $extra_flags \
        >"$client_log" 2>&1 &
    _BENCH_CLIENT_PID=$!
    sleep 2
    return 0
}

# --- run_test wrapper (copied from run_control_api_test.sh) ---

run_test() {
    local name="$1"
    shift
    echo ""
    echo "--- Test: $name ---"
    if "$@"; then
        echo "  PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $name"
        FAIL=$((FAIL + 1))
    fi
}

# --- Shared helpers ---

# Apply netem to a single path slot's veth pair only (both ends), leaving
# the other path slot untouched. Copied verbatim from
# tests/test_e2e_hybrid_h2.sh's apply_path_netem.
apply_path_netem() {
    local idx="$1" netem="$2"
    local vc vs
    vc="$(bench_path_veth_client "$idx")"
    vs="$(bench_path_veth_server "$idx")"
    ip netns exec "$NS_CLIENT" tc qdisc del dev "$vc" root 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc del dev "$vs" root 2>/dev/null || true
    ip netns exec "$NS_CLIENT" tc qdisc add dev "$vc" root netem ${netem}
    ip netns exec "$NS_SERVER" tc qdisc add dev "$vs" root netem ${netem}
}

# Parse the first client's assigned tunnel IP out of the server log's
# "ADDRESS_ASSIGN: client=<ip>/32" marker (the ADDRESS_ASSIGN log in mqvpn_server.c — same
# convention scripts/ci_e2e/run_ipv6_dataplane_test.sh greps for). Falls
# back to the well-known first-client address (10.0.0.2) if the marker
# hasn't landed yet.
get_client_tunnel_ip() {
    local slog="$1"
    local ip
    ip=$(grep -oE 'ADDRESS_ASSIGN: client=[0-9.]+' "$slog" 2>/dev/null \
        | head -1 | cut -d= -f2)
    if [[ -z "$ip" ]]; then
        ip="10.0.0.2"
    fi
    echo "$ip"
}

# Echoes the max "reinject_tx_bytes" across every client/path in a
# get_status response, or -1 if no paths are present.
max_reinject_tx_bytes() {
    python3 - "$1" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
vals = []
for c in d.get("clients", []):
    for p in c.get("paths", []):
        vals.append(p.get("reinject_tx_bytes", 0))
print(max(vals) if vals else -1)
PY
}

# End-of-scenario teardown: sanitizer-check both endpoints (same idiom as
# run_backup_fec_test.sh's cleanup_processes -> stop_and_check_sanitizer)
# and clear the PID vars so the next scenario's bench_cleanup doesn't try
# to re-kill an already-reaped process. A sanitizer failure is recorded in
# the global SANITIZER_FAIL (checked once at final script exit) rather
# than flipping this scenario's own PASS/FAIL — same separation of
# concerns as the reference script.
finish_scenario() {
    local desc="$1" server_log="$2" client_log="$3"
    stop_and_check_sanitizer "$_BENCH_CLIENT_PID" "${desc} client" "$client_log" \
        || SANITIZER_FAIL=1
    stop_and_check_sanitizer "$_BENCH_SERVER_PID" "${desc} server" "$server_log" \
        || SANITIZER_FAIL=1
    _BENCH_CLIENT_PID=""
    _BENCH_SERVER_PID=""
}

# --- Scenario 1: off ---

_off_body() {
    local server_log="$1" client_log="$2"

    bench_cleanup
    bench_setup_netns

    start_server_with_flags "$server_log" \
        --control-port "$CTRL_PORT" \
        || return 1

    start_client_with_auth_key "$_BENCH_PSK" "$client_log" "" || return 1

    if ! wait_for 10 ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_SERVER_IP"; then
        echo "  tunnel never came up"; tail -20 "$client_log"; return 1
    fi
    echo "  off: tunnel up"

    # Traffic, server -> client (same direction convention as the other
    # scenarios, even though the assertion below holds regardless of
    # direction when reinjection is off).
    local tunnel_client_ip
    tunnel_client_ip=$(get_client_tunnel_ip "$server_log")
    ip netns exec "$NS_SERVER" ping -c 5 -W 2 "$tunnel_client_ip" >/dev/null 2>&1 || true
    sleep 1

    # 1) marker absence in BOTH logs — the byte-frozen observable this
    #    scenario pins per Task 7's brief. grep -l so a hit names which
    #    log(s) actually carried the marker, instead of a flat yes/no.
    local marker_hit
    marker_hit=$(grep -l "reinjection enabled: mode=" "$server_log" "$client_log" 2>/dev/null || true)
    if [[ -n "$marker_hit" ]]; then
        echo "  FAIL: 'reinjection enabled: mode=' marker present with Reinjection unset, found in:"
        echo "$marker_hit" | sed 's/^/    /'
        return 1
    fi
    echo "  off: marker absent on both ends: OK"

    # 2) every reinject_tx_bytes in get_status is 0.
    local resp
    resp=$(ctrl_local '{"cmd":"get_status"}') || return 1
    if ! assert_json_field "$resp" ok true; then
        echo "  get_status failed: $resp"; return 1
    fi

    local max_bytes
    max_bytes=$(max_reinject_tx_bytes "$resp")
    if (( max_bytes < 0 )); then
        echo "  FAIL: no reinject_tx_bytes fields in get_status (no paths?): $resp"
        return 1
    fi
    if (( max_bytes != 0 )); then
        echo "  FAIL: reinject_tx_bytes nonzero while Reinjection=off (max=$max_bytes): $resp"
        return 1
    fi
    echo "  off: reinject_tx_bytes all zero: OK"

    return 0
}

test_scenario_off() {
    local server_log="${LOG_DIR}/off_server.log"
    local client_log="${LOG_DIR}/off_client.log"
    local rc=0
    _off_body "$server_log" "$client_log" || rc=1
    finish_scenario "off" "$server_log" "$client_log"
    return "$rc"
}

# --- Scenario 2: deadline ---

_deadline_body() {
    local server_log="$1" client_log="$2"
    local ini="${LOG_DIR}/deadline.ini"
    local http_target_port=8090
    local http_docroot

    HTTP_TARGET_IP="10.223.0.1"
    http_docroot="$(mktemp -d)"
    SCENARIO_TMP_DIRS+=("$http_docroot")

    bench_cleanup
    bench_setup_netns

    # Keys cross-checked against src/config.c cfg_keys[] (SEC_MULTIPATH,
    # SEC_HYBRID) and src/mqvpn_sched_names.h's MQVPN_REINJ_LIST (exact
    # accepted string is "deadline"). Both sides share one INI, mirroring
    # tests/test_e2e_hybrid_h2.sh's INI_STREAM (server-only EgressAllow is
    # harmless to also load on the client).
    cat >"$ini" <<EOF
[Multipath]
Reinjection = deadline

[Hybrid]
Enabled = true
Tcp = stream
EgressAllow = ${HTTP_TARGET_IP}/32
EOF

    # HTTP egress target: a /32 loopback alias inside NS_SERVER (same
    # addressing pattern as test_e2e_hybrid_h2.sh's HTTP_TARGET_IP note).
    ip netns exec "$NS_SERVER" ip addr add "${HTTP_TARGET_IP}/32" dev lo
    head -c $((16 * 1024 * 1024)) /dev/urandom >"${http_docroot}/payload.bin"

    ip netns exec "$NS_SERVER" python3 -m http.server "$http_target_port" \
        --bind "$HTTP_TARGET_IP" --directory "$http_docroot" >/dev/null 2>&1 &
    HTTP_PID=$!

    local http_ready=0 _i
    for _i in $(seq 1 20); do
        if ip netns exec "$NS_SERVER" curl -s --max-time 1 -o /dev/null \
                "http://${HTTP_TARGET_IP}:${http_target_port}/payload.bin" 2>/dev/null; then
            http_ready=1
            break
        fi
        sleep 0.5
    done
    if (( http_ready != 1 )); then
        echo "  FAIL: HTTP test server never became ready"
        return 1
    fi

    # Baseline shaping BEFORE the tunnel comes up: path 0 (idx 0) is the
    # lower-RTT leg, so the stream lane's MinRTT fallback (AGENTS.md:
    # "hybrid TCP lane is scheduled by MinRTT, not by WLB — by
    # construction") prefers it. Rate-limited so a 16 MiB download takes
    # long enough to degrade mid-transfer, not so fast it finishes first.
    local baseline_a="delay 5ms rate 12mbit"
    local baseline_b="delay 8ms rate 12mbit"
    apply_path_netem 0 "$baseline_a"
    apply_path_netem 1 "$baseline_b"

    start_server_with_flags "$server_log" \
        --control-port "$CTRL_PORT" \
        --config "$ini" \
        || return 1

    start_client_with_auth_key "$_BENCH_PSK" "$client_log" "--config $ini" || return 1

    if ! wait_for 15 ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_SERVER_IP"; then
        echo "  tunnel never came up"; tail -30 "$client_log"
        return 1
    fi
    echo "  deadline: tunnel up"

    # Both ends log the deadline marker at connection-setup time
    # (the post-build_conn_settings log blocks in mqvpn_server.c / mqvpn_client.c) — must be present by now.
    if ! grep -q "reinjection enabled: mode=deadline" "$server_log"; then
        echo "  FAIL: server log missing 'reinjection enabled: mode=deadline'"
        return 1
    fi
    if ! grep -q "reinjection enabled: mode=deadline" "$client_log"; then
        echo "  FAIL: client log missing 'reinjection enabled: mode=deadline'"
        return 1
    fi
    echo "  deadline: marker present on both ends: OK"

    # Download -> mid-transfer degrade -> sample reinject_tx_bytes, in a
    # bounded 2-attempt retry. Arming a lateness-triggered reinjection path
    # is inherently timing sensitive (scheduling jitter on a busy CI runner
    # can let a transfer finish, or finish reinjecting, before/after the
    # sample point); a single-shot version is the likeliest flake in this
    # file, so a failed arming attempt restores the baseline netem on path
    # 0 and retries once before failing the scenario.
    local max_bytes=0
    local armed=0
    local attempt
    for attempt in 1 2; do
        if (( attempt > 1 )); then
            echo "  deadline: attempt $attempt — restoring baseline netem on path 0 and retrying"
            apply_path_netem 0 "$baseline_a"
            sleep 1
        fi

        # Per-attempt baseline: the counter is cumulative across the
        # connection, so without a baseline, attempt 2 could false-pass on
        # attempt 1's bytes. A failed/unparseable capture fails the ATTEMPT
        # (substituting 0 would resurrect the same false-pass).
        local baseline_resp baseline_bytes
        if ! baseline_resp=$(ctrl_local '{"cmd":"get_status"}'); then
            echo "  deadline attempt ${attempt}: baseline capture failed; failing attempt" >&2
            continue
        fi
        baseline_bytes=$(max_reinject_tx_bytes "$baseline_resp")
        if ! [[ "$baseline_bytes" =~ ^-?[0-9]+$ ]]; then
            echo "  deadline attempt ${attempt}: baseline unparseable; failing attempt" >&2
            continue
        fi
        if (( baseline_bytes < 0 )); then baseline_bytes=0; fi  # -1 = no paths yet

        # Download in the background (server -> client bytes, by
        # construction of an HTTP GET response body), then degrade the
        # ACTIVE path (idx 0) mid-transfer so its in-flight stream data
        # goes late and arms deadline reinjection onto path 1.
        local dl_out="${LOG_DIR}/deadline_download_attempt${attempt}.bin"
        ip netns exec "$NS_CLIENT" curl -s --max-time 90 -o "$dl_out" \
            "http://${HTTP_TARGET_IP}:${http_target_port}/payload.bin" &
        local curl_pid=$!

        sleep 3
        apply_path_netem 0 "delay 400ms loss 30%"

        local curl_rc=0
        wait "$curl_pid" || curl_rc=$?

        if (( curl_rc != 0 )); then
            echo "  deadline attempt $attempt: download did not complete (curl rc=$curl_rc)"
            continue
        fi
        if ! cmp -s "${http_docroot}/payload.bin" "$dl_out"; then
            echo "  deadline attempt $attempt: downloaded content mismatch"
            continue
        fi
        echo "  deadline attempt $attempt: download completed byte-identical under path-A degradation"

        # Sample reinject_tx_bytes WHILE paths are still live — the client
        # is still connected at this point, so no path has dropped out of
        # the get_status snapshot yet. Armed only if this SAME attempt's
        # post-download counter exceeds its own pre-download baseline.
        local resp
        resp=$(ctrl_local '{"cmd":"get_status"}') || continue
        max_bytes=$(max_reinject_tx_bytes "$resp")
        if (( max_bytes > baseline_bytes )); then
            armed=1
            echo "  deadline: attempt $attempt armed reinjection (reinject_tx_bytes=$max_bytes, baseline=$baseline_bytes)"
            break
        fi
        echo "  deadline attempt $attempt: transfer OK but reinjection not armed (reinject_tx_bytes=$max_bytes, baseline=$baseline_bytes)"
    done

    if (( armed != 1 )); then
        echo "  FAIL: no path shows reinject_tx_bytes increase over its per-attempt baseline after 2 attempts"
        echo "  --- server_log reinjection lines (last 5) ---"
        grep 'reinjection' "$server_log" | tail -5
        return 1
    fi
    echo "  deadline: reinject_tx_bytes=$max_bytes on at least one path: OK"

    return 0
}

test_scenario_deadline() {
    local server_log="${LOG_DIR}/deadline_server.log"
    local client_log="${LOG_DIR}/deadline_client.log"
    local rc=0
    _deadline_body "$server_log" "$client_log" || rc=1
    cleanup_http_server
    finish_scenario "deadline" "$server_log" "$client_log"
    return "$rc"
}

# --- Scenario 3: dgram_unrecognized ---

_dgram_unrecognized_body() {
    local server_log="$1" client_log="$2"
    local ini="${LOG_DIR}/dgram_unrecognized.ini"

    bench_cleanup
    bench_setup_netns

    cat >"$ini" <<EOT
[Multipath]
Reinjection = dgram
EOT

    start_server_with_flags "$server_log" \
        --control-port "$CTRL_PORT" \
        --config "$ini" \
        || return 1

    start_client_with_auth_key "$_BENCH_PSK" "$client_log" "--config $ini" || return 1

    if ! wait_for 10 ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_SERVER_IP"; then
        echo "  tunnel never came up"; tail -30 "$client_log"; return 1
    fi
    echo "  dgram_unrecognized: tunnel up"

    local f
    for f in "$server_log" "$client_log"; do
        if ! grep -F "Reinjection 'dgram' not recognized" "$f" >/dev/null; then
            echo "  FAIL: $f missing the 'not recognized' warning"; return 1
        fi
        if grep -F "reinjection enabled:" "$f" >/dev/null; then
            echo "  FAIL: $f has 'reinjection enabled:' although dgram is not recognized"
            return 1
        fi
    done
    echo "  dgram_unrecognized: warning present, reinjection stays off on both ends: OK"
    return 0
}

test_scenario_dgram_unrecognized() {
    local server_log="${LOG_DIR}/dgram_unrecognized_server.log"
    local client_log="${LOG_DIR}/dgram_unrecognized_client.log"
    local rc=0
    _dgram_unrecognized_body "$server_log" "$client_log" || rc=1
    finish_scenario "dgram_unrecognized" "$server_log" "$client_log"
    return "$rc"
}

# --- Scenario 4: redundant ---

_redundant_body() {
    local server_log="$1" client_log="$2"
    local ini="${LOG_DIR}/redundant.ini"
    local udp_port=5304

    bench_cleanup
    bench_setup_netns

    # Client only; the server runs with defaults and ignores the key.
    cat >"$ini" <<EOT
[Multipath]
Redundant = on
EOT

    start_server_with_flags "$server_log" \
        --control-port "$CTRL_PORT" \
        || return 1

    start_client_with_auth_key "$_BENCH_PSK" "$client_log" "--config $ini" || return 1

    if ! wait_for 10 ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_SERVER_IP"; then
        echo "  tunnel never came up"; tail -30 "$client_log"; return 1
    fi
    echo "  redundant: tunnel up"

    if ! grep -F "redundant mode enabled: ports=all" "$client_log" >/dev/null; then
        echo "  FAIL: client log missing 'redundant mode enabled: ports=all'"
        return 1
    fi
    echo "  redundant: client marker present: OK"

    # Sample only once both paths carry copies, or the second path's delta can miss.
    if ! wait_for 10 grep -qE "activated:.*iface=${VETH_B0}" "$client_log"; then
        echo "  FAIL: second path never activated"; tail -30 "$client_log"; return 1
    fi

    # Inner UDP flow, client -> server: iperf3 server in NS_SERVER on the
    # tunnel address. The server-side veth rx_bytes of each path show how
    # many bytes arrived on it.
    ip netns exec "$NS_SERVER" iperf3 -s -B "$TUNNEL_SERVER_IP" -p "$udp_port" -1 \
        >/dev/null 2>&1 &
    local iperf_srv_pid=$!
    sleep 1

    local rx_a_0 rx_b_0 rx_a_1 rx_b_1
    rx_a_0=$(ip netns exec "$NS_SERVER" cat "/sys/class/net/${VETH_A1}/statistics/rx_bytes")
    rx_b_0=$(ip netns exec "$NS_SERVER" cat "/sys/class/net/${VETH_B1}/statistics/rx_bytes")

    local udp_ok=1
    if ! ip netns exec "$NS_CLIENT" iperf3 -c "$TUNNEL_SERVER_IP" -p "$udp_port" \
            -u -b 2M -l 1200 -t 6 >/dev/null 2>&1; then
        udp_ok=0
    fi

    rx_a_1=$(ip netns exec "$NS_SERVER" cat "/sys/class/net/${VETH_A1}/statistics/rx_bytes")
    rx_b_1=$(ip netns exec "$NS_SERVER" cat "/sys/class/net/${VETH_B1}/statistics/rx_bytes")
    kill "$iperf_srv_pid" 2>/dev/null || true
    wait "$iperf_srv_pid" 2>/dev/null || true

    if (( udp_ok != 1 )); then
        echo "  FAIL: inner UDP workload (client -> server) did not complete"
        return 1
    fi

    local d_a=$(( rx_a_1 - rx_a_0 )) d_b=$(( rx_b_1 - rx_b_0 ))
    echo "  redundant: server rx delta path A=${d_a} B=${d_b} bytes"
    # 2 Mbit/s x 6 s is about 1.5 MB of payload per path; duplication puts the
    # whole flow on each path, while a WLB split would give about 0.75 MB each.
    local min_bytes=1400000
    if (( d_a < min_bytes || d_b < min_bytes )); then
        echo "  FAIL: a path received less than ${min_bytes} bytes (A=${d_a} B=${d_b})"
        return 1
    fi
    local lo=$d_a hi=$d_b
    if (( d_b < d_a )); then lo=$d_b; hi=$d_a; fi
    if (( lo * 10 < hi * 8 )); then
        echo "  FAIL: paths unbalanced, min/max < 0.8 (A=${d_a} B=${d_b})"
        return 1
    fi
    echo "  redundant: both paths carried the flow (A=${d_a} B=${d_b}): OK"
    return 0
}

test_scenario_redundant() {
    local server_log="${LOG_DIR}/redundant_server.log"
    local client_log="${LOG_DIR}/redundant_client.log"
    local rc=0
    _redundant_body "$server_log" "$client_log" || rc=1
    finish_scenario "redundant" "$server_log" "$client_log"
    return "$rc"
}

# --- Main runner ---

echo ""
echo "================================================================"
echo " Reinjection E2E"
echo " Binary: $MQVPN"
echo "================================================================"

run_test "scenario off — no marker, reinject_tx_bytes==0"      test_scenario_off
run_test "scenario deadline — stream lane reinjection on path degrade" test_scenario_deadline
run_test "scenario dgram_unrecognized — removed mode warns, runs off" test_scenario_dgram_unrecognized
run_test "scenario redundant — uplink UDP copied on every path"       test_scenario_redundant

echo ""
echo "================================================================"
echo " Results: PASS=$PASS  FAIL=$FAIL"
echo "================================================================"

if (( FAIL > 0 )); then
    exit 1
fi
exit 0
