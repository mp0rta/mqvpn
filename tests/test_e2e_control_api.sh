#!/bin/bash
# test_e2e_control_api.sh — end-to-end test for the v0.4.0 server control API.
#
# Verifies all 5 control commands (add_user / remove_user / list_users / get_stats /
# get_status), the --status CLI, security boundaries (bind addr, malformed input,
# max-users, max-conns), restart resilience, and a scheduler smoke pass across
# minrtt / wlb / backup_fec.
#
# REQUIRES:
#   - root (TUN + netns)
#   - GNU netcat (`nc` with the `-q` flag)
#   - python3
#   - iperf3 (Phase B only)
#   - openssl (used transitively via bench_env_setup.sh for cert generation)
#   - mqvpn binary built with FEC + XOR enabled (Phase F backup_fec iteration);
#     when built without FEC the script skips that iteration with a clear
#     diagnostic (preflight probes for support).
#
# Run manually:
#   sudo bash tests/test_e2e_control_api.sh [path/to/mqvpn]
#
# Exit code: 0 if all phases pass, 1 if any phase fails. No SKIP path.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../benchmarks/bench_env_setup.sh"

MQVPN="${1:-${MQVPN}}"
LOG_DIR="$(mktemp -d)"
CTRL_PORT=9090

# Preserve LOG_DIR on failure so the operator can post-mortem; clean up on
# success. `set -e` exit codes propagate to the trap via $?.
trap '_rc=$?; bench_cleanup; if (( _rc != 0 )); then echo "Logs preserved at: $LOG_DIR" >&2; else rm -rf "$LOG_DIR"; fi' EXIT
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
if [[ -z "$MQVPN" || ! -x "$MQVPN" ]]; then
    echo "ERROR: mqvpn binary not found (pass path as argv[1] or set MQVPN env)" >&2
    exit 2
fi

bench_check_deps

# Probe whether the mqvpn binary supports the backup_fec scheduler. Two cases
# get caught:
#   (1) FEC-disabled current build → main.c emits "requires rebuild ..." at
#       --scheduler parse (see src/main.c:356-363).
#   (2) Pre-backup_fec ancient build → --help has only "minrtt|wlb" and the
#       parser rejects backup_fec with a generic "must be 'minrtt' or 'wlb'".
# The cleanest discriminator is the --help text: backup_fec is mentioned
# only when the binary actually supports it.
MQVPN_HAS_FEC=1
if ! "$MQVPN" --help 2>&1 | grep -q 'backup_fec'; then
    MQVPN_HAS_FEC=0
    echo "NOTE: mqvpn binary lacks backup_fec support; Phase F will skip that iteration."
    echo "      (Build with -DXQC_ENABLE_FEC=ON -DXQC_ENABLE_XOR=ON, or rebuild from"
    echo "      a current source tree if you are using a stale binary.)"
fi

PASS=0
FAIL=0

# --- Control-API helpers ---

# ctrl_send <ns> <addr> <port> <json>  → echoes the response (one JSON object)
# Sends one request, reads up to 16 KiB of response, strips trailing newline.
ctrl_send() {
    local ns="$1" addr="$2" port="$3" json="$4"
    if [[ -n "$ns" ]]; then
        printf '%s' "$json" | ip netns exec "$ns" nc -q1 "$addr" "$port" 2>/dev/null \
            | head -c 16384
    else
        printf '%s' "$json" | nc -q1 "$addr" "$port" 2>/dev/null | head -c 16384
    fi
}

# assert_json_field <response> <key> <expected_json>  → returns 0 if d[key] == expected
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

# assert_json_users_eq <response> <comma-separated user list>  → ignores order
assert_json_users_eq() {
    python3 - "$1" "$2" <<'PY'
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(1)
got = sorted(d.get("users", []))
want = sorted([u for u in sys.argv[2].split(",") if u])
sys.exit(0 if got == want else 1)
PY
}

# assert_json_users_contains <response> <username>
assert_json_users_contains() {
    python3 - "$1" "$2" <<'PY'
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(1)
sys.exit(0 if sys.argv[2] in d.get("users", []) else 1)
PY
}

# assert_json_users_excludes <response> <username>
assert_json_users_excludes() {
    python3 - "$1" "$2" <<'PY'
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(1)
sys.exit(0 if sys.argv[2] not in d.get("users", []) else 1)
PY
}

# wait_for <secs> <bash-cmd>  → polls every 0.2s up to <secs>, returns 0 when cmd succeeds
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

# expect_refused <ns> <addr> <port>  → returns 0 if connection is refused/timed-out
expect_refused() {
    local ns="$1" addr="$2" port="$3"
    if [[ -n "$ns" ]]; then
        ! ip netns exec "$ns" nc -w 2 -z "$addr" "$port" >/dev/null 2>&1
    else
        ! nc -w 2 -z "$addr" "$port" >/dev/null 2>&1
    fi
}

# --- Server launcher (kill+restart pattern; takes flags directly) ---
#
# Generates cert/key/PSK once via bench_start_vpn_server, then kills its server
# and re-launches with the supplied extra flags so we can pass --user / --control-port.
# Caller MUST pass at least: --auth-key "$_BENCH_PSK" --control-port $CTRL_PORT
# Caller MAY pass: --user NAME:KEY (repeatable), --scheduler X, --control-addr Y
#
# After this returns, the server runs as $_BENCH_SERVER_PID, log goes to $1.
start_server_with_flags() {
    local server_log="$1"
    shift
    # Run bench_start_vpn_server with output captured to a per-call log so
    # cert/PSK setup failures (e.g., openssl missing) can be inspected after
    # the fact. The function's own success/failure is reflected in `_BENCH_PSK`
    # and the server.crt/.key files; don't `|| true` it without re-checking.
    if ! bench_start_vpn_server >"${server_log}.bringup" 2>&1; then
        echo "  bench_start_vpn_server failed; tail of bringup log:" >&2
        tail -20 "${server_log}.bringup" >&2
        return 1
    fi
    kill "$_BENCH_SERVER_PID" 2>/dev/null || true
    wait "$_BENCH_SERVER_PID" 2>/dev/null || true

    ip netns exec "$NS_SERVER" "$MQVPN" --mode server \
        --listen "0.0.0.0:${VPN_LISTEN_PORT}" \
        --subnet 10.0.0.0/24 \
        --cert "$_BENCH_WORK_DIR/server.crt" \
        --key "$_BENCH_WORK_DIR/server.key" \
        --log-level "$BENCH_LOG_LEVEL" \
        "$@" \
        >"$server_log" 2>&1 &
    _BENCH_SERVER_PID=$!
    sleep 1

    # Confirm the server is alive
    if ! kill -0 "$_BENCH_SERVER_PID" 2>/dev/null; then
        echo "  ERROR: server failed to start; tail of $server_log:" >&2
        tail -20 "$server_log" >&2
        return 1
    fi
    return 0
}

# --- Client launcher with a custom auth-key ---
#
# bench_start_vpn_client always uses $_BENCH_PSK; we need to authenticate as
# alice / dave / etc. with their per-user keys. Mirrors the helper at
# bench_env_setup.sh:162 but takes the auth-key as the first argument.
#
# Tracks PID in $_BENCH_CLIENT_PID so bench_cleanup still works.
start_client_with_auth_key() {
    local auth_key="$1"
    local client_log="$2"
    local extra_flags="$3"  # e.g. "--scheduler backup_fec"

    # Stop any prior client
    if [[ -n "$_BENCH_CLIENT_PID" ]]; then
        kill "$_BENCH_CLIENT_PID" 2>/dev/null || true
        wait "$_BENCH_CLIENT_PID" 2>/dev/null || true
        _BENCH_CLIENT_PID=""
    fi

    # NOTE: --server uses IP_A_SERVER_ADDR (the physical Path-A listen IP, 10.100.0.1),
    # NOT TUNNEL_SERVER_IP (which is the VPN VIP — that doesn't exist until the tunnel
    # is up). bench_start_vpn_client also uses IP_A_SERVER_ADDR (bench_env_setup.sh:176).
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

# Convenience: send a control-API command from inside NS_SERVER on 127.0.0.1.
# Guards against empty responses (which usually mean the server died) so the
# resulting assertion fails at the source instead of in some downstream JSON
# parse.
ctrl_local() {
    local r
    r=$(ctrl_send "$NS_SERVER" 127.0.0.1 "$CTRL_PORT" "$1")
    if [[ -z "$r" ]]; then
        echo "  ctrl_local: empty response (server may be dead)" >&2
        return 1
    fi
    printf '%s' "$r"
}

# --- run_test wrapper ---

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
    # Each phase is responsible for its own teardown — main runner doesn't
    # call bench_cleanup here, because some phases share a server across calls.
}

# --- Phase A: basic command coverage (no client) ---

test_phase_a_basic() {
    local server_log="${LOG_DIR}/phase_a_server.log"

    bench_setup_netns
    start_server_with_flags "$server_log" \
        --auth-key "$_BENCH_PSK" \
        --control-port "$CTRL_PORT" \
        --user alice:secret_a \
        --user bob:secret_b \
        || return 1

    # list_users baseline
    local resp
    resp=$(ctrl_local '{"cmd":"list_users"}')
    if ! assert_json_field "$resp" ok true; then
        echo "  list_users: bad response: $resp"; return 1
    fi
    if ! assert_json_users_eq "$resp" "alice,bob"; then
        echo "  list_users baseline mismatch: $resp"; return 1
    fi
    echo "  list_users baseline: OK"

    # add_user carol
    resp=$(ctrl_local '{"cmd":"add_user","name":"carol","key":"secret_c"}')
    if ! assert_json_field "$resp" ok true; then
        echo "  add_user carol failed: $resp"; return 1
    fi
    resp=$(ctrl_local '{"cmd":"list_users"}')
    if ! assert_json_users_contains "$resp" "carol"; then
        echo "  list_users does not include carol: $resp"; return 1
    fi
    echo "  add_user carol: OK"

    # remove_user carol
    resp=$(ctrl_local '{"cmd":"remove_user","name":"carol"}')
    if ! assert_json_field "$resp" ok true; then
        echo "  remove_user carol failed: $resp"; return 1
    fi
    resp=$(ctrl_local '{"cmd":"list_users"}')
    if ! assert_json_users_excludes "$resp" "carol"; then
        echo "  list_users still has carol: $resp"; return 1
    fi
    echo "  remove_user carol: OK"

    # add_user with missing key
    resp=$(ctrl_local '{"cmd":"add_user","name":"eve"}')
    if ! assert_json_field "$resp" ok false; then
        echo "  add_user-missing-key should have ok=false: $resp"; return 1
    fi
    if [[ "$resp" != *"required"* ]]; then
        echo "  add_user-missing-key error not 'required': $resp"; return 1
    fi
    echo "  add_user missing key: OK"

    # remove_user nonexistent
    resp=$(ctrl_local '{"cmd":"remove_user","name":"ghost"}')
    if ! assert_json_field "$resp" ok false; then
        echo "  remove_user-ghost should have ok=false: $resp"; return 1
    fi
    if [[ "$resp" != *"not found"* ]]; then
        echo "  remove_user-ghost error not 'not found': $resp"; return 1
    fi
    echo "  remove_user nonexistent: OK"

    # get_stats baseline
    resp=$(ctrl_local '{"cmd":"get_stats"}')
    if ! assert_json_field "$resp" ok true; then echo "  get_stats: $resp"; return 1; fi
    if ! assert_json_field "$resp" n_clients 0; then echo "  n_clients != 0: $resp"; return 1; fi
    if ! assert_json_field "$resp" bytes_tx 0; then echo "  bytes_tx != 0: $resp"; return 1; fi
    if ! assert_json_field "$resp" bytes_rx 0; then echo "  bytes_rx != 0: $resp"; return 1; fi
    echo "  get_stats baseline: OK"

    # get_status baseline
    resp=$(ctrl_local '{"cmd":"get_status"}')
    if ! assert_json_field "$resp" ok true; then echo "  get_status: $resp"; return 1; fi
    if ! assert_json_field "$resp" n_clients 0; then echo "  n_clients != 0: $resp"; return 1; fi
    if ! assert_json_field "$resp" clients '[]'; then echo "  clients != []: $resp"; return 1; fi
    echo "  get_status baseline: OK"

    # --status CLI must run inside NS_SERVER
    if ! ip netns exec "$NS_SERVER" "$MQVPN" --status --control-port "$CTRL_PORT" >/dev/null 2>&1; then
        echo "  --status CLI exit nonzero"; return 1
    fi
    echo "  --status CLI: OK"

    return 0
}

# --- Phase B: active session counters ---

test_phase_b_active_session() {
    # Reuse the server left running by phase A (same netns, same CTRL_PORT).
    # If bench_cleanup was called in between, this will fail — that is intentional.
    local client_log="${LOG_DIR}/phase_b_client.log"

    # Connect a client as alice
    start_client_with_auth_key "secret_a" "$client_log" || return 1

    # Wait up to 10s for tunnel to come up via ping
    if ! wait_for 10 ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_SERVER_IP"; then
        echo "  tunnel never came up"; tail -20 "$client_log"; return 1
    fi
    echo "  client connected: OK"

    # Drive 5s of iperf3 traffic (client NS → server VIP)
    ip netns exec "$NS_SERVER" iperf3 -s -1 -D --logfile "${LOG_DIR}/phase_b_iperf3_server.log" || true
    sleep 0.2
    ip netns exec "$NS_CLIENT" iperf3 -c "$TUNNEL_SERVER_IP" -t 5 \
        >"${LOG_DIR}/phase_b_iperf3_client1.log" 2>&1 || true
    sleep 1

    # get_stats: n_clients >= 1 and bytes_tx + bytes_rx > 0
    local resp
    resp=$(ctrl_local '{"cmd":"get_stats"}')
    if ! assert_json_field "$resp" ok true; then
        echo "  get_stats failed: $resp"; return 1
    fi
    local bytes_total
    bytes_total=$(python3 - "$resp" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
print(d.get("bytes_tx", 0) + d.get("bytes_rx", 0))
PY
)
    if (( bytes_total <= 0 )); then
        echo "  bytes_tx + bytes_rx == 0 after iperf3 burst (got $bytes_total): $resp"; return 1
    fi
    echo "  get_stats bytes_total=$bytes_total: OK"

    # get_status: clients[0].user == "alice", paths populated, pkt_sent > 0
    resp=$(ctrl_local '{"cmd":"get_status"}')
    if ! assert_json_field "$resp" ok true; then
        echo "  get_status failed: $resp"; return 1
    fi
    local check_status
    check_status=$(python3 - "$resp" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
clients = d.get("clients", [])
if not clients:
    print("no clients"); sys.exit(1)
c = clients[0]
if c.get("user") != "alice":
    print(f"user={c.get('user')} want alice"); sys.exit(1)
paths = c.get("paths") or []
if not paths:
    print("paths empty"); sys.exit(1)
# pkt_sent is per-path (control_socket.c:169); sum across paths.
total_pkt_sent = sum(p.get("pkt_sent", 0) for p in paths)
if total_pkt_sent <= 0:
    print(f"total pkt_sent across paths = {total_pkt_sent}"); sys.exit(1)
print("ok")
PY
)
    if [[ "$check_status" != "ok" ]]; then
        echo "  get_status check failed ($check_status): $resp"; return 1
    fi
    echo "  get_status alice/paths/pkt_sent: OK"

    # Second iperf3 burst — byte total must grow
    ip netns exec "$NS_SERVER" iperf3 -s -1 -D --logfile "${LOG_DIR}/phase_b_iperf3_server2.log" || true
    sleep 0.2
    ip netns exec "$NS_CLIENT" iperf3 -c "$TUNNEL_SERVER_IP" -t 5 \
        >"${LOG_DIR}/phase_b_iperf3_client2.log" 2>&1 || true
    sleep 1

    local resp2
    resp2=$(ctrl_local '{"cmd":"get_stats"}')
    local bytes_total2
    bytes_total2=$(python3 - "$resp2" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
print(d.get("bytes_tx", 0) + d.get("bytes_rx", 0))
PY
)
    if (( bytes_total2 <= bytes_total )); then
        echo "  byte total did not grow after 2nd burst ($bytes_total2 <= $bytes_total)"; return 1
    fi
    echo "  byte total grew ($bytes_total -> $bytes_total2): OK"

    # --status CLI must exit 0 AND print non-empty output (run inside NS_SERVER).
    # run_test calls phase functions via `if "$@"`, which silences `set -e`,
    # so we cannot rely on it for exit-code propagation; check explicitly.
    local status_out
    if ! status_out=$(ip netns exec "$NS_SERVER" "$MQVPN" --status --control-port "$CTRL_PORT" 2>&1); then
        echo "  --status CLI exited nonzero: $status_out"; return 1
    fi
    if [[ -z "$status_out" ]]; then
        echo "  --status CLI produced empty output"; return 1
    fi
    echo "  --status CLI non-empty: OK"

    # Teardown: stop client (server stays up for any subsequent phases)
    if [[ -n "$_BENCH_CLIENT_PID" ]]; then
        kill "$_BENCH_CLIENT_PID" 2>/dev/null || true
        wait "$_BENCH_CLIENT_PID" 2>/dev/null || true
        _BENCH_CLIENT_PID=""
    fi

    return 0
}

# --- Phase C: user lifecycle with immediate-kick on remove_user ---

# `xqc_h3_conn_close` is asynchronous: it queues a CONNECTION_CLOSE frame and
# only triggers `cb_h3_conn_close` (which removes the entry from
# `s->sessions[]`) once the close handshake completes. Localhost veth makes
# this sub-second on a healthy box, but we keep a generous budget so the
# assertion is "kick happens within a few seconds" rather than a precise
# timing test.
KICK_OBSERVE_SEC=10

# Helper used by wait_for to poll get_status until n_clients drops to 0.
# Defined as a named function rather than inlined into `bash -c "..."` because
# bash does not export shell functions to subshells by default, so embedded
# `ctrl_local` calls would fail.
_phase_c_status_dropped_dave() {
    local r
    r=$(ctrl_local '{"cmd":"get_status"}') || return 1
    python3 - "$r" <<'PY'
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(1)
sys.exit(0 if d.get('n_clients', 1) == 0 else 1)
PY
}

test_phase_c_lifecycle() {
    local server_log="${LOG_DIR}/phase_c_server.log"
    local client_log="${LOG_DIR}/phase_c_client.log"

    # Tear down Phase B and start a fresh server with the same boot user set.
    bench_cleanup
    bench_setup_netns
    start_server_with_flags "$server_log" \
        --auth-key "$_BENCH_PSK" \
        --control-port "$CTRL_PORT" \
        --user alice:secret_a \
        --user bob:secret_b \
        || return 1

    # Sanity check
    local resp
    resp=$(ctrl_local '{"cmd":"list_users"}')
    if ! assert_json_users_eq "$resp" "alice,bob"; then
        echo "  fresh server users mismatch: $resp"; return 1
    fi

    # add_user dave
    resp=$(ctrl_local '{"cmd":"add_user","name":"dave","key":"secret_d"}')
    if ! assert_json_field "$resp" ok true; then echo "  add_user dave: $resp"; return 1; fi
    echo "  add_user dave: OK"

    # Connect dave's client (uses runtime-added user; verifies immediate effect)
    start_client_with_auth_key secret_d "$client_log" "" || return 1
    if ! wait_for 10 ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_SERVER_IP"; then
        echo "  dave tunnel never came up"; tail -20 "$client_log"; return 1
    fi

    # get_status shows dave
    resp=$(ctrl_local '{"cmd":"get_status"}')
    local user
    user=$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d['clients'][0]['user'] if d.get('clients') else '')" "$resp")
    if [[ "$user" != "dave" ]]; then echo "  status user=$user expected dave: $resp"; return 1; fi
    echo "  runtime add_user → new client connects as dave: OK"

    # remove_user dave  (kick contract starts here)
    resp=$(ctrl_local '{"cmd":"remove_user","name":"dave"}')
    if ! assert_json_field "$resp" ok true; then echo "  remove_user dave: $resp"; return 1; fi

    # list_users no longer contains dave
    resp=$(ctrl_local '{"cmd":"list_users"}')
    if ! assert_json_users_excludes "$resp" "dave"; then
        echo "  list_users still contains dave: $resp"; return 1
    fi

    # Within KICK_OBSERVE_SEC: get_status drops dave.
    # Use the named helper `_phase_c_status_dropped_dave` (defined just above
    # this phase function) rather than inlining `bash -c "..."` with embedded
    # ctrl_local references; functions are not exported to subshells.
    if ! wait_for "$KICK_OBSERVE_SEC" _phase_c_status_dropped_dave; then
        echo "  get_status did not drop dave within ${KICK_OBSERVE_SEC}s"
        echo "  --- last 30 lines of $server_log ---"
        tail -30 "$server_log" 2>/dev/null
        echo "  --- last response from get_status ---"
        ctrl_local '{"cmd":"get_status"}' 2>/dev/null
        return 1
    fi
    echo "  remove_user kicks active session within ${KICK_OBSERVE_SEC}s: OK"

    # Inner ping now fails
    if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
        echo "  inner ping still succeeds after kick"; return 1
    fi
    echo "  inner ping fails after kick: OK"

    # Reconnect attempt with secret_d is rejected.
    # Asserting only "ping fails" is too weak (client could die for unrelated
    # reasons). Asserting only client-side log is also weak (we'd be testing the
    # client's error reporting, not the server's auth-revoke). Assert the
    # server-side authoritative signal:
    #   (a) inner ping fails (tunnel never came up)
    #   (b) get_status still shows zero clients (nobody slipped through auth)
    #   (c) server log records "authentication failed" (mqvpn_server.c:801) —
    #       this is the load-bearing assertion that the server rejected the
    #       request specifically because the credential was revoked.
    local reconnect_log="${LOG_DIR}/phase_c_reconnect.log"
    start_client_with_auth_key secret_d "$reconnect_log" "" || return 1
    sleep 4

    # (a) Inner ping must fail
    if ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
        echo "  reconnect with revoked secret_d unexpectedly succeeded (ping)"; return 1
    fi

    # (b) Server-side: still 0 clients
    resp=$(ctrl_local '{"cmd":"get_status"}')
    local status_n
    status_n=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('n_clients',1))" "$resp")
    if (( status_n != 0 )); then
        echo "  reconnect: server reports n_clients=$status_n, expected 0: $resp"; return 1
    fi

    # (c) Server log must contain "authentication failed" emitted from
    # mqvpn_server.c:801 ("authentication failed: invalid or missing PSK").
    # `$server_log` was set at the top of this phase function.
    if ! grep -q 'authentication failed' "$server_log" 2>/dev/null; then
        echo "  reconnect: server log lacks 'authentication failed' message"
        echo "  --- last 30 lines of $server_log ---"
        tail -30 "$server_log"
        return 1
    fi
    echo "  reconnect with revoked key rejected (server-side auth fail confirmed): OK"

    # Stop the rejected client so cleanup is clean
    if [[ -n "$_BENCH_CLIENT_PID" ]]; then
        kill "$_BENCH_CLIENT_PID" 2>/dev/null || true
        wait "$_BENCH_CLIENT_PID" 2>/dev/null || true
        _BENCH_CLIENT_PID=""
    fi

    return 0
}

# --- Phase D: security & robustness ---

test_phase_d_security() {
    local server_log="${LOG_DIR}/phase_d_server.log"

    # Fresh server, default bind (127.0.0.1)
    bench_cleanup
    bench_setup_netns
    start_server_with_flags "$server_log" \
        --auth-key "$_BENCH_PSK" \
        --control-port "$CTRL_PORT" \
        || return 1

    # D1 — default bind: NS_SERVER 127.0.0.1 succeeds, NS_CLIENT veth IP refused
    local resp
    resp=$(ctrl_local '{"cmd":"list_users"}')
    if ! assert_json_field "$resp" ok true; then
        echo "  D1 NS_SERVER 127.0.0.1 should succeed: $resp"; return 1
    fi
    # NS_SERVER's veth IP on Path A is the well-known IP_A_SERVER_ADDR (10.100.0.1).
    # NB: the device on the server side is VETH_A1, not VETH_A0 — VETH_A0 is moved
    # to NS_CLIENT at bench_env_setup.sh:79. Use the IP directly to avoid lookups.
    local server_veth_ip="$IP_A_SERVER_ADDR"
    if ! expect_refused "$NS_CLIENT" "$server_veth_ip" "$CTRL_PORT"; then
        echo "  D1 NS_CLIENT $server_veth_ip:$CTRL_PORT should be refused"; return 1
    fi
    echo "  D1 default bind: OK"

    # D2 — --control-addr 0.0.0.0
    bench_cleanup
    bench_setup_netns
    start_server_with_flags "$server_log" \
        --auth-key "$_BENCH_PSK" \
        --control-port "$CTRL_PORT" \
        --control-addr 0.0.0.0 \
        || return 1
    # IP_A_SERVER_ADDR is stable across netns recreates (it's a constant in bench_env_setup.sh).
    server_veth_ip="$IP_A_SERVER_ADDR"
    resp=$(ctrl_send "$NS_CLIENT" "$server_veth_ip" "$CTRL_PORT" '{"cmd":"list_users"}')
    if ! assert_json_field "$resp" ok true; then
        echo "  D2 --control-addr 0.0.0.0 from NS_CLIENT should succeed: $resp"; return 1
    fi
    echo "  D2 --control-addr 0.0.0.0: OK"

    # Restart with default bind for D3-D6
    bench_cleanup
    bench_setup_netns
    start_server_with_flags "$server_log" \
        --auth-key "$_BENCH_PSK" \
        --control-port "$CTRL_PORT" \
        || return 1

    # D3 — missing cmd
    resp=$(ctrl_local '{}')
    if [[ "$resp" != *"missing cmd"* ]]; then
        echo "  D3 missing cmd: $resp"; return 1
    fi
    echo "  D3 missing cmd: OK"

    # D4 — unknown cmd
    resp=$(ctrl_local '{"cmd":"shutdown"}')
    if [[ "$resp" != *"unknown cmd"* ]]; then
        echo "  D4 unknown cmd: $resp"; return 1
    fi
    echo "  D4 unknown cmd: OK"

    # D5a — partial JSON closed by EOF (returns "name and key required")
    resp=$(ctrl_local '{"cmd":"add_user"')
    if [[ "$resp" != *"required"* ]]; then
        echo "  D5a truncated EOF: $resp"; return 1
    fi
    # Server still responsive
    resp=$(ctrl_local '{"cmd":"list_users"}')
    if ! assert_json_field "$resp" ok true; then echo "  D5a follow-up failed: $resp"; return 1; fi
    echo "  D5a partial JSON via EOF returns 'required' error: OK"

    # D5b — partial JSON held open (no EOF, idle timeout closes silently with no response)
    local d5b_out
    d5b_out=$(timeout 8 bash -c "
        (printf '{\"cmd\":\"add_user\"'; sleep 7) | ip netns exec '$NS_SERVER' nc 127.0.0.1 '$CTRL_PORT' 2>/dev/null
    " || true)
    if [[ -n "$d5b_out" ]]; then
        echo "  D5b expected silent close (empty output) but got: $d5b_out"; return 1
    fi
    # Server still responsive
    resp=$(ctrl_local '{"cmd":"list_users"}')
    if ! assert_json_field "$resp" ok true; then echo "  D5b follow-up failed: $resp"; return 1; fi
    echo "  D5b partial JSON held open closes silently: OK"

    # D6 — oversized request (8 KB)
    local big_payload
    big_payload=$(python3 -c "import sys; sys.stdout.write('{\"cmd\":\"add_user\",\"name\":\"a\",\"key\":\"' + 'x'*8192 + '\"}')")
    resp=$(printf '%s' "$big_payload" | ip netns exec "$NS_SERVER" nc -q1 127.0.0.1 "$CTRL_PORT" 2>/dev/null | head -c 16384 || true)
    # Either some JSON-shaped response or empty close — both acceptable, just no crash
    sleep 1
    resp=$(ctrl_local '{"cmd":"list_users"}')
    if ! assert_json_field "$resp" ok true; then echo "  D6 follow-up failed (server may have crashed): $resp"; return 1; fi
    echo "  D6 oversized request handled, server still responsive: OK"

    # D7 — max users on a fresh empty-table server
    bench_cleanup
    bench_setup_netns
    start_server_with_flags "$server_log" \
        --auth-key "$_BENCH_PSK" \
        --control-port "$CTRL_PORT" \
        || return 1
    local d7_succ=0
    local d7_fail=0
    for i in $(seq 1 70); do
        resp=$(ctrl_local "{\"cmd\":\"add_user\",\"name\":\"u$i\",\"key\":\"k$i\"}")
        if assert_json_field "$resp" ok true; then
            d7_succ=$((d7_succ + 1))
        elif [[ "$resp" == *"add_user failed"* ]]; then
            d7_fail=$((d7_fail + 1))
        fi
    done
    if (( d7_succ != 64 )); then
        echo "  D7 expected 64 successes, got $d7_succ"; return 1
    fi
    if (( d7_fail < 6 )); then
        echo "  D7 expected ≥6 'add_user failed' errors, got $d7_fail"; return 1
    fi
    echo "  D7 max users: 64 succ + $d7_fail fail: OK"

    # D8 — concurrent connections (max-conns enforcement)
    bench_cleanup
    bench_setup_netns
    start_server_with_flags "$server_log" \
        --auth-key "$_BENCH_PSK" \
        --control-port "$CTRL_PORT" \
        || return 1

    # Open 8 connections that hold for ~4s (long enough for the retry loop below
    # to register all 8 on the server before timing out).
    local d8_holders=()
    for i in $(seq 1 8); do
        ip netns exec "$NS_SERVER" bash -c "(sleep 4) | nc 127.0.0.1 $CTRL_PORT >/dev/null 2>&1" &
        d8_holders+=("$!")
    done

    # The original "sleep 0.3 then send 9th" pattern races on busy hosts because
    # we have no way to poll n_conns from the control API. Instead, retry the
    # 9th connection up to 20 times (200 ms each = 4 s budget) until we observe
    # either the expected "too many connections" error OR the budget runs out.
    # This converges in ≤1 retry on a normal box but tolerates a slow netns boot.
    local resp9=""
    local attempts=0
    while (( attempts < 20 )); do
        resp9=$(ctrl_local '{"cmd":"x"}' || true)
        if [[ "$resp9" == *"too many connections"* ]]; then
            break
        fi
        sleep 0.2
        attempts=$((attempts + 1))
    done
    # Wait ONLY for the holder PIDs — bare `wait` would also wait on the
    # mqvpn server (which is also a backgrounded job in this shell) and hang
    # the test forever. Guard each `wait` with `|| true` because some `nc`
    # implementations return nonzero when the server closes on empty input.
    local h
    for h in "${d8_holders[@]}"; do
        wait "$h" 2>/dev/null || true
    done

    if [[ "$resp9" != *"too many connections"* ]]; then
        echo "  D8 9th connection never got 'too many connections' (last resp: $resp9)"; return 1
    fi
    echo "  D8 max-conns enforcement (after $attempts retries): OK"

    # Server recovered: list_users succeeds
    sleep 1
    resp=$(ctrl_local '{"cmd":"list_users"}')
    if ! assert_json_field "$resp" ok true; then
        echo "  D8 server did not recover: $resp"; return 1
    fi
    echo "  D8 server recovered after holders released: OK"

    return 0
}

# --- Phase E: restart does not persist runtime users ---

test_phase_e_restart() {
    local server_log="${LOG_DIR}/phase_e_server.log"
    bench_cleanup
    bench_setup_netns
    start_server_with_flags "$server_log" \
        --auth-key "$_BENCH_PSK" \
        --control-port "$CTRL_PORT" \
        || return 1

    # Add two runtime users
    local resp
    resp=$(ctrl_local '{"cmd":"add_user","name":"erin","key":"secret_e"}')
    assert_json_field "$resp" ok true || { echo "  add erin: $resp"; return 1; }
    resp=$(ctrl_local '{"cmd":"add_user","name":"frank","key":"secret_f"}')
    assert_json_field "$resp" ok true || { echo "  add frank: $resp"; return 1; }
    resp=$(ctrl_local '{"cmd":"list_users"}')
    if ! assert_json_users_eq "$resp" "erin,frank"; then
        echo "  pre-restart users != [erin,frank]: $resp"; return 1
    fi
    echo "  pre-restart users: OK"

    # SIGTERM the running server, wait for exit.
    kill -TERM "$_BENCH_SERVER_PID" 2>/dev/null || true
    wait "$_BENCH_SERVER_PID" 2>/dev/null || true

    # Restart with the IDENTICAL flags. Append (>>) instead of truncate (>)
    # so the pre-restart log is preserved — useful for post-mortem if the
    # restart itself fails (we want to see what the original server logged).
    ip netns exec "$NS_SERVER" "$MQVPN" --mode server \
        --listen "0.0.0.0:${VPN_LISTEN_PORT}" \
        --subnet 10.0.0.0/24 \
        --cert "$_BENCH_WORK_DIR/server.crt" \
        --key "$_BENCH_WORK_DIR/server.key" \
        --log-level "$BENCH_LOG_LEVEL" \
        --auth-key "$_BENCH_PSK" \
        --control-port "$CTRL_PORT" \
        >>"$server_log" 2>&1 &
    _BENCH_SERVER_PID=$!
    sleep 2

    if ! kill -0 "$_BENCH_SERVER_PID" 2>/dev/null; then
        echo "  restart failed; tail of log:"; tail -20 "$server_log"; return 1
    fi

    # New list_users must be empty
    resp=$(ctrl_local '{"cmd":"list_users"}')
    if ! assert_json_users_eq "$resp" ""; then
        echo "  post-restart users != []: $resp"; return 1
    fi
    echo "  post-restart users empty (runtime users not persisted): OK"

    return 0
}

# --- Phase F: scheduler matrix smoke ---

# Helper: _phase_f_one <scheduler>
# Tear down, fresh netns, start server and client with the given scheduler,
# drive ping, and assert clients[0].paths non-empty, pkt_sent > 0, bytes_tx > 0.
_phase_f_one() {
    local sched="$1"
    local server_log="${LOG_DIR}/phase_f_server_${sched}.log"
    local client_log="${LOG_DIR}/phase_f_client_${sched}.log"

    # Tear down prior state and set up fresh netns
    bench_cleanup
    bench_setup_netns

    # Start server with the given scheduler and alice
    start_server_with_flags "$server_log" \
        --auth-key "$_BENCH_PSK" \
        --control-port "$CTRL_PORT" \
        --scheduler "$sched" \
        --user alice:secret_a \
        || { echo "  server failed for scheduler=$sched"; return 1; }

    # Start client with the same scheduler
    start_client_with_auth_key secret_a "$client_log" "--scheduler $sched" || return 1

    # Wait up to 10s for tunnel to come up via ping
    if ! wait_for 10 ip netns exec "$NS_CLIENT" ping -c 1 -W 1 "$TUNNEL_SERVER_IP"; then
        echo "  scheduler=$sched: tunnel never came up"
        tail -20 "$client_log" >&2
        return 1
    fi
    echo "  scheduler=$sched: tunnel up"

    # Drive ping -c 5 to generate traffic
    ip netns exec "$NS_CLIENT" ping -c 5 "$TUNNEL_SERVER_IP" >/dev/null 2>&1 || true
    sleep 1

    # Assert clients[0].paths non-empty, pkt_sent > 0, bytes_tx > 0
    local resp
    resp=$(ctrl_local '{"cmd":"get_status"}')
    if ! assert_json_field "$resp" ok true; then
        echo "  scheduler=$sched: get_status failed: $resp"; return 1
    fi

    local check_paths
    check_paths=$(python3 - "$resp" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
clients = d.get("clients", [])
if not clients:
    print("no clients"); sys.exit(1)
c = clients[0]
paths = c.get("paths") or []
if not paths:
    print("paths empty"); sys.exit(1)
# pkt_sent is per-path (control_socket.c:169); sum across paths.
total_pkt_sent = sum(p.get("pkt_sent", 0) for p in paths)
if total_pkt_sent <= 0:
    print(f"total pkt_sent across paths = {total_pkt_sent}"); sys.exit(1)
print("ok")
PY
)
    if [[ "$check_paths" != "ok" ]]; then
        echo "  scheduler=$sched: paths/pkt_sent check failed ($check_paths): $resp"; return 1
    fi

    # Check bytes_tx via get_stats
    local resp_stats
    resp_stats=$(ctrl_local '{"cmd":"get_stats"}')
    if ! assert_json_field "$resp_stats" ok true; then
        echo "  scheduler=$sched: get_stats failed: $resp_stats"; return 1
    fi

    local bytes_tx
    bytes_tx=$(python3 - "$resp_stats" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
print(d.get("bytes_tx", 0))
PY
)
    if (( bytes_tx <= 0 )); then
        echo "  scheduler=$sched: bytes_tx=$bytes_tx (expected > 0): $resp_stats"; return 1
    fi

    echo "  scheduler=$sched: OK (paths OK, pkt_sent OK, bytes_tx=$bytes_tx)"
    return 0
}

test_phase_f_scheduler_smoke() {
    local sched
    for sched in minrtt wlb backup_fec; do
        if [[ "$sched" == "backup_fec" && "$MQVPN_HAS_FEC" -eq 0 ]]; then
            echo "  scheduler=backup_fec: skipped (binary built without FEC; see preflight NOTE)"
            continue
        fi
        if ! _phase_f_one "$sched"; then
            return 1
        fi
    done
    return 0
}

# --- Main runner ---

# (empty for this chunk; phases will be wired in their own chunks)

# --- Summary ---

echo ""
echo "================================================================"
echo " Server control API E2E"
echo " Binary: $MQVPN"
echo "================================================================"

run_test "phase_a basic command coverage" test_phase_a_basic
run_test "phase_b active session" test_phase_b_active_session
run_test "phase_c user lifecycle (immediate-revoke)" test_phase_c_lifecycle
run_test "phase_d security & robustness" test_phase_d_security
run_test "phase_e restart resilience" test_phase_e_restart
run_test "phase_f scheduler matrix smoke" test_phase_f_scheduler_smoke

echo ""
echo "================================================================"
echo " Results: PASS=$PASS  FAIL=$FAIL"
echo "================================================================"

if (( FAIL > 0 )); then
    exit 1
fi
exit 0
