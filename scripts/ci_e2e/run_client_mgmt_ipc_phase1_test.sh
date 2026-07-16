#!/bin/bash
# run_client_mgmt_ipc_phase1_test.sh — Phase 1 integration test for the
# mqvpnctl management CLI (src/cli/) against the OS-neutral CMP dispatcher
# (src/mgmt/) driven over the mgmt_endpoint_host test harness
# (tests/mgmt_endpoint_host.c). No sudo, no netns — everything here is a
# plain Unix domain socket.
#
# Covers T1-T13:
#   T1  host startup / socket appears
#   T2  `mqvpnctl version` (text) against a live endpoint
#   T3  `mqvpnctl --json version` against a live endpoint
#   T4  endpoint unreachable -> exit 5, text + --json "unavailable"
#   T5  malformed request survives, connection stays usable
#   T6  oversized request is rejected, endpoint stays usable
#   T7  4 pipelined requests on one persistent connection, ids in order
#   T8a raw hello with an unsupported protocol -> PROTOCOL_INCOMPATIBLE
#   T8b `mqvpnctl version` against an incompatible endpoint -> exit 9
#   T9  mqvpnctl links neither libmqvpn, xquic, nor libevent
#   T10 two concurrent `mqvpnctl version` invocations both succeed
#   T11 `mqvpnctl --timeout 1 version` against a silent endpoint -> exit 8
#   T12 `mgmt_endpoint_host --mode 0640` produces a 0640 socket
#   T13 permission boundary (root-only; SKIP under non-root)
#
# Usage: scripts/ci_e2e/run_client_mgmt_ipc_phase1_test.sh [build-dir]
# Exit code: 0 if all run tests pass, 1 if any fails.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

BUILD_DIR="${1:-build-lib}"
if [[ "${BUILD_DIR}" != /* ]]; then
    BUILD_DIR="${REPO_ROOT}/${BUILD_DIR}"
fi

MQVPNCTL="${BUILD_DIR}/mqvpnctl"
HOST_BIN="${BUILD_DIR}/tests/mgmt_endpoint_host"

# --- Preflight ---

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not on PATH" >&2
    exit 2
fi
if [[ ! -x "${MQVPNCTL}" ]]; then
    echo "ERROR: mqvpnctl binary not found or not executable: ${MQVPNCTL}" >&2
    exit 2
fi
if [[ ! -x "${HOST_BIN}" ]]; then
    echo "ERROR: mgmt_endpoint_host binary not found or not executable: ${HOST_BIN}" >&2
    exit 2
fi

TMPD="$(mktemp -d)"
declare -a BG_PIDS=()

cleanup() {
    local pid
    for pid in "${BG_PIDS[@]:-}"; do
        [[ -n "${pid}" ]] && kill "${pid}" >/dev/null 2>&1
    done
    for pid in "${BG_PIDS[@]:-}"; do
        [[ -n "${pid}" ]] && wait "${pid}" 2>/dev/null
    done
    rm -rf "${TMPD}"
}
trap cleanup EXIT

echo "mqvpnctl:         ${MQVPNCTL}"
echo "mgmt_endpoint_host: ${HOST_BIN}"
echo "Scratch dir:       ${TMPD}"

PASS=0
FAIL=0

run_test() {
    local name="$1"
    shift
    echo ""
    echo "--- Test: ${name} ---"
    if "$@"; then
        echo "  PASS: ${name}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: ${name}"
        FAIL=$((FAIL + 1))
    fi
}

# start_host <sock-path> [extra host args...]
# Starts mgmt_endpoint_host in the background, tracks its pid for cleanup,
# and echoes the pid on stdout (capture with $(...)).
start_host() {
    local sock="$1"
    shift
    "${HOST_BIN}" "${sock}" "$@" >"${TMPD}/host_$(basename "${sock}").log" 2>&1 &
    local pid=$!
    BG_PIDS+=("${pid}")
    echo "${pid}"
}

# wait_for_socket <path> [timeout-seconds, default 5]
# Polls (no fixed sleep) until the AF_UNIX socket file appears.
wait_for_socket() {
    local sock="$1"
    local timeout="${2:-5}"
    local waited_ms=0
    while [[ ! -S "${sock}" ]]; do
        sleep 0.05
        waited_ms=$((waited_ms + 50))
        if (( waited_ms > timeout * 1000 )); then
            return 1
        fi
    done
    return 0
}

# ── T1 ──────────────────────────────────────────────────────────────────
SOCK_MAIN="${TMPD}/main.sock"
HOST_MAIN_PID=""

test_t1() {
    HOST_MAIN_PID="$(start_host "${SOCK_MAIN}")"
    wait_for_socket "${SOCK_MAIN}" 5
}
run_test "T1 host startup / socket appears" test_t1

# ── T2 ──────────────────────────────────────────────────────────────────
test_t2() {
    local out
    out="$("${MQVPNCTL}" --endpoint "unix://${SOCK_MAIN}" version 2>&1)"
    local rc=$?
    echo "${out}"
    [[ ${rc} -eq 0 ]] || { echo "  unexpected exit ${rc}"; return 1; }
    [[ "${out}" == *"mqvpnctl"* ]] || { echo "  missing 'mqvpnctl' in output"; return 1; }
    [[ "${out}" == *"host-test-1.0"* ]] || { echo "  missing endpoint version in output"; return 1; }
}
run_test "T2 mqvpnctl version (text)" test_t2

# ── T3 ──────────────────────────────────────────────────────────────────
test_t3() {
    local out
    out="$("${MQVPNCTL}" --endpoint "unix://${SOCK_MAIN}" --json version 2>&1)"
    local rc=$?
    echo "${out}"
    [[ ${rc} -eq 0 ]] || { echo "  unexpected exit ${rc}"; return 1; }
    python3 -c '
import json, sys
d = json.loads(sys.argv[1])
assert d["cli_version"], d
assert d["endpoint"]["version"] == "host-test-1.0", d
assert d["endpoint"]["name"] == "mqvpn-client", d
assert d["endpoint"]["protocol"] == "1.0", d
' "${out}"
}
run_test "T3 mqvpnctl --json version" test_t3

# ── T4 ──────────────────────────────────────────────────────────────────
test_t4() {
    local sock="${TMPD}/no_listener.sock"
    local out rc

    out="$("${MQVPNCTL}" --endpoint "unix://${sock}" version 2>&1)"
    rc=$?
    echo "${out}"
    [[ ${rc} -eq 5 ]] || { echo "  text variant: expected exit 5, got ${rc}"; return 1; }
    [[ "${out}" == *"unavailable"* ]] || { echo "  text variant: missing 'unavailable'"; return 1; }

    out="$("${MQVPNCTL}" --endpoint "unix://${sock}" --json version 2>&1)"
    rc=$?
    echo "${out}"
    [[ ${rc} -eq 5 ]] || { echo "  json variant: expected exit 5, got ${rc}"; return 1; }
    python3 -c '
import json, sys
d = json.loads(sys.argv[1])
assert d["endpoint"] is None, d
' "${out}"
}
run_test "T4 endpoint unreachable -> exit 5" test_t4

# ── T5 ──────────────────────────────────────────────────────────────────
test_t5() {
    python3 - "${SOCK_MAIN}" <<'PYEOF'
import socket, sys, json

sock_path = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)

s.sendall(b"{oops\n")
buf = b""
while not buf.endswith(b"\n"):
    chunk = s.recv(65536)
    if not chunk:
        raise SystemExit("connection closed before error response")
    buf += chunk
resp = json.loads(buf.decode())
assert resp["ok"] is False, resp
assert resp["error"]["code"] == "MQVPN_CLIENT_INVALID_ARGUMENT", resp

# Same connection must still be usable afterward.
hello = json.dumps({
    "id": 1, "protocol": "1.0", "method": "system.hello",
    "params": {"client_name": "t5", "client_version": "1",
               "supported_protocols": ["1.0"]},
}) + "\n"
s.sendall(hello.encode())
buf2 = b""
while not buf2.endswith(b"\n"):
    chunk = s.recv(65536)
    if not chunk:
        raise SystemExit("connection closed before hello response")
    buf2 += chunk
resp2 = json.loads(buf2.decode())
assert resp2["ok"] is True, resp2
s.close()
print("T5_OK")
PYEOF
}
run_test "T5 malformed request survives, connection reusable" test_t5

# ── T6 ──────────────────────────────────────────────────────────────────
test_t6() {
    python3 - "${SOCK_MAIN}" <<'PYEOF'
import socket, sys

sock_path = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)

s.sendall(b"x" * 70000)  # no LF: never a complete line
buf = b""
while b"\n" not in buf:
    chunk = s.recv(65536)
    if not chunk:
        break
    buf += chunk
assert b"request too large" in buf, buf

# Clean EOF should follow (FIN, not RST-induced garbage).
rest = s.recv(4096)
assert rest == b"", rest
s.close()

# Endpoint must still accept new connections.
s2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s2.connect(sock_path)
s2.close()
print("T6_OK")
PYEOF
}
run_test "T6 oversized request rejected, endpoint stays usable" test_t6

# ── T7 ──────────────────────────────────────────────────────────────────
test_t7() {
    python3 - "${SOCK_MAIN}" <<'PYEOF'
import socket, sys, json

sock_path = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)

def send_recv(i, method, params):
    req = json.dumps({"id": i, "protocol": "1.0", "method": method,
                       "params": params}) + "\n"
    s.sendall(req.encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            raise SystemExit(f"connection closed waiting for response to id={i}")
        buf += chunk
    return json.loads(buf.decode())

r1 = send_recv(1, "system.hello",
                {"client_name": "t7", "client_version": "1",
                 "supported_protocols": ["1.0"]})
r2 = send_recv(2, "system.version", {})
r3 = send_recv(3, "system.capabilities", {})
r4 = send_recv(4, "system.ping", {})
s.close()

for expected_id, r in enumerate([r1, r2, r3, r4], start=1):
    assert r["ok"] is True, r
    assert r["id"] == expected_id, r
print("T7_OK")
PYEOF
}
run_test "T7 4 pipelined requests, ids in order" test_t7

# ── T8a ─────────────────────────────────────────────────────────────────
test_t8a() {
    python3 - "${SOCK_MAIN}" <<'PYEOF'
import socket, sys, json

sock_path = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)

req = json.dumps({
    "id": 1, "protocol": "1.0", "method": "system.hello",
    "params": {"client_name": "t8a", "client_version": "1",
               "supported_protocols": ["9.9"]},
}) + "\n"
s.sendall(req.encode())
buf = b""
while not buf.endswith(b"\n"):
    chunk = s.recv(65536)
    if not chunk:
        raise SystemExit("connection closed before response")
    buf += chunk
resp = json.loads(buf.decode())
s.close()

assert resp["ok"] is False, resp
assert resp["error"]["code"] == "MQVPN_CLIENT_PROTOCOL_INCOMPATIBLE", resp
assert "1.0" in resp["error"]["details"]["supported_protocols"], resp
print("T8A_OK")
PYEOF
}
run_test "T8a raw hello, unsupported protocol -> PROTOCOL_INCOMPATIBLE" test_t8a

# ── T8b ─────────────────────────────────────────────────────────────────
FAKE_INCOMPAT_PY="${TMPD}/fake_incompat.py"
cat >"${FAKE_INCOMPAT_PY}" <<'PYEOF'
import socket, sys, os, time

sock_path = sys.argv[1]
if os.path.exists(sock_path):
    os.remove(sock_path)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
s.listen(1)
conn, _ = s.accept()
buf = b""
while not buf.endswith(b"\n"):
    chunk = conn.recv(65536)
    if not chunk:
        sys.exit(0)
    buf += chunk
resp = (b'{"id":1,"protocol":"1.0","ok":false,"error":{"code":'
        b'"MQVPN_CLIENT_PROTOCOL_INCOMPATIBLE","message":'
        b'"no compatible protocol version","retryable":false,'
        b'"details":{"supported_protocols":["1.0"]}}}\n')
conn.sendall(resp)
time.sleep(30)  # keep the connection open; the CLI closes its side
PYEOF

test_t8b() {
    local sock="${TMPD}/fake_incompat.sock"
    local pid
    python3 "${FAKE_INCOMPAT_PY}" "${sock}" &
    pid=$!
    BG_PIDS+=("${pid}")
    wait_for_socket "${sock}" 5 || { echo "  fake endpoint never bound"; return 1; }

    local out rc
    out="$("${MQVPNCTL}" --endpoint "unix://${sock}" version 2>&1)"
    rc=$?
    echo "${out}"
    kill "${pid}" >/dev/null 2>&1
    [[ ${rc} -eq 9 ]] || { echo "  expected exit 9, got ${rc}"; return 1; }
}
run_test "T8b mqvpnctl version vs incompatible endpoint -> exit 9" test_t8b

# ── T9 ──────────────────────────────────────────────────────────────────
test_t9() {
    local ldd_out leak_count
    ldd_out="$(ldd "${MQVPNCTL}")"
    echo "${ldd_out}"
    if echo "${ldd_out}" | grep -Eq 'libmqvpn|libxquic|libevent'; then
        echo "  ldd shows a forbidden dependency"
        return 1
    fi
    leak_count="$(nm "${MQVPNCTL}" 2>/dev/null | grep -c 'mqvpn_client_\|xqc_')"
    echo "  static-link leak symbol count: ${leak_count}"
    [[ "${leak_count}" -eq 0 ]]
}
run_test "T9 mqvpnctl links neither libmqvpn/xquic/libevent" test_t9

# ── T10 ─────────────────────────────────────────────────────────────────
test_t10() {
    local out_a="${TMPD}/t10_a.log"
    local out_b="${TMPD}/t10_b.log"
    "${MQVPNCTL}" --endpoint "unix://${SOCK_MAIN}" version >"${out_a}" 2>&1 &
    local pid_a=$!
    "${MQVPNCTL}" --endpoint "unix://${SOCK_MAIN}" version >"${out_b}" 2>&1 &
    local pid_b=$!

    local rc_a=0 rc_b=0
    wait "${pid_a}" || rc_a=$?
    wait "${pid_b}" || rc_b=$?
    cat "${out_a}"
    cat "${out_b}"
    [[ ${rc_a} -eq 0 && ${rc_b} -eq 0 ]]
}
run_test "T10 two concurrent version invocations both succeed" test_t10

# ── T11 ─────────────────────────────────────────────────────────────────
FAKE_SILENT_PY="${TMPD}/fake_silent.py"
cat >"${FAKE_SILENT_PY}" <<'PYEOF'
import socket, sys, os, time

sock_path = sys.argv[1]
if os.path.exists(sock_path):
    os.remove(sock_path)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
s.listen(1)
conn, _ = s.accept()
time.sleep(30)  # accept but never read/reply
PYEOF

test_t11() {
    local sock="${TMPD}/fake_silent.sock"
    local pid
    python3 "${FAKE_SILENT_PY}" "${sock}" &
    pid=$!
    BG_PIDS+=("${pid}")
    wait_for_socket "${sock}" 5 || { echo "  fake endpoint never bound"; return 1; }

    local out rc start end elapsed
    start=$(date +%s%N)
    out="$(timeout 3 "${MQVPNCTL}" --endpoint "unix://${sock}" --timeout 1 version 2>&1)"
    rc=$?
    end=$(date +%s%N)
    elapsed=$(( (end - start) / 1000000 ))
    echo "${out}"
    echo "  elapsed: ${elapsed}ms"
    kill "${pid}" >/dev/null 2>&1
    [[ ${rc} -eq 8 ]] || { echo "  expected exit 8, got ${rc}"; return 1; }
    [[ ${elapsed} -lt 3000 ]] || { echo "  took too long (${elapsed}ms)"; return 1; }
}
run_test "T11 --timeout 1 vs silent endpoint -> exit 8 within ~3s" test_t11

# ── T12 ─────────────────────────────────────────────────────────────────
test_t12() {
    local sock="${TMPD}/t12.sock"
    local pid
    pid="$(start_host "${sock}" --mode 0640)"
    wait_for_socket "${sock}" 5 || { echo "  host never bound"; return 1; }
    local mode
    mode="$(stat -c %a "${sock}")"
    echo "  socket mode: ${mode}"
    kill "${pid}" >/dev/null 2>&1
    [[ "${mode}" == "640" ]]
}
run_test "T12 mgmt_endpoint_host --mode 0640" test_t12

# ── T13 ─────────────────────────────────────────────────────────────────
test_t13() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "T13 SKIP (requires root)"
        return 0
    fi

    if ! id nobody >/dev/null 2>&1; then
        echo "T13 SKIP (no 'nobody' user available)"
        return 0
    fi

    local sock="${TMPD}/t13.sock"
    local pid
    pid="$(start_host "${sock}")"
    wait_for_socket "${sock}" 5 || { echo "  host never bound"; return 1; }
    # Default mode (0660, root:root) — connecting as an unrelated
    # unprivileged user must fail with a permission error.
    local out rc
    out="$(runuser -u nobody -- "${MQVPNCTL}" --endpoint "unix://${sock}" version 2>&1)"
    rc=$?
    echo "${out}"
    kill "${pid}" >/dev/null 2>&1
    [[ ${rc} -ne 0 ]] || { echo "  expected a failure exit code for permission-denied connect"; return 1; }
    [[ "${out}" == *"ermission"* || "${out}" == *"unavailable"* ]] || {
        echo "  expected a permission-related message"; return 1; }
}
run_test "T13 permission boundary (root-only)" test_t13

# ── Summary ─────────────────────────────────────────────────────────────
echo ""
echo "=== Results: PASS=${PASS} FAIL=${FAIL} ==="

if (( FAIL > 0 )); then
    exit 1
fi
exit 0
