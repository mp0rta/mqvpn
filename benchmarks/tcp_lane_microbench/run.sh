#!/usr/bin/env bash
# benchmarks/tcp_lane_microbench/run.sh — H2a gate: TUN(MTU 8500) →
# classifier → lwIP termination → /dev/null sink, single bulk TCP flow.
# Gate: >= 10 Gbit/s receiver-side (spec H2a).
#
# Traffic generator: a plain python bulk sender, NOT iperf3. Verified
# empirically (2026-07-03 dry run): the lwIP wildcard listener intercepts
# the SYN to 10.99.0.2:5201 before any real server could see it, so
# `iperf3 -s` never receives traffic, and `iperf3 -c` stalls forever in its
# control-channel handshake against a pure sink (it sends its control
# opener — 38 bytes: the 37-byte cookie plus one control byte — then blocks
# waiting for the server's PARAM_EXCHANGE byte that a byte sink can never
# produce). The gate metric is unchanged: sustained
# bytes/sec through classifier + lwIP termination at MTU 8500, measured on
# the receiver (harness) side between first and last payload byte.
#
# Entry modes (all end up running the same measurement core in an isolated
# network namespace; the harness self-configures the TUN via ioctl, so no
# iproute2 is needed inside the namespace):
#   1. root:           creates a named netns (ip netns) and re-execs inside.
#   2. non-root:       re-execs under `unshare -r -n` (user+net namespace).
#      Blocked on hosts with kernel.apparmor_restrict_unprivileged_userns=1
#      (e.g. recent Ubuntu) — use mode 1 or a NET_ADMIN container instead:
#        docker run --rm --network none --cap-add NET_ADMIN \
#          --device /dev/net/tun -v <repo>:<repo>:ro -e MQVPN_BENCH_IN_NS=1 \
#          <image-with-python3> bash <repo>/benchmarks/tcp_lane_microbench/run.sh
#   3. MQVPN_BENCH_IN_NS=1: already inside an isolated netns — run directly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# NOTE: the default Debug build clears the 10 Gbit/s gate with only ~5%
# headroom on the reference box (Ryzen 9 5950X) — point HARNESS at a
# Release build (-O3) for margin if re-running on a slower machine.
HARNESS="${HARNESS:-${SCRIPT_DIR}/../../build-debug/tcp_lane_microbench}"
TUN=tunbench0
DUR="${DUR:-10}"

if [[ "${MQVPN_BENCH_IN_NS:-0}" != 1 ]]; then
    if [[ "$EUID" -eq 0 ]]; then
        NS=mqvpn_bench_tcplane
        trap 'ip netns del "$NS" 2>/dev/null || true' EXIT
        ip netns add "$NS"
        ip netns exec "$NS" env MQVPN_BENCH_IN_NS=1 HARNESS="$HARNESS" DUR="$DUR" \
            bash "$0" "$@"
        exit $?
    elif unshare -r -n true 2>/dev/null; then
        exec unshare -r -n env MQVPN_BENCH_IN_NS=1 HARNESS="$HARNESS" DUR="$DUR" \
            bash "$0" "$@"
    else
        echo "ERROR: need root (ip netns) or working unprivileged user" >&2
        echo "namespaces (unshare -r -n). On hosts with" >&2
        echo "kernel.apparmor_restrict_unprivileged_userns=1, run via sudo or a" >&2
        echo "NET_ADMIN container (see header comment)." >&2
        exit 1
    fi
fi

# ---- measurement core (inside an isolated netns, EUID 0 in the ns) ----
[[ -x "$HARNESS" ]] || { echo "harness not built: $HARNESS" >&2; exit 1; }
OUT="$(mktemp)"
ERR="$(mktemp)"

# Harness creates the TUN (TUNSETIFF) and self-configures 10.99.0.1/24 MTU
# 8500 via ioctl; the kernel installs the connected /24 route, so traffic to
# 10.99.0.2 flows into the TUN where lwIP's wildcard listener intercepts it.
"$HARNESS" "$TUN" 10.99.0.1 24 8500 > "$OUT" 2> "$ERR" &
HARNESS_PID=$!
trap 'kill "$HARNESS_PID" 2>/dev/null || true; rm -f "$OUT" "$ERR"' EXIT
sleep 0.5
# Surface harness startup failures (TUNSETIFF EPERM, missing /dev/net/tun)
# with the harness's own perror instead of an opaque sender traceback.
kill -0 "$HARNESS_PID" 2>/dev/null || {
    echo "harness died:" >&2
    cat "$ERR" >&2
    exit 1
}

python3 - 10.99.0.2 5201 "$DUR" <<'PYEOF'
import socket, sys, time
host, port, dur = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
s = socket.create_connection((host, port))
buf = memoryview(bytes(1 << 20))
start = time.monotonic()
end = start + dur
sent = 0
while time.monotonic() < end:
    sent += s.send(buf)
elapsed = time.monotonic() - start
s.shutdown(socket.SHUT_WR)  # FIN -> harness prints its flow_close RESULT
print(f"SENDER bytes={sent} elapsed_s={elapsed:.3f} "
      f"gbps={sent*8/elapsed/1e9:.2f}")
s.close()
PYEOF

# Wait for the harness to see the FIN and print the receiver-side RESULT.
for _ in $(seq 1 50); do
    grep -q "RESULT reason=flow_close" "$OUT" && break
    sleep 0.2
done
kill "$HARNESS_PID" 2>/dev/null || true

echo "--- harness output ---"
cat "$OUT"
tail -3 "$ERR" || true

GBPS="$(sed -n 's/.*reason=flow_close.*gbps=\([0-9.]*\).*/\1/p' "$OUT" | head -1)"
[[ -n "$GBPS" ]] || { echo "FAIL: no receiver-side RESULT found" >&2; exit 1; }
python3 - "$GBPS" <<'PYEOF'
import sys
gbps = float(sys.argv[1])
print(f"{gbps:.2f} Gbit/s (receiver-side, through classifier + lwIP)")
if gbps < 10.0:
    print("FAIL: below 10 Gbit/s gate")
    sys.exit(1)
print("PASS")
PYEOF
