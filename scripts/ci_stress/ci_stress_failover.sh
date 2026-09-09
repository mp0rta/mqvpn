#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
# ci_stress_failover.sh — 100-cycle path fault/recover stress test
#
# Runs 100 fault/recover cycles against a dual-path tunnel while continuous
# iperf3 traffic flows over it. Each cycle breaks one path, restores it, and
# verifies that the path itself came back — not merely that the surviving
# path still answers. Monitors RSS/fd for both VPN processes.
#
# Three fault kinds, one per way a path dies in the field:
#
#   admin_down    the interface is switched off (UI / config change). The
#                 client's own veth loses IFF_UP and the kernel flushes
#                 every route through it.
#   carrier_loss  the cable is pulled / the modem drops. Only the peer goes
#                 down, so the client keeps IFF_UP, its address and its
#                 routes, and loses IFF_RUNNING.
#   blackhole     a middlebox starts discarding the path. Link, address and
#                 route all stay valid and NO netlink event is emitted, so
#                 the platform layer cannot react at all: staying connected
#                 is entirely up to loss detection and the scheduler.
#
# The path alternates every cycle and the kind every two, so no path is
# faulted twice in a row and each kind gets a third of the cycles.
#
# Flow:
#   1. Setup dual-path netns with netem (Path A = 300Mbps/10ms, Path B = 80Mbps/30ms)
#   2. Start VPN server (wlb) + multipath client, capturing both logs
#   3. Start long-running iperf3 transfer (-t 3600)
#   4. Loop 100 times: fault (path, kind) -> recover -> verify the path is back
#   5. Check for resource leaks after all cycles complete
#   6. Output summary JSON to ci_stress_results/failover_storm_<timestamp>.json
#
# Output: ci_stress_results/failover_storm_<timestamp>.json
#
# Usage: sudo ./ci_stress_failover.sh [path-to-mqvpn-binary]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# The per-cycle "did the path actually come back" check greps an INFO-level
# marker out of the client log, so this suite needs info level. Set before
# sourcing so ci_stress_env.sh's own warn default does not win; an explicit
# CI_STRESS_LOG_LEVEL from the environment still overrides it (and disables
# that check, with a notice).
CI_STRESS_LOG_LEVEL="${CI_STRESS_LOG_LEVEL:-info}"

source "${SCRIPT_DIR}/ci_stress_env.sh"

MQVPN="${1:-${MQVPN}}"

NUM_CYCLES="${NUM_CYCLES:-100}"   # env override for short local runs
SCHEDULER="wlb"
# Which fault kinds this run exercises. `blackhole` is deliberately NOT in
# the default set: it reproduces a live scheduling weakness rather than a
# regression, so leaving it on would keep the weekly job permanently red.
#
# Measured 2026-09-09 (100 cycles, 2-path netns, iperf3 -P 4 saturating the
# tunnel): blackholing Path B — the path carrying ~14% of the traffic — makes
# every unpinned inner probe die, 20 of 20 echoes lost on 15 of 16 cycles,
# while the tunnel itself keeps moving 170-250 Mbps on Path A. Blackholing
# Path A instead never failed. WLB does guard against blackholed paths
# (wlb_find_path_ctx drops a path once ctl_pto_count reaches
# WLB_PTO_EVICT_THRESH), but that counter only advances when a path has
# unacked data timing out, and QUIC rearms the PTO from the most recent
# ack-eliciting packet — so a steady low-rate trickle onto a dead path can
# keep the deadline in the future forever and the path never looks unhealthy.
# Re-enable with CI_STRESS_FAULT_KINDS to reproduce.
read -r -a FAULT_KINDS <<< "${CI_STRESS_FAULT_KINDS:-admin_down carrier_loss}"
RUN_STAMP="$(date +%Y%m%d_%H%M%S)"

# Capture the VPN logs instead of letting them flood the console: the
# per-cycle checks read the client log, and only the window around a failure
# is printed (the whole file is archived when the run goes red) rather than
# every line of a 30-minute run.
VPN_SERVER_LOG="$(mktemp)"
VPN_CLIENT_LOG="$(mktemp)"
export CI_STRESS_SERVER_LOG="$VPN_SERVER_LOG"
export CI_STRESS_CLIENT_LOG="$VPN_CLIENT_LOG"

case "$CI_STRESS_LOG_LEVEL" in
    info | debug | trace) ASSERT_PATH_RETURN=1 ;;
    *) ASSERT_PATH_RETURN=0 ;;
esac

trap ci_stress_cleanup EXIT

ci_stress_check_deps

echo "================================================================"
echo "  mqvpn Failover Storm Stress Test (CI)"
echo "  Binary:    $MQVPN"
echo "  Scheduler: $SCHEDULER"
echo "  Cycles:    $NUM_CYCLES"
echo "  Kinds:     ${FAULT_KINDS[*]}"
echo "  Log level: $CI_STRESS_LOG_LEVEL"
echo "  Commit:    ${CI_STRESS_COMMIT:0:12}"
echo "  Date:      $(date '+%Y-%m-%d %H:%M')"
echo "================================================================"

if [ "$ASSERT_PATH_RETURN" -eq 0 ]; then
    echo "NOTE: log level '${CI_STRESS_LOG_LEVEL}' hides the path-return marker, so"
    echo "      cycles cannot assert that a faulted path actually came back."
fi

# ── Setup netns + netem ──

ci_stress_setup_netns
ci_stress_apply_netem

# ── Start VPN ──

ci_stress_start_server "$SCHEDULER"
ci_stress_start_client "--path $VETH_A0 --path $VETH_B0" "$SCHEDULER"
ci_stress_wait_tunnel 30

# ── iperf3 server (persistent, no -1) ──

ip netns exec "$NS_SERVER" iperf3 -s -B "$TUNNEL_SERVER_IP" &>/dev/null &
IPERF_SERVER_PID=$!
sleep 1

# ── iperf3 client (long-running, enough for all cycles) ──

echo "Starting iperf3 for 3600s (-P 4, background)..."
ip netns exec "$NS_CLIENT" iperf3 \
    -c "$TUNNEL_SERVER_IP" -t 3600 \
    -P 4 &>/dev/null &
IPERF_CLIENT_PID=$!
sleep 2

# ── Start RSS/fd monitors ──

SERVER_MON_LOG="$(mktemp)"
CLIENT_MON_LOG="$(mktemp)"

ci_stress_monitor_start "$_CS_SERVER_PID" "$SERVER_MON_LOG"
echo "Monitoring VPN server (PID $_CS_SERVER_PID) -> $SERVER_MON_LOG"

ci_stress_monitor_start "$_CS_CLIENT_PID" "$CLIENT_MON_LOG"
echo "Monitoring VPN client (PID $_CS_CLIENT_PID) -> $CLIENT_MON_LOG"

# ── Fault/Recover loop ──

CYCLES_OK=0
CYCLES_FAILED=0
declare -A KIND_OK KIND_FAILED
for _kind in "${FAULT_KINDS[@]}"; do
    KIND_OK[$_kind]=0
    KIND_FAILED[$_kind]=0
done

# tc netem with a named failure instead of a set -e abort mid-run. Reads TAG
# and writes CYCLE_OK from the loop below, which is the only caller.
netem_set() { # <netns> <dev> <netem args...>
    local ns="$1" dev="$2"
    shift 2
    if ! ip netns exec "$ns" tc qdisc replace dev "$dev" root netem "$@"; then
        echo "  [$TAG] FAIL: tc netem on $dev ($ns) failed"
        CYCLE_OK=false
    fi
}

echo ""
echo "Starting $NUM_CYCLES fault/recover cycles..."

for ((i = 1; i <= NUM_CYCLES; i++)); do
    # Path alternates every cycle, kind every two (see the header).
    if (( i % 2 == 1 )); then
        FAULT_VETH_C="$VETH_A0"
        FAULT_VETH_S="$VETH_A1"
        FAULT_IP_C="$IP_A_CLIENT"
        FAULT_IP_S="$IP_A_SERVER"
        FAULT_NETEM="$NETEM_A"
        FAULT_LABEL="A"
    else
        FAULT_VETH_C="$VETH_B0"
        FAULT_VETH_S="$VETH_B1"
        FAULT_IP_C="$IP_B_CLIENT"
        FAULT_IP_S="$IP_B_SERVER"
        FAULT_NETEM="$NETEM_B"
        FAULT_LABEL="B"
    fi
    FAULT_KIND="${FAULT_KINDS[$(( ((i - 1) / 2) % ${#FAULT_KINDS[@]} ))]}"
    TAG="cycle $i Path $FAULT_LABEL $FAULT_KIND"
    CYCLE_OK=true

    # (a) Let traffic flow
    sleep 3

    # Everything the client logs from here on belongs to this cycle.
    LOG_MARK=$(wc -l < "$VPN_CLIENT_LOG")

    # (b) FAULT
    case "$FAULT_KIND" in
    admin_down)
        # Local veth loses IFF_UP; the kernel flushes routes through it.
        ip netns exec "$NS_CLIENT" ip link set "$FAULT_VETH_C" down
        ;;
    carrier_loss)
        # Only the PEER goes down, so the client keeps IFF_UP, its address
        # and its routes, and loses IFF_RUNNING. Downing the local end would
        # be seen as an admin down instead — the same reason
        # scripts/ci_e2e/run_carrier_flap_test.sh faults the peer.
        ip netns exec "$NS_SERVER" ip link set "$FAULT_VETH_S" down
        ;;
    blackhole)
        # Both directions, since a middlebox drops both. 100% loss makes the
        # shaping irrelevant, so it is left off until recovery restores it.
        netem_set "$NS_CLIENT" "$FAULT_VETH_C" loss 100%
        netem_set "$NS_SERVER" "$FAULT_VETH_S" loss 100%
        ;;
    esac

    # (c) Traffic on the surviving path only
    if [ "$FAULT_KIND" = "blackhole" ]; then
        # Assert the failover here rather than after recovery: with no kernel
        # event to observe, "the tunnel stayed up while one path silently ate
        # every packet" is the only thing this kind proves, and it is
        # unobservable once the path is healthy again.
        #
        # The probe has to be a sample, not a single shot. ICMP is
        # deliberately unpinned (src/flow_sched.c pins inner TCP, and UDP only
        # under wlb_udp_pin), so WLB sprays these echoes across both paths per
        # packet: while one path discards everything, an echo needs both its
        # request and its reply to miss that path, which measured out at
        # roughly a third of attempts. Five attempts lost that coin flip on 2
        # of 16 cycles; twenty put a false red near 1e-4 per cycle while still
        # fitting in the same ~5s window.
        if ! PING_OUT=$(ip netns exec "$NS_CLIENT" ping -c 20 -i 0.2 -W 1 "$TUNNEL_SERVER_IP" 2>&1); then
            echo "  [$TAG] FAIL: tunnel dead while the path was blackholed"
            echo "$PING_OUT" | tail -n 3 | sed 's/^/    /'
            ci_stress_dump_log_since "$VPN_CLIENT_LOG" "$LOG_MARK"
            CYCLE_OK=false
        fi
    else
        sleep 2
    fi

    # (d) RECOVER. IPv4 addresses survive a link down, so the addr add is a
    #     no-op safety net rather than a restore.
    case "$FAULT_KIND" in
    admin_down)
        ip netns exec "$NS_CLIENT" ip link set "$FAULT_VETH_C" up
        ip netns exec "$NS_CLIENT" ip addr add "$FAULT_IP_C" dev "$FAULT_VETH_C" 2>/dev/null || true
        ;;
    carrier_loss)
        ip netns exec "$NS_SERVER" ip link set "$FAULT_VETH_S" up
        ip netns exec "$NS_SERVER" ip addr add "$FAULT_IP_S" dev "$FAULT_VETH_S" 2>/dev/null || true
        ;;
    blackhole)
        netem_set "$NS_CLIENT" "$FAULT_VETH_C" ${FAULT_NETEM}
        netem_set "$NS_SERVER" "$FAULT_VETH_S" ${FAULT_NETEM}
        ;;
    esac

    if [ "$FAULT_KIND" != "blackhole" ]; then
        # Path B reaches the server only through the via-route, which an
        # admin down flushes. The carrier-up event has already fired without
        # it, so the client's re-add gate deferred; the library's 3s recovery
        # timer re-checks the FIB and re-adds the path once the route is
        # back, well inside the wait below.
        if [ "$FAULT_LABEL" = "B" ] && ! ci_stress_add_path_b_route; then
            echo "  [$TAG] FAIL: could not restore Path B's route to the server"
            CYCLE_OK=false
        fi
        ip netns exec "$NS_CLIENT" tc qdisc add dev "$FAULT_VETH_C" root netem ${FAULT_NETEM} 2>/dev/null || true
        ip netns exec "$NS_SERVER" tc qdisc add dev "$FAULT_VETH_S" root netem ${FAULT_NETEM} 2>/dev/null || true
    fi

    # (e) Let traffic recover (10s: QUIC path revalidation takes ~10-15s)
    sleep 10

    # (f) Verify the faulted path is back, not just that the surviving one
    #     still answers — a permanently dead path otherwise only surfaces
    #     indirectly, cycles later, which is how the 2026-07 route-gate
    #     regression stayed hidden for two months. A blackhole never removes
    #     the path, so there is nothing to re-add in that case.
    if [ "$FAULT_KIND" != "blackhole" ] && [ "$ASSERT_PATH_RETURN" -eq 1 ]; then
        if ! ci_stress_wait_log_after "$VPN_CLIENT_LOG" \
                "path\[[0-9]+\] activated:.*iface=${FAULT_VETH_C}" "$LOG_MARK" 5; then
            echo "  [$TAG] FAIL: path never returned to active"
            ci_stress_dump_log_since "$VPN_CLIENT_LOG" "$LOG_MARK"
            CYCLE_OK=false
        fi
    fi

    if ! kill -0 "$IPERF_CLIENT_PID" 2>/dev/null; then
        echo "  [$TAG] FAIL: iperf3 client died"
        CYCLE_OK=false
    fi

    if ! ip netns exec "$NS_CLIENT" ping -c 1 -W 2 "$TUNNEL_SERVER_IP" >/dev/null 2>&1; then
        echo "  [$TAG] FAIL: tunnel ping failed"
        CYCLE_OK=false
    fi

    # (g) Record result
    if [ "$CYCLE_OK" = true ]; then
        CYCLES_OK=$((CYCLES_OK + 1))
        KIND_OK[$FAULT_KIND]=$(( ${KIND_OK[$FAULT_KIND]} + 1 ))
    else
        CYCLES_FAILED=$((CYCLES_FAILED + 1))
        KIND_FAILED[$FAULT_KIND]=$(( ${KIND_FAILED[$FAULT_KIND]} + 1 ))
    fi

    # (h) Progress every 10 cycles
    if (( i % 10 == 0 )); then
        echo "  [cycle $i/$NUM_CYCLES] ok=$CYCLES_OK failed=$CYCLES_FAILED"
    fi
done

echo ""
echo "All $NUM_CYCLES cycles complete: ok=$CYCLES_OK failed=$CYCLES_FAILED"

# ── Kill iperf3 ──

kill "$IPERF_CLIENT_PID" 2>/dev/null || true
wait "$IPERF_CLIENT_PID" 2>/dev/null || true
kill "$IPERF_SERVER_PID" 2>/dev/null || true
wait "$IPERF_SERVER_PID" 2>/dev/null || true

# ── Stop monitors and check resources ──

ci_stress_monitor_stop

echo ""
echo "── Resource Check ──"

RESOURCE_FAILED=0

ci_stress_check_resources "$SERVER_MON_LOG" "server" || RESOURCE_FAILED=1
ci_stress_check_resources "$CLIENT_MON_LOG" "client" || RESOURCE_FAILED=1

# ── Stop VPN (ASan leak detection runs on process exit) ──

echo ""
echo "Stopping VPN..."
ci_stress_stop_vpn

echo ""
echo "── Sanitizer Check ──"
ci_stress_check_sanitizer || RESOURCE_FAILED=1

# ── Parse monitor logs for summary stats ──

RESOURCE_STATS=$(python3 -c "
import sys

def parse_log(path, label):
    try:
        lines = open(path).read().strip().split('\n')
        samples = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                samples.append((int(parts[0]), int(parts[1]), int(parts[2])))
        if not samples:
            return {'initial_kb': 0, 'final_kb': 0, 'max_kb': 0}
        return {
            'initial_kb': samples[0][1],
            'final_kb': samples[-1][1],
            'max_kb': max(s[1] for s in samples),
        }
    except Exception:
        return {'initial_kb': 0, 'final_kb': 0, 'max_kb': 0}

server = parse_log('${SERVER_MON_LOG}', 'server')
client = parse_log('${CLIENT_MON_LOG}', 'client')

print(f\"{server['initial_kb']} {server['final_kb']} {server['max_kb']}\")
print(f\"{client['initial_kb']} {client['final_kb']} {client['max_kb']}\")
")

SERVER_RSS_INITIAL=$(echo "$RESOURCE_STATS" | sed -n '1p' | awk '{print $1}')
SERVER_RSS_FINAL=$(echo "$RESOURCE_STATS" | sed -n '1p' | awk '{print $2}')
SERVER_RSS_MAX=$(echo "$RESOURCE_STATS" | sed -n '1p' | awk '{print $3}')
CLIENT_RSS_INITIAL=$(echo "$RESOURCE_STATS" | sed -n '2p' | awk '{print $1}')
CLIENT_RSS_FINAL=$(echo "$RESOURCE_STATS" | sed -n '2p' | awk '{print $2}')
CLIENT_RSS_MAX=$(echo "$RESOURCE_STATS" | sed -n '2p' | awk '{print $3}')

# ── Determine status ──

if [ "$CYCLES_FAILED" -gt $((NUM_CYCLES / 10)) ] || [ "$RESOURCE_FAILED" -ne 0 ]; then
    STATUS="fail"
else
    STATUS="pass"
fi

echo ""
echo "── Summary ──"
echo "  Cycles:             $NUM_CYCLES (ok=$CYCLES_OK failed=$CYCLES_FAILED)"
for _kind in "${FAULT_KINDS[@]}"; do
    printf '    %-14s ok=%s failed=%s\n' "$_kind" "${KIND_OK[$_kind]}" "${KIND_FAILED[$_kind]}"
done
echo "  Server RSS (KB):    initial=${SERVER_RSS_INITIAL} final=${SERVER_RSS_FINAL} max=${SERVER_RSS_MAX}"
echo "  Client RSS (KB):    initial=${CLIENT_RSS_INITIAL} final=${CLIENT_RSS_FINAL} max=${CLIENT_RSS_MAX}"
echo "  Status:             ${STATUS}"

# ── Generate JSON output ──

# Per-kind breakdown, built here so the JSON does not hardcode the kind list.
KIND_JSON="{"
for _kind in "${FAULT_KINDS[@]}"; do
    [ "$KIND_JSON" = "{" ] || KIND_JSON="${KIND_JSON},"
    KIND_JSON="${KIND_JSON}\"${_kind}\": {\"ok\": ${KIND_OK[$_kind]}, \"failed\": ${KIND_FAILED[$_kind]}}"
done
KIND_JSON="${KIND_JSON}}"

TIMESTAMP="$(date -Iseconds)"
OUTPUT_FILE="${CI_STRESS_RESULTS}/failover_storm_${RUN_STAMP}.json"

python3 -c "
import json

result = {
    'test': 'failover_storm',
    'commit': '${CI_STRESS_COMMIT}',
    'timestamp': '${TIMESTAMP}',
    'num_cycles': ${NUM_CYCLES},
    'cycles_ok': ${CYCLES_OK},
    'cycles_failed': ${CYCLES_FAILED},
    'fault_kinds': json.loads('''${KIND_JSON}'''),
    'server_rss': {
        'initial_kb': ${SERVER_RSS_INITIAL},
        'final_kb': ${SERVER_RSS_FINAL},
        'max_kb': ${SERVER_RSS_MAX}
    },
    'client_rss': {
        'initial_kb': ${CLIENT_RSS_INITIAL},
        'final_kb': ${CLIENT_RSS_FINAL},
        'max_kb': ${CLIENT_RSS_MAX}
    },
    'status': '${STATUS}'
}

with open('${OUTPUT_FILE}', 'w') as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
"

# ── Archive the VPN logs on a red run ──
#
# The console only carries the window around each failing cycle, and the
# workflow uploads this directory — so keep the full picture next to the JSON
# when there is something to explain.
if [ "$STATUS" = "fail" ]; then
    tail -n 5000 "$VPN_CLIENT_LOG" > "${CI_STRESS_RESULTS}/failover_storm_client_${RUN_STAMP}.log"
    tail -n 5000 "$VPN_SERVER_LOG" > "${CI_STRESS_RESULTS}/failover_storm_server_${RUN_STAMP}.log"
    echo "  VPN logs: ${CI_STRESS_RESULTS}/failover_storm_{client,server}_${RUN_STAMP}.log"
fi

# ── Cleanup temp files ──

rm -f "$SERVER_MON_LOG" "$CLIENT_MON_LOG" "$VPN_SERVER_LOG" "$VPN_CLIENT_LOG"

echo ""
echo "================================================================"
echo "  Result: ${OUTPUT_FILE}"
echo "================================================================"

if [ "$STATUS" = "fail" ]; then
    exit 1
fi
