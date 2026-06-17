#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# sweep_reorder.sh — Netns + tc-netem parameter-sweep driver for the
# reorder-buffer feature. A parameter-sweeping generalization of
# tests/test_e2e_reorder.sh: instead of a single ON/OFF functional run, it
# sweeps {environment} x {reorder params} and emits one CSV row per repeat.
#
# It SOURCES benchmarks/bench_env_setup.sh and reuses its netns/veth/netem/
# process plumbing verbatim (bench_setup_netns_n / bench_add_server_host_routes
# / bench_apply_netem / bench_start_vpn_server / bench_start_vpn_client /
# bench_wait_tunnel / bench_query_control / bench_stop_vpn / bench_cleanup).
# The reorder section is INI/JSON only (no CLI flag), so — exactly like the e2e
# test — we generate a tiny [Reorder]/[ReorderRule] INI per cell and pass it via
# --config alongside the harness's --listen/--server/--path/--auth-key flags.
#
# Inner workload: picoquicdemo HTTP/3 bulk GET (a real inner QUIC flow), which
# is what genuinely exercises the reorder engine end-to-end. The picoquicdemo
# flags are pinned against picoquic master (v1.1.50) built by
# scripts/ci_interop/build_picoquic.sh; see run_inner_http3() for the exact
# invocation. The script degrades loudly (non-zero exit) if PICOQUICDEMO is
# unset/not found.
#
# Two modes:
#   perf  (default) — sweep added-latency / goodput, write the optimal-value CSV.
#   scale           — exercise MaxFlows / ResetMarkPackets / EgressIdleSec idle
#                     eviction, write a human .md report (NOT the CSV).
#
# Requires: root (netns), netcat-openbsd, jq, picoquicdemo (PICOQUICDEMO=<path>).
# Usage:
#   sudo PICOQUICDEMO=<path> ./sweep_reorder.sh [--out CSV] [--env NAME]
#        [--axis rtt|jitter|loss|bw|profiles] [--stage 1|2]
#        [--mode perf|scale] [--quick]
#   Env overrides: REPEATS, MQVPN, PICOQUICDEMO, PICO_FILE_BYTES.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=./bench_env_setup.sh
source "${SCRIPT_DIR}/bench_env_setup.sh"

# ─── Sweep tables ────────────────────────────────────────────────────────────
# Each value is "<pathA netem>|<pathB netem>" (split on '|' for bench_apply_netem).
declare -A ENV_NETEM=(
  [baseline]="delay 20ms rate 50mbit|delay 20ms rate 50mbit"
  [rtt_40]="delay 20ms rate 50mbit|delay 40ms rate 50mbit"
  [rtt_70]="delay 20ms rate 50mbit|delay 70ms rate 50mbit"
  [rtt_120]="delay 20ms rate 50mbit|delay 120ms rate 50mbit"
  [rtt_320]="delay 20ms rate 50mbit|delay 320ms rate 50mbit"
  [jit_5]="delay 20ms jitter 5ms rate 50mbit|delay 20ms jitter 5ms rate 50mbit"
  [jit_20]="delay 20ms jitter 20ms rate 50mbit|delay 20ms jitter 20ms rate 50mbit"
  [loss_05]="delay 20ms loss 0.5% rate 50mbit|delay 20ms loss 0.5% rate 50mbit"
  [loss_2]="delay 20ms loss 2% rate 50mbit|delay 20ms loss 2% rate 50mbit"
  [bw_4to1]="delay 20ms rate 50mbit|delay 20ms rate 12mbit"
  [bw_10to1]="delay 20ms rate 100mbit|delay 20ms rate 10mbit"
  [dual_lte]="delay 30ms jitter 5ms loss 0.5% rate 40mbit|delay 45ms jitter 8ms loss 0.5% rate 25mbit"
  [fiber_lte]="delay 8ms rate 300mbit|delay 40ms jitter 8ms loss 0.5% rate 30mbit"
  [lte_starlink]="delay 35ms jitter 8ms rate 40mbit|delay 50ms jitter 25ms loss 1% rate 100mbit"
  [lte_geo]="delay 35ms rate 40mbit|delay 320ms jitter 20ms loss 0.5% rate 20mbit"
  [congested]="delay 50ms jitter 20ms loss 2% rate 20mbit|delay 60ms jitter 25ms loss 2% rate 15mbit"
)

# axis -> which env keys belong to each OFAT (one-factor-at-a-time) axis.
declare -A AXIS_ENVS=(
  [rtt]="baseline rtt_40 rtt_70 rtt_120 rtt_320"
  [jitter]="baseline jit_5 jit_20"
  [loss]="baseline loss_05 loss_2"
  [bw]="baseline bw_4to1 bw_10to1"
  [profiles]="dual_lte fiber_lte lte_starlink lte_geo congested"
)

# Stage-2 (cap sweep) operates only over these representative environments.
STAGE2_ENVS=(baseline dual_lte fiber_lte lte_starlink lte_geo congested)

WAIT_VALUES=(10 20 30 50 80 120 200 300)
CAP_VALUES=(256 512 1024 2048 4096)
REPEATS="${REPEATS:-3}"

# Per-env chosen wait for the Stage-2 cap sweep. Default 30 (engine default);
# override here once Stage-1 picks an optimum per env.
declare -A ENV_CHOSEN_WAIT=(
  [baseline]=30
  [dual_lte]=50
  [fiber_lte]=50
  [lte_starlink]=80
  [lte_geo]=200
  [congested]=80
)
DEFAULT_CHOSEN_WAIT=30

# ─── Fixed knobs ─────────────────────────────────────────────────────────────
N_PATHS=2
CTRL_PORT="${CTRL_PORT:-9097}"
PICO_PORT="${PICO_PORT:-5401}"   # ReorderRule Port == picoquicdemo UDP port
PICO_FILE_BYTES="${PICO_FILE_BYTES:-52428800}"   # 50 MiB bulk GET
# picoquicdemo TLS material + SNI. The vendored tree ships test certs under
# certs/; the demo H3 server generates a file of N bytes for the numeric path
# "/N" (no -w web root needed). SNI must be non-empty or H3 GET is rejected.
PICO_CERT="${PICO_CERT:-${REPO_ROOT}/third_party/picoquic/certs/cert.pem}"
PICO_KEY="${PICO_KEY:-${REPO_ROOT}/third_party/picoquic/certs/key.pem}"
PICO_SNI="${PICO_SNI:-test}"
STAGE1_CAP=1024   # Stage 1 holds cap fixed at 1024 while sweeping wait

# Scale-mode knobs (perf-mode ignores these). IngressIdleSec < EgressIdleSec is
# a hard config-validation invariant (engine silently RAW-falls-back otherwise).
SCALE_MAX_FLOWS="${SCALE_MAX_FLOWS:-8}"
SCALE_RESET_MARK="${SCALE_RESET_MARK:-64}"
SCALE_INGRESS_IDLE="${SCALE_INGRESS_IDLE:-2}"
SCALE_EGRESS_IDLE="${SCALE_EGRESS_IDLE:-5}"
SCALE_CONCURRENT_FLOWS="${SCALE_CONCURRENT_FLOWS:-16}"

# ─── CLI parsing ─────────────────────────────────────────────────────────────
MODE="perf"
OUT=""
SEL_ENV=""
SEL_AXIS=""
SEL_STAGE=""   # empty = both stages
QUICK=0

usage() {
    cat >&2 <<EOF
usage: sudo PICOQUICDEMO=<path> $0 [options]
  --out <csv>          output CSV (default ci_sweep_results/reorder_sweep_DATE.csv)
  --env <name>         restrict to one environment key
  --axis <a>           restrict to an OFAT axis: rtt|jitter|loss|bw|profiles
  --stage <1|2>        restrict to Stage 1 (wait sweep) or Stage 2 (cap sweep)
  --mode <perf|scale>  perf (default) or scale-mode exercise
  --quick              alias: REPEATS=1 + --axis rtt (smoke). With --mode scale,
                       this is the scale-mode smoke.
Environments: ${!ENV_NETEM[*]}
EOF
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --out)   OUT="${2:?--out needs a path}"; shift 2 ;;
        --env)   SEL_ENV="${2:?--env needs a name}"; shift 2 ;;
        --axis)  SEL_AXIS="${2:?--axis needs a name}"; shift 2 ;;
        --stage) SEL_STAGE="${2:?--stage needs 1|2}"; shift 2 ;;
        --mode)  MODE="${2:?--mode needs perf|scale}"; shift 2 ;;
        --quick) QUICK=1; shift ;;
        -h|--help) usage ;;
        *) echo "error: unknown argument '$1'" >&2; usage ;;
    esac
done

# --quick is an ALIAS, not a separate code path.
if [ "$QUICK" -eq 1 ]; then
    REPEATS=1
    [ -z "$SEL_AXIS" ] && SEL_AXIS="rtt"
fi

case "$MODE" in
    perf|scale) ;;
    *) echo "error: --mode must be perf or scale (got '$MODE')" >&2; usage ;;
esac

if [ -n "$SEL_AXIS" ] && [ -z "${AXIS_ENVS[$SEL_AXIS]:-}" ]; then
    echo "error: unknown --axis '$SEL_AXIS' (valid: ${!AXIS_ENVS[*]})" >&2
    exit 2
fi
if [ -n "$SEL_ENV" ] && [ -z "${ENV_NETEM[$SEL_ENV]:-}" ]; then
    echo "error: unknown --env '$SEL_ENV' (valid: ${!ENV_NETEM[*]})" >&2
    exit 2
fi
if [ -n "$SEL_STAGE" ] && [ "$SEL_STAGE" != "1" ] && [ "$SEL_STAGE" != "2" ]; then
    echo "error: --stage must be 1 or 2 (got '$SEL_STAGE')" >&2
    exit 2
fi

# ─── Output paths ────────────────────────────────────────────────────────────
RESULTS_SWEEP_DIR="${REPO_ROOT}/ci_sweep_results"
mkdir -p "$RESULTS_SWEEP_DIR"
DATE_TAG="$(date +%Y%m%d)"
[ -z "$OUT" ] && OUT="${RESULTS_SWEEP_DIR}/reorder_sweep_${DATE_TAG}.csv"
SCALE_MD="${RESULTS_SWEEP_DIR}/reorder_scale_${DATE_TAG}.md"

CSV_HEADER="timestamp,env_name,axis,max_wait_ms,cap_pkts,repeat,goodput_mbps,added_p99_ms,added_max_ms,added_buffered_p99_ms,gap_count,gap_filled,gap_timeout,gap_overflow,delivered,picoquic_pin"

# ─── picoquicdemo locator ────────────────────────────────────────────────────
# Prefer the PICOQUICDEMO env var; else search the vendored tree.
PICOQUICDEMO="${PICOQUICDEMO:-}"
if [ -z "$PICOQUICDEMO" ]; then
    PICOQUICDEMO="$(find "${REPO_ROOT}/third_party/picoquic" -name picoquicdemo -type f 2>/dev/null | head -1 || true)"
fi
PICO_PIN=""   # filled in once we know the binary; recorded per CSV row

require_picoquic() {
    if [ -z "$PICOQUICDEMO" ] || [ ! -x "$PICOQUICDEMO" ]; then
        echo "error: picoquicdemo not found." >&2
        echo "       Build it:   ${REPO_ROOT}/scripts/ci_interop/build_picoquic.sh" >&2
        echo "       Then run:   sudo PICOQUICDEMO=<path-to-picoquicdemo> $0 ..." >&2
        return 1
    fi
    PICOQUICDEMO="$(realpath "$PICOQUICDEMO")"
    # picoquic_pin: best-effort identity of the binary used, recorded per row so
    # results stay attributable across rebuilds (no stable --version flag known).
    PICO_PIN="$(cd "${REPO_ROOT}/third_party/picoquic" 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || true)"
    [ -z "$PICO_PIN" ] && PICO_PIN="$(basename "$PICOQUICDEMO")"
}

# ─── Temp files + trap ───────────────────────────────────────────────────────
SERVER_LOG="$(mktemp)"
CLIENT_LOG="$(mktemp)"
INI_FILE="$(mktemp --suffix=.ini)"
PICO_SVR_LOG="$(mktemp)"
PICO_CLI_LOG="$(mktemp)"

cleanup_all() {
    # Stop any inner picoquic processes inside the benchmark netns first.
    ip netns exec "$NS_SERVER" pkill -f picoquicdemo 2>/dev/null || true
    ip netns exec "$NS_CLIENT" pkill -f picoquicdemo 2>/dev/null || true
    bench_cleanup
    rm -f "$SERVER_LOG" "$CLIENT_LOG" "$INI_FILE" "$PICO_SVR_LOG" "$PICO_CLI_LOG"
}
trap cleanup_all EXIT

# ─── INI generation ──────────────────────────────────────────────────────────
# Keys cross-checked against src/config.c (SEC_REORDER): MaxWaitMs/CapPackets/
# MaxFlows/IngressIdleSec/EgressIdleSec/ResetMarkPackets. Proto/Port/Profile in
# [ReorderRule]. CapPackets is the cap key (NOT CapPacketsPerFlow).
write_ini() {
    local wait="$1" cap="$2"
    {
        echo "[Reorder]"
        echo "Enabled = on"
        echo "MaxWaitMs = ${wait}"
        echo "CapPackets = ${cap}"
        if [ "$MODE" = "scale" ]; then
            # IngressIdleSec < EgressIdleSec invariant enforced (else RAW fallback).
            echo "MaxFlows = ${SCALE_MAX_FLOWS}"
            echo "IngressIdleSec = ${SCALE_INGRESS_IDLE}"
            echo "EgressIdleSec = ${SCALE_EGRESS_IDLE}"
            echo "ResetMarkPackets = ${SCALE_RESET_MARK}"
        fi
        echo ""
        echo "[ReorderRule]"
        echo "Proto = udp"
        echo "Port = ${PICO_PORT}"
        echo "Profile = quic_bulk"
    } >"$INI_FILE"
}

# ─── Inner HTTP/3 bulk-GET workload (picoquicdemo) ───────────────────────────
# Launches a picoquicdemo H3 server in NS_SERVER (UDP PICO_PORT == ReorderRule
# Port) and a client in NS_CLIENT doing a fixed-size bulk GET, parsing goodput
# (Mbps) from the client output. Echoes the goodput (float, "0" on failure).
#
# Flags pinned against picoquicdemo v1.1.50 (picoquic master, built by
# scripts/ci_interop/build_picoquic.sh):
#   * -G bbr            BBR congestion control (also the build default; -h lists
#                       bbr among newreno/cubic/dcubic/fast/bbr/prague/bbr1/c4).
#   * "/<bytes>"        scenario: the demo H3 server GENERATES <bytes> bytes for a
#                       numeric path on the fly — no -w web root / sized file needed.
#   * -n <sni>          SNI is mandatory; a NULL SNI makes the H3 GET fail.
#   * -D                no-disk on both ends (don't write the 50 MiB to disk).
#   * qlog/binlog/text log are OFF by simply omitting -q/-b/-l.
#   * goodput line (client stdout): "Received <N> bytes in <T> seconds, <X> Mbps."
#     NOTE the client ALSO prints a "Sent ... Mbps." line (upload), so we must
#     extract the RECEIVED (download) line specifically, not the last Mbps token.
run_inner_http3() {
    require_picoquic || return 1

    : >"$PICO_SVR_LOG"
    : >"$PICO_CLI_LOG"

    # Server: serves the generated object; -1 closes after one connection (one
    # cell == one bulk GET), -D = no disk.
    ip netns exec "$NS_SERVER" "$PICOQUICDEMO" \
        -p "$PICO_PORT" \
        -c "$PICO_CERT" -k "$PICO_KEY" \
        -G bbr -1 -D \
        >"$PICO_SVR_LOG" 2>&1 &
    local pico_svr_pid=$!
    sleep 1
    if ! kill -0 "$pico_svr_pid" 2>/dev/null; then
        echo "  (picoquicdemo server failed to start; see $PICO_SVR_LOG)" >&2
        echo "NA"
        return 1
    fi

    # Client: bulk GET of a generated PICO_FILE_BYTES object over the tunnel.
    local scenario="/${PICO_FILE_BYTES}"
    ip netns exec "$NS_CLIENT" "$PICOQUICDEMO" \
        -G bbr -D -n "$PICO_SNI" \
        "$TUNNEL_SERVER_IP" "$PICO_PORT" "$scenario" \
        >"$PICO_CLI_LOG" 2>&1 || true

    kill "$pico_svr_pid" 2>/dev/null || true
    wait "$pico_svr_pid" 2>/dev/null || true

    # Parse the RECEIVED (download) goodput. The line is:
    #   "Received <N> bytes in <T> seconds, <X> Mbps."
    # Pick the token immediately before "Mbps" on the Received line only (the Sent
    # line carries the upload Mbps and must NOT be matched).
    local gp
    gp="$(awk '
        /^Received [0-9]+ bytes in .* Mbps/ {
            for (i = 1; i <= NF; i++)
                if ($i == "Mbps" || $i == "Mbps.") { print $(i - 1); break }
        }' "$PICO_CLI_LOG" 2>/dev/null | tail -1 || true)"
    # Unparseable / failed transfer is reported as the sentinel "NA" — NOT 0 — so
    # the downstream analyzer filters it instead of mistaking it for a true
    # zero-throughput measurement.
    [ -z "$gp" ] && gp="NA"
    echo "$gp"
}

# ─── Stats harvest ───────────────────────────────────────────────────────────
# Echoes a comma-joined tail of the CSV row (the reorder-stats columns) by
# querying get_reorder_stats. JSON shape per control_socket.c get_reorder_stats.
harvest_reorder_stats() {
    local rs p99 maxl bufp99 gap gfill gto gov deliv
    rs="$(bench_query_control "$CTRL_PORT" get_reorder_stats)"
    # An empty control response (control timeout / server died) is NOT valid data:
    # `echo "" | jq '... // 0'` exits 0 with EMPTY output, so the `// 0` default
    # never fires and the CSV cell would silently become "" (looks like, but is
    # not, a measurement). Reject empty / non-JSON responses as a failed cell.
    if [ -z "$rs" ] || ! echo "$rs" | jq -e . >/dev/null 2>&1; then
        echo "ERR: empty or invalid control response for cell" >&2
        return 1
    fi
    p99=$(echo "$rs"    | jq '.reorder.added_latency_p99_ms // 0'           2>/dev/null || echo 0)
    maxl=$(echo "$rs"   | jq '.reorder.added_latency_max_ms // 0'           2>/dev/null || echo 0)
    bufp99=$(echo "$rs" | jq '.reorder.added_latency_buffered_p99_ms // 0'  2>/dev/null || echo 0)
    gap=$(echo "$rs"    | jq '.reorder.gap_count // 0'                      2>/dev/null || echo 0)
    gfill=$(echo "$rs"  | jq '.reorder.gap_filled_count // 0'               2>/dev/null || echo 0)
    gto=$(echo "$rs"    | jq '.reorder.gap_timeout_count // 0'              2>/dev/null || echo 0)
    gov=$(echo "$rs"    | jq '.reorder.gap_overflow_count // 0'             2>/dev/null || echo 0)
    deliv=$(echo "$rs"  | jq '.reorder.delivered_count // 0'                2>/dev/null || echo 0)
    # Belt-and-suspenders: never emit an empty field even if a parse slips through.
    echo "${p99:-0},${maxl:-0},${bufp99:-0},${gap:-0},${gfill:-0},${gto:-0},${gov:-0},${deliv:-0}"
}

# ─── Lifecycle helper: start a fresh server+client for the current INI ───────
start_tunnel() {
    : >"$SERVER_LOG"
    : >"$CLIENT_LOG"
    bench_start_vpn_server "--control-port ${CTRL_PORT} --config ${INI_FILE}" "$SERVER_LOG"
    local paths_arg="" i
    for (( i=0; i<N_PATHS; i++ )); do
        paths_arg="${paths_arg} --path $(bench_path_veth_client "$i")"
    done
    bench_start_vpn_client "${paths_arg} --config ${INI_FILE}" "$CLIENT_LOG"
    bench_wait_tunnel 25
}

# ─── Resume support ──────────────────────────────────────────────────────────
# Build a set of already-done (env,wait,cap,repeat) keys from an existing CSV so
# re-running appends only the missing cells.
declare -A DONE_KEYS=()
load_done_keys() {
    [ -f "$OUT" ] || return 0
    # CSV columns: 1=ts 2=env 3=axis 4=wait 5=cap 6=repeat ... (CSV_HEADER fields).
    local line raw env wait cap rep nfields
    # Expected field count = number of columns in CSV_HEADER.
    local want_fields=$(( $(echo "$CSV_HEADER" | tr ',' '\n' | wc -l) ))
    # `|| [ -n "$raw" ]` keeps the final newline-less line (a row half-written when
    # a prior run was killed) instead of having `read` silently drop it.
    while IFS= read -r raw || [ -n "$raw" ]; do
        [ -z "$raw" ] && continue
        # Validate field count: ignore a short/truncated tail row (e.g. a row cut
        # off mid-write) rather than registering a partial — incomplete key.
        nfields=$(( $(echo "$raw" | tr ',' '\n' | wc -l) ))
        [ "$nfields" -ne "$want_fields" ] && continue
        IFS=, read -r _ env _ wait cap rep _ <<<"$raw"
        [ "$env" = "env_name" ] && continue   # header
        [ -z "$env" ] && continue
        DONE_KEYS["${env}|${wait}|${cap}|${rep}"]=1
    done <"$OUT"
    line=$(wc -l <"$OUT")
    echo "[resume] $OUT exists (${line} lines); ${#DONE_KEYS[@]} cell(s) already recorded — will skip them"
}

ensure_csv_header() {
    if [ ! -f "$OUT" ]; then
        echo "$CSV_HEADER" >"$OUT"
    fi
}

# ─── run_one_cell(env, wait, cap, repeat) ────────────────────────────────────
# Applies netem for the env, generates INI, brings the tunnel up, runs the inner
# H3 workload, harvests reorder stats, appends one CSV row, tears the tunnel
# down. $5 is the axis label for the row.
run_one_cell() {
    local env="$1" wait="$2" cap="$3" rep="$4" axis="$5"
    local key="${env}|${wait}|${cap}|${rep}"

    if [ -n "${DONE_KEYS[$key]:-}" ]; then
        echo "[skip] env=$env wait=$wait cap=$cap rep=$rep (already in CSV)"
        return 0
    fi

    echo ""
    echo "[cell] env=$env axis=$axis wait=${wait}ms cap=$cap rep=$rep"

    # Split "pathA|pathB" netem and apply.
    local spec="${ENV_NETEM[$env]}"
    local netem_a="${spec%%|*}"
    local netem_b="${spec#*|}"
    bench_apply_netem "$netem_a" "$netem_b"

    write_ini "$wait" "$cap"

    if ! start_tunnel; then
        echo "  (tunnel failed to come up for env=$env wait=$wait cap=$cap; skipping cell)" >&2
        bench_stop_vpn
        return 0
    fi

    # run_inner_http3 emits the sentinel "NA" (not "0") on workload/parse failure,
    # so a truly-zero throughput stays distinguishable from "not measured"
    # downstream (the analyzer filters NA rows).
    local goodput
    goodput="$(run_inner_http3)" || {
        echo "  (inner workload failed; recording goodput=NA)" >&2
        goodput="NA"
    }
    [ -z "$goodput" ] && goodput="NA"

    # Harvest reorder stats. If the control response is empty/invalid, the cell's
    # reorder data is unreliable: skip the row (don't write blank/zero stats) so
    # the cell remains un-recorded and gets retried on the next resume run.
    local stats_tail
    if ! stats_tail="$(harvest_reorder_stats)"; then
        echo "  (reorder-stats harvest failed for env=$env wait=$wait cap=$cap rep=$rep; skipping row, will retry on resume)" >&2
        bench_stop_vpn
        return 0
    fi

    local ts
    ts="$(date -u +%FT%TZ)"
    echo "${ts},${env},${axis},${wait},${cap},${rep},${goodput},${stats_tail},${PICO_PIN}" >>"$OUT"
    DONE_KEYS["$key"]=1
    echo "  -> goodput=${goodput} Mbps  reorder=[${stats_tail}]"

    bench_stop_vpn
}

# ─── Environment selection ───────────────────────────────────────────────────
# Resolve the set of env keys to sweep, honoring --env / --axis (and the
# --quick alias which forces --axis rtt).
select_envs() {
    if [ -n "$SEL_ENV" ]; then
        echo "$SEL_ENV"
        return
    fi
    if [ -n "$SEL_AXIS" ]; then
        echo "${AXIS_ENVS[$SEL_AXIS]}"
        return
    fi
    # No subset: all environments.
    echo "${!ENV_NETEM[*]}"
}

axis_of_env() {
    # Reverse lookup: which axis label a given env belongs to (first match).
    local env="$1" a
    for a in rtt jitter loss bw profiles; do
        case " ${AXIS_ENVS[$a]} " in
            *" $env "*) echo "$a"; return ;;
        esac
    done
    echo "other"
}

# ─── perf-mode sweep ─────────────────────────────────────────────────────────
run_perf_sweep() {
    require_picoquic   # fail loudly up front before any netns work
    ensure_csv_header
    load_done_keys

    local envs rep env
    envs="$(select_envs)"
    echo "[perf] envs: ${envs}"
    echo "[perf] stage: ${SEL_STAGE:-1+2}  repeats: ${REPEATS}  out: ${OUT}"

    # ── Stage 1: sweep WAIT_VALUES at cap=STAGE1_CAP over the selected envs. ──
    if [ -z "$SEL_STAGE" ] || [ "$SEL_STAGE" = "1" ]; then
        local wait
        for env in $envs; do
            local axis; axis="$(axis_of_env "$env")"
            for wait in "${WAIT_VALUES[@]}"; do
                for (( rep=1; rep<=REPEATS; rep++ )); do
                    run_one_cell "$env" "$wait" "$STAGE1_CAP" "$rep" "$axis"
                done
            done
        done
    fi

    # ── Stage 2: sweep CAP_VALUES at each env's chosen wait, STAGE2_ENVS only. ─
    if [ -z "$SEL_STAGE" ] || [ "$SEL_STAGE" = "2" ]; then
        local cap s2env wait
        for s2env in "${STAGE2_ENVS[@]}"; do
            # Honor --env / --axis subsetting for Stage 2 as well.
            case " $envs " in *" $s2env "*) ;; *) continue ;; esac
            local axis; axis="$(axis_of_env "$s2env")"
            wait="${ENV_CHOSEN_WAIT[$s2env]:-$DEFAULT_CHOSEN_WAIT}"
            for cap in "${CAP_VALUES[@]}"; do
                for (( rep=1; rep<=REPEATS; rep++ )); do
                    run_one_cell "$s2env" "$wait" "$cap" "$rep" "$axis"
                done
            done
        done
    fi

    echo ""
    echo "[perf] done. CSV: $OUT"
}

# ─── scale-mode workloads ────────────────────────────────────────────────────
# (a) Multi-flow run: several concurrent inner flows on distinct src ports under
#     a LOW MaxFlows, expecting per_flow_limit_drop_count / evictions to appear.
# (b) Flow-churn run: exercise ResetMarkPackets + EgressIdleSec idle eviction.
#
# For simplicity (and because picoquic flags aren't pinned) we use N concurrent
# UDP flows via iperf3 if available, else nc, to multiplex distinct 4-tuples
# through the ReorderRule. Goodput is not the metric here — the reorder counters
# are. picoquic-specific multi-flow is left as a TODO.
scale_launch_concurrent_udp() {
    local nflows="$1" dur="${2:-8}" i
    # Only wait on the flow PIDs we spawn here — a bare `wait` would also block on
    # the long-lived VPN server+client background jobs (started with & by
    # bench_start_vpn_server/_client), which never exit, hanging scale mode.
    local flow_pids=()
    # Scale mode stresses FLOW-TABLE capacity, so it only needs N distinct reorder
    # flows — each iperf3 client uses a distinct --cport, giving a distinct inner
    # UDP 4-tuple == a distinct reorder flow key. That is sufficient to exercise
    # MaxFlows / per_flow_limit_drop, so we keep the lightweight iperf3/nc multiplex
    # here rather than N concurrent picoquicdemo processes (perf mode already uses
    # real H3; N-flow picoquic is optional extra realism, deferred).
    if command -v iperf3 >/dev/null 2>&1; then
        ip netns exec "$NS_SERVER" iperf3 -s -p "$PICO_PORT" -D \
            --pidfile /tmp/sweep-reorder-iperf3.pid >/dev/null 2>&1 || true
        sleep 1
        for (( i=0; i<nflows; i++ )); do
            ip netns exec "$NS_CLIENT" iperf3 -c "$TUNNEL_SERVER_IP" \
                -p "$PICO_PORT" -u -b 5M -l 1200 -t "$dur" \
                --cport "$(( 40000 + i ))" >/dev/null 2>&1 &
            flow_pids+=("$!")
        done
        [ "${#flow_pids[@]}" -gt 0 ] && wait "${flow_pids[@]}"
        kill "$(cat /tmp/sweep-reorder-iperf3.pid 2>/dev/null)" 2>/dev/null || true
        rm -f /tmp/sweep-reorder-iperf3.pid
    else
        # nc fallback: fire short UDP bursts from distinct src ports.
        for (( i=0; i<nflows; i++ )); do
            ip netns exec "$NS_CLIENT" bash -c \
                "head -c 1000000 /dev/zero | timeout ${dur} nc -u -p $(( 40000 + i )) -w 1 ${TUNNEL_SERVER_IP} ${PICO_PORT}" \
                >/dev/null 2>&1 &
            flow_pids+=("$!")
        done
        [ "${#flow_pids[@]}" -gt 0 ] && wait "${flow_pids[@]}"
    fi
}

run_scale_mode() {
    # scale-mode writes the .md report, NOT the optimal-value CSV.
    echo "[scale] MaxFlows=${SCALE_MAX_FLOWS} ResetMark=${SCALE_RESET_MARK} \
IngressIdle=${SCALE_INGRESS_IDLE}s EgressIdle=${SCALE_EGRESS_IDLE}s \
concurrent=${SCALE_CONCURRENT_FLOWS} report: ${SCALE_MD}"

    # Use the baseline env (or the user's --env) with a mild RTT spread so the
    # reorder engine actually arms while we stress flow capacity.
    local env="${SEL_ENV:-baseline}"
    [ -z "${ENV_NETEM[$env]:-}" ] && env="baseline"
    local spec="${ENV_NETEM[$env]}"
    bench_apply_netem "${spec%%|*}" "${spec#*|}"

    # cap=1024 fixed for scale runs (cap sweeping is perf-mode's job).
    write_ini 30 1024

    {
        echo "# Reorder scale-mode report — ${DATE_TAG}"
        echo ""
        echo "- env: \`${env}\`  (netem: \`${spec}\`)"
        echo "- MaxFlows=${SCALE_MAX_FLOWS}, ResetMarkPackets=${SCALE_RESET_MARK}, IngressIdleSec=${SCALE_INGRESS_IDLE}, EgressIdleSec=${SCALE_EGRESS_IDLE}"
        echo "- concurrent flows: ${SCALE_CONCURRENT_FLOWS} (quick=${QUICK})"
        echo ""
    } >"$SCALE_MD"

    if ! start_tunnel; then
        echo "[scale] tunnel failed to come up" >&2
        { echo "## ERROR"; echo "tunnel failed to establish — see logs"; } >>"$SCALE_MD"
        bench_stop_vpn
        return 1
    fi

    # ── (a) Multi-flow over-capacity run ──────────────────────────────────────
    local nflows="$SCALE_CONCURRENT_FLOWS"
    [ "$QUICK" -eq 1 ] && nflows=$(( SCALE_MAX_FLOWS + 2 ))   # smoke: just over cap
    echo "[scale] (a) ${nflows} concurrent flows vs MaxFlows=${SCALE_MAX_FLOWS}"
    scale_launch_concurrent_udp "$nflows" 8

    local rs_a per_flow_drop pool_drop deliv_a
    rs_a="$(bench_query_control "$CTRL_PORT" get_reorder_stats)"
    per_flow_drop=$(echo "$rs_a" | jq '.reorder.per_flow_limit_drop_count // 0' 2>/dev/null || echo 0)
    pool_drop=$(echo "$rs_a"     | jq '.reorder.pool_drop_count // 0'           2>/dev/null || echo 0)
    deliv_a=$(echo "$rs_a"       | jq '.reorder.delivered_count // 0'           2>/dev/null || echo 0)

    {
        echo "## (a) Multi-flow over-capacity"
        echo ""
        echo "- concurrent flows: ${nflows} vs MaxFlows ${SCALE_MAX_FLOWS}"
        echo "- per_flow_limit_drop_count: **${per_flow_drop}**  (expected > 0 when flows > MaxFlows)"
        echo "- pool_drop_count: ${pool_drop}"
        echo "- delivered_count: ${deliv_a}"
        if [ "${per_flow_drop:-0}" -gt 0 ]; then
            echo "- RESULT: **PASS** — flow-capacity limit observed"
        else
            echo "- RESULT: INCONCLUSIVE — no per-flow drops seen. Raise"
            echo "  SCALE_CONCURRENT_FLOWS above MaxFlows (${SCALE_MAX_FLOWS}), or confirm the"
            echo "  flows reached the engine (each --cport is a distinct inner 4-tuple ="
            echo "  a distinct reorder flow; check the tunnel actually carried them)."
        fi
        echo ""
    } >>"$SCALE_MD"

    # ── (b) Flow-churn / idle-eviction run ────────────────────────────────────
    # Fire flows, then idle past EgressIdleSec so egress idle eviction triggers;
    # ResetMarkPackets exercises the reset path under sustained traffic.
    echo "[scale] (b) flow-churn + idle past EgressIdleSec=${SCALE_EGRESS_IDLE}s"
    scale_launch_concurrent_udp "$(( SCALE_MAX_FLOWS / 2 + 1 ))" 4
    echo "[scale]     idling $(( SCALE_EGRESS_IDLE + 2 ))s to trigger egress idle eviction..."
    sleep "$(( SCALE_EGRESS_IDLE + 2 ))"

    local rs_b reset_discard deliv_b gap_b
    rs_b="$(bench_query_control "$CTRL_PORT" get_reorder_stats)"
    reset_discard=$(echo "$rs_b" | jq '.reorder.reset_discard_count // 0' 2>/dev/null || echo 0)
    deliv_b=$(echo "$rs_b"       | jq '.reorder.delivered_count // 0'     2>/dev/null || echo 0)
    gap_b=$(echo "$rs_b"         | jq '.reorder.gap_count // 0'           2>/dev/null || echo 0)

    {
        echo "## (b) Flow-churn + idle eviction"
        echo ""
        echo "- ResetMarkPackets=${SCALE_RESET_MARK}, IngressIdleSec=${SCALE_INGRESS_IDLE}, EgressIdleSec=${SCALE_EGRESS_IDLE}"
        echo "- reset_discard_count: ${reset_discard}"
        echo "- gap_count: ${gap_b}"
        echo "- delivered_count: ${deliv_b}"
        echo "- (idle eviction is internal — surfaced indirectly; raw stats below)"
        echo ""
        echo '```json'
        echo "$rs_b"
        echo '```'
        echo ""
    } >>"$SCALE_MD"

    bench_stop_vpn
    echo "[scale] done. report: $SCALE_MD"
}

# ─── Main ────────────────────────────────────────────────────────────────────
echo "[sweep_reorder] mode=$MODE binary=$MQVPN ctrl-port=$CTRL_PORT pico-port=$PICO_PORT"
bench_check_test_deps nc jq

bench_setup_netns_n "$N_PATHS"
bench_add_server_host_routes "$N_PATHS"

if [ "$MODE" = "scale" ]; then
    run_scale_mode
else
    run_perf_sweep
fi

echo "[sweep_reorder] complete."
