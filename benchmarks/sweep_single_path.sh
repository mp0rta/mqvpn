#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 mp0rta and mqvpn contributors
#
# sweep_single_path.sh — single-path baseline for the reorder report.
#
# Companion to sweep_reorder.sh. For each environment in the ENV_NETEM table
# (sourced verbatim so the two sweeps stay in lockstep), runs the inner
# picoquicdemo bulk GET over a SINGLE veth path using that environment's leg-A
# netem, then again using its leg-B netem. The result answers a question the
# OFF-vs-ON table cannot: "is multipath + reorder actually faster than just
# picking the better single path?" If best-single >> best-ON, the right
# recommendation is "don't multipath", not "tune the reorder buffer".
#
# Differences from sweep_reorder.sh:
#   * N_PATHS=1 (only veth-a0/veth-a1 exist).
#   * No reorder-param sweep — [Reorder] Enabled=off (a single path has no
#     cross-path reordering for the buffer to fix).
#   * Per env, two cells: leg=A applies the env's pathA netem, leg=B applies its
#     pathB netem. Both to the same lone veth pair.
#
# CSV schema (header row):
#   timestamp,env_name,leg,repeat,goodput_mbps,picoquic_pin
#
# Requires: root (netns), netcat-openbsd, jq, picoquicdemo (PICOQUICDEMO=<path>).
# Usage:
#   sudo PICOQUICDEMO=<path> ./sweep_single_path.sh [--out CSV] [--env NAME] [--quick]
#   Env overrides: REPEATS (default 3), PICO_FILE_BYTES, PICO_TIMEOUT.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=./bench_env_setup.sh
source "${SCRIPT_DIR}/bench_env_setup.sh"

# ─── Sweep table ─────────────────────────────────────────────────────────────
# Bound by nameref to BENCH_ENV_NETEM (defined in bench_env_setup.sh) so the
# perf sweep and the single-path baseline cannot drift on netem. Drift would
# silently invalidate the 3-way comparison in sweep_reorder_analyze.py (the
# joins are by env_name only).
declare -n ENV_NETEM=BENCH_ENV_NETEM

REPEATS="${REPEATS:-3}"

# ─── Fixed knobs (mirror sweep_reorder.sh) ───────────────────────────────────
N_PATHS=1
CTRL_PORT="${CTRL_PORT:-9097}"
PICO_PORT="${PICO_PORT:-5401}"
PICO_FILE_BYTES="${PICO_FILE_BYTES:-20971520}"   # 20 MiB
PICO_TIMEOUT="${PICO_TIMEOUT:-90}"
PICO_CERT="${PICO_CERT:-${REPO_ROOT}/third_party/picoquic/certs/cert.pem}"
PICO_KEY="${PICO_KEY:-${REPO_ROOT}/third_party/picoquic/certs/key.pem}"
PICO_SNI="${PICO_SNI:-test}"

# ─── CLI parsing ─────────────────────────────────────────────────────────────
OUT=""
SEL_ENV=""
QUICK=0
FORCE=0

usage() {
    cat >&2 <<EOF
usage: sudo PICOQUICDEMO=<path> $0 [options]
  --out <csv>    output CSV (default ci_sweep_results/reorder_single_DATE.csv)
  --env <name>   restrict to one environment key
  --quick        REPEATS=1 smoke
  --force        re-run cells already recorded in the CSV
Environments: ${!ENV_NETEM[*]}
EOF
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --out)   OUT="${2:?--out needs a path}"; shift 2 ;;
        --env)   SEL_ENV="${2:?--env needs a name}"; shift 2 ;;
        --quick) QUICK=1; shift ;;
        --force) FORCE=1; shift ;;
        -h|--help) usage ;;
        *) echo "error: unknown argument '$1'" >&2; usage ;;
    esac
done
[ "$QUICK" -eq 1 ] && REPEATS=1

if [ -n "$SEL_ENV" ] && [ -z "${ENV_NETEM[$SEL_ENV]:-}" ]; then
    echo "error: unknown --env '$SEL_ENV' (valid: ${!ENV_NETEM[*]})" >&2
    exit 2
fi

# ─── Output ──────────────────────────────────────────────────────────────────
RESULTS_SWEEP_DIR="${REPO_ROOT}/ci_sweep_results"
mkdir -p "$RESULTS_SWEEP_DIR"
DATE_TAG="$(date +%Y%m%d)"
[ -z "$OUT" ] && OUT="${RESULTS_SWEEP_DIR}/reorder_single_${DATE_TAG}.csv"
CSV_HEADER="timestamp,env_name,leg,repeat,goodput_mbps,picoquic_pin"

# ─── picoquicdemo locator (mirror sweep_reorder.sh) ──────────────────────────
PICOQUICDEMO="${PICOQUICDEMO:-}"
if [ -z "$PICOQUICDEMO" ]; then
    PICOQUICDEMO="$(find "${REPO_ROOT}/third_party/picoquic" -name picoquicdemo -type f 2>/dev/null | head -1 || true)"
fi
PICO_PIN=""

require_picoquic() {
    if [ -z "$PICOQUICDEMO" ] || [ ! -x "$PICOQUICDEMO" ]; then
        echo "error: picoquicdemo not found." >&2
        echo "       Build it:   ${REPO_ROOT}/scripts/ci_interop/build_picoquic.sh" >&2
        return 1
    fi
    PICOQUICDEMO="$(realpath "$PICOQUICDEMO")"
    PICO_PIN="$(cd "${REPO_ROOT}/third_party/picoquic" 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || true)"
    [ -n "$PICO_PIN" ] || PICO_PIN="$(basename "$PICOQUICDEMO")"
    return 0
}

# ─── Temp files + trap ───────────────────────────────────────────────────────
SERVER_LOG="$(mktemp)"
CLIENT_LOG="$(mktemp)"
INI_FILE="$(mktemp --suffix=.ini)"
PICO_SVR_LOG="$(mktemp)"
PICO_CLI_LOG="$(mktemp)"

cleanup_all() {
    ip netns exec "$NS_SERVER" pkill -f picoquicdemo 2>/dev/null || true
    ip netns exec "$NS_CLIENT" pkill -f picoquicdemo 2>/dev/null || true
    bench_cleanup
    rm -f "$SERVER_LOG" "$CLIENT_LOG" "$INI_FILE" "$PICO_SVR_LOG" "$PICO_CLI_LOG"
}
trap cleanup_all EXIT

# ─── Single-path netem helper (only veth-a0/veth-a1 exist with N_PATHS=1) ────
apply_single_netem() {
    local netem="$1"
    ip netns exec "$NS_CLIENT" tc qdisc del dev "$VETH_A0" root 2>/dev/null || true
    ip netns exec "$NS_SERVER" tc qdisc del dev "$VETH_A1" root 2>/dev/null || true
    ip netns exec "$NS_CLIENT" tc qdisc add dev "$VETH_A0" root netem ${netem}
    ip netns exec "$NS_SERVER" tc qdisc add dev "$VETH_A1" root netem ${netem}
}

# ─── INI: reorder off (single path → no cross-path reordering to fix) ────────
write_ini_off() {
    {
        echo "[Reorder]"
        echo "Enabled = off"
    } >"$INI_FILE"
}

# ─── Inner HTTP/3 bulk GET (mirror sweep_reorder.sh run_inner_http3) ─────────
run_inner_http3() {
    require_picoquic || return 1
    : >"$PICO_SVR_LOG"
    : >"$PICO_CLI_LOG"

    ip netns exec "$NS_SERVER" "$PICOQUICDEMO" \
        -p "$PICO_PORT" \
        -c "$PICO_CERT" -k "$PICO_KEY" \
        -G bbr -1 -D \
        >"$PICO_SVR_LOG" 2>&1 &
    local pico_svr_pid=$!
    sleep 1
    if ! kill -0 "$pico_svr_pid" 2>/dev/null; then
        echo "  (picoquicdemo server failed to start)" >&2
        echo "NA"
        return 1
    fi

    local scenario="/${PICO_FILE_BYTES}"
    timeout -k 5 "$PICO_TIMEOUT" \
        ip netns exec "$NS_CLIENT" "$PICOQUICDEMO" \
        -G bbr -D -n "$PICO_SNI" \
        "$TUNNEL_SERVER_IP" "$PICO_PORT" "$scenario" \
        >"$PICO_CLI_LOG" 2>&1 || true

    kill "$pico_svr_pid" 2>/dev/null || true
    wait "$pico_svr_pid" 2>/dev/null || true

    local gp
    gp="$(awk '
        /^Received [0-9]+ bytes in .* Mbps/ {
            for (i = 1; i <= NF; i++)
                if ($i == "Mbps" || $i == "Mbps.") { print $(i - 1); break }
        }' "$PICO_CLI_LOG" 2>/dev/null | tail -1 || true)"
    [ -z "$gp" ] && gp="NA"
    echo "$gp"
}

# ─── Lifecycle: single-path tunnel ───────────────────────────────────────────
start_tunnel_single() {
    : >"$SERVER_LOG"
    : >"$CLIENT_LOG"
    bench_start_vpn_server "--control-port ${CTRL_PORT} --config ${INI_FILE}" "$SERVER_LOG"
    # Only veth-a0 exists; bench_path_veth_client 0 == veth-a0.
    local paths_arg="--path $(bench_path_veth_client 0)"
    bench_start_vpn_client "${paths_arg} --config ${INI_FILE}" "$CLIENT_LOG"
    bench_wait_tunnel 25
}

# ─── Resume support (mirror sweep_reorder.sh) ────────────────────────────────
declare -A DONE_KEYS=()
load_done_keys() {
    [ -f "$OUT" ] || return 0
    local raw env leg rep nfields want_fields
    want_fields=$(( $(echo "$CSV_HEADER" | tr ',' '\n' | wc -l) ))
    while IFS= read -r raw || [ -n "$raw" ]; do
        [ -z "$raw" ] && continue
        nfields=$(( $(echo "$raw" | tr ',' '\n' | wc -l) ))
        [ "$nfields" -ne "$want_fields" ] && continue
        IFS=, read -r _ env leg rep _ <<<"$raw"
        [ "$env" = "env_name" ] && continue
        [ -z "$env" ] && continue
        DONE_KEYS["${env}|${leg}|${rep}"]=1
    done <"$OUT"
    local line; line=$(wc -l <"$OUT")
    echo "[resume] $OUT exists (${line} lines); ${#DONE_KEYS[@]} cell(s) recorded — will skip"
}

ensure_csv_header() {
    if [ ! -f "$OUT" ]; then
        echo "$CSV_HEADER" >"$OUT"
    fi
}

# ─── run_one_cell(env, leg, repeat) ──────────────────────────────────────────
run_one_cell() {
    local env="$1" leg="$2" rep="$3"
    local key="${env}|${leg}|${rep}"
    if [ "$FORCE" -eq 0 ] && [ -n "${DONE_KEYS[$key]:-}" ]; then
        echo "[skip] env=$env leg=$leg rep=$rep (already in CSV; --force to re-run)"
        return 0
    fi

    echo ""
    echo "[cell] env=$env leg=$leg rep=$rep"

    # Pick the netem for this leg.
    local spec="${ENV_NETEM[$env]}"
    local netem
    case "$leg" in
        A) netem="${spec%%|*}" ;;
        B) netem="${spec#*|}" ;;
        *) echo "BUG: unknown leg '$leg'" >&2; return 1 ;;
    esac
    apply_single_netem "$netem"

    write_ini_off
    if ! start_tunnel_single; then
        echo "  (tunnel failed for env=$env leg=$leg; skipping cell)" >&2
        bench_stop_vpn
        return 0
    fi

    local goodput
    goodput="$(run_inner_http3)" || goodput="NA"
    [ -z "$goodput" ] && goodput="NA"

    local ts; ts="$(date -u +%FT%TZ)"
    echo "${ts},${env},${leg},${rep},${goodput},${PICO_PIN}" >>"$OUT"
    DONE_KEYS["$key"]=1
    echo "  -> goodput=${goodput} Mbps"

    bench_stop_vpn
    return 0
}

# ─── Main ────────────────────────────────────────────────────────────────────
echo "[sweep_single_path] binary=$MQVPN ctrl-port=$CTRL_PORT pico-port=$PICO_PORT n_paths=$N_PATHS"
bench_check_test_deps nc jq
bench_setup_netns_n "$N_PATHS"
bench_add_server_host_routes "$N_PATHS"

require_picoquic
ensure_csv_header
load_done_keys

ENVS_TO_RUN=()
if [ -n "$SEL_ENV" ]; then
    ENVS_TO_RUN=("$SEL_ENV")
else
    # Stable order across runs for resume readability.
    while IFS= read -r e; do ENVS_TO_RUN+=("$e"); done < <(printf '%s\n' "${!ENV_NETEM[@]}" | sort)
fi

echo "[sweep_single_path] envs: ${ENVS_TO_RUN[*]}"
echo "[sweep_single_path] repeats: ${REPEATS}  out: ${OUT}"

for env in "${ENVS_TO_RUN[@]}"; do
    for leg in A B; do
        for (( rep=1; rep<=REPEATS; rep++ )); do
            run_one_cell "$env" "$leg" "$rep"
        done
    done
done

echo ""
echo "[sweep_single_path] complete. CSV: $OUT"
