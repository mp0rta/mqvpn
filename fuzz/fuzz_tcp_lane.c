// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* libFuzzer target: raw TUN bytes -> classifier -> (if TCP lane) lwIP packet
 * intake. Establishes the fuzz/ pattern for this repo; kept deliberately
 * minimal (no harness framework, no persistent flow table).
 *
 * Scope: this fuzzes classifier parsing (mqvpn_hybrid_classify /
 * mqvpn_parse_l3l4) and lwIP's netif->input path
 * (mqvpn_lwip_input/mqvpn_lwip_tick) for crash-safety on ARBITRARY bytes — a
 * real TUN device can deliver anything, so both must never crash regardless
 * of input. It does NOT touch xquic/H3: the client relay (tcp_lane.c /
 * tcp_lane_uplink.c) only ever sees bytes lwIP itself already validated as a
 * well-formed TCP stream, not raw wire bytes. It also does NOT cover
 * svr_tcp_egress_parse_path (server-side, attacker-controlled H3 :path
 * parsing) — that surface is exercised by the malformed-input unit tests
 * added with the egress ACL task; a dedicated fuzz target for it is a
 * plausible future candidate if a real need for one shows up, not built
 * here (YAGNI).
 *
 * A minimal accept callback IS registered on the lwIP listener (below),
 * mirroring production's mqvpn_tcp_lane_lwip_accept (tcp_lane.c): it always
 * returns ERR_MEM, the same shape as production's pcb-pool-exhaustion branch
 * (tcp_lane.c: the !newpcb || err != ERR_OK case), without tracking or using
 * the accepted pcb — a live flow table (tcp_lane.c)
 * would be needed to do anything useful with received data, which is out of
 * scope for this target. Registering a callback (any callback) is required,
 * not optional: with none registered, the listener keeps lwIP's default
 * tcp_accept_null, and tcp_listen_input's pcb-pool-exhaustion path
 * (tcp_in.c) calls it with (NULL, ERR_MEM) — tcp_accept_null asserts on the
 * NULL pcb ("tcp_accept_null: invalid pcb", tcp.c), aborting the fuzz
 * process on a condition production never hits.
 *
 * Determinism / replay: mqvpn_lwip_ctx_new's clock_fn is the ONLY time
 * source sys_now() reads (lwip_glue.c: sys_now() calls
 * s_lwip_ctx_for_sys_now->clock_fn, never gettimeofday/clock_gettime
 * directly) — the deterministic fuzz_clock below fully replaces the real
 * wall-clock client_now_us() used in production, so a saved crash input
 * replays identically. lwIP's LWIP_TIMERS is compiled out (0) in this
 * port (lwip_port/lwipopts.h) so no libc timer thread is involved either.
 *
 * Persistent-ctx replay caveat (Task 26 triage): g_ctx and the lwIP pcb
 * lists are process-global and accumulate across inputs within one run — so
 * a crash that depends on cross-input state (e.g. a pcb left half-open by an
 * earlier input) will NOT reproduce from the single saved crash artifact
 * alone. Whole-run replay (re-running the fuzzer over the same corpus with
 * the same -seed) is still deterministic and is the fallback when a
 * single-input artifact doesn't repro.
 */

#include <stddef.h>
#include <stdint.h>

#include "hybrid/classifier.h"
#include "hybrid/lwip_glue.h"

static mqvpn_lwip_ctx_t *g_ctx;

static uint64_t
fuzz_clock(void *unused)
{
    (void)unused;
    static uint64_t t;
    return t += 1000; /* monotonic, deterministic, no real clock read */
}

/* Mirrors production's mqvpn_tcp_lane_lwip_accept's pcb-pool-exhaustion
 * branch (tcp_lane.c, the !newpcb || err != ERR_OK case): unconditionally
 * ERR_MEM, no pcb tracking. See the file
 * comment above for why registering a callback at all (not just this
 * specific behavior) is required for crash-safety. */
static err_t
fuzz_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    (void)arg;
    (void)newpcb;
    (void)err;
    return ERR_MEM;
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    /* NULL output_fn: no TUN to deliver lwIP's generated packets to —
     * mqvpn_tcp_lane_netif_output() no-ops safely on a NULL output_fn
     * (lwip_glue.c). */
    g_ctx = mqvpn_lwip_ctx_new(fuzz_clock, NULL, NULL, NULL, 1500);
    if (!g_ctx) {
        return -1;
    }
    mqvpn_lwip_ctx_set_accept_cb(g_ctx, fuzz_accept_cb, NULL);
    return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1 || size > 9500) return 0;

    mqvpn_hybrid_config_t pol;
    mqvpn_hybrid_config_default(&pol);
    pol.enabled = 1;
    pol.tcp_mode = MQVPN_HYBRID_TCP_STREAM;
    /* client_tunnel_subnet[] stays family==0 (unset sentinel) from the
     * memset in mqvpn_hybrid_config_default — gate off, per classifier.h's
     * docstring; fine for fuzzing the parser/lane-selection surface. */

    mqvpn_flow_key_t key;
    mqvpn_hybrid_lane_t lane = mqvpn_hybrid_classify(data, size, &pol, &key);
    if (lane == MQVPN_LANE_TCP) mqvpn_lwip_input(g_ctx, data, size);
    mqvpn_lwip_tick(g_ctx);
    return 0;
}
