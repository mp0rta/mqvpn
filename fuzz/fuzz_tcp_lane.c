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
 * No accept callback is registered on the lwIP listener: an accepted
 * connection would need a live flow table (tcp_lane.c) to do anything
 * useful with received data, which is out of scope for this target. A SYN
 * that completes the handshake with no accept callback set is a normal,
 * crash-safe lwIP outcome (TCP_EVENT_ACCEPT sees accept==NULL, returns
 * ERR_ARG, lwIP resets the pcb) — see lwip/tcp_in.c's LISTEN handling.
 *
 * Determinism / replay: mqvpn_lwip_ctx_new's clock_fn is the ONLY time
 * source sys_now() reads (lwip_glue.c: sys_now() calls
 * s_lwip_ctx_for_sys_now->clock_fn, never gettimeofday/clock_gettime
 * directly) — the deterministic fuzz_clock below fully replaces the real
 * wall-clock client_now_us() used in production, so a saved crash input
 * replays identically. lwIP's LWIP_TIMERS is compiled out (0) in this
 * port (lwip_port/lwipopts.h) so no libc timer thread is involved either.
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

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    /* NULL output_fn: no TUN to deliver lwIP's generated packets to —
     * mqvpn_tcp_lane_netif_output() no-ops safely on a NULL output_fn
     * (lwip_glue.c). */
    g_ctx = mqvpn_lwip_ctx_new(fuzz_clock, NULL, NULL, NULL, 1500);
    return g_ctx ? 0 : -1;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1 || size > 9500) return 0;

    mqvpn_hybrid_config_t pol;
    mqvpn_hybrid_config_default(&pol);
    pol.enabled = 1;
    pol.tcp_mode = MQVPN_HYBRID_TCP_STREAM;
    /* client_tunnel_subnet stays mask==0 (unset sentinel) from the memset
     * in mqvpn_hybrid_config_default — gate off, per classifier.h's
     * docstring; fine for fuzzing the parser/lane-selection surface. */

    mqvpn_flow_key_t key;
    mqvpn_hybrid_lane_t lane = mqvpn_hybrid_classify(data, size, &pol, &key);
    if (lane == MQVPN_LANE_TCP) mqvpn_lwip_input(g_ctx, data, size);
    mqvpn_lwip_tick(g_ctx);
    return 0;
}
