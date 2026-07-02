// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* Hybrid-mode TCP lane (H2): NO_SYS=1 lwIP driver. Keep every lwIP type
 * behind this file; nothing here leaks into libmqvpn public headers
 * (spec: "do not let lwip types leak into libmqvpn headers"). */
#ifndef MQVPN_HYBRID_LWIP_GLUE_H
#define MQVPN_HYBRID_LWIP_GLUE_H

#include <stddef.h>
#include <stdint.h>

typedef struct mqvpn_lwip_ctx mqvpn_lwip_ctx_t;

/* clock_us: matches client_now_us()'s signature shape (microseconds);
 * lwip_glue.c converts to the milliseconds sys_now() wants. */
typedef uint64_t (*mqvpn_lwip_clock_fn)(void *clock_ctx);

/* Every packet lwIP's TCP stack generates (SYN-ACK, ACK, data segments —
 * this netif plays the server role for every intercepted connection, so it
 * transmits on essentially every accepted flow) comes out here and must be
 * delivered to the real TUN device so the intercepted inner OS actually
 * receives it — mirror image of mqvpn_lwip_input(). Signature matches
 * mqvpn_tun_output_fn on purpose. */
typedef void (*mqvpn_lwip_output_fn)(const uint8_t *pkt, size_t len, void *output_ctx);

/* Bring up the lwIP stack: one pretend netif (heiher fork wildcard TCP
 * intercept) + one wildcard listener. Single instance per process (same
 * single-client assumption client_now_us/xqc_custom_timestamp document);
 * a second concurrent ctx is refused with NULL.
 *
 * tun_mtu: real TUN MTU, applied to netif->mtu; lwIP derives each pcb's
 * effective MSS from it at accept time (tcp_eff_send_mss_netif — there is
 * no per-pcb MSS setter, see lwip_port/lwipopts.h). */
mqvpn_lwip_ctx_t *mqvpn_lwip_ctx_new(mqvpn_lwip_clock_fn clock_fn, void *clock_ctx,
                                     mqvpn_lwip_output_fn output_fn, void *output_ctx,
                                     int tun_mtu);

/* Tear down listener + netif and free ctx. The future tcp_lane must have
 * aborted every accepted pcb first — this only closes the glue-owned
 * listener; live connection pcbs left behind would reference a removed
 * netif. */
void mqvpn_lwip_ctx_free(mqvpn_lwip_ctx_t *ctx);

/* Feed one IPv4 TCP packet (already classified MQVPN_LANE_TCP) into the
 * netif, unmodified — no rewriting (the wildcard bind accepts SYNs for any
 * destination; the accepted pcb's local_ip/local_port ARE the original
 * dst). Returns 0 on success, <0 if pbuf alloc failed (caller drops the
 * packet). */
int mqvpn_lwip_input(mqvpn_lwip_ctx_t *ctx, const uint8_t *pkt, size_t len);

/* Drive lwIP's manual timers (LWIP_TIMERS=0: the sys_timeout wheel is
 * compiled out; the glue calls tcp_tmr()/ip_reass_tmr() itself on their
 * documented cadence). Call every tick(), matching the existing tick
 * sub-function pattern (tick_handshake_watchdog / tick_path_recovery). */
void mqvpn_lwip_tick(mqvpn_lwip_ctx_t *ctx);

/* Milliseconds until mqvpn_lwip_tick() next needs to run. Returns -1 if no
 * timer is pending (idle — get_interest() must NOT force a wakeup then,
 * only shorten). */
int mqvpn_lwip_next_timeout_ms(mqvpn_lwip_ctx_t *ctx);

#endif /* MQVPN_HYBRID_LWIP_GLUE_H */
