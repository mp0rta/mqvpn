// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* Hybrid-mode TCP lane (H2): NO_SYS=1 single-threaded lwIP driver.
 *
 * Everything runs on the tick thread (SYS_LIGHTWEIGHT_PROT=0). The port
 * layer compiles lwIP with LWIP_TIMERS=0, so this file also implements the
 * manual timer cadence (tcp_tmr every 250 ms, ip_reass_tmr every 1000 ms)
 * that lwip_port/lwipopts.h promises. */

#include "hybrid/lwip_glue.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4_frag.h" /* ip_reass_tmr, IP_TMR_INTERVAL */
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/priv/tcp_priv.h" /* tcp_tmr + tcp_active_pcbs/tcp_tw_pcbs —
                                 * the documented NO_SYS manual-timer surface */
#include "lwip/tcp.h"

#include "log.h"

/* Upper bound for one lwIP-emitted IP packet — a true invariant via two
 * independent bounds: ctx_new clamps netif->mtu to 9216 (the project's
 * documented jumbo ceiling; ip4_output never emits more than netif->mtu),
 * and TCP segments are additionally capped by compile-time TCP_MSS 8960
 * (~9000-byte IP packet). 9500 covers both with slack. */
#define MQVPN_LWIP_OUT_BUF 9500

struct mqvpn_lwip_ctx {
    struct netif netif;
    mqvpn_lwip_clock_fn clock_fn;
    void *clock_ctx;
    mqvpn_lwip_output_fn output_fn; /* the netif->output real-delivery path —
                                     * without it no TCP-lane handshake can
                                     * ever complete */
    void *output_ctx;
    struct tcp_pcb *listen_pcb;
    u16_t mtu;              /* real TUN MTU; applied in the netif init cb */
    u32_t tcp_tmr_last_ms;  /* sys_now() of the last tcp_tmr() run */
    u32_t ip_reass_last_ms; /* sys_now() of the last ip_reass_tmr() run */
};

/* sys_now() is a global lwIP-internal function with no ctx param.
 * Single-client-per-process assumption (same as client_now_us/
 * xqc_custom_timestamp already document) — one process-wide ctx pointer,
 * mirroring the s_xqc_clock_fn shim in mqvpn_client.c. */
static mqvpn_lwip_ctx_t *s_lwip_ctx_for_sys_now;

/* LWIP_PLATFORM_DIAG sink — declared (with the printf format attribute) in
 * lwip_port/arch/cc.h, routed into mqvpn's logger here so the lwIP TUs
 * never include src/log.h. */
void
mqvpn_lwip_platform_diag(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    LOG_WRN("lwip: %s", buf);
}

u32_t
sys_now(void)
{
    if (!s_lwip_ctx_for_sys_now || !s_lwip_ctx_for_sys_now->clock_fn) return 0;
    uint64_t us = s_lwip_ctx_for_sys_now->clock_fn(s_lwip_ctx_for_sys_now->clock_ctx);
    return (u32_t)(us / 1000);
}

/* Pretend pseudo-netif (heiher/lwip convention): NETIF_FLAG_PRETEND + a
 * listener bound tcp_bind_netif-then-tcp_bind(pcb, NULL, 0) accepts SYNs
 * for ANY destination arriving on this netif. The netif STILL transmits
 * (SYN-ACK, ACKs, downlink data) — pretend != non-transmitting.
 *
 * Shared body for the v4 (netif->output) and v6 (netif->output_ip6) output
 * callbacks below — lwIP gives the two a different pbuf-to-dest-address
 * signature (ip4_addr_t* vs ip6_addr_t*), but neither wrapper actually reads
 * its ipaddr argument (the pbuf already carries the dest in its own IP
 * header), so there is nothing family-specific left to do once inside. */
static err_t
mqvpn_tcp_lane_netif_emit(struct netif *netif, struct pbuf *p)
{
    mqvpn_lwip_ctx_t *ctx = (mqvpn_lwip_ctx_t *)netif->state;
    if (!ctx->output_fn) return ERR_OK; /* no sink configured — drop, don't crash */

    uint8_t buf[MQVPN_LWIP_OUT_BUF];
    if (p->tot_len > sizeof(buf)) {
        LOG_WRN("lwip: dropping oversized output packet (%u bytes)",
                (unsigned)p->tot_len);
        return ERR_OK;
    }
    u16_t len = pbuf_copy_partial(p, buf, sizeof(buf), 0);
    ctx->output_fn(buf, (size_t)len, ctx->output_ctx);
    return ERR_OK;
}

static err_t
mqvpn_tcp_lane_netif_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    (void)ipaddr;
    return mqvpn_tcp_lane_netif_emit(netif, p);
}

static err_t
mqvpn_tcp_lane_netif_output_ip6(struct netif *netif, struct pbuf *p,
                                const ip6_addr_t *ipaddr)
{
    (void)ipaddr;
    return mqvpn_tcp_lane_netif_emit(netif, p);
}

static err_t
mqvpn_tcp_lane_netif_init(struct netif *netif)
{
    /* netif_add() zeroes mtu/flags/output right before calling this — the
     * init callback is the canonical place to fill in driver fields. */
    mqvpn_lwip_ctx_t *ctx = (mqvpn_lwip_ctx_t *)netif->state;
    netif->name[0] = 'p';
    netif->name[1] = 'r';
    netif->output = mqvpn_tcp_lane_netif_output;         /* NOT NULL — see above */
    netif->output_ip6 = mqvpn_tcp_lane_netif_output_ip6; /* v6 sibling; without
                                                          * this override
                                                          * netif_add() leaves
                                                          * its own safe
                                                          * netif_null_output_ip6
                                                          * stub in place
                                                          * (netif.c) — no
                                                          * crash, but every
                                                          * v6 SYN-ACK / RST /
                                                          * downlink packet
                                                          * silently vanishes
                                                          * (ERR_IF, no-op) and
                                                          * no v6 handshake can
                                                          * ever complete */
    netif->mtu = ctx->mtu; /* per-pcb MSS derives from this at accept time
                            * (netif_add() also copies this into netif->mtu6
                            * right after this callback returns, since
                            * LWIP_ND6_ALLOW_RA_UPDATES defaults to 1 — v6
                            * MSS derivation reuses the same value, no
                            * separate mtu6 assignment needed here). */
    netif->flags |= NETIF_FLAG_PRETEND;
    return ERR_OK;
}

mqvpn_lwip_ctx_t *
mqvpn_lwip_ctx_new(mqvpn_lwip_clock_fn clock_fn, void *clock_ctx,
                   mqvpn_lwip_output_fn output_fn, void *output_ctx, int tun_mtu)
{
    /* One live ctx per process: sys_now() has a single global slot, and
     * lwIP's pcb lists/pools are process-global anyway. */
    if (s_lwip_ctx_for_sys_now) {
        LOG_ERR("lwip: ctx already exists (single instance per process)");
        return NULL;
    }

    mqvpn_lwip_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->clock_fn = clock_fn;
    ctx->clock_ctx = clock_ctx;
    ctx->output_fn = output_fn;
    ctx->output_ctx = output_ctx;
    if (tun_mtu < 576) tun_mtu = 576; /* sane TCP floor; caller passes >= 68 */
    if (tun_mtu > 9216)
        tun_mtu = 9216; /* project jumbo ceiling — also what
                         * makes MQVPN_LWIP_OUT_BUF a bound */
    ctx->mtu = (u16_t)tun_mtu;
    s_lwip_ctx_for_sys_now = ctx; /* before lwip_init so sys_now() works */

    /* lwip_init() must run exactly once per process: a second run would
     * memp_init() the pools, wiping any pcbs that survived a previous ctx
     * (e.g. TIME-WAIT pcbs across a reconnect). netif/listener setup below
     * is the per-ctx part. */
    static int s_lwip_inited;
    if (!s_lwip_inited) {
        lwip_init();
        s_lwip_inited = 1;
    }

    /* The netif needs SOME IPv4 address: the fork's ip4_input_accept()
     * PRETEND branch sits inside `!ip4_addr_isany_val(netif->ip_addr)` —
     * an address-less netif (netif_add_noaddr) silently rejects every
     * packet. The address is a pure "configured" flag-enabler: accepted
     * flows use the original inner dst as local_ip, so this placeholder
     * never appears on the wire. Link-local /32, deliberately unroutable. */
    ip4_addr_t addr, mask, gw;
    IP4_ADDR(&addr, 169, 254, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 255);
    ip4_addr_set_zero(&gw);
    if (!netif_add(&ctx->netif, &addr, &mask, &gw, ctx, mqvpn_tcp_lane_netif_init,
                   ip_input)) {
        LOG_ERR("lwip: netif_add failed");
        goto fail;
    }
    netif_set_up(&ctx->netif);
    netif_set_link_up(&ctx->netif);
    /* Load-bearing for MSS derivation: at accept time tcp_in.c sets
     * npcb->mss = tcp_eff_send_mss(...), which expands to
     * tcp_eff_send_mss_netif(sendmss, ip_route(src, dest), dest)
     * (tcp_priv.h) — and ip_route() can only resolve the arbitrary inner
     * addresses via the default netif (the /32 placeholder above matches
     * nothing). Without it the per-pcb MSS would not derive from
     * netif->mtu. RSTs for unmatched segments do NOT need this: the fork
     * sends those via tcp_rst_netif(ip_data.current_input_netif, ...)
     * (tcp_in.c), no ip_route() involved. */
    netif_set_default(&ctx->netif);

    /* IPADDR_TYPE_ANY (not _V4): a same-family-only listener DROPS every
     * SYN of the other family at tcp_input's pcb-match step (tcp_in.c) —
     * dual-stack needs the ANY-type wildcard match on both local_ip type
     * and address. */
    ctx->listen_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!ctx->listen_pcb) {
        LOG_ERR("lwip: tcp_new_ip_type failed (pcb pool exhausted?)");
        goto fail_netif;
    }
    /* Order matters: the fork's wildcard-intercept gate in tcp_bind()
     * (tcp.c: ipaddr == NULL && port == 0 && netif_idx != NETIF_NO_INDEX)
     * only fires when the netif binding is already set — tcp_bind_netif
     * MUST come first, else this silently becomes an ordinary ANY-bind
     * with an auto-assigned port. */
    tcp_bind_netif(ctx->listen_pcb, &ctx->netif);
    err_t err = tcp_bind(ctx->listen_pcb, NULL, 0); /* NULL pointer, not
        IP4_ADDR_ANY — the intercept codepath keys off this exact shape */
    if (err != ERR_OK) {
        LOG_ERR("lwip: wildcard tcp_bind failed (err=%d)", (int)err);
        goto fail_pcb;
    }
    struct tcp_pcb *lpcb = tcp_listen(ctx->listen_pcb);
    if (!lpcb) {
        LOG_ERR("lwip: tcp_listen failed (listen pcb pool exhausted?)");
        goto fail_pcb; /* on failure the original pcb is untouched */
    }
    ctx->listen_pcb = lpcb;
    /* tcp_accept() registration is the caller's move (via
     * mqvpn_lwip_ctx_set_accept_cb below) — the glue stays free of
     * flow-table types. */

    ctx->tcp_tmr_last_ms = sys_now();
    ctx->ip_reass_last_ms = ctx->tcp_tmr_last_ms;
    return ctx;

fail_pcb:
    tcp_close(ctx->listen_pcb); /* CLOSED/bound pcb: frees immediately */
    ctx->listen_pcb = NULL;
fail_netif:
    netif_remove(&ctx->netif);
fail:
    s_lwip_ctx_for_sys_now = NULL;
    free(ctx);
    return NULL;
}

void
mqvpn_lwip_ctx_free(mqvpn_lwip_ctx_t *ctx)
{
    if (!ctx) return;
    /* Teardown-ordering guard: the tcp_lane owns every ACCEPTED pcb and
     * must abort them all before freeing the glue ctx — such a pcb
     * surviving past here would reference a removed netif. Warn so that
     * mistake surfaces immediately instead of as a later use-after-remove.
     *
     * This can ALSO fire spuriously for a pcb tcp_lane
     * genuinely has no way to know about or abort — a half-open SYN_RCVD
     * pcb sitting in tcp_active_pcbs (vendored tcp_alloc registers it
     * there immediately on SYN receipt) whose accept callback hasn't run
     * yet, i.e. before tcp_lane's flow table ever binds a pcb pointer to
     * it. Such a pcb is bounded (it either completes the handshake and
     * gets accepted, or lwIP's own SYN_RCVD retransmit/timeout reaps it)
     * and is not the leak this warning exists to catch — the log line is
     * a coarse signal for triage, not proof of a tcp_lane bug. */
    if (tcp_active_pcbs)
        LOG_WRN("lwip: ctx_free with active pcbs — tcp_lane must abort flows first "
                "(or a half-open pre-accept SYN_RCVD pcb, which is expected/bounded)");
    if (ctx->listen_pcb) {
        tcp_close(ctx->listen_pcb); /* LISTEN pcb: closes + frees */
        ctx->listen_pcb = NULL;
    }
    netif_remove(&ctx->netif);
    if (s_lwip_ctx_for_sys_now == ctx) s_lwip_ctx_for_sys_now = NULL;
    free(ctx);
}

void
mqvpn_lwip_ctx_set_accept_cb(mqvpn_lwip_ctx_t *ctx, mqvpn_lwip_accept_fn cb, void *arg)
{
    /* listen_pcb is the tcp_listen()-swapped LISTEN pcb; tcp_arg/tcp_accept
     * both operate on it (accepted pcbs inherit the arg at accept time). */
    tcp_arg(ctx->listen_pcb, arg);
    tcp_accept(ctx->listen_pcb, cb);
}

int
mqvpn_lwip_input(mqvpn_lwip_ctx_t *ctx, const uint8_t *pkt, size_t len)
{
    if (len == 0 || len > 0xFFFF) return -1;
    /* I1: PBUF_RAM, not PBUF_POOL — an exact-size, MEM_LIBC_MALLOC-backed
     * heap allocation (lwipopts.h's CAUTION comment on PBUF_POOL_SIZE has
     * the full rationale). PBUF_POOL would burn one full ~9 KB
     * PBUF_POOL_BUFSIZE slot out of the GLOBAL 256-slot pool per ingress
     * packet regardless of its real size — at the real ~1382-byte tunnel
     * MTU, one xquic-backpressured flow's stash could exhaust that shared
     * pool and stall RX (SYNs/ACKs/FINs) for every OTHER flow. pbuf_take's
     * copy cost is unchanged either way; the real per-flow bound becomes
     * TCP_WND (the pcb's own receive window), which is what the relay
     * (tcp_lane.c) already backpressures against. */
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_RAM);
    if (!p) return -1;
    pbuf_take(p, pkt, (u16_t)len); /* cannot fail: p was sized for len */
    if (ctx->netif.input(p, &ctx->netif) != ERR_OK) {
        pbuf_free(p);
        return -1;
    }
    return 0;
}

void
mqvpn_lwip_tick(mqvpn_lwip_ctx_t *ctx)
{
    u32_t now = sys_now();

    /* tcp_tmr() every TCP_TMR_INTERVAL (250 ms) while any active or
     * TIME-WAIT pcb exists (the same condition timeouts.c's own cyclic
     * scheduler uses via tcp_timer_needed). While no pcbs exist keep the
     * phase fresh so the first tick after idle isn't an immediate fire. */
    if (tcp_active_pcbs || tcp_tw_pcbs) {
        if ((u32_t)(now - ctx->tcp_tmr_last_ms) >= TCP_TMR_INTERVAL) {
            ctx->tcp_tmr_last_ms = now;
            tcp_tmr();
        }
    } else {
        ctx->tcp_tmr_last_ms = now;
    }

    /* ip_reass_tmr() every IP_TMR_INTERVAL (1000 ms), opportunistically:
     * the classifier routes IPv4 fragments to the RAW lane, so this netif
     * should never queue reassembly state — driven anyway (it is a cheap
     * no-op when idle) so a stray fragment can't pin pool pbufs forever.
     * Deliberately NOT reflected in next_timeout_ms(): scheduling wakeups
     * for a timer that never has work would defeat the idle contract. */
    if ((u32_t)(now - ctx->ip_reass_last_ms) >= IP_TMR_INTERVAL) {
        ctx->ip_reass_last_ms = now;
        ip_reass_tmr();
    }
}

int
mqvpn_lwip_next_timeout_ms(mqvpn_lwip_ctx_t *ctx)
{
    if (!tcp_active_pcbs && !tcp_tw_pcbs) return -1; /* idle — no timer */
    u32_t elapsed = sys_now() - ctx->tcp_tmr_last_ms;
    if (elapsed >= TCP_TMR_INTERVAL) return 0; /* due now */
    return (int)(TCP_TMR_INTERVAL - elapsed);
}
