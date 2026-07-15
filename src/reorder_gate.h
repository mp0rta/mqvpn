// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_REORDER_GATE_H
#define MQVPN_REORDER_GATE_H

/*
 * reorder_gate.h — shared TUN-ingress reorder-TX gating (STAMP/RAW/DROP_MTU)
 * and ICMP Packet-Too-Big rate limiter, shared by mqvpn_client.c and
 * mqvpn_server.c (§5/§9 of the reorder design; RFC 9484-adjacent PTB on the
 * TUN side).
 *
 * Header-only (static inline), same pattern as reorder.h: no xquic headers,
 * so it stays unit-testable and link-light. Callers own their own clock
 * (client_now_us()/now_us() for the reorder peek, now_ms_mono() for the PTB
 * bucket) and pass it in — this header has no wall-clock/monotonic-clock
 * dependency of its own, which also means no POSIX/Win32 headers are needed
 * here (unlike reorder.h's platform split, there is nothing to guard).
 *
 * Design note: the two known caller differences (PTB source address, clock
 * value) stay at the call site by construction — this header takes the
 * source address and both clocks as parameters instead of deriving them.
 */

#include <stddef.h>
#include <stdint.h>

#include "icmp.h"       /* mqvpn_icmp_send_v4/_v6, mqvpn_tun_output_fn */
#include "reorder_tx.h" /* mqvpn_reorder_tx_peek, MQVPN_REORDER_HDR_LEN */

#ifdef __cplusplus
extern "C" {
#endif

/* ─────────────────────── PTB token-bucket rate limiter ─────────────────────
 *
 * Structurally identical implementation formerly duplicated as
 * `ptb_rate_allow()` + `PTB_RATE_LIMIT` + `ptb_tokens`/`ptb_refill_ms` in both
 * mqvpn_client.c and mqvpn_server.c. The refill clock (now_ms, monotonic
 * milliseconds) is injected by the caller, same as reorder.h/reorder_tx.h's
 * now_us injection — this header stays clock-source-free.
 */

#define MQVPN_PTB_RATE_LIMIT 10 /* tokens per 1000ms window */

typedef struct {
    int tokens;
    int64_t refill_ms;
} mqvpn_ptb_bucket_t;

/* Init to a full bucket, mirroring the historical explicit
 * `ptb_tokens = PTB_RATE_LIMIT` at struct-init time (belt-and-suspenders with
 * the calloc'd zero state: a fresh bucket allows immediately either way, but
 * this keeps behavior pinned regardless of how large now_ms is at first
 * use). */
static inline void
mqvpn_ptb_bucket_init(mqvpn_ptb_bucket_t *b)
{
    b->tokens = MQVPN_PTB_RATE_LIMIT;
    b->refill_ms = 0;
}

/* Returns 1 if a PTB may be sent now (and consumes a token), 0 if
 * rate-limited. 1000ms fixed window, refilled to MQVPN_PTB_RATE_LIMIT on
 * expiry. */
static inline int
mqvpn_ptb_bucket_allow(mqvpn_ptb_bucket_t *b, int64_t now_ms)
{
    if (now_ms - b->refill_ms >= 1000) {
        b->tokens = MQVPN_PTB_RATE_LIMIT;
        b->refill_ms = now_ms;
    }
    if (b->tokens > 0) {
        b->tokens--;
        return 1;
    }
    return 0;
}

/* ───────────────────────── reorder-TX gate decision ────────────────────────
 *
 * §5/§9: reorder gating decides STAMP vs RAW vs DROP_MTU. Stamping is
 * additionally gated on peer support (§19.3/§19.4): until the peer
 * advertises mqvpn-reorder, everything stays RAW (wire-compatible with
 * non-reorder peers). udp_mss is the max inner IP that fits the DATAGRAM;
 * with reorder a STAMP consumes MQVPN_REORDER_HDR_LEN of those bytes (§9), so
 * the peek uses udp_mss as the "max inner without reorder" budget.
 */
typedef enum {
    MQVPN_RGATE_STAMP, /* *do_stamp set, peek->hdr filled: caller stamps + sends */
    MQVPN_RGATE_RAW,   /* proceed RAW (no header prepended) */
    /* Both DROP verdicts mean: drop the packet and consider a PTB via
     * mqvpn_rgate_send_ptb() with *out_mtu. They are split only so the
     * caller can pick its own log wording (log text differs between the two
     * historically — see mqvpn_server.c's two distinct LOG_D strings) — the
     * ICMP type/code/rate-limit handling is identical either way. */
    MQVPN_RGATE_DROP_REORDER_MTU, /* stamped form would exceed the DATAGRAM
                                   * budget; out_mtu = reorder-reduced
                                   * effective MTU (udp_mss - HDR_LEN) */
    MQVPN_RGATE_DROP_RAW_MTU,     /* RAW packet exceeds tunnel capacity;
                                   * out_mtu = udp_mss */
} mqvpn_rgate_verdict_t;

/*
 * Decide STAMP / RAW / DROP for one TUN-read inner-IP packet.
 *
 * reorder_tx may be NULL (no reorder engine for this connection/session).
 * The MQVPN_RGATE_STAMP return value is the single source of truth for
 * whether the caller stamps ("do_stamp"); there is no separate out-flag.
 * peek->action is written whenever the reorder branch runs (the peek
 * memsets *peek and sets action on every path — see reorder_tx.h); hdr/flow
 * are meaningful only on STAMP. *out_mtu is written only on the two DROP
 * verdicts.
 */
static inline mqvpn_rgate_verdict_t
mqvpn_rgate_decide(mqvpn_reorder_tx_t *reorder_tx, int peer_reorder_supported,
                   mqvpn_reorder_mode_t reorder_mode, const uint8_t *pkt, size_t len,
                   uint64_t now_us, uint32_t udp_mss, mqvpn_reorder_tx_peek_t *peek,
                   size_t *out_mtu)
{
    if (reorder_tx && peer_reorder_supported && reorder_mode != MQVPN_REORDER_OFF &&
        udp_mss > 0) {
        mqvpn_reorder_tx_action_t act =
            mqvpn_reorder_tx_peek(reorder_tx, pkt, len, now_us, udp_mss, peek);
        if (act == MQVPN_REORDER_TX_STAMP) {
            return MQVPN_RGATE_STAMP;
        } else if (act == MQVPN_REORDER_TX_DROP_MTU) {
            /* MQVPN_REORDER_HDR_LEN (8) + len exceeds the DATAGRAM payload:
             * advertise the reorder-reduced effective MTU. */
            *out_mtu =
                udp_mss > MQVPN_REORDER_HDR_LEN ? udp_mss - MQVPN_REORDER_HDR_LEN : 0;
            return MQVPN_RGATE_DROP_REORDER_MTU;
        }
        /* MQVPN_REORDER_TX_RAW falls through to the RAW/oversize check. */
    }

    /* ICMP PTB if a RAW packet exceeds tunnel capacity. (When stamping, the
     * §9 MTU reduction already keeps len within budget; the DROP_MTU branch
     * above covers the stamped over-MTU case, hence the early returns
     * above.) */
    if (udp_mss > 0 && len > udp_mss) {
        *out_mtu = udp_mss;
        return MQVPN_RGATE_DROP_RAW_MTU;
    }

    return MQVPN_RGATE_RAW;
}

/*
 * Send a rate-limited ICMP(v6) Packet-Too-Big for a dropped packet, per the
 * PTB gate above. `ip_ver` is 4 or 6. `addr_ok` gates whether the caller's
 * source address is currently usable (client: conn->addr_assigned /
 * conn->addr6_assigned; server: always for v4, pool.has_v6 for v6) — when
 * false, no token is consumed (mirrors the historical
 * `if (addr_ok && ptb_rate_allow(...))` short-circuit). `src_ip` is 4 bytes
 * for ip_ver==4, 16 bytes for ip_ver==6. On ip_ver==4 an mtu above the
 * 16-bit ICMP field silently clamps to 0xFFFF (v6 carries the full 32-bit
 * value) — same as the historical inline emission. Returns 1 if the ICMP was
 * actually sent (rate limit + addr_ok both passed) so the caller can log
 * identically to before; 0 otherwise.
 */
static inline int
mqvpn_rgate_send_ptb(mqvpn_ptb_bucket_t *bucket, int64_t now_ms, uint8_t ip_ver,
                     int addr_ok, const uint8_t *src_ip, size_t mtu,
                     mqvpn_tun_output_fn tun_output, void *user_ctx, const uint8_t *pkt,
                     size_t len)
{
    if (!addr_ok || !mqvpn_ptb_bucket_allow(bucket, now_ms)) return 0;
    if (ip_ver == 4) {
        mqvpn_icmp_send_v4(tun_output, user_ctx, src_ip, 3, 4,
                           (mtu > 0xFFFF) ? 0xFFFF : (uint16_t)mtu, pkt, len);
    } else {
        mqvpn_icmp_send_v6(tun_output, user_ctx, src_ip, 2, 0, (uint32_t)mtu, pkt, len);
    }
    return 1;
}

#ifdef __cplusplus
}
#endif

#endif /* MQVPN_REORDER_GATE_H */
