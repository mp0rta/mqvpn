// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_REORDER_TX_H
#define MQVPN_REORDER_TX_H

/*
 * reorder_tx.h — sender-side state for the flow-aware reorder-only datagram
 * shim (design spec v2.5 §10, §14.2, §15.1).
 *
 * The TX side owns a 5-tuple-keyed send_flow table and stamps eligible UDP
 * packets with an 8-byte reorder header. It holds no buffer and no timer; the
 * caller drives everything via peek/commit.
 *
 * TX and RX are zero-coupled: they share ONLY reorder.h (wire format, flow key,
 * config). This header must never include any rx header.
 */

#include <stddef.h>
#include <stdint.h>

#include "reorder.h" /* wire codec, flow_key, config, 5-tuple parser */

/* Opaque sender state. */
typedef struct mqvpn_reorder_tx mqvpn_reorder_tx_t;

/* §10.2 gating outcome for a single TUN-read packet. */
typedef enum {
    MQVPN_REORDER_TX_STAMP,    /* eligible: send hdr || pkt as REORDERED_UDP_V1 */
    MQVPN_REORDER_TX_RAW,      /* send the bare inner IP packet (no header) */
    MQVPN_REORDER_TX_DROP_MTU, /* 8+len exceeds DATAGRAM payload; emit ICMP PTB */
} mqvpn_reorder_tx_action_t;

/* Result of a peek. On STAMP, hdr[0..7] holds the 8-byte header to prepend and
 * flow points at the send_flow that a later commit advances. For RAW/DROP_MTU,
 * hdr is unspecified and flow may be NULL. */
typedef struct {
    mqvpn_reorder_tx_action_t action;
    uint8_t hdr[MQVPN_REORDER_HDR_LEN];
    void *flow; /* opaque send_flow*; pass the same peek to commit */
} mqvpn_reorder_tx_peek_t;

/* TX-owned statistics (§17). Separate from the RX stats struct. */
typedef struct {
    uint64_t forced_evict_count; /* idle<egress_idle send_flow force-evicted (~0) */
    uint64_t flows_created;
    uint64_t idle_evict_count; /* idle>egress_idle send_flow evicted on full */
    uint64_t table_full_raw;   /* full + no idle victim → new flow sent RAW */
} mqvpn_reorder_tx_stats_t;

/* Create/destroy. cfg is copied; hash_seed seeds the keyed flow hash (§6.2). */
mqvpn_reorder_tx_t *mqvpn_reorder_tx_new(const mqvpn_reorder_config_t *cfg,
                                         uint64_t hash_seed);
void mqvpn_reorder_tx_free(mqvpn_reorder_tx_t *tx);

/*
 * §10.2 gating + peek. Examines the bare inner IP packet `pkt[0..len)`:
 *   - parse fail / fragment / non-UDP                → RAW
 *   - flow not eligible (port/proto rule, §15.1)     → RAW
 *   - table full and no idle victim                  → RAW
 *   - 8+len > max_inner_without_reorder (§9)         → DROP_MTU
 *   - else                                           → STAMP, out->hdr filled
 *
 * peek does NOT advance next_seq or reset_marks_left (§10.3); commit does, on
 * successful datagram send. now_us is injected (no wall-clock inside).
 * Returns out->action (also returned directly).
 */
mqvpn_reorder_tx_action_t mqvpn_reorder_tx_peek(mqvpn_reorder_tx_t *tx,
                                                const uint8_t *pkt, size_t len,
                                                uint64_t now_us,
                                                uint32_t max_inner_without_reorder,
                                                mqvpn_reorder_tx_peek_t *out);

/* Commit a successful send: advances next_seq, decrements reset_marks_left, and
 * updates last_activity (§10.3). Call only after a STAMP peek whose datagram
 * actually went out. No-op if peek->action != STAMP or peek->flow is NULL. */
void mqvpn_reorder_tx_commit(mqvpn_reorder_tx_t *tx, mqvpn_reorder_tx_peek_t *peek,
                             uint64_t now_us);

/* Read-only stats accessor. */
const mqvpn_reorder_tx_stats_t *mqvpn_reorder_tx_stats(const mqvpn_reorder_tx_t *tx);

/* Test/introspection helper: reset_marks_left of a send_flow handle. */
uint32_t mqvpn_reorder_tx_flow_reset_marks_left(const void *flow);

#endif /* MQVPN_REORDER_TX_H */
