// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_HYBRID_TCP_LANE_H
#define MQVPN_HYBRID_TCP_LANE_H

#include <stdint.h>
#include "reorder.h"           /* mqvpn_flow_key_t, mqvpn_flow_key_hash/eq */
#include "hybrid/classifier.h" /* mqvpn_hybrid_config_t */

typedef struct mqvpn_tcp_lane mqvpn_tcp_lane_t;

/* Flow-starting SYN test for TUN-ingress lane policy (IPv4 only — the
 * classifier routes IPv6 TCP to RAW in v1). Re-parses the one flags byte
 * at the IHL-derived offset DELIBERATELY instead of extending reorder.h's
 * parser: the spec scopes mqvpn_parse_l3l4 to classifier needs (5-tuple),
 * and flags are a lane-policy concern only.
 *
 * Returns 1 only for a pure SYN (SYN set, ACK clear). SYN|ACK is
 * intentionally NOT flow-starting: on the client's TUN ingress a SYN|ACK
 * for an unknown 5-tuple is the inner OS answering an INBOUND connection
 * that arrived via the RAW downlink. Committing it to the TCP lane would
 * feed lwIP a SYN|ACK with no matching pcb — lwIP RSTs it and the inbound
 * connection dies. Not committing keeps the whole inbound flow on RAW
 * (every packet re-evaluates as unknown non-SYN → RAW), which is correct:
 * only client-originated outbound flows enter the TCP lane.
 *
 * Bounds-checked: needs len >= IHL + 14 to reach the flags byte at
 * tcp_off + 13. Truncated/garbage packets return 0 (treated as non-SYN;
 * unknown-flow non-SYN falls to RAW where existing paths handle it). */
static inline int
mqvpn_tcp_syn_flag(const uint8_t *pkt, size_t len)
{
    if (len < 20 || (pkt[0] >> 4) != 4) {
        return 0;
    }
    size_t ihl = (size_t)(pkt[0] & 0x0F) * 4;
    if (ihl < 20 || len < ihl + 14) {
        return 0;
    }
    uint8_t flags = pkt[ihl + 13];
    return (flags & 0x12) == 0x02; /* SYN set, ACK clear */
}

typedef struct {
    uint64_t flows_active; /* gauge: derived from the live TCP-flow count at
                            * snapshot time (never tracked in parallel) */
    uint64_t flows_total;
    uint64_t flows_rejected_cap;
    uint64_t flows_rejected_other;
    uint64_t flows_idle_evicted;
    uint64_t raw_markers_active; /* gauge, same derivation: sticky-RAW markers
                                  * currently in the table (visibility into
                                  * marker accumulation for Task 24's counter
                                  * wiring) */
} mqvpn_tcp_lane_stats_t;

/* client_ctx is opaque to tcp_lane.c's callers outside mqvpn_client.c; it is
 * threaded through to the H3-stream-open call (Task 8) without tcp_lane.c
 * needing to know cli_conn_t's layout. */
mqvpn_tcp_lane_t *mqvpn_tcp_lane_new(const mqvpn_hybrid_config_t *cfg, uint64_t hash_seed,
                                     void *client_ctx);
void mqvpn_tcp_lane_free(mqvpn_tcp_lane_t *lane);

/* Sticky-lane lookup: returns 1 if found (fills *out_raw: 1 if sticky-RAW,
 * 0 if active/pending TCP-lane flow), 0 if brand-new (caller decides policy
 * and calls mqvpn_tcp_lane_on_syn to commit). */
int mqvpn_tcp_lane_lookup(mqvpn_tcp_lane_t *lane, const mqvpn_flow_key_t *key,
                          int *out_raw);

/* Commit a brand-new flow's lane decision at SYN time. to_tcp=0 records a
 * sticky-RAW marker. to_tcp=1 inserts a pending-accept entry AND is the
 * caller's cue to feed the SYN into lwIP (Task 7). Returns 0 on success;
 * -1 on cap, on NULL args, on allocation failure, or on a duplicate key
 * (a key already in the table is a caller bug — the protocol is
 * lookup-then-commit; alloc failure and duplicates are counted in
 * flows_rejected_other). The two kinds are capped INDEPENDENTLY:
 *   - to_tcp=1: capped by cfg.tcp_max_flows, counted in flows_rejected_cap.
 *     The check happens BEFORE lwIP sees the packet —
 *     reject-before-side-effect. On -1 HERE the caller may safely fall the
 *     flow back to RAW, ONLY because lwIP never saw the SYN (no half-built
 *     pcb state to contradict later packets). Once lwIP HAS seen the SYN —
 *     Task 8's rejection point inside the lwIP accept callback — RAW
 *     fallback is forbidden: the flow must be rejected explicitly (abort),
 *     never silently rerouted.
 *   - to_tcp=0: capped by an internal marker cap (memory bound only, see
 *     TCP_LANE_RAW_MARKER_CAP in tcp_lane.c), NOT counted in
 *     flows_rejected_cap — the flow just stays unsticky and re-evaluates
 *     per SYN. Markers never consume tcp_max_flows budget (they are never
 *     idle-evicted, so a shared cap would permanently starve the TCP lane
 *     under tcp=auto on a single path). */
int mqvpn_tcp_lane_on_syn(mqvpn_tcp_lane_t *lane, const mqvpn_flow_key_t *key,
                          int to_tcp);

/* Idle-timeout sweep + stats snapshot, called from tick() (Task 13). */
void mqvpn_tcp_lane_tick(mqvpn_tcp_lane_t *lane, uint64_t now_us);
void mqvpn_tcp_lane_get_stats(const mqvpn_tcp_lane_t *lane, mqvpn_tcp_lane_stats_t *out);

#endif
