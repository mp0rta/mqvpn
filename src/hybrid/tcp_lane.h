// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_HYBRID_TCP_LANE_H
#define MQVPN_HYBRID_TCP_LANE_H

#include <stdint.h>
#include "reorder.h"           /* mqvpn_flow_key_t, mqvpn_flow_key_hash/eq */
#include "hybrid/classifier.h" /* mqvpn_hybrid_config_t */
#include "hybrid/lwip_glue.h"  /* err_t + forward-declared struct tcp_pcb +
                                * mqvpn_lwip_clock_fn/mqvpn_lwip_accept_fn —
                                * the accept-callback surface below reuses the
                                * exact lwIP-opaque treatment lwip_glue.h
                                * already established; no lwIP struct
                                * internals leak (both headers are internal
                                * to src/hybrid/). */

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
 * unknown-flow non-SYN falls to RAW where existing paths handle it).
 *
 * PRECONDITION: pkt must already be classified MQVPN_LANE_TCP
 * (non-fragment IPv4 TCP); this helper does not re-verify protocol or
 * fragment offset. */
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
 * threaded through to the H3-stream-open call (cli_tcp_lane_open_stream)
 * without tcp_lane.c needing to know cli_conn_t's layout. clock_fn/clock_ctx
 * (nullable — flows then get last_activity_us = 0) is the same injected
 * microsecond clock the caller hands mqvpn_lwip_ctx_new, used for
 * per-flow last-activity stamps (Task 13's idle sweep). */
mqvpn_tcp_lane_t *mqvpn_tcp_lane_new(const mqvpn_hybrid_config_t *cfg, uint64_t hash_seed,
                                     void *client_ctx, mqvpn_lwip_clock_fn clock_fn,
                                     void *clock_ctx);
void mqvpn_tcp_lane_free(mqvpn_tcp_lane_t *lane);

/* lwIP accept callback — signature matches mqvpn_lwip_accept_fn verbatim, so
 * mqvpn_client.c registers it directly (no trampoline):
 *   mqvpn_lwip_ctx_set_accept_cb(ctx, mqvpn_tcp_lane_lwip_accept, lane).
 * Matches the SYN-committed PENDING_ACCEPT entry, wires pcb callbacks, and
 * opens the per-flow H3 stream via cli_tcp_lane_open_stream. Rejections here
 * are post-SYN-ACK: the pcb is aborted (RST), NEVER fallen back to RAW (see
 * mqvpn_tcp_lane_on_syn's contract). */
err_t mqvpn_tcp_lane_lwip_accept(void *arg, struct tcp_pcb *newpcb, err_t err);

/* Bind the H3 request/stream cli_tcp_lane_open_stream opened back onto the
 * flow (opaque: xqc_h3_request_t* / cli_stream_t* — the dependency stays
 * one-way, tcp_lane.c never includes xquic headers). Stores h3_request/
 * stream and leaves the flow in PENDING_STREAM: the request is sent but no
 * response has arrived yet. The 2xx/4xx response gate
 * (mqvpn_tcp_lane_on_stream_established / _rejected below) is what actually
 * moves the flow to ACTIVE or CLOSING. */
void mqvpn_tcp_lane_bind_h3_request(void *flow_handle, void *h3_request, void *stream);

/* Reject a flow whose H3 stream open failed after lwIP already accepted it.
 * Post-SYN-ACK, so abort-only — RAW fallback is forbidden. Stub until
 * Task 12 lands the real pcb abort + flow removal. */
void mqvpn_tcp_lane_abort_pending(void *flow_handle);

/* H3 response gating for a bound mqvpn-tcp stream (Task 9). `stream` is the
 * opaque cli_stream_t* handed to mqvpn_tcp_lane_bind_h3_request — these
 * functions locate the owning flow by its stored f->stream back-pointer (a
 * bounded O(n) walk over the whole flow table, n <= cfg.tcp_max_flows +
 * TCP_LANE_RAW_MARKER_CAP, 256 + 4096 by default; markers have
 * f->stream == NULL so never false-match) rather than caching a flow
 * pointer inside cli_stream_t.
 * That keeps the flow table the single source of truth: once Task 12/13
 * remove a flow, the table walk simply stops finding it — no separate
 * back-pointer to remember to invalidate and no risk of dereferencing freed
 * flow memory through a stale cached pointer. All three tolerate
 * stream-not-found (the flow may already be gone) by no-op'ing. */

/* 2xx response headers received: PENDING_STREAM -> ACTIVE, stamp
 * last_activity. Task 10 adds the flush of uplink bytes buffered before the
 * gate opened at the marked hook site in the .c. */
void mqvpn_tcp_lane_on_stream_established(mqvpn_tcp_lane_t *lane, void *stream);

/* Non-2xx response headers received: -> CLOSING. Task 12 does the real
 * tcp_abort(pcb) + flow removal; this only routes the signal. */
void mqvpn_tcp_lane_on_stream_rejected(mqvpn_tcp_lane_t *lane, void *stream);

/* H3 send-window became writable again. Stub returning 0; Task 10 re-arms
 * uplink delivery that was withheld for lack of H3 write credit. */
int mqvpn_tcp_lane_on_h3_writable(mqvpn_tcp_lane_t *lane, void *stream);

/* Implemented in mqvpn_client.c — the ONE deliberate tcp_lane.c →
 * mqvpn_client.c coupling point (direct .c-to-.c call, no callback-pointer
 * indirection: exactly one impl + one call site ever). flow_handle is a
 * mqvpn_tcp_flow_t*, passed back via mqvpn_tcp_lane_bind_h3_request /
 * mqvpn_tcp_lane_abort_pending. */
void cli_tcp_lane_open_stream(void *client_ctx, void *flow_handle,
                              const mqvpn_flow_key_t *key);

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
