// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_HYBRID_TCP_LANE_INTERNAL_H
#define MQVPN_HYBRID_TCP_LANE_INTERNAL_H

/*
 * tcp_lane_internal.h — shared internal seam between tcp_lane.c (flow
 * table, accept callback, downlink relay, close/error mapping) and
 * tcp_lane_uplink.c (uplink queue + send + flush + FIN machinery).
 *
 * Split out at Task 12 (tcp_lane.c crossed the file's ~800-line extraction
 * trigger): the two .c files are logically ONE module, just divided for
 * size hygiene. This header is NOT part of the public API (src/hybrid/ is
 * internal to libmqvpn already; this header is internal to tcp_lane.c's own
 * pair of TUs) — it holds:
 *   - the mqvpn_tcp_flow_t / uplink-node struct layouts both TUs need full
 *     visibility into (tcp_lane.h's public surface stays lwIP-opaque);
 *   - the MQVPN_TCP_LANE_TEST_* compile-time hook macros (test-double
 *     substitution idiom — see each macro's comment below), which must
 *     apply identically to code in BOTH TUs;
 *   - the small set of cross-TU function declarations (each documented at
 *     its declaration below).
 *
 * test_tcp_lane.c #include's both tcp_lane.c and tcp_lane_uplink.c into one
 * translation unit (same idiom test_reorder_rx.c uses for a single file) —
 * it must #define every hook macro below BEFORE either #include so the
 * #ifndef guards here pick up the test doubles instead of the real lwIP
 * calls (calling the real tcp_recved/tcp_write/tcp_shutdown/tcp_output/
 * tcp_abort/tcp_close on the test's stack-fake `struct tcp_pcb`s would
 * touch pool/list internals never initialized by a real tcp_new()+accept —
 * see each hook's comment).
 */

#include "hybrid/tcp_lane.h"

#include <stdint.h>

/* This TU pair wires real pcbs (tcp_arg/tcp_recv/.../tcp_abort/tcp_close),
 * so both need full lwIP types — tcp_lane.h's PUBLIC surface stays
 * lwIP-opaque (err_t + forward-declared struct tcp_pcb only); that rule was
 * always about the public header, not these two .c files. */
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"

typedef enum {
    TCP_FLOW_STICKY_RAW,     /* SYN-time verdict was RAW; remembered so
                              * later packets on this 5-tuple skip
                              * re-classification (§ sticky-lane). */
    TCP_FLOW_PENDING_ACCEPT, /* to_tcp verdict recorded; lwIP has not yet
                              * accepted the SYN (Task 7). */
    TCP_FLOW_PENDING_STREAM, /* lwIP accepted; H3 CONNECT-TCP stream not
                              * yet open (Task 8). */
    TCP_FLOW_ACTIVE,         /* pcb + h3 stream both live, relaying. */
    TCP_FLOW_CLOSING,        /* C1 (post-Task-12 fix): both directions
                              * completed a clean bidi FIN
                              * (tcp_lane_finish_clean_close) — the pcb is
                              * gracefully tcp_close()d (left in LAST_ACK or
                              * heading into TIME_WAIT) and f->pcb == NULL:
                              * we no longer need our own pointer to it,
                              * because lwIP demuxes any further packet on
                              * this 5-tuple against ITS OWN pcb (the
                              * lingering LAST_ACK pcb, or its TIME_WAIT
                              * entry) once tun_decide_lane routes the
                              * packet to lwip_input — we are purely a
                              * ROUTING MARKER at this point (TIME_WAIT-
                              * adjacent residency), not a relay endpoint.
                              * Without this state a post-close inner-OS
                              * packet (the LAST_ACK final ACK, or any
                              * TIME_WAIT-era stray) would miss the flow
                              * table entirely (unknown non-SYN -> RAW),
                              * leaking it to the already-closed origin and
                              * making the LAST_ACK pcb retransmit its FIN
                              * until TCP_MAXRTX gives up (minutes) —
                              * see tcp_lane_finish_clean_close and
                              * mqvpn_tcp_lane_tick's grace sweep.
                              * f->h3_request/f->stream are NULL (already
                              * cleared, both directions closed the H3 side
                              * cleanly), so nothing further to relay.
                              * Excluded from n_tcp_flows (tracked instead
                              * in the lane's separate n_closing counter —
                              * a CLOSING entry consumes no relay resource,
                              * just table space) and never re-enters
                              * on_lwip_recv/on_lwip_sent (callbacks were
                              * detached before the transition). Swept by
                              * mqvpn_tcp_lane_tick after a grace period
                              * (TCP_LANE_CLOSING_GRACE_US), or evicted
                              * immediately (oldest first) on
                              * TCP_LANE_CLOSING_CAP overflow. A fresh pure
                              * SYN reusing this 5-tuple (ephemeral port
                              * recycling) removes the marker and
                              * re-evaluates policy as a brand-new flow —
                              * see mqvpn_tcp_lane_on_syn's own comment. */
} mqvpn_tcp_flow_state_t;

/* Flow-liveness status returned by the teardown funnel and by every helper
 * a lwIP-invoked callback frame (accept/recv/sent) can reach — Task 12's
 * ERR_ABRT plumbing. lwIP's callback contract (vendored tcp_in.c): a
 * callback that tcp_abort()s its own pcb MUST return ERR_ABRT; on any other
 * return the core keeps dereferencing the freed pcb (tcp_in.c:474
 * TCP_EVENT_SENT and :507 TCP_EVENT_RECV only `goto aborted` on ERR_ABRT —
 * on ERR_OK they continue into refused_data/TF_GOT_FIN/tcp_output(pcb);
 * TCP_EVENT_ACCEPT in tcp_process SYN_RCVD, tcp_in.c:962, proceeds to
 * tcp_receive(pcb) on ERR_OK). Conversely, returning ERR_ABRT WITHOUT
 * having aborted leaks/stalls the pcb (tcp.c's tcp_abort doc: "never return
 * ERR_ABRT otherwise"), so GONE (pcb gracefully tcp_close()d — which does
 * NOT free a FIN_WAIT_1/LAST_ACK pcb — or already NULL) must stay
 * distinguishable from ABORTED. GONE covers two distinct outcomes from the
 * relay code's point of view, both "stop, don't touch f again": a real
 * free (tcp_lane_teardown_flow, when there was no pcb to abort) or, since
 * C1, a transition to TCP_FLOW_CLOSING (tcp_lane_finish_clean_close) —
 * `f` is NOT freed in the latter case, it becomes a routing-only marker
 * the relay code no longer owns, but the calling convention is identical:
 * the status flows via return values, never via flags on the flow, and
 * callers must not dereference relay fields (h3_request, uplink queue,
 * etc.) on `f` again either way. Only frames lwIP itself invoked translate
 * ABORTED to ERR_ABRT; xquic-context callers (downlink read notify,
 * writable notify, closing-notify, response gating) ignore the status. */
typedef enum {
    TCP_LANE_FLOW_LIVE = 0,    /* flow still in the table */
    TCP_LANE_FLOW_GONE = 1,    /* flow freed; pcb NOT aborted in this call
                                * (gracefully closed, or was already NULL) */
    TCP_LANE_FLOW_ABORTED = 2, /* flow freed AND its pcb tcp_abort()ed — a
                                * lwIP-invoked frame must return ERR_ABRT */
} tcp_lane_flow_status_t;

/* One queued uplink delivery. p is a whole recv-callback pbuf (possibly a
 * CHAIN — pbuf->next is the intra-packet chain pointer and must NOT be
 * reused for queueing, hence this separate node). offset counts the leading
 * bytes xquic already accepted (partial-accept resume point): re-delivering
 * from 0 after a partial send would DUPLICATE bytes on the stream. */
typedef struct mqvpn_tcp_uplink_node {
    struct pbuf *p;  /* owned; freed when fully sent (or on queue teardown) */
    uint16_t offset; /* bytes of p already handed to H3; < p->tot_len */
    struct mqvpn_tcp_uplink_node *next;
} mqvpn_tcp_uplink_node_t;

typedef struct mqvpn_tcp_flow {
    mqvpn_flow_key_t key;
    mqvpn_tcp_flow_state_t state;
    uint64_t last_activity_us;

    struct tcp_pcb *pcb;  /* set by the lwIP accept callback */
    ip4_addr_t target_ip; /* original inner dst (== pcb->local_ip at accept —
                           * wildcard intercept), network byte order */
    uint16_t target_port; /* host order, same as the flow key's ports */
    void *h3_request;     /* opaque xqc_h3_request_t*; set by bind_h3_request */
    void *stream;         /* opaque cli_stream_t*; set by bind_h3_request */

    /* Uplink queue — ONE mechanism serving both pre-2xx buffering
     * (PENDING_STREAM: nothing may be sent before the gate opens) and
     * EAGAIN/partial-accept retry (ACTIVE: xquic backpressure). FIFO; flushed
     * by the writable notify and by the 2xx transition. uplink_queued_bytes
     * counts UNSENT bytes only (sum of tot_len - offset), which is the
     * watermark metric: what xquic has not yet taken from us.
     * (Task 6 reserved a uplink_inflight_bytes field here; it was never
     * decremented anywhere in the plan and its "accepted by xquic" meaning
     * has no completion signal to drive it, so it is replaced by
     * uplink_queued_bytes — see tcp_lane.h's watermark comment.) */
    mqvpn_tcp_uplink_node_t *uplink_q_head;
    mqvpn_tcp_uplink_node_t *uplink_q_tail;
    uint32_t uplink_queued_bytes;    /* unsent bytes across the queue */
    uint32_t uplink_withheld_recved; /* delivered bytes whose tcp_recved is
                                      * deferred until the low-water resume */
    int uplink_withheld;
    int downlink_paused;
    int fin_sent_to_h3;
    int fin_received_from_h3;
    int tcp_fin_seen;

    /* Downlink stash (Task 11): the ONE chunk already pulled out of the H3
     * response body (recv_body is destructive — a re-read is not possible)
     * but not yet accepted by tcp_write, because sndbuf/ERR_MEM said no.
     * Exactly one slot always suffices: the pump stops consuming recv_body
     * the INSTANT a write can't be queued, so at most one just-read chunk
     * is ever awaiting a retry. Lazily malloc'd (most flows never pause) and
     * kept for the flow's lifetime once allocated — freed by
     * tcp_lane_downlink_stash_free (relay error, lane teardown). */
    uint8_t *downlink_stash;
    uint16_t downlink_stash_len;

    /* Back-pointer to the owning lane. Set in mqvpn_tcp_lane_on_syn at flow
     * creation for every to_tcp=1 flow (Task 13: the idle sweep's teardown
     * funnel can reach a flow before it ever gets to the accept callback,
     * and tcp_lane_remove_flow asserts this non-NULL), re-affirmed
     * (harmlessly, same pointer) by the accept callback. Needed because the
     * lwIP callbacks (on_lwip_recv/on_lwip_sent) receive only the flow as
     * tcp_arg, not the lane — this is how they reach lane->clock_fn for
     * last_activity_us stamping, how on_lwip_sent's resume path can call the
     * public mqvpn_tcp_lane_downlink_pump(lane, stream) API, and (Task 12)
     * how the uplink TU's fatal-FIN-send/clean-close paths reach
     * tcp_lane_remove_flow(f->lane, f) without needing a `lane` parameter of
     * their own. NULL for sticky-RAW markers (they never reach the teardown
     * funnel at all — excluded from the idle sweep by state, and never
     * bound to a pcb/h3_request) — every function that dereferences f->lane
     * is only ever reachable for a to_tcp=1 flow. */
    mqvpn_tcp_lane_t *lane;

    struct mqvpn_tcp_flow *next; /* hash chain */
} mqvpn_tcp_flow_t;

/* ─── Compile-time test-double hooks ───
 *
 * Every lwIP pcb-mutating call this module pair makes is indirected through
 * one of these macros. Production (#ifndef not triggered) expands to the
 * real lwIP call, zero cost. test_tcp_lane.c #defines all of these before
 * #include-ing tcp_lane.c/tcp_lane_uplink.c to substitute recording/
 * scriptable doubles — required because that test drives hand-built
 * stack-fake `struct tcp_pcb`s (never registered via tcp_new()/the real pcb
 * pool), and every one of these real calls walks or mutates pool-global
 * state (active_pcbs list, rcv_wnd accounting, send-queue/pbuf-chain
 * internals) that a stack-fake pcb was never initialized into — calling the
 * real function would corrupt lwIP's pools or assert. */

/* tcp_recved(): the deferred-resume window reopen (uplink backpressure). */
#ifndef MQVPN_TCP_LANE_TEST_RECVED
#  define MQVPN_TCP_LANE_TEST_RECVED(pcb, len) tcp_recved((pcb), (len))
#endif

/* tcp_write/tcp_sndbuf/tcp_shutdown/tcp_output: the downlink relay
 * (tcp_lane.c). tcp_sndbuf is a pure field read (`(pcb)->snd_buf`) with no
 * side effect to script around, but is hooked too for scriptability
 * independent of mutating the fake pcb's field. */
#ifndef MQVPN_TCP_LANE_TCP_WRITE
#  define MQVPN_TCP_LANE_TCP_WRITE(pcb, buf, len, flags) \
      tcp_write((pcb), (buf), (len), (flags))
#endif
#ifndef MQVPN_TCP_LANE_TCP_SNDBUF
#  define MQVPN_TCP_LANE_TCP_SNDBUF(pcb) tcp_sndbuf(pcb)
#endif
#ifndef MQVPN_TCP_LANE_TCP_SHUTDOWN
#  define MQVPN_TCP_LANE_TCP_SHUTDOWN(pcb, rx, tx) tcp_shutdown((pcb), (rx), (tx))
#endif
#ifndef MQVPN_TCP_LANE_TCP_OUTPUT
#  define MQVPN_TCP_LANE_TCP_OUTPUT(pcb) tcp_output(pcb)
#endif

/* tcp_abort/tcp_close (Task 12): the close/error-mapping teardown paths.
 * tcp_abort in particular sends an RST and FREES the pcb synchronously
 * (vendored tcp.c: tcp_abandon) — on a stack-fake test pcb this would
 * tcp_free() (memp_free) memory lwIP's pool never allocated. tcp_close is
 * only ever reached here on a pcb already past its own FIN-sending state
 * transition (reconciliation H's clean-close path), which is a proven
 * no-op status-wise, but it still unconditionally sets the TF_RXCLOSED flag
 * via tcp_set_flags() before delegating — a harmless field write on a real
 * pcb, but still routed through the hook for symmetry with tcp_abort and so
 * tests can observe/count the call. */
#ifndef MQVPN_TCP_LANE_TCP_ABORT
#  define MQVPN_TCP_LANE_TCP_ABORT(pcb) tcp_abort(pcb)
#endif
#ifndef MQVPN_TCP_LANE_TCP_CLOSE
#  define MQVPN_TCP_LANE_TCP_CLOSE(pcb) tcp_close(pcb)
#endif

/* ─── Cross-TU declarations (tcp_lane.c <-> tcp_lane_uplink.c) ───
 *
 * The two .c files are one logical module; these are the seam. Everything
 * else each file needs stays static/private to it. */

/* Defined in tcp_lane_uplink.c. Frees every queued node + its owned pbuf;
 * idempotent on an already-empty queue. Called from tcp_lane.c's
 * mqvpn_tcp_lane_free teardown loop and tcp_lane_remove_flow. */
void tcp_lane_uplink_queue_free(mqvpn_tcp_flow_t *f);

/* Defined in tcp_lane_uplink.c. Drains the FIFO retry queue, then the
 * pending FIN (see tcp_lane_uplink.c's maybe_fin), then the low-water
 * recved resume. Called from tcp_lane.c's on_lwip_recv (peer-FIN case —
 * which must translate ABORTED to ERR_ABRT), on_stream_established
 * (post-2xx gate open), and on_h3_writable (both xquic-context — status
 * ignored, only "don't touch f after non-LIVE" matters). */
tcp_lane_flow_status_t tcp_lane_uplink_flush(mqvpn_tcp_flow_t *f);

/* Defined in tcp_lane_uplink.c. Handles one lwIP data-arrival delivery:
 * fast-path direct send, fallback stash on EAGAIN/partial-accept/pre-2xx,
 * and the recved-withholding backpressure policy. Called from tcp_lane.c's
 * on_lwip_recv (thin dispatcher) for the p != NULL case; takes ownership of
 * p (frees it or hands it to the queue) REGARDLESS of the returned status —
 * ERR_ABRT-on-consumed-pbuf matches lwIP convention (the core gives up its
 * inseg reference either way). Never returns GONE: the only teardown this
 * path can trigger is on_relay_error (LIVE or ABORTED). */
tcp_lane_flow_status_t tcp_lane_uplink_deliver(mqvpn_tcp_flow_t *f, struct pbuf *p);

/* Defined in tcp_lane.c. Fatal relay failure, from EITHER TU: an H3
 * send/recv error, a pcb write/shutdown error, or an allocation failure
 * that would otherwise force dropping already-ACKed TCP bytes. Task 12:
 * does the FULL local-initiated teardown (RST the pcb, RST the H3 request,
 * unlink + free the flow) — see tcp_lane.c's comment on
 * mqvpn_tcp_lane_on_relay_error and tcp_lane_teardown_flow for the exact
 * sequence and the re-entrancy hazard it avoids. Callers in
 * tcp_lane_uplink.c must treat `f` as freed and touch it no further after
 * this call, and must propagate the returned status (ABORTED when a live
 * pcb was tcp_abort()ed, GONE otherwise) up to their own caller — a
 * lwIP-invoked frame at the top of the chain turns ABORTED into ERR_ABRT
 * (see tcp_lane_flow_status_t above). */
tcp_lane_flow_status_t mqvpn_tcp_lane_on_relay_error(mqvpn_tcp_flow_t *f);

/* Defined in tcp_lane.c. Both directions have now cleanly FIN'd (the
 * uplink FIN was forwarded to H3 AND the downlink FIN was forwarded to the
 * pcb) — gracefully detach and let both sides finish on their own; see
 * tcp_lane.c's comment for the source-verified lwIP/xquic semantics
 * (reconciliation H). Called from tcp_lane_uplink.c's maybe_fin and
 * tcp_lane.c's own downlink-shutdown path, whichever direction's flag
 * transition observes the OTHER flag already set.
 *
 * C1 fix: this does NOT free `f` — it transitions it to TCP_FLOW_CLOSING,
 * a TIME_WAIT-adjacent routing-marker residency (see that state's comment,
 * tcp_lane_internal.h), so a stray post-close inner-OS packet (the
 * LAST_ACK final ACK, a TIME_WAIT-era duplicate) still finds an entry and
 * gets routed to lwIP instead of leaking out as RAW. Callers must still
 * treat `f` as gone from the RELAY's point of view and touch it no
 * further after this call — the flow no longer belongs to the uplink/
 * downlink machinery, only to the CLOSING sweep/cap-eviction/tuple-reuse
 * paths in tcp_lane.c. Void, always status-GONE: the pcb is tcp_close()d,
 * never tcp_abort()ed (tcp_close on a FIN_WAIT_1/LAST_ACK pcb does not
 * free it — tcp.c), so the enclosing lwIP frame, if any, correctly
 * returns ERR_OK. */
void tcp_lane_finish_clean_close(mqvpn_tcp_flow_t *f);

#endif /* MQVPN_HYBRID_TCP_LANE_INTERNAL_H */
