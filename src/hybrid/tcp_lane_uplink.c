// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * tcp_lane_uplink.c — client-side TCP-lane uplink relay: lwIP recv -> H3
 * send_body (Task 10), extracted from tcp_lane.c at Task 12 once that file
 * crossed the ~800-line extraction trigger.
 *
 * This is the uplink QUEUE + SEND + FLUSH + FIN machinery only. tcp_lane.c
 * keeps: the flow table itself, the lwIP accept callback, the downlink
 * relay (H3 recv_body -> lwIP tcp_write, Task 11), and the close/error
 * mapping + flow removal (Task 12) — including on_lwip_recv, which stays a
 * thin dispatcher onto tcp_lane_uplink_flush/_deliver below. The two files
 * are one logical module; see tcp_lane_internal.h for the shared struct
 * layouts, the compile-time test-double hooks, and the small cross-TU
 * function seam (this file <-> tcp_lane.c).
 */

#include "hybrid/tcp_lane_internal.h"

#include <stdlib.h> /* malloc/free (queue nodes) */

/* tcp_recved takes a u16_t; the deferred resume total can exceed 65535
 * (bounded by TCP_WND ~2 MiB), so re-open the window in u16-sized steps. */
static void
tcp_lane_recved(struct tcp_pcb *pcb, uint32_t len)
{
    while (len > 0) {
        u16_t chunk = (len > 0xFFFFu) ? (u16_t)0xFFFFu : (u16_t)len;
        MQVPN_TCP_LANE_TEST_RECVED(pcb, chunk);
        len -= chunk;
    }
}

void
tcp_lane_uplink_queue_free(mqvpn_tcp_flow_t *f)
{
    mqvpn_tcp_uplink_node_t *n = f->uplink_q_head;
    while (n) {
        mqvpn_tcp_uplink_node_t *next = n->next;
        pbuf_free(n->p);
        free(n);
        n = next;
    }
    f->uplink_q_head = NULL;
    f->uplink_q_tail = NULL;
    f->uplink_queued_bytes = 0;
}

/* Hand p's bytes [offset, tot_len) to the H3 stream. Returns the new offset
 * (== tot_len when fully accepted, < tot_len on EAGAIN/partial-accept
 * backpressure) or -1 on a fatal send error. A contiguous pbuf is sent
 * straight from its payload (no copy); a CHAINED pbuf (ooseq coalescing can
 * hand chains whose tot_len exceeds any single segment) is flattened through
 * a TCP_MSS-sized stack slice via pbuf_copy_partial — the loop slices until
 * done, never truncates. Partial accepts advance offset by exactly the
 * accepted byte count so nothing is ever resent. */
static int32_t
tcp_lane_uplink_send_from(mqvpn_tcp_flow_t *f, struct pbuf *p, uint16_t offset)
{
    uint8_t slice[TCP_MSS];

    while (offset < p->tot_len) {
        const uint8_t *ptr;
        uint16_t chunk;
        if (p->next == NULL) {
            ptr = (const uint8_t *)p->payload + offset;
            chunk = (uint16_t)(p->tot_len - offset);
        } else {
            uint16_t want = (uint16_t)(p->tot_len - offset);
            if (want > sizeof(slice)) {
                want = (uint16_t)sizeof(slice);
            }
            chunk = pbuf_copy_partial(p, slice, want, offset);
            if (chunk == 0) {
                return -1; /* offset out of range — internal invariant broken */
            }
            ptr = slice;
        }
        ssize_t sent = cli_tcp_lane_h3_send(f->h3_request, ptr, chunk, 0);
        if (sent == MQVPN_TCP_LANE_H3_SEND_AGAIN) {
            break;
        }
        if (sent < 0) {
            return -1;
        }
        offset = (uint16_t)(offset + (uint16_t)sent);
        if ((size_t)sent < (size_t)chunk) {
            break; /* partial accept == backpressure; resume from offset */
        }
    }
    return (int32_t)offset;
}

/* Append a (possibly partially sent) delivery to the flow's uplink queue.
 * Takes ownership of p on success; on failure the caller still owns p. */
static int
tcp_lane_uplink_stash(mqvpn_tcp_flow_t *f, struct pbuf *p, uint16_t offset)
{
    mqvpn_tcp_uplink_node_t *n = malloc(sizeof(*n));
    if (!n) {
        return -1;
    }
    n->p = p;
    n->offset = offset;
    n->next = NULL;
    if (f->uplink_q_tail) {
        f->uplink_q_tail->next = n;
    } else {
        f->uplink_q_head = n;
    }
    f->uplink_q_tail = n;
    f->uplink_queued_bytes += (uint32_t)(p->tot_len - offset);
    return 0;
}

/* KQ 8 close mapping, uplink direction: lwIP recv(NULL) == peer FIN ->
 * half-close the H3 stream (zero-length body with fin=1) once every queued
 * uplink byte has drained. FIN-after-EAGAIN needs no dedicated retry entry:
 * tcp_fin_seen && !fin_sent_to_h3 IS the pending state, re-checked at the
 * end of every flush (writable notifies keep arriving while the stream has
 * anything pending).
 *
 * Retry necessity (reconciliation A, verified against the vendored xquic
 * source): a fin-only xqc_h3_request_send_body is NOT a one-shot latch
 * inside xquic. Tracing xqc_h3_request_send_body -> xqc_h3_stream_send_data
 * -> xqc_h3_stream_send_data_frame -> xqc_stream_send: on the normal
 * post-handshake 1-RTT path (pkt_type == XQC_PTYPE_SHORT_HEADER, i.e. not
 * 0-RTT), every -XQC_EAGAIN return point `goto do_buff` and fall straight
 * through — xqc_stream_buff_data (the only place a send gets remembered
 * across calls) only runs `if (pkt_type == XQC_PTYPE_0RTT)`. An EAGAIN
 * fin-only send therefore leaves NOTHING queued inside xquic: the FIN frame
 * bytes were never handed to the connection's send state, so nothing will
 * flush automatically. This retry (re-attempted on every subsequent flush,
 * driven by the writable notify) is what actually gets the FIN out — not a
 * harmless-redundant duplicate of xquic's own bookkeeping.
 *
 * Return: 0 if the flow is still live (AGAIN-pending or fully done with
 * nothing further to do here); -1 if `f` was torn down inside this call
 * (fatal send error -> mqvpn_tcp_lane_on_relay_error, or both directions
 * just completed cleanly -> tcp_lane_finish_clean_close) — in the -1 case
 * `f` must not be touched again by the caller (see tcp_lane_uplink_flush
 * below, which is exactly why this needs a return value instead of the
 * original void). */
static int
tcp_lane_uplink_maybe_fin(mqvpn_tcp_flow_t *f)
{
    if (f->state != TCP_FLOW_ACTIVE || !f->h3_request || !f->tcp_fin_seen ||
        f->fin_sent_to_h3 || f->uplink_q_head) {
        return 0;
    }
    ssize_t r = cli_tcp_lane_h3_send(f->h3_request, NULL, 0, 1);
    if (r == MQVPN_TCP_LANE_H3_SEND_ERR) {
        /* Fatal — mirror the general relay-error contract (full teardown,
         * not just a state flip) rather than leaving the flow ACTIVE with a
         * FIN that can now never be sent. */
        mqvpn_tcp_lane_on_relay_error(f);
        return -1;
    }
    if (r >= 0) {
        f->fin_sent_to_h3 = 1;
        if (f->fin_received_from_h3) {
            /* Reconciliation H: the downlink direction already forwarded
             * its FIN to the pcb (tcp_shutdown succeeded) before this one
             * completed — both directions are now cleanly closed. */
            tcp_lane_finish_clean_close(f);
            return -1;
        }
    }
    /* AGAIN: stays pending, retried on the next writable notify / flush. */
    return 0;
}

/* Drain the uplink queue FIFO, stopping at the first EAGAIN/partial (later
 * entries MUST wait — ordering). Idempotent under repeated all-EAGAIN
 * writable notifies: nothing is popped until fully accepted, offsets only
 * advance. After a full drain, sends the pending H3 FIN (see above); then,
 * once the unsent backlog is below low-water, re-opens the lwIP receive
 * window withheld under backpressure. */
void
tcp_lane_uplink_flush(mqvpn_tcp_flow_t *f)
{
    if (f->state != TCP_FLOW_ACTIVE || !f->h3_request) {
        return;
    }
    while (f->uplink_q_head) {
        mqvpn_tcp_uplink_node_t *n = f->uplink_q_head;
        int32_t off = tcp_lane_uplink_send_from(f, n->p, n->offset);
        if (off < 0) {
            mqvpn_tcp_lane_on_relay_error(f);
            return;
        }
        f->uplink_queued_bytes -= ((uint32_t)off - n->offset);
        n->offset = (uint16_t)off;
        if (n->offset < n->p->tot_len) {
            break; /* backpressure — retry from here on the next notify */
        }
        f->uplink_q_head = n->next;
        if (!f->uplink_q_head) {
            f->uplink_q_tail = NULL;
        }
        pbuf_free(n->p);
        free(n);
    }

    if (tcp_lane_uplink_maybe_fin(f) < 0) {
        return; /* f was torn down (fatal error or clean-close completion) */
    }

    if (f->uplink_withheld && f->uplink_queued_bytes < MQVPN_TCP_LANE_BP_LOW_WATER) {
        f->uplink_withheld = 0;
        if (f->uplink_withheld_recved > 0 && f->pcb) {
            tcp_lane_recved(f->pcb, f->uplink_withheld_recved);
        }
        f->uplink_withheld_recved = 0;
    }
}

/* One lwIP data-arrival delivery (tcp_lane.c's on_lwip_recv dispatches here
 * for the p != NULL case, after confirming the flow is ACTIVE or
 * PENDING_STREAM). Takes ownership of p. Fast path: ACTIVE with an empty
 * queue -> hand straight to xquic. A non-empty queue forces the stash path
 * even when ACTIVE (FIFO ordering: new bytes must ride behind the backlog).
 * PENDING_STREAM always stashes (pre-2xx: nothing may be sent yet). */
void
tcp_lane_uplink_deliver(mqvpn_tcp_flow_t *f, struct pbuf *p)
{
    uint16_t tot = p->tot_len;
    uint16_t off = 0;

    if (f->state == TCP_FLOW_ACTIVE && !f->uplink_q_head && f->h3_request) {
        int32_t r = tcp_lane_uplink_send_from(f, p, 0);
        if (r < 0) {
            pbuf_free(p);
            mqvpn_tcp_lane_on_relay_error(f);
            return;
        }
        off = (uint16_t)r;
    }

    if (off == tot) {
        pbuf_free(p);
        tcp_lane_recved(f->pcb, tot); /* fully accepted — window re-opens */
        return;
    }

    /* Withhold/pre-2xx buffer — the SAME queue (one code path, not two). */
    if (tcp_lane_uplink_stash(f, p, off) < 0) {
        /* Alloc failure: these bytes are already ACKed at the TCP level —
         * dropping them would silently corrupt the relayed stream. Fail the
         * flow instead. */
        pbuf_free(p);
        mqvpn_tcp_lane_on_relay_error(f);
        return;
    }

    /* recved-withholding policy (tcp_lane.h watermark comment):
     *  - ACTIVE + anything queued  = xquic said EAGAIN/partial -> withhold
     *    immediately (backpressure signal, no threshold);
     *  - PENDING_STREAM            = no xquic signal exists yet -> buffer
     *    freely up to high-water, withhold beyond it.
     * Withheld deliveries accumulate in uplink_withheld_recved and are
     * recved in one batch at the low-water resume in flush(). */
    if (f->state == TCP_FLOW_ACTIVE ||
        f->uplink_queued_bytes >= MQVPN_TCP_LANE_BP_HIGH_WATER) {
        f->uplink_withheld = 1;
    }
    if (f->uplink_withheld) {
        f->uplink_withheld_recved += tot;
    } else {
        tcp_lane_recved(f->pcb, tot);
    }
}
