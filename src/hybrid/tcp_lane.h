// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_HYBRID_TCP_LANE_H
#define MQVPN_HYBRID_TCP_LANE_H

#include <stdint.h>
#include <stdio.h> /* snprintf (mqvpn_tcp_lane_format_connect_path) */
#ifdef _MSC_VER
/* MSVC has no ssize_t. NOTE: vendored xquic also typedefs ssize_t on
 * Windows (xquic_typedef.h, __int64 on 64-bit) and mqvpn_client.c sees
 * both in one TU — this typedef MUST resolve to the identical type
 * (SSIZE_T = LONG_PTR = __int64 on _WIN64; a benign redefinition).
 * Win32/x86 would clash — not a supported target. */
#  include <basetsd.h> /* SSIZE_T */
typedef SSIZE_T ssize_t;
#else
#  include <sys/types.h> /* ssize_t (cli_tcp_lane_h3_send) */
#endif
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

/* Flow-starting SYN test for TUN-ingress lane policy. Family-aware since
 * Chunk 3: IPv4 re-parses the one flags byte at the IHL-derived offset;
 * IPv6 re-parses it at the FIXED offset 40 (the v6 fixed header is always
 * exactly 40 bytes, and Chunk 2's classifier only ever lanes a v6 packet
 * whose BASE Next Header is already TCP — no extension headers, no
 * fragments — so the TCP header always starts right there; see
 * mqvpn_hybrid_classify's pkt[6] gate in classifier.c). Re-parses
 * DELIBERATELY instead of extending reorder.h's parser: the spec scopes
 * mqvpn_parse_l3l4 to classifier needs (5-tuple), and flags are a
 * lane-policy concern only.
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
 * Bounds-checked: needs len >= tcp_off + 14 to reach the flags byte at
 * tcp_off + 13 (tcp_off = IHL for v4, fixed 40 for v6). Truncated/garbage
 * packets return 0 (treated as non-SYN; unknown-flow non-SYN falls to RAW
 * where existing paths handle it). A version nibble that is neither 4 nor 6
 * (dispatched purely on pkt[0]) also returns 0.
 *
 * PRECONDITION: pkt must already be classified MQVPN_LANE_TCP (non-fragment
 * IPv4 TCP, or direct-base-NH IPv6 TCP); this helper does not re-verify
 * protocol, fragment offset, or — for IPv6 — the base Next Header byte
 * itself. It trusts the classifier's base-NH==TCP gate (Chunk 2) for the
 * v6 fixed-offset assumption and only dispatches on IP version. */
static inline int
mqvpn_tcp_syn_flag(const uint8_t *pkt, size_t len)
{
    if (len < 1) {
        return 0;
    }
    size_t tcp_off;
    if ((pkt[0] >> 4) == 4) {
        if (len < 20) {
            return 0;
        }
        tcp_off = (size_t)(pkt[0] & 0x0F) * 4;
        if (tcp_off < 20) {
            return 0;
        }
    } else if ((pkt[0] >> 4) == 6) {
        tcp_off = 40;
    } else {
        return 0;
    }
    if (len < tcp_off + 14) {
        return 0;
    }
    uint8_t flags = pkt[tcp_off + 13];
    return (flags & 0x12) == 0x02; /* SYN set, ACK clear */
}

/* I2: extract the ISN (TCP sequence number, bytes 4-7 of the TCP header)
 * from a pure SYN packet. Family-aware since Chunk 3, mirroring
 * mqvpn_tcp_syn_flag's v4-IHL-derived-offset / v6-fixed-offset-40 split.
 *
 * PRECONDITION: mqvpn_tcp_syn_flag(pkt, len) must already have returned 1
 * for this EXACT packet — that check's bounds requirement (len >=
 * tcp_off + 14, to reach the flags byte) is strictly larger than what
 * reading the 4-byte seq field at tcp_off+4..tcp_off+7 needs, so no
 * separate bounds check is done here (same PRECONDITION idiom as
 * mqvpn_tcp_syn_flag's own header comment); it also guarantees pkt[0]'s
 * version nibble is 4 or 6 (any other value returns 0 from the flag check
 * above, so this function is never reached for it). Used to re-evaluate a
 * sticky-RAW marker on tuple reuse: same ISN means the same handshake
 * retransmitting (keep the marker), a different ISN means a genuinely new
 * connection (see mqvpn_tcp_lane_marker_isn / mqvpn_tcp_lane_on_syn). */
static inline uint32_t
mqvpn_tcp_syn_isn(const uint8_t *pkt, size_t len)
{
    (void)len;
    const uint8_t *seq;
    if ((pkt[0] >> 4) == 6) {
        seq = pkt + 40 + 4;
    } else {
        size_t ihl = (size_t)(pkt[0] & 0x0F) * 4;
        seq = pkt + ihl + 4;
    }
    return ((uint32_t)seq[0] << 24) | ((uint32_t)seq[1] << 16) | ((uint32_t)seq[2] << 8) |
           (uint32_t)seq[3];
}

typedef struct {
    uint64_t flows_active; /* gauge: derived from the live TCP-flow count at
                            * snapshot time (never tracked in parallel) */
    uint64_t flows_total;
    uint64_t flows_rejected_cap;
    uint64_t flows_rejected_other;
    uint64_t flows_idle_evicted;
    uint64_t raw_markers_active; /* gauge, same derivation: sticky-RAW markers
                                  * currently in the table — surfaced through
                                  * mqvpn_client_get_stats as the public
                                  * raw_markers_active stat */
} mqvpn_tcp_lane_stats_t;

/* client_ctx is opaque to tcp_lane.c's callers outside mqvpn_client.c; it is
 * threaded through to the H3-stream-open call (cli_tcp_lane_open_stream)
 * without tcp_lane.c needing to know cli_conn_t's layout. clock_fn/clock_ctx
 * (nullable — flows then get last_activity_us = 0) is the same injected
 * microsecond clock the caller hands mqvpn_lwip_ctx_new, used for
 * per-flow last-activity stamps (used by the idle sweep). With a NULL clock,
 * set cfg.tcp_idle_timeout_sec = 0 or flows evict spuriously (stamps stuck
 * at 0 while tick's now_us advances past the timeout). */
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
 * mqvpn_tcp_lane_on_syn's contract). Returns ERR_ABRT when the open-stream
 * failure path already tcp_abort()ed newpcb itself (lwIP contract: on any
 * other return value tcp_process would keep using — or double-abort — the
 * freed pcb; see cli_tcp_lane_open_stream / mqvpn_tcp_lane_abort_pending
 * below), a different non-ERR_OK code when lwIP itself should abort the
 * still-live pcb, ERR_OK otherwise. */
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
 * Post-SYN-ACK, so abort-only — RAW fallback is forbidden. Never closes the
 * H3 request itself (the caller, cli_tcp_lane_open_stream, either never
 * created one yet or already closed the one it did create on its own
 * failure path) — just tears the pcb + flow down.
 *
 * Returns 1 if the flow's pcb was tcp_abort()ed inside this call, 0
 * otherwise (NULL handle, or a flow with no live pcb). This matters because
 * the ONLY call chain reaching here starts inside lwIP's accept callback
 * frame (mqvpn_tcp_lane_lwip_accept -> cli_tcp_lane_open_stream -> here),
 * and lwIP's contract requires that frame to return ERR_ABRT when its pcb
 * was aborted (vendored tcp_in.c, tcp_process SYN_RCVD: on ERR_OK the core
 * proceeds to tcp_receive(pcb) on the now-freed pcb — use-after-free).
 * cli_tcp_lane_open_stream propagates this value for exactly that
 * translation. */
int mqvpn_tcp_lane_abort_pending(void *flow_handle);

/* H3 response gating for a bound mqvpn-tcp stream. `stream` is the
 * opaque cli_stream_t* handed to mqvpn_tcp_lane_bind_h3_request — these
 * functions locate the owning flow by its stored f->stream back-pointer (a
 * bounded O(n) walk over the whole flow table, n <= cfg.tcp_max_flows +
 * TCP_LANE_RAW_MARKER_CAP, 256 + 4096 by default; markers have
 * f->stream == NULL so never false-match) rather than caching a flow
 * pointer inside cli_stream_t.
 * That keeps the flow table the single source of truth: once a flow is
 * removed, the table walk simply stops finding it — no separate
 * back-pointer to remember to invalidate and no risk of dereferencing freed
 * flow memory through a stale cached pointer. All three tolerate
 * stream-not-found (the flow may already be gone) by no-op'ing. */

/* 2xx response headers received: PENDING_STREAM -> ACTIVE, stamp
 * last_activity, and flush the uplink bytes buffered before the gate opened
 * (pre-2xx buffering and EAGAIN-retry share ONE per-flow queue). */
void mqvpn_tcp_lane_on_stream_established(mqvpn_tcp_lane_t *lane, void *stream);

/* Non-2xx response headers received: a LOCAL decision to abandon the flow —
 * RST the pcb, RST the H3 request (the server may have sent a body we're
 * not going to read), and remove the flow from the table. */
void mqvpn_tcp_lane_on_stream_rejected(mqvpn_tcp_lane_t *lane, void *stream);

/* H3 closing-notify: xquic is already tearing this request down.
 * Verified against the vendored xquic source that this notify fires ONLY on
 * RESET_STREAM frame reception (never on STOP_SENDING alone — that only
 * makes xquic send back a RESET_STREAM of our own — and never on a clean
 * bidi-FIN completion, which has no closing-notify at all; see tcp_lane.c's
 * comment on tcp_lane_finish_clean_close for that path). RSTs our local pcb
 * side and removes the flow; deliberately does NOT close the H3 request
 * again (it's already being reset by xquic). Tolerates an unknown/
 * already-removed stream (no-op) — the flow may already be gone via a
 * different teardown path. */
void mqvpn_tcp_lane_on_h3_closing(mqvpn_tcp_lane_t *lane, void *stream);

/* H3 send-window became writable again: flush the flow's uplink retry queue
 * (FIFO, stops at the first EAGAIN — idempotent under repeated notifies) and,
 * once the queue drains below the low-water mark, re-open the lwIP receive
 * window that was withheld under backpressure (tcp_recved for every byte
 * whose acknowledgment-to-lwIP was deferred). */
int mqvpn_tcp_lane_on_h3_writable(mqvpn_tcp_lane_t *lane, void *stream);

/* H3 downlink body/EMPTY_FIN notify: drain the flow's H3 response
 * body into lwIP via tcp_write, gated by tcp_sndbuf (mirrors the uplink's
 * xquic-EAGAIN gate, just the other direction). `stream` is the same opaque
 * cli_stream_t* used by the functions above (flow located the same way).
 * No-ops (returns 0) on: unknown stream, CLOSING flow (dying, never
 * consumes recv_body), or a flow already paused on sndbuf backpressure
 * (deliberately not draining — xquic's per-stream flow control then
 * backpressures the server, mirroring the uplink's EAGAIN backpressure).
 * Also called from the sndbuf-recovered resume path (mqvpn_tcp_lane's own
 * lwIP sent callback) to continue draining after a pause. Returns 0 on
 * success/no-op, -1 if the flow is no longer live when this returns — either
 * a fatal relay error (fully torn down internally via on_relay_error) or a
 * clean bidi-FIN completion (both directions FIN'd; see tcp_lane.c's
 * tcp_lane_finish_clean_close) — callers must NOT propagate -1 to xquic as
 * a stream/connection error either way; see cli_connect_tcp_on_body's
 * contract comment in mqvpn_client.c for why. */
int mqvpn_tcp_lane_downlink_pump(mqvpn_tcp_lane_t *lane, void *stream);

/* ─── Uplink backpressure watermarks ───
 *
 * Internal compile-time constants, deliberately NOT public config — no
 * classifier/config/ABI surface.
 *
 * Semantics — these are RECVED-WITHHOLDING hysteresis thresholds, not hard
 * memory caps: bytes lwIP has already delivered to the recv callback were
 * already sequenced and ACKed on the wire, so they can never be dropped and
 * MUST be queued when xquic won't take them. Withholding tcp_recved() only
 * stops the receive window from RE-opening; the peer may still fill whatever
 * window was already advertised, so the true worst-case per-flow queue bound
 * is TCP_WND (~2 MiB, lwip_port/lwipopts.h) by TCP mechanics — the memory
 * budget (docs/hybrid_h2_memory_budget.md) must cite TCP_WND, not the
 * high-water mark. */
#define MQVPN_TCP_LANE_BP_HIGH_WATER                                            \
    (262144u) /* 256 KiB — pre-2xx buffering                                  \
               * withholds recved beyond this; between mqproxy's 64 KiB minimum \
               * and the multi-MB TCP_WND: headroom without approaching the     \
               * memory-budget concerns. */
#define MQVPN_TCP_LANE_BP_LOW_WATER                                       \
    (65536u) /* 64 KiB — recved resumes only                            \
              * once the unsent queue drains below this; the gap prevents \
              * withhold/resume flapping. */

/* cli_tcp_lane_h3_send return contract (tcp_lane.c never includes xquic
 * headers, so xquic error codes are normalized at this boundary). */
#define MQVPN_TCP_LANE_H3_SEND_AGAIN                                        \
    (-1)                                /* stream not writable — retry on \
                                         * the next writable notify */
#define MQVPN_TCP_LANE_H3_SEND_ERR (-2) /* fatal stream error */

/* cli_tcp_lane_h3_recv return contract (same normalization
 * boundary as h3_send above). Verified against xqc_h3_request_recv_body
 * (third_party/xquic src/http3/xqc_h3_request.c): fin may be signaled
 * EITHER with the final data chunk in the SAME call (n > 0 && *fin) OR on
 * its own zero-byte call (n == 0 && *fin) — both are real, reachable wire
 * shapes, not a plan simplification. *fin is only meaningful when the
 * return value is >= 0.
 *
 * fin is LEVEL-TRIGGERED in xquic, not edge-triggered: once the transport
 * FIN has arrived, every subsequent recv call re-reports *fin=1
 * (xqc_h3_request.c:795-801 re-derives *fin from the request's sticky
 * fin_flag whenever body_buf_count == 0, and the n==0 && !*fin EAGAIN
 * guard therefore can never fire again after that point). A caller may
 * therefore stash a data+fin chunk, DROP the local fin flag, and rely on
 * the re-report when its resumed drain calls recv again — the downlink
 * pump's stash/pause path depends on exactly this (see tcp_lane.c). The
 * only side effect of the repeated fin observation is a second
 * xqc_h3_request_end call, which is a harmless timestamp re-record
 * (xqc_h3_request.c:1055-1058: XQC_H3_REQUEST_RECORD_TIME of h3r_end_time,
 * nothing else). Test doubles for this function must model the re-report
 * or they will falsify the stash-then-resume fin path. */
#define MQVPN_TCP_LANE_H3_RECV_AGAIN                                       \
    (-1) /* drained for now (would-block) — retry on the next READ_BODY/ \
          * EMPTY_FIN notify */
#define MQVPN_TCP_LANE_H3_RECV_ERR (-2) /* fatal stream error */

/* connect-tcp :path formatter — extracted (Chunk 5) from the inline snprintf
 * that used to live directly in cli_tcp_lane_open_stream (mqvpn_client.c),
 * purely so it gets a unit-test seam: that function is static and this file's
 * test double stubs cli_tcp_lane_open_stream instead of linking the real one.
 * `static inline` like the SYN helpers above, so both mqvpn_client.c and
 * test_tcp_lane.c get it from this one header.
 *
 * key->dst_ip holds v4 in [0..3] (raw network-order header bytes — direct
 * indexing prints correctly) and dst_port is host order (reorder.h key
 * contract). Writes the request target as
 * "/.well-known/mqvpn/tcp/<dst>/<port>/" into out (capacity cap) and returns
 * snprintf's return value, so a caller can detect truncation the same way any
 * snprintf caller would (return >= cap). */
static inline int
mqvpn_tcp_lane_format_connect_path(char *out, size_t cap, const mqvpn_flow_key_t *key)
{
    return snprintf(out, cap, "/.well-known/mqvpn/tcp/%u.%u.%u.%u/%u/", key->dst_ip[0],
                    key->dst_ip[1], key->dst_ip[2], key->dst_ip[3],
                    (unsigned)key->dst_port);
}

/* Implemented in mqvpn_client.c — the deliberate tcp_lane.c →
 * mqvpn_client.c coupling points (direct .c-to-.c calls, no callback-pointer
 * indirection: exactly one impl + minimal call sites each; the one-way
 * boundary stands — tcp_lane.c never includes xquic headers). flow_handle is
 * a mqvpn_tcp_flow_t*, passed back via mqvpn_tcp_lane_bind_h3_request /
 * mqvpn_tcp_lane_abort_pending.
 *
 * Returns 0 when the flow proceeds (request opened, or a failure that did
 * NOT abort the pcb); 1 when a failure path tore the flow down AND
 * tcp_abort()ed its pcb (mqvpn_tcp_lane_abort_pending's return value,
 * propagated verbatim). The caller is lwIP's accept callback frame
 * (mqvpn_tcp_lane_lwip_accept), which must return ERR_ABRT in the latter
 * case — see mqvpn_tcp_lane_abort_pending's contract above. */
int cli_tcp_lane_open_stream(void *client_ctx, void *flow_handle,
                             const mqvpn_flow_key_t *key);

/* Send uplink body bytes (or, with len==0 && fin==1, a bare FIN) on the
 * flow's bound H3 request. Returns bytes accepted by xquic (may be a PARTIAL
 * accept — the caller must resume from the returned offset, never resend),
 * MQVPN_TCP_LANE_H3_SEND_AGAIN, or MQVPN_TCP_LANE_H3_SEND_ERR. buf may be
 * NULL only when len == 0. */
ssize_t cli_tcp_lane_h3_send(void *h3_request, const uint8_t *buf, size_t len, int fin);

/* Recv downlink body bytes from the flow's bound H3 request. buf/
 * len is the caller's scratch buffer; *fin is written 1 when the request's
 * FIN has been observed (see the MQVPN_TCP_LANE_H3_RECV_* contract above for
 * exactly when that can co-occur with data). Returns bytes read (may be 0
 * with *fin == 1 for a fin-only delivery), MQVPN_TCP_LANE_H3_RECV_AGAIN, or
 * MQVPN_TCP_LANE_H3_RECV_ERR. *fin is undefined on a negative return. */
ssize_t cli_tcp_lane_h3_recv(void *h3_request, uint8_t *buf, size_t len, int *fin);

/* Close the flow's bound H3 request with a RESET_STREAM (the RST direction
 * of the close-mapping table). Wraps
 * xqc_h3_request_close; best-effort/void, matching tcp_abort's contract on
 * the pcb side — the caller has already decided the flow is dead regardless
 * of this call's outcome, and cb_request_close/on_h3_closing will fire
 * (idempotently, against an already-removed flow) once xquic finishes
 * tearing the request down either way. */
void cli_tcp_lane_h3_close(void *h3_request);

/* Sticky-lane lookup: returns 1 if found (fills *out_raw: 1 if sticky-RAW,
 * 0 if active/pending/CLOSING TCP-lane flow), 0 if brand-new (caller
 * decides policy and calls mqvpn_tcp_lane_on_syn to commit).
 *
 * *out_closing (nullable; C1): 1 if the found entry is TCP_FLOW_CLOSING —
 * a post-clean-close TIME_WAIT-adjacent routing marker (see that state's
 * comment, tcp_lane_internal.h): the pcb is already gone, ownership handed
 * to lwIP, and the entry exists purely so tun_decide_lane keeps routing
 * stray post-close packets to lwip_input instead of falling back to RAW.
 * *out_raw is always 0 when *out_closing is 1 (CLOSING is never sticky-
 * RAW). Callers that don't care about tuple-reuse-after-close (everything
 * except tun_decide_lane) may pass NULL. */
int mqvpn_tcp_lane_lookup(mqvpn_tcp_lane_t *lane, const mqvpn_flow_key_t *key,
                          int *out_raw, int *out_closing);

/* Commit a brand-new flow's lane decision at SYN time. to_tcp=0 records a
 * sticky-RAW marker. to_tcp=1 inserts a pending-accept entry AND is the
 * caller's cue to feed the SYN into lwIP. Returns 0 on success;
 * -1 on cap, on NULL args, on allocation failure, or on a duplicate key
 * (a key already in the table is a caller bug — the protocol is
 * lookup-then-commit; alloc failure and duplicates are counted in
 * flows_rejected_other). The two kinds are capped INDEPENDENTLY:
 *   - to_tcp=1: capped by cfg.tcp_max_flows, counted in flows_rejected_cap.
 *     The check happens BEFORE lwIP sees the packet —
 *     reject-before-side-effect. On -1 HERE the caller may safely fall the
 *     flow back to RAW, ONLY because lwIP never saw the SYN (no half-built
 *     pcb state to contradict later packets). Once lwIP HAS seen the SYN —
 *     the lwIP accept callback's own rejection point — RAW
 *     fallback is forbidden: the flow must be rejected explicitly (abort),
 *     never silently rerouted.
 *   - to_tcp=0: capped by an internal marker cap (memory bound only, see
 *     TCP_LANE_RAW_MARKER_CAP in tcp_lane.c), NOT counted in
 *     flows_rejected_cap — the flow just stays unsticky and re-evaluates
 *     per SYN. Markers never consume tcp_max_flows budget (they are never
 *     idle-evicted, so a shared cap would permanently starve the TCP lane
 *     under tcp=auto on a single path).
 *
 * C1: an existing key is NOT always a caller-bug duplicate — if the
 * existing entry is TCP_FLOW_CLOSING (a post-close routing-residency
 * marker, see that state's comment), this is 5-tuple reuse after the
 * prior connection finished, not a protocol violation. on_syn removes the
 * stale CLOSING entry itself and proceeds with the fresh commit; the
 * caller (tun_decide_lane) is responsible for having already confirmed
 * this is a genuine new SYN (mqvpn_tcp_lane_lookup's *out_closing) before
 * calling on_syn in that situation — on_syn does not re-verify SYN-ness.
 *
 * I2: the same is true for an existing TCP_FLOW_STICKY_RAW marker whose
 * stored ISN differs from `syn_isn` — the caller has already compared
 * `syn_isn` against mqvpn_tcp_lane_marker_isn's return before deciding to
 * call on_syn here (a SAME-ISN retransmit of the same handshake instead
 * stays sticky-RAW without ever reaching on_syn — see tun_decide_lane).
 * on_syn removes the stale marker and proceeds with the fresh commit,
 * exactly like the CLOSING case above.
 *
 * `syn_isn` is stored on the new entry ONLY when to_tcp == 0 (a fresh
 * sticky-RAW marker) — real TCP-lane flows need no ISN logic (see
 * mqvpn_tcp_flow_t's field comment, tcp_lane_internal.h); pass the SYN's
 * ISN regardless (harmlessly ignored for to_tcp == 1), or 0 if unknown. */
int mqvpn_tcp_lane_on_syn(mqvpn_tcp_lane_t *lane, const mqvpn_flow_key_t *key, int to_tcp,
                          uint32_t syn_isn);

/* I2: returns the ISN stored on the sticky-RAW marker at `key`, or 0 if
 * there is no such marker (unknown key, or a key whose entry is not
 * TCP_FLOW_STICKY_RAW). Only meaningful when a prior
 * mqvpn_tcp_lane_lookup already reported *out_raw == 1 for this key —
 * callers use it to decide whether a new pure SYN on that 5-tuple is the
 * SAME handshake retransmitting (matching ISN — stays sticky-RAW) or a
 * genuinely NEW connection reusing the tuple (different ISN — re-evaluate
 * via on_syn, which removes the stale marker). A separate accessor rather
 * than a third mqvpn_tcp_lane_lookup out-param: the ISN is only ever
 * needed on the already-uncommon is_raw-AND-pure-SYN path, so a dedicated
 * second (bounded, small) table walk there is cheaper than widening every
 * lookup call's signature for a value almost no caller needs. */
uint32_t mqvpn_tcp_lane_marker_isn(mqvpn_tcp_lane_t *lane, const mqvpn_flow_key_t *key);

/* Idle-timeout sweep + CLOSING grace-sweep + stats snapshot, called from
 * tick() (C1). */
void mqvpn_tcp_lane_tick(mqvpn_tcp_lane_t *lane, uint64_t now_us);
void mqvpn_tcp_lane_get_stats(const mqvpn_tcp_lane_t *lane, mqvpn_tcp_lane_stats_t *out);

#endif
