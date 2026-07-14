// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* Server-side `:protocol == "mqvpn-tcp"` dispatch. This task only wires the
 * H3 request/body entry points into mqvpn_server.c's dispatch; auth/ACL,
 * connect, and relay land in later tasks. */
#ifndef MQVPN_HYBRID_TCP_EGRESS_H
#define MQVPN_HYBRID_TCP_EGRESS_H

#include "libmqvpn.h"              /* mqvpn_server_t */
#include "hybrid/classifier.h"     /* mqvpn_cidr_entry_t */
#include "mqvpn_server_internal.h" /* svr_req_headers_t */

#include <stdint.h>

#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>

/* Called from cb_request_read's header path once :protocol==mqvpn-tcp and
 * hdrs.is_connect are confirmed. Owns the full request lifecycle from here:
 * auth (reusing svr_auth_check) -> ACL -> connect -> relay.
 *
 * `stream` is the caller's private svr_stream_t*, opaque here — connect and
 * relay (later tasks) hang their per-flow state off its tcp_egress_flow
 * field via an opaque void*, so stream internals never need to leak into
 * this file. `hdrs` is now the real svr_req_headers_t* (shared via
 * mqvpn_server_internal.h) since this task needs several of its fields
 * directly. */
int svr_tcp_egress_on_request(mqvpn_server_t *server, void *stream,
                              xqc_h3_request_t *h3_request,
                              const svr_req_headers_t *hdrs);
int svr_tcp_egress_on_body(mqvpn_server_t *server, void *stream,
                           xqc_h3_request_t *h3_request);

/* H3-writable notify dispatch — mqvpn_server.c's cb_request_write delegates
 * here for SVR_STREAM_ROLE_CONNECT_TCP streams (one entry point rather than
 * poking flow fields mqvpn_server.c can't see the layout of). Flushes the
 * uplink retry stash and/or retries the pending pure-FIN send
 * (send_body(NULL,0,1)) once the egress socket has hit EOF — xquic does NOT
 * buffer a fin-only send across -XQC_EAGAIN, so this retry is mandatory.
 * No-op on an unknown/already-torn-down flow. `stream` is the caller's
 * opaque svr_stream_t*. */
void svr_tcp_egress_on_h3_writable(mqvpn_server_t *server, void *stream);

/* Body of mqvpn_server_on_egress_fd_ready (public API in libmqvpn.h) —
 * dispatched here so mqvpn_server.c's public entry point stays a one-line
 * delegation. fd_ctx is the svr_tcp_egress_flow_t* the flow was registered
 * with. Handles both connect-completion (fd was registered want_write for
 * the connect signal) and, once the next task lands relay, ordinary
 * readable/writable relay events on an already-ACTIVE flow. */
void svr_tcp_egress_fd_ready(mqvpn_server_t *server, int fd, void *fd_ctx, int readable,
                             int writable);

/* Connect-timeout + idle-timeout sweep, called once per mqvpn_server_tick()
 * pass. Walks the D3 intrusive list of in-flight flows: any still
 * EGRESS_FLOW_CONNECTING past its connect_deadline_us is failed with
 * ETIMEDOUT (-> 504); any EGRESS_FLOW_ACTIVE flow whose last_activity_us has
 * not advanced within config.hybrid.tcp_idle_timeout_sec (0 = disabled) has
 * its H3 stream closed (no 5xx — it already sent its 200; see
 * svr_tcp_egress_on_idle_evict). One list, one tick function; the walk is
 * unlink-safe (a flow can be destroyed mid-walk by the timeout/eviction it
 * just hit). */
void svr_tcp_egress_tick(mqvpn_server_t *server, uint64_t now_us);

/* Full teardown for exactly one flow: unregisters the fd from the platform
 * reactor (if a callback was ever registered), close()s it, unlinks it
 * from the D3 tick list, decrements both the per-connection and global
 * in-flight-connect counters, NULLs the owning stream's tcp_egress_flow
 * slot, and frees the flow. This is the ONLY place any of that bookkeeping
 * happens — every teardown site (synchronous connect() error, failed
 * connect completion, connect timeout, and the owning stream closing
 * early) funnels through here so a live flow is counted exactly once and
 * torn down exactly once regardless of which site gets there first. Safe
 * to call from a stream-close path: this function never touches
 * h3_request. `flow` is a svr_tcp_egress_flow_t*, opaque outside this
 * file. */
void svr_tcp_egress_flow_destroy(mqvpn_server_t *server, void *flow);

/* Defensive sweep for mqvpn_server_destroy's teardown contingency: normal
 * flow teardown funnels through svr_tcp_egress_flow_destroy (see above), but
 * if xqc_engine_destroy() tears down H3 requests without firing the close
 * notify for every stream (mirrors the analogous session sweep already done
 * for s->sessions[]), any egress flow still on the D3 tick list would leak
 * its open OS fd and heap allocation. Walks *ctx.flow_list_head start to
 * finish, destroying each flow (saving `next` before each destroy, since
 * svr_tcp_egress_flow_destroy unlinks). Safe to call on an empty list
 * (no-op) and safe to call after normal shutdown has already emptied it. */
void svr_tcp_egress_destroy_all(mqvpn_server_t *server);

/* Maps a connect()/SO_ERROR errno to the H3 :status this task sends back
 * over the CONNECT-TCP response stream. Exposed (not static) purely for
 * tests/test_tcp_egress.c's direct unit test — this is a pure function, no
 * live mqvpn_server_t needed. */
int svr_tcp_egress_errno_to_status(int err);

/* Exposed for unit testing (tests/test_tcp_egress.c) — attacker-controlled
 * H3 :path bytes land here directly off the wire, so this is the highest-
 * value defensive-test surface in the file.
 *
 * Parses exactly "/.well-known/mqvpn/tcp/<ipv4>/<port>/" — byte-for-byte
 * the client's template (see mqvpn_client.c's connect-tcp request builder).
 * out_host must be at least 16 bytes (IPv4 dotted-quad + NUL); a host that
 * doesn't fit is rejected outright, never truncated. Returns 0 on success,
 * -1 on any malformed input (wrong prefix, missing/non-numeric/out-of-range
 * port, oversized host, empty input). Purely a format check — it does NOT
 * validate that out_host is a syntactically valid IPv4 address; that's
 * left to inet_pton() in the ACL check below. */
int svr_tcp_egress_parse_path(const char *path, size_t path_len, char *out_host,
                              size_t out_host_cap, uint16_t *out_port);

/* Pure ACL decision core — no live mqvpn_server_t needed, so unit tests can
 * exercise the default-deny table and allow/deny precedence directly with
 * plain parsed inputs. `addr` is network-byte-order, 16 bytes, v4 in [0..3]
 * (same layout as mqvpn_flow_key_t / mqvpn_cidr_entry_t.net); `allow`/`deny`
 * may be NULL when n_allow/n_deny are 0. `tunnel` must be a valid (non-NULL)
 * pointer to a single entry — "no tunnel subnet configured" is expressed as
 * family == 0 (the unset sentinel mqvpn_cidr_match already treats as a
 * guaranteed non-match), not a NULL pointer. Returns 1 = allowed, 0 =
 * denied. v1: only ever called with family == 4 — the built-in default-deny
 * table below is IPv4-only (DEFAULT_DENY_V4); a v6 counterpart is future
 * work, not a second signature change (mqvpn_cidr_match's own family gate
 * already makes every v4 table entry a no-op against a v6 addr).
 *
 * Evaluation order (do not reorder without updating the docstring AND the
 * self-review note in the task that introduced this):
 *   1. tunnel subnet   -> always denied, even if also present in `allow`
 *   2. egress_allow    -> punches holes through the default-deny below
 *   3. built-in default-deny ranges (loopback/RFC1918/link-local/CGNAT/
 *      multicast/broadcast)
 *   4. egress_deny     -> extra blocks past the built-in set
 *   5. default allow — this is a general-purpose egress proxy, not a
 *      walled garden; only enumerated private/special ranges are blocked
 *      by default. */
int svr_tcp_egress_acl_decide(uint8_t family, const uint8_t addr[16],
                              const mqvpn_cidr_entry_t *allow, int n_allow,
                              const mqvpn_cidr_entry_t *deny, int n_deny,
                              const mqvpn_cidr_entry_t *tunnel);

#endif /* MQVPN_HYBRID_TCP_EGRESS_H */
