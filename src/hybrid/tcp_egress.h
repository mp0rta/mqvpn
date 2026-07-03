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
 * plain parsed inputs. All values host-byte-order; `allow`/`deny` may be
 * NULL when n_allow/n_deny are 0. Returns 1 = allowed, 0 = denied.
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
int svr_tcp_egress_acl_decide(uint32_t ip, const mqvpn_cidr_entry_t *allow, int n_allow,
                              const mqvpn_cidr_entry_t *deny, int n_deny,
                              uint32_t tunnel_net, uint32_t tunnel_mask);

#endif /* MQVPN_HYBRID_TCP_EGRESS_H */
