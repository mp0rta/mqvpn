// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* Server-side dispatch entry points for `:protocol == "mqvpn-tcp"` Extended
 * CONNECT requests (the hybrid TCP-lane egress path). Unlike the client-side
 * hybrid code (tcp_lane.c/.h), this file is tightly server-coupled and has
 * no lwIP dependency — it is EXPECTED to include xquic headers directly. */
#ifndef MQVPN_HYBRID_TCP_EGRESS_H
#define MQVPN_HYBRID_TCP_EGRESS_H

#include "libmqvpn.h" /* mqvpn_server_t */

#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>

/* Called from cb_request_read's header path once :protocol==mqvpn-tcp and
 * hdrs.is_connect are confirmed. Owns the full request lifecycle from here:
 * auth (reusing svr_auth_check) -> ACL -> connect -> relay.
 *
 * `stream` is the caller's private svr_stream_t*, opaque here; `hdrs` is
 * the caller's private svr_req_headers_t*, also opaque here. Both structs
 * are static-private to mqvpn_server.c — if a later task needs more than a
 * couple of field accesses through these opaque pointers, switch to a
 * shared internal header (mqvpn_server_internal.h) instead of growing an
 * accessor-function sprawl here. */
int svr_tcp_egress_on_request(mqvpn_server_t *server, void *stream,
                              xqc_h3_request_t *h3_request, const void *hdrs);
int svr_tcp_egress_on_body(mqvpn_server_t *server, void *stream,
                           xqc_h3_request_t *h3_request);

#endif /* MQVPN_HYBRID_TCP_EGRESS_H */
