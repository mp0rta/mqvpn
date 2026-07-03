// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* Server-side `:protocol == "mqvpn-tcp"` dispatch. This task only wires the
 * H3 request/body entry points into mqvpn_server.c's dispatch; auth/ACL,
 * connect, and relay land in later tasks. */

#include "hybrid/tcp_egress.h"

int
svr_tcp_egress_on_request(mqvpn_server_t *server, void *stream,
                          xqc_h3_request_t *h3_request, const void *hdrs)
{
    (void)server;
    (void)stream;
    (void)hdrs;

    /* auth+ACL land next. For now: unconditional 403, proves the dispatch
     * wiring without implementing egress yet. */
    xqc_http_header_t resp[] = {
        {.name = {.iov_base = ":status", .iov_len = 7},
         .value = {.iov_base = "403", .iov_len = 3},
         .flags = 0},
    };
    xqc_http_headers_t resp_hdrs = {.headers = resp, .count = 1, .capacity = 1};
    /* Send-failure deliberately not escalated: returning an error from the
     * H3 read-notify path would kill the whole H3 connection. */
    xqc_h3_request_send_headers(h3_request, &resp_hdrs, 1);
    return 0;
}

int
svr_tcp_egress_on_body(mqvpn_server_t *server, void *stream, xqc_h3_request_t *h3_request)
{
    (void)server;
    (void)stream;
    (void)h3_request;
    return 0;
}
