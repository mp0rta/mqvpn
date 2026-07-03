// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mqvpn_server_internal.h — narrow internal boundary shared between
 * mqvpn_server.c and src/hybrid/tcp_egress.c.
 *
 * NOT installed; NOT part of the public API. This is deliberately NOT a
 * dump of mqvpn_server.c's private `struct mqvpn_server_s` (session table,
 * stats counters, tick-thread debug asserts, ...) — tcp_egress.c doesn't
 * need any of that. It needs exactly: the parsed-request-header shape
 * (so it isn't handed an opaque blob it can't safely cast), the existing
 * constant-time credential check (reused, not reimplemented), and a
 * read-only snapshot of the egress ACL policy + tunnel subnet. Everything
 * else about mqvpn_server_t stays private to mqvpn_server.c.
 */
#ifndef MQVPN_SERVER_INTERNAL_H
#define MQVPN_SERVER_INTERNAL_H

#include "libmqvpn.h"          /* mqvpn_server_t */
#include "hybrid/classifier.h" /* mqvpn_cidr_entry_t */

#include <stddef.h>

/* Parsed request headers relevant to dispatch/auth. Values live only for
 * the callback invocation that filled them in (mqvpn_server.c's
 * svr_parse_request_headers, called from cb_request_read). `path` is the
 * raw H3 :path bytes — connect-tcp needs them to parse its own
 * "/.well-known/mqvpn/tcp/<ip>/<port>/" template; CONNECT-IP only needs
 * has_valid_path (its own fixed-prefix check, done at parse time). */
typedef struct {
    int is_connect;
    int is_connect_ip;
    const char *protocol; /* raw :protocol value, not NUL-terminated */
    size_t protocol_len;
    int has_scheme_https;
    int has_capsule_proto;
    int has_valid_path; /* CONNECT-IP's /.well-known/masque/ip/ prefix matched */
    const char *path;   /* raw :path value, not NUL-terminated */
    size_t path_len;
    const char *auth_token; /* Bearer payload, not NUL-terminated */
    size_t auth_token_len;
} svr_req_headers_t;

/* Whether request-level auth (Bearer PSK) must be checked before granting a
 * MASQUE request. Identical condition for CONNECT-IP and connect-tcp on
 * purpose: a server with no PSK/users configured is intentionally open on
 * BOTH protocols, not just one — do not let the two call sites diverge. */
int svr_auth_required(const mqvpn_server_t *s);

/* Credential check shared by every authenticated request type. Constant-
 * time over the global PSK and ALL configured users regardless of early
 * match. Returns 0 and writes the matched identity ("(global)" or the user
 * name) into out_username on success; -1 on failure. Precondition: caller
 * has already determined auth is required (svr_auth_required) — with no
 * credentials configured this always returns -1. */
int svr_auth_check(const mqvpn_server_t *s, const char *auth_token, size_t auth_token_len,
                   char *out_username, size_t username_cap);

/* Egress ACL policy snapshot for the connect-tcp destination check.
 * *allow/*deny point into the server's own config (valid for the server's
 * lifetime; caller must not free them). tunnel_net/tunnel_mask are host-
 * byte-order IPv4 network/mask derived from the SAME address pool
 * CONNECT-IP address assignment already uses — the pool is the single
 * source of truth for "what is the tunnel subnet". */
void svr_get_egress_policy(const mqvpn_server_t *s, const mqvpn_cidr_entry_t **allow,
                           int *n_allow, const mqvpn_cidr_entry_t **deny, int *n_deny,
                           uint32_t *tunnel_net, uint32_t *tunnel_mask);

#endif /* MQVPN_SERVER_INTERNAL_H */
