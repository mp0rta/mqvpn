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

/*
 * ---- connect()/relay boundary ----
 *
 * tcp_egress.c defines its own svr_tcp_egress_flow_t (fd, state, deadline,
 * intrusive D3 tick-list links, ...) but never sees svr_stream_t/svr_conn_s
 * or mqvpn_server_t's real layout. The seam below is deliberately capped —
 * boundary rule, pinned:
 *   - SERVER-scope state crosses via ONE bundled ctx accessor
 *     (svr_get_tcp_egress_ctx), extended field-by-field as needs grow.
 *   - PER-OBJECT (stream/conn) fields get at most one pointer accessor each.
 *   - Behavior bridges (register/unregister/clock/log) are separate — they
 *     forward calls, not field access.
 * If a future change can't fit those three buckets, that's the signal to
 * move the struct definitions into this header instead of adding accessors.
 */

/* Per-flow egress state slot on the stream (svr_tcp_egress_flow_t*, opaque
 * here — only tcp_egress.c casts it). Pointer-accessor form: the caller
 * reads/writes *return-value directly. Exactly one slot per stream, ever
 * (see D2 in tcp_egress.h) — nothing else may write through this pointer.
 * `stream` is the same opaque void* svr_tcp_egress_on_request/on_body
 * receive. */
void **svr_stream_tcp_egress_flow_ptr(void *stream);

/* Per-connection concurrent connect-tcp flow counter (reached via
 * stream->conn), for start_connect's per-session admission check against
 * config.hybrid.tcp_max_flows. Pointer-accessor form, same idiom as above.
 * Returns NULL only if stream or stream->conn is NULL (never true for a
 * live request). */
int *svr_conn_tcp_flow_count_ptr(void *stream);

/* Per-flow egress state — DEFINED in src/hybrid/tcp_egress.c only; forward
 * declaration here so the list-head plumbing below is typed (compiler
 * catches misuse) while the layout stays opaque to mqvpn_server.c. */
struct svr_tcp_egress_flow_s;

/* Server-scope egress state + config, bundled (svr_get_egress_policy
 * precedent). Pointer fields: tcp_egress.c owns the CONTENTS (global
 * in-flight-connect fd count + the D3 intrusive tick-list head) but not
 * the STORAGE — that lives inside mqvpn_server_t so the state is naturally
 * per-server without tcp_egress.c holding statics/globals. Both pointers
 * stay valid for the server's lifetime. Value fields are per-call
 * snapshots of the admission limits. */
typedef struct {
    struct svr_tcp_egress_flow_s **flow_list_head; /* D3 intrusive list head slot */
    int *global_fd_count;                          /* in-flight + active egress fds */
    uint32_t tcp_max_flows;                        /* per-session cap (config.hybrid) */
    uint32_t tcp_connect_timeout_sec; /* connect() deadline (config.hybrid) */
    int global_fd_budget;             /* mqvpn_server_egress_fd_budget(s) */
} svr_tcp_egress_srv_ctx_t;

/* Fill *out. Call ONCE per entry point (start_connect / flow_destroy /
 * tick), not per line — helpers take what they need as parameters. */
void svr_get_tcp_egress_ctx(mqvpn_server_t *s, svr_tcp_egress_srv_ctx_t *out);

/* fd-interest registration passthrough — server owns cbs/user_ctx, neither
 * of which tcp_egress.c can see. Returns 0 if forwarded to the platform
 * callback, -1 if the platform never installed egress_fd_register (caller
 * decides whether/how to log; this accessor does not log itself). */
int svr_egress_fd_register(mqvpn_server_t *s, int fd, int want_read, int want_write,
                           void *fd_ctx);

/* Drop interest in fd — the libmqvpn.h contract has a DEDICATED
 * egress_fd_unregister callback for this, distinct from calling
 * egress_fd_register with want_read=want_write=0 (see the platform_linux.c
 * reference implementation: register replaces a libevent event in place,
 * unregister tears it down and frees the registry slot). No-op if the
 * platform never installed the callback. */
void svr_egress_fd_unregister(mqvpn_server_t *s, int fd);

/* Wall-clock microseconds — the SAME source mqvpn_server.c uses everywhere
 * else (gettimeofday-based; see now_us() in mqvpn_server.c). Exposed so
 * tcp_egress.c's connect-deadline computation doesn't introduce a second
 * clock idiom. */
uint64_t svr_now_us(void);

/* Logging bridge: tcp_egress.c has no logging path of its own (a deliberate
 * narrow boundary from the previous task); connect-stage observability
 * needs one now, so this reuses mqvpn_server.c's existing callback-routed
 * logger rather than inventing a second one. */
#ifndef _MSC_VER
void svr_log(mqvpn_server_t *s, mqvpn_log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
#else
void svr_log(mqvpn_server_t *s, mqvpn_log_level_t level, const char *fmt, ...);
#endif

#endif /* MQVPN_SERVER_INTERNAL_H */
