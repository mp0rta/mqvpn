// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* Server-side `:protocol == "mqvpn-tcp"` dispatch: real auth reuse + a
 * mandatory, default-on egress ACL. connect()/relay wiring (the actual TCP
 * socket work) lands in a follow-up task — svr_tcp_egress_start_connect is
 * a stub here that responds 503 once auth+ACL have both passed. */

#include "hybrid/tcp_egress.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

/* "/.well-known/mqvpn/tcp/" — byte-for-byte the prefix mqvpn_client.c's
 * connect-tcp request builder emits (snprintf("/.well-known/mqvpn/tcp/"
 * "%u.%u.%u.%u/%u/", ...)). */
#define TCP_EGRESS_PATH_PREFIX     "/.well-known/mqvpn/tcp/"
#define TCP_EGRESS_PATH_PREFIX_LEN (sizeof(TCP_EGRESS_PATH_PREFIX) - 1)

int
svr_tcp_egress_parse_path(const char *path, size_t path_len, char *out_host,
                          size_t out_host_cap, uint16_t *out_port)
{
    if (!path || !out_host || !out_port || out_host_cap == 0) return -1;
    if (path_len <= TCP_EGRESS_PATH_PREFIX_LEN) return -1;
    if (memcmp(path, TCP_EGRESS_PATH_PREFIX, TCP_EGRESS_PATH_PREFIX_LEN) != 0) return -1;

    const char *p = path + TCP_EGRESS_PATH_PREFIX_LEN;
    const char *end = path + path_len;

    /* Host: everything up to the next '/'. Rejected outright (not
     * truncated) if it doesn't fit out_host_cap incl. NUL. */
    const void *slash1_v = memchr(p, '/', (size_t)(end - p));
    if (!slash1_v) return -1;
    const char *slash1 = (const char *)slash1_v;
    size_t host_len = (size_t)(slash1 - p);
    if (host_len == 0 || host_len >= out_host_cap) return -1;
    memcpy(out_host, p, host_len);
    out_host[host_len] = '\0';

    /* Port: digits only, terminated by exactly one trailing '/' that must
     * be the LAST byte of the path (byte-for-byte match with the client's
     * trailing-slash template — no query string, no extra segments). */
    const char *port_start = slash1 + 1;
    if (port_start > end) return -1;
    const void *slash2_v = memchr(port_start, '/', (size_t)(end - port_start));
    if (!slash2_v) return -1;
    const char *slash2 = (const char *)slash2_v;
    if (slash2 + 1 != end) return -1;

    size_t port_len = (size_t)(slash2 - port_start);
    if (port_len == 0 || port_len > 5) return -1; /* "65535" = 5 digits, max */

    uint32_t port = 0;
    for (size_t i = 0; i < port_len; i++) {
        char c = port_start[i];
        if (c < '0' || c > '9') return -1;
        port = port * 10 + (uint32_t)(c - '0');
        if (port > 65535) return -1; /* overflow guard */
    }
    if (port < 1) return -1; /* 1-65535: reject "0" */

    *out_port = (uint16_t)port;
    return 0;
}

/* Mandatory, default-on deny set: loopback, RFC1918, link-local, CGNAT,
 * multicast, broadcast. Evaluated regardless of config — egress_allow is
 * the only way through (see svr_tcp_egress_acl_decide's docstring for the
 * full precedence order, including the tunnel-subnet check that isn't in
 * this table because it depends on the server's own config). */
static const struct {
    uint32_t net;
    uint32_t mask;
    const char *name; /* diagnostic only, currently unused by any log site */
} DEFAULT_DENY_V4[] = {
    {0x7F000000u, 0xFF000000u, "loopback"},        /* 127.0.0.0/8 */
    {0x0A000000u, 0xFF000000u, "rfc1918-10"},      /* 10.0.0.0/8 */
    {0xAC100000u, 0xFFF00000u, "rfc1918-172-16"},  /* 172.16.0.0/12 */
    {0xC0A80000u, 0xFFFF0000u, "rfc1918-192-168"}, /* 192.168.0.0/16 */
    {0xA9FE0000u, 0xFFFF0000u, "link-local"},      /* 169.254.0.0/16 */
    {0x64400000u, 0xFFC00000u, "cgnat"},           /* 100.64.0.0/10 */
    {0xE0000000u, 0xF0000000u, "multicast"},       /* 224.0.0.0/4 */
    {0xFFFFFFFFu, 0xFFFFFFFFu, "broadcast"},       /* 255.255.255.255/32 */
};

int
svr_tcp_egress_acl_decide(uint32_t ip, const mqvpn_cidr_entry_t *allow, int n_allow,
                          const mqvpn_cidr_entry_t *deny, int n_deny, uint32_t tunnel_net,
                          uint32_t tunnel_mask)
{
    if ((ip & tunnel_mask) == tunnel_net) return 0;

    for (int i = 0; i < n_allow; i++) {
        if ((ip & allow[i].mask) == allow[i].net) return 1;
    }

    for (size_t i = 0; i < sizeof(DEFAULT_DENY_V4) / sizeof(DEFAULT_DENY_V4[0]); i++) {
        if ((ip & DEFAULT_DENY_V4[i].mask) == DEFAULT_DENY_V4[i].net) return 0;
    }

    for (int i = 0; i < n_deny; i++) {
        if ((ip & deny[i].mask) == deny[i].net) return 0;
    }

    return 1;
}

/* server-bound wrapper: resolves the target string and the server's own
 * policy/tunnel-subnet, then defers to the pure decision core above. */
static int
svr_tcp_egress_acl_allowed(mqvpn_server_t *server, const char *target_host,
                           uint16_t target_port)
{
    (void)target_port; /* v1: host-only ACL — no port-scoped rules requested;
                        * don't add scope beyond what's asked. */

    struct in_addr addr;
    if (inet_pton(AF_INET, target_host, &addr) != 1)
        return 0; /* unparseable target — reject closed, not open */
    uint32_t ip = ntohl(addr.s_addr);

    const mqvpn_cidr_entry_t *allow = NULL, *deny = NULL;
    int n_allow = 0, n_deny = 0;
    uint32_t tunnel_net = 0, tunnel_mask = 0;
    svr_get_egress_policy(server, &allow, &n_allow, &deny, &n_deny, &tunnel_net,
                          &tunnel_mask);

    return svr_tcp_egress_acl_decide(ip, allow, n_allow, deny, n_deny, tunnel_net,
                                     tunnel_mask);
}

/* Canned status-only response, generalizing the 403 stub this replaces.
 * Mirrors mqvpn_server.c's svr_masque_send_403/501 (kept separate on
 * purpose — see the boundary decision in this task: those two stay
 * CONNECT-IP-flavored helpers private to mqvpn_server.c, this one is the
 * connect-tcp-flavored equivalent private to this file). */
static int
svr_tcp_egress_respond(xqc_h3_request_t *h3_request, int status)
{
    char status_str[4];
    snprintf(status_str, sizeof(status_str), "%03d", status);

    xqc_http_header_t resp[] = {
        {.name = {.iov_base = ":status", .iov_len = 7},
         .value = {.iov_base = status_str, .iov_len = 3},
         .flags = 0},
    };
    xqc_http_headers_t resp_hdrs = {.headers = resp, .count = 1, .capacity = 1};
    /* Send-failure deliberately not escalated: returning an error from the
     * H3 read-notify path would kill the whole H3 connection. */
    xqc_h3_request_send_headers(h3_request, &resp_hdrs, 1);
    return 0;
}

/* connect()/relay wiring lands in a follow-up task. 503 = the feature is
 * recognized and passed auth+ACL but isn't available at this build/stage
 * yet — distinct from 403 (denied) and 400 (malformed request). */
static int
svr_tcp_egress_start_connect(mqvpn_server_t *server, void *stream,
                             xqc_h3_request_t *h3_request, const char *target_host,
                             uint16_t target_port, const char *username)
{
    (void)server;
    (void)stream;
    (void)target_host;
    (void)target_port;
    (void)username;
    return svr_tcp_egress_respond(h3_request, 503);
}

int
svr_tcp_egress_on_request(mqvpn_server_t *server, void *stream,
                          xqc_h3_request_t *h3_request, const svr_req_headers_t *hdrs)
{
    /* Same optionality as CONNECT-IP, not stricter: svr_auth_required
     * encodes the exact condition svr_connect_ip_on_request uses (PSK or
     * users configured). An intentionally open server (no PSK, testing/
     * trusted-network deployments) stays open on both protocols. */
    char username[64] = "(global)";
    if (svr_auth_required(server) &&
        svr_auth_check(server, hdrs->auth_token, hdrs->auth_token_len, username,
                       sizeof(username)) != 0) {
        return svr_tcp_egress_respond(h3_request, 403);
    }

    /* The egress ACL below is unconditional regardless of auth: an open
     * (no-PSK) server still gets default-deny-private-ranges protection —
     * only the identity check is optional, not the network-reachability
     * check. An open tunnel can already reach the same destinations via
     * RAW/DGRAM, so connect-tcp adds no new exposure, only a second
     * protocol surface. */
    char target_host[16];
    uint16_t target_port;
    if (svr_tcp_egress_parse_path(hdrs->path, hdrs->path_len, target_host,
                                  sizeof(target_host), &target_port) != 0) {
        return svr_tcp_egress_respond(h3_request, 400);
    }

    if (!svr_tcp_egress_acl_allowed(server, target_host, target_port)) {
        return svr_tcp_egress_respond(h3_request, 403);
    }

    return svr_tcp_egress_start_connect(server, stream, h3_request, target_host,
                                        target_port, username);
}

int
svr_tcp_egress_on_body(mqvpn_server_t *server, void *stream, xqc_h3_request_t *h3_request)
{
    (void)server;
    (void)stream;
    (void)h3_request;
    return 0;
}
