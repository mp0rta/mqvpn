// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* Hybrid-mode ingress classifier (H1). Pure functions only — no
 * allocation, no state, no lwIP types may leak out of src/hybrid/. */
#ifndef MQVPN_HYBRID_CLASSIFIER_H
#define MQVPN_HYBRID_CLASSIFIER_H

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#endif
#include "reorder.h" /* mqvpn_flow_key_t, mqvpn_parse_l3l4 */

typedef enum {
    MQVPN_LANE_TCP,   /* IPv4 TCP, hybrid enabled, tcp mode != raw */
    MQVPN_LANE_DGRAM, /* parseable UDP — reorder engine decides profile */
    MQVPN_LANE_RAW,   /* everything else — existing CONNECT-IP RAW */
} mqvpn_hybrid_lane_t;

typedef enum {
    MQVPN_HYBRID_TCP_STREAM = 0,
    MQVPN_HYBRID_TCP_RAW,
    MQVPN_HYBRID_TCP_AUTO,
} mqvpn_hybrid_tcp_mode_t;

/* [Hybrid] EgressAllow/EgressDeny — CIDR lists for the server-side
 * connect-tcp egress ACL. Clients embed mqvpn_hybrid_config_t too
 * (tcp_mode/tcp_max_flows drive client-side tcp_lane.c) but never read
 * these fields — egress reachability is purely a server concern, exactly
 * like tcp_max_flows is purely a client concern. Sized a bit above
 * [ReorderRule]'s cap (MQVPN_REORDER_MAX_RULES=16): egress ranges are
 * hand-authored network blocks evaluated once per connect-tcp request, not
 * a hot per-packet list, so a slightly larger ceiling costs nothing. */
#define MQVPN_EGRESS_ACL_MAX 32

/* One parsed CIDR range (v4 or v6), network-byte-order, net pre-masked
 * (bits beyond prefix_len are zeroed) so a match test is a fixed bit-prefix
 * compare against the SAME byte layout the flow key uses (mqvpn_flow_key_t's
 * src_ip/dst_ip in reorder.h: v4 in [0..3], rest zero) — no host-order
 * conversion needed at the classifier gate. family 0 is the "unset"
 * sentinel (replaces the old mask==0 dual-use: a real 0.0.0.0/0 or ::/0 ACL
 * row now has its own family+prefix_len==0 shape, distinct from "never
 * learned"). */
typedef struct {
    uint8_t family;     /* 4 or 6; 0 = unset sentinel */
    uint8_t prefix_len; /* 0..32 (v4) or 0..128 (v6) */
    uint8_t net[16];    /* network-order, pre-masked; v4 in [0..3], rest zero */
} mqvpn_cidr_entry_t;

/* Zero any net[] bits beyond prefix_len (route-table convention: a
 * caller-supplied host part, e.g. "10.1.2.3/8", is silently normalized the
 * way route tables normally are). Shared by mqvpn_parse_cidr and
 * mqvpn_tunnel_subnet_learn{,_v6} so the masking logic can't drift between
 * them. prefix_len must already be validated into [0,128] by the caller. */
static inline void
mqvpn_cidr_premask(uint8_t net[16], int prefix_len)
{
    int full = prefix_len / 8;
    int rem = prefix_len % 8;
    if (rem) {
        uint8_t m = (uint8_t)(0xFF << (8 - rem));
        net[full] = (uint8_t)(net[full] & m);
        full++;
    }
    for (int i = full; i < 16; i++)
        net[i] = 0;
}

/* Single-site CIDR membership test, shared by the classifier's tunnel-
 * subnet gate and the server egress ACL's tunnel/allow/deny walks
 * (svr_tcp_egress_acl_decide). addr is network byte order, 16 bytes, v4 in
 * [0..3] — same layout as mqvpn_flow_key_t's src_ip/dst_ip, so callers never
 * need a host-order round trip. A family mismatch (including the e->family
 * == 0 unset sentinel) always misses; a real "match everything" row is
 * family + prefix_len == 0 (e.g. a parsed "0.0.0.0/0"), NOT the unset
 * sentinel — the two are no longer the same bit pattern, so no caller-side
 * gate is needed on top of this function anymore. Precondition (same as
 * mqvpn_cidr_premask): prefix_len is in [0,128]; every producer here
 * (mqvpn_parse_cidr, mqvpn_tunnel_subnet_learn{,_v6}, svr_get_egress_policy)
 * enforces it, but a prefix_len > 128 would drive full > 16 and over-read
 * addr[]/net[], so a careless future caller is fenced off with an explicit
 * guard rather than left to corrupt memory. */
static inline int
mqvpn_cidr_match(const mqvpn_cidr_entry_t *e, uint8_t family, const uint8_t addr[16])
{
    if (e->family == 0 || e->family != family) return 0;
    if (e->prefix_len > 128) return 0; /* malformed entry: fail closed, no over-read */

    int nbits = e->prefix_len;
    int full = nbits / 8;
    int rem = nbits % 8;
    for (int i = 0; i < full; i++) {
        if (addr[i] != e->net[i]) return 0;
    }
    if (rem) {
        uint8_t m = (uint8_t)(0xFF << (8 - rem));
        if ((addr[full] & m) != (e->net[full] & m)) return 0;
    }
    return 1;
}

/* Learn the client-side IPv4 tunnel subnet from a CONNECT-IP ADDRESS_ASSIGN
 * (assigned address bytes as they appear on the wire, network order). The
 * server assigns a single /32 (this client's own address), not the pool
 * subnet, so a wire prefix narrower than /24 is widened to /24 — the SAME
 * assumption the client's server-IP derivation bakes in ("Server IP is .1
 * in same subnet", mqvpn_client.c) — while a /24-or-wider wire prefix is
 * honored as-is. A degenerate prefix <= 0 leaves *out zeroed (family stays
 * 0, the "not learned" sentinel that keeps the classifier gate off via
 * mqvpn_cidr_match's own family check — no separate caller-side gate needed
 * anymore). Kept here rather than inline in mqvpn_client.c so the widening
 * rule is host-unit-testable: honoring the wire /32 verbatim would still
 * pass every classifier gate test yet silently break the tunnel-subnet
 * exclusion in deployment. */
static inline void
mqvpn_tunnel_subnet_learn(const uint8_t ip[4], int assigned_prefix,
                          mqvpn_cidr_entry_t *out)
{
    memset(out, 0, sizeof(*out));
    if (assigned_prefix <= 0) return; /* family stays 0: not learned */

    int plen = assigned_prefix < 24 ? assigned_prefix : 24;
    out->family = 4;
    out->prefix_len = (uint8_t)plen;
    out->net[0] = ip[0];
    out->net[1] = ip[1];
    out->net[2] = ip[2];
    out->net[3] = ip[3];
    mqvpn_cidr_premask(out->net, plen);
}

/* IPv6 counterpart of mqvpn_tunnel_subnet_learn above. Unlike the v4 form,
 * the assigned prefix is honored DIRECTLY (no >=24 widening) — that clamp
 * exists only because the server's v4 pool always assigns a client its own
 * /32 inside a /24-or-wider pool; the v6 ADDRESS_ASSIGN prefix is already
 * the real tunnel-subnet prefix, nothing to widen. A degenerate prefix
 * (<= 0 or > 128) leaves *out zeroed (family 0, unset sentinel). */
static inline void
mqvpn_tunnel_subnet_learn_v6(const uint8_t ip6[16], int assigned_prefix,
                             mqvpn_cidr_entry_t *out)
{
    memset(out, 0, sizeof(*out));
    if (assigned_prefix <= 0 || assigned_prefix > 128) return;

    out->family = 6;
    out->prefix_len = (uint8_t)assigned_prefix;
    memcpy(out->net, ip6, 16);
    mqvpn_cidr_premask(out->net, assigned_prefix);
}

/* Parse "a.b.c.d/n" (n = 0..32) or "x:x::.../n" (n = 0..128) into *out,
 * network-byte-order, net pre-masked so a caller-supplied host part (e.g.
 * "10.1.2.3/8") is quietly normalized the way route tables normally are.
 * Family is auto-detected by the presence of ':' in the address part
 * (bare-address/implicit-prefix forms are not accepted for either family,
 * and neither is surrounding whitespace). Returns 0 on success, -1 on
 * malformed input — this header has no logging dependency on purpose
 * (config.h pulls it in), so callers decide how/whether to log a failure.
 * static inline for the same reason mqvpn_hybrid_config_default is: src/
 * config.c, src/mqvpn_config.c, and test binaries that skip mqvpn_lib all
 * need this, and an out-of-line definition would need a .c home in every
 * one of those link sets. buf is sized for the longest valid full-form v6
 * literal ("xxxx:" x8 = 39 chars) plus the "/128" suffix and slack. */
static inline int
mqvpn_parse_cidr(const char *s, mqvpn_cidr_entry_t *out)
{
    if (!s || !out) return -1;

    char buf[INET6_ADDRSTRLEN + 8];
    size_t len = strlen(s);
    if (len == 0 || len >= sizeof(buf)) return -1;
    memcpy(buf, s, len + 1);

    char *slash = strchr(buf, '/');
    if (!slash) return -1;
    *slash = '\0';

    int is_v6 = strchr(buf, ':') != NULL;
    int max_prefix = is_v6 ? 128 : 32;

    uint8_t net[16];
    memset(net, 0, sizeof(net));
    if (is_v6) {
        if (inet_pton(AF_INET6, buf, net) != 1) return -1;
    } else {
        struct in_addr addr;
        if (inet_pton(AF_INET, buf, &addr) != 1) return -1;
        uint32_t hip = ntohl(addr.s_addr);
        net[0] = (uint8_t)(hip >> 24);
        net[1] = (uint8_t)(hip >> 16);
        net[2] = (uint8_t)(hip >> 8);
        net[3] = (uint8_t)(hip);
    }

    const char *prefix_str = slash + 1;
    if (!isdigit((unsigned char)*prefix_str)) return -1;
    char *end = NULL;
    long prefix = strtol(prefix_str, &end, 10);
    if (*end != '\0' || prefix < 0 || prefix > max_prefix) return -1;

    mqvpn_cidr_premask(net, (int)prefix);

    out->family = is_v6 ? 6 : 4;
    out->prefix_len = (uint8_t)prefix;
    memcpy(out->net, net, sizeof(net));
    return 0;
}

/* Static per-session policy. The per-flow SYN-time verdict for tcp=auto
 * (active_paths >= 2) belongs to tcp_lane.c at flow creation — NOT
 * evaluated here; classify() applies only the static gates so it stays
 * pure and per-packet. */
typedef struct {
    int enabled;
    mqvpn_hybrid_tcp_mode_t tcp_mode;
    uint32_t tcp_max_flows;           /* consumed by tcp_lane.c */
    uint32_t tcp_idle_timeout_sec;    /* consumed by tcp_lane.c (client) AND, since the
                                       * limits task, svr_tcp_egress_tick (server): the
                                       * SAME field/semantics on both sides ("symmetric
                                       * single [hybrid] config block" — no separate
                                       * server-side idle key). 0 = disabled (never
                                       * evict), mirroring tcp_lane.c's documented
                                       * opt-out; a nonzero value evicts a flow whose
                                       * last_activity_us has not advanced in that many
                                       * seconds. Server-side: CONNECTING flows are
                                       * excluded (they use connect_deadline_us
                                       * instead, see svr_tcp_egress_tick); an ACTIVE
                                       * flow gets its H3 stream closed, not a 5xx
                                       * response (it already sent its 200). */
    uint32_t tcp_connect_timeout_sec; /* server: egress connect() timeout —
                                       * consumed when the connect stage lands */
    uint32_t tcp_max_global_flows;    /* server: whole-server cap on concurrent egress TCP
                                       * fds tcp_egress.c will ever open, before
                                       * mqvpn_server_egress_fd_budget()'s rlimit-derived
                                       * headroom check (svr_compute_egress_fd_budget)
                                       * narrows it further — see
                                       * MQVPN_TCP_MAX_GLOBAL_FLOWS_DEFAULT below for the
                                       * default. Distinct from the per-session
                                       * tcp_max_flows above (that one bounds concurrent
                                       * flows on a SINGLE H3 connection; this one bounds
                                       * the whole server). Ignored by client-side
                                       * classify(), like the egress ACL fields below. */

    /* Server-only egress ACL (connect-tcp destination policy).
     * egress_allow punches holes through the mandatory default-deny;
     * egress_deny adds extra blocks. Ignored by client-side classify(). */
    mqvpn_cidr_entry_t egress_allow[MQVPN_EGRESS_ACL_MAX];
    int n_egress_allow;
    mqvpn_cidr_entry_t egress_deny[MQVPN_EGRESS_ACL_MAX];
    int n_egress_deny;

    /* Client-only, runtime-learned — NOT a config key (deliberately absent
     * from cfg_keys[]): the tunnel subnet this client's CONNECT-IP address
     * lives in, filled at ADDRESS_ASSIGN time (mqvpn_client.c, tunnel-
     * config-ready path). Index 0 = IPv4 (mqvpn_tunnel_subnet_learn), index
     * 1 = IPv6 (mqvpn_tunnel_subnet_learn_v6). classify() forces IPv4 TCP
     * destined INSIDE the v4 entry onto the RAW lane: the server's
     * connect-tcp egress ACL denies the tunnel subnet unconditionally
     * (before EgressAllow is even consulted — svr_tcp_egress_acl_decide), so
     * a TCP-lane flow to a tunnel-subnet destination can only ever end in a
     * RESET, while RAW keeps intra-VPN TCP working exactly as it did before
     * the lane existed. An unfilled entry has family == 0 ("not learned",
     * disables the check for that family — the default memset below covers
     * both entries). Ignored by the server, mirroring how the egress ACL
     * fields above are ignored by the client. */
    mqvpn_cidr_entry_t client_tunnel_subnet[2];
} mqvpn_hybrid_config_t;

/* Default for tcp_max_global_flows above — also the fallback budget when
 * getrlimit(RLIMIT_NOFILE) headroom (rlim_cur - 64) is larger than this
 * (svr_compute_egress_fd_budget takes min(headroom, tcp_max_global_flows)). */
#define MQVPN_TCP_MAX_GLOBAL_FLOWS_DEFAULT 4096

/* Per-field defaults shared by mqvpn_hybrid_config_default and
 * mqvpn_hybrid_config_sanitize below — named so the two can't drift. */
#define MQVPN_TCP_MAX_FLOWS_DEFAULT           256
#define MQVPN_TCP_CONNECT_TIMEOUT_SEC_DEFAULT 10

/* static inline ON PURPOSE (not in classifier.c): src/config.c and
 * src/mqvpn_config.c will call these, and three test targets link those
 * sources WITHOUT mqvpn_lib — out-of-line definitions would break links. */
static inline void
mqvpn_hybrid_config_default(mqvpn_hybrid_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->enabled = 0;
    cfg->tcp_mode = MQVPN_HYBRID_TCP_AUTO;
    cfg->tcp_max_flows = MQVPN_TCP_MAX_FLOWS_DEFAULT;
    cfg->tcp_idle_timeout_sec = 300;
    cfg->tcp_connect_timeout_sec = MQVPN_TCP_CONNECT_TIMEOUT_SEC_DEFAULT;
    cfg->tcp_max_global_flows = MQVPN_TCP_MAX_GLOBAL_FLOWS_DEFAULT;
    /* n_egress_allow / n_egress_deny already 0 from the memset above. */
}

static inline int
mqvpn_hybrid_config_validate(const mqvpn_hybrid_config_t *cfg)
{
    if (!cfg) return -1;
    if (cfg->tcp_mode > MQVPN_HYBRID_TCP_AUTO) return -1;
    if (cfg->tcp_max_flows == 0) return -1;
    if (cfg->tcp_connect_timeout_sec == 0) return -1;
    /* tcp_max_global_flows == 0, like tcp_max_flows, would admit zero
     * connect-tcp flows server-wide — treated as a misconfiguration, not a
     * disable switch (tcp_idle_timeout_sec is the one field here where 0 is
     * a legitimate "off" value; this isn't that kind of field). */
    if (cfg->tcp_max_global_flows == 0) return -1;
    return 0;
}

/* Per-field companion to validate, run at the CONSUMERS (mqvpn_server_new /
 * the client's tcp_lane init site — same validate-at-consumer pattern as
 * mqvpn_reorder_config_validate): each field validate would reject is reset
 * to its own default, and ONLY that field. enabled, every valid field, and
 * the egress ACL lists are left untouched — a whole-block default reset
 * would silently DROP an operator's EgressDeny policy over an unrelated
 * typo (fail-open), where per-field reset matches the loaders' own per-key
 * "invalid X; using default" convention. Returns the number of fields
 * reset; names[0..min(ret,max_names)-1] receives static string literals
 * (INI key spelling) so the caller can log one warn per field with
 * whatever logger it owns (this header has no logging dependency on
 * purpose — see mqvpn_parse_cidr's note above). */
static inline int
mqvpn_hybrid_config_sanitize(mqvpn_hybrid_config_t *cfg, const char **names,
                             int max_names)
{
    int n = 0;
    if (!cfg) return 0;
    if (cfg->tcp_mode > MQVPN_HYBRID_TCP_AUTO) {
        cfg->tcp_mode = MQVPN_HYBRID_TCP_AUTO;
        if (names && n < max_names) names[n] = "Tcp";
        n++;
    }
    if (cfg->tcp_max_flows == 0) {
        cfg->tcp_max_flows = MQVPN_TCP_MAX_FLOWS_DEFAULT;
        if (names && n < max_names) names[n] = "TcpMaxFlows";
        n++;
    }
    if (cfg->tcp_connect_timeout_sec == 0) {
        cfg->tcp_connect_timeout_sec = MQVPN_TCP_CONNECT_TIMEOUT_SEC_DEFAULT;
        if (names && n < max_names) names[n] = "TcpConnectTimeoutSec";
        n++;
    }
    if (cfg->tcp_max_global_flows == 0) {
        cfg->tcp_max_global_flows = MQVPN_TCP_MAX_GLOBAL_FLOWS_DEFAULT;
        if (names && n < max_names) names[n] = "TcpMaxGlobalFlows";
        n++;
    }
    /* Postcondition pinned: a sanitized config always passes validate —
     * the four resets above cover exactly validate's four checks. Keep the
     * two functions in lockstep when adding fields. */
    return n;
}

/* Classify one inner IP packet from TUN. Fills *out_key (nullable) for
 * TCP/UDP verdicts. Rules: IPv4 fragment → RAW; IPv4 TCP → TCP lane iff
 * enabled && tcp_mode != RAW && dst outside client_tunnel_subnet (see the
 * field's docstring above); UDP → DGRAM; IPv6 TCP → RAW (v1);
 * ICMP/other/parse-fail → RAW. */
mqvpn_hybrid_lane_t mqvpn_hybrid_classify(const uint8_t *pkt, size_t len,
                                          const mqvpn_hybrid_config_t *pol,
                                          mqvpn_flow_key_t *out_key);

#endif
