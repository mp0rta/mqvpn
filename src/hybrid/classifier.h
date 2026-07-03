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
 * connect-tcp egress ACL (Task 16). Clients embed mqvpn_hybrid_config_t too
 * (tcp_mode/tcp_max_flows drive client-side tcp_lane.c) but never read
 * these fields — egress reachability is purely a server concern, exactly
 * like tcp_max_flows is purely a client concern. Sized a bit above
 * [ReorderRule]'s cap (MQVPN_REORDER_MAX_RULES=16): egress ranges are
 * hand-authored network blocks evaluated once per connect-tcp request, not
 * a hot per-packet list, so a slightly larger ceiling costs nothing. */
#define MQVPN_EGRESS_ACL_MAX 32

/* One parsed IPv4 CIDR range, host-byte-order, net pre-masked (net = addr &
 * mask) so a match test is a single `(ip & mask) == net`. */
typedef struct {
    uint32_t net;
    uint32_t mask;
} mqvpn_cidr_entry_t;

/* Host-order /n mask, n clamped to [0,32]. n<=0 -> 0, n>=32 -> 0xFFFFFFFF —
 * both branches exist to avoid undefined behavior shifting a 32-bit value
 * by 32 (n=0 would otherwise require `~0u << 32`). */
static inline uint32_t
mqvpn_cidr_mask_from_prefix(int prefix_len)
{
    if (prefix_len <= 0) return 0u;
    if (prefix_len >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - prefix_len);
}

/* Parse strict "a.b.c.d/n" (n = 0..32) into *out, host-byte-order, network
 * pre-masked so a caller-supplied host part (e.g. "10.1.2.3/8") is quietly
 * normalized the way route tables normally are. No bare-address (implicit
 * /32) form, no surrounding whitespace tolerance. Returns 0 on success, -1
 * on malformed input — this header has no logging dependency on purpose
 * (config.h pulls it in), so callers decide how/whether to log a failure.
 * static inline for the same reason mqvpn_hybrid_config_default is: src/
 * config.c, src/mqvpn_config.c, and test binaries that skip mqvpn_lib all
 * need this, and an out-of-line definition would need a .c home in every
 * one of those link sets. */
static inline int
mqvpn_parse_cidr_v4(const char *s, mqvpn_cidr_entry_t *out)
{
    if (!s || !out) return -1;

    char buf[32];
    size_t len = strlen(s);
    if (len == 0 || len >= sizeof(buf)) return -1;
    memcpy(buf, s, len + 1);

    char *slash = strchr(buf, '/');
    if (!slash) return -1;
    *slash = '\0';

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return -1;

    const char *prefix_str = slash + 1;
    if (!isdigit((unsigned char)*prefix_str)) return -1;
    char *end = NULL;
    long prefix = strtol(prefix_str, &end, 10);
    if (*end != '\0' || prefix < 0 || prefix > 32) return -1;

    uint32_t mask = mqvpn_cidr_mask_from_prefix((int)prefix);
    out->mask = mask;
    out->net = ntohl(addr.s_addr) & mask;
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
    uint32_t tcp_idle_timeout_sec;    /* consumed by tcp_lane.c */
    uint32_t tcp_connect_timeout_sec; /* server: egress connect() timeout (Task 17) */

    /* Server-only egress ACL (connect-tcp destination policy, Task 16).
     * egress_allow punches holes through the mandatory default-deny;
     * egress_deny adds extra blocks. Ignored by client-side classify(). */
    mqvpn_cidr_entry_t egress_allow[MQVPN_EGRESS_ACL_MAX];
    int n_egress_allow;
    mqvpn_cidr_entry_t egress_deny[MQVPN_EGRESS_ACL_MAX];
    int n_egress_deny;
} mqvpn_hybrid_config_t;

/* Server-wide cap on concurrent egress TCP fds tcp_egress will ever open,
 * before mqvpn_server_egress_fd_budget()'s rlimit-derived headroom check
 * narrows it further. This is a whole-server bound, distinct from the
 * per-flow-table tcp_max_flows above. config key lands with the
 * server-side cap enforcement. */
#define MQVPN_TCP_MAX_GLOBAL_FLOWS_DEFAULT 4096

/* static inline ON PURPOSE (not in classifier.c): src/config.c and
 * src/mqvpn_config.c will call these, and three test targets link those
 * sources WITHOUT mqvpn_lib — out-of-line definitions would break links. */
static inline void
mqvpn_hybrid_config_default(mqvpn_hybrid_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->enabled = 0;
    cfg->tcp_mode = MQVPN_HYBRID_TCP_AUTO;
    cfg->tcp_max_flows = 256;
    cfg->tcp_idle_timeout_sec = 300;
    cfg->tcp_connect_timeout_sec = 10;
    /* n_egress_allow / n_egress_deny already 0 from the memset above. */
}

static inline int
mqvpn_hybrid_config_validate(const mqvpn_hybrid_config_t *cfg)
{
    if (!cfg) return -1;
    if (cfg->tcp_mode > MQVPN_HYBRID_TCP_AUTO) return -1;
    if (cfg->tcp_max_flows == 0) return -1;
    if (cfg->tcp_connect_timeout_sec == 0) return -1;
    return 0;
}

/* Classify one inner IP packet from TUN. Fills *out_key (nullable) for
 * TCP/UDP verdicts. Rules: IPv4 fragment → RAW; IPv4 TCP → TCP lane iff
 * enabled && tcp_mode != RAW; UDP → DGRAM; IPv6 TCP → RAW (v1);
 * ICMP/other/parse-fail → RAW. */
mqvpn_hybrid_lane_t mqvpn_hybrid_classify(const uint8_t *pkt, size_t len,
                                          const mqvpn_hybrid_config_t *pol,
                                          mqvpn_flow_key_t *out_key);

#endif
