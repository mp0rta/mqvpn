// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * dns_common.c — portable DNS/sockaddr helpers shared by all POSIX platforms
 * (split from linux/dns.c)
 */
#include "dns.h"
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>

int
mqvpn_resolve_host(const char *host, struct sockaddr_storage *out, socklen_t *out_len)
{
    if (!host || !host[0]) {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    /* Fast path: try IPv4 literal */
    struct in_addr addr4;
    if (inet_pton(AF_INET, host, &addr4) == 1) {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;
        sin->sin_family = AF_INET;
        sin->sin_addr = addr4;
        *out_len = sizeof(struct sockaddr_in);
        return 0;
    }

    /* Fast path: try IPv6 literal */
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, host, &addr6) == 1) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = addr6;
        *out_len = sizeof(struct sockaddr_in6);
        return 0;
    }

    /* Slow path: hostname resolution via getaddrinfo (dual-stack) */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    int ret = getaddrinfo(host, NULL, &hints, &res);
    if (ret != 0 || !res) {
        LOG_WRN("dns: failed to resolve '%s': %s", host, gai_strerror(ret));
        if (res) freeaddrinfo(res);
        return -1;
    }

    memcpy(out, res->ai_addr, res->ai_addrlen);
    *out_len = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

void
mqvpn_sa_set_port(struct sockaddr_storage *ss, uint16_t port)
{
    if (ss->ss_family == AF_INET) {
        ((struct sockaddr_in *)ss)->sin_port = htons(port);
    } else if (ss->ss_family == AF_INET6) {
        ((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
    }
}

const char *
mqvpn_sa_ntop(const struct sockaddr_storage *ss, char *buf, size_t buflen)
{
    if (ss->ss_family == AF_INET) {
        return inet_ntop(AF_INET, &((const struct sockaddr_in *)ss)->sin_addr, buf,
                         (socklen_t)buflen);
    } else if (ss->ss_family == AF_INET6) {
        return inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)ss)->sin6_addr, buf,
                         (socklen_t)buflen);
    }
    return NULL;
}

int
mqvpn_sa_host_prefix(const struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET) return 32;
    if (ss->ss_family == AF_INET6) return 128;
    return 0;
}

int
mqvpn_dns_add_server(mqvpn_dns_t *dns, const char *addr)
{
    if (dns->n_servers >= MQVPN_DNS_MAX_SERVERS) {
        LOG_WRN("dns: max %d servers supported", MQVPN_DNS_MAX_SERVERS);
        return -1;
    }
    snprintf(dns->servers[dns->n_servers], sizeof(dns->servers[0]), "%s", addr);
    dns->n_servers++;
    return 0;
}
