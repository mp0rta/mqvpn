// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * routing.c — Split tunnel routing for Darwin
 *
 * Twin of linux/routing.c: manages route(8) commands for VPN split
 * tunneling:
 *   - Pin server route via original gateway
 *   - Catch-all 0.0.0.0/1 + 128.0.0.0/1 via TUN
 *   - IPv6 catch-all ::/1 + 8000::/1 via TUN
 */

#include "platform_internal.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

static int
run_route_cmd(const char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execvp("route", (char *const *)argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR) return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* `route -n get [-inet6] <dest>` output parsing.
 *
 * UNVERIFIED on real macOS (no Darwin hardware in this dev environment).
 * Assumed format per route(8), indented "key: value" lines, e.g.:
 *
 *      route to: 10.0.0.1
 *   destination: 10.0.0.1
 *       gateway: 10.0.0.254
 *     interface: en0
 *
 * or, for an on-link destination, a "link#N" gateway entry instead of an
 * IP (no gateway hop — the caller must not pin a route via it). Verify
 * against real macOS output before relying on this in production; the
 * key names/whitespace handling here may need adjustment.
 */
int
mqvpn_parse_route_get_output(const char *out, char *gateway, size_t gw_len, char *iface,
                             size_t if_len)
{
    gateway[0] = '\0';
    iface[0] = '\0';

    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", out);

    char *saveptr = NULL;
    for (char *line = strtok_r(buf, "\r\n", &saveptr); line;
         line = strtok_r(NULL, "\r\n", &saveptr)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';

        char *key = line;
        while (*key == ' ' || *key == '\t')
            key++;
        size_t klen = strlen(key);
        while (klen > 0 && (key[klen - 1] == ' ' || key[klen - 1] == '\t'))
            key[--klen] = '\0';

        char *value = colon + 1;
        while (*value == ' ' || *value == '\t')
            value++;
        size_t vlen = strlen(value);
        while (vlen > 0 && (value[vlen - 1] == ' ' || value[vlen - 1] == '\t'))
            value[--vlen] = '\0';

        if (strcmp(key, "gateway") == 0) {
            /* "link#N" is an on-link ARP/ND entry, not a gateway hop. */
            if (strncmp(value, "link#", 5) != 0) snprintf(gateway, gw_len, "%s", value);
        } else if (strcmp(key, "interface") == 0) {
            snprintf(iface, if_len, "%s", value);
        }
    }
    return iface[0] ? 0 : -1;
}

static int
discover_route(const char *server_ip, sa_family_t af, char *gateway, size_t gw_len,
               char *iface, size_t if_len)
{
    int fds[2];
    if (pipe(fds) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }

    if (pid == 0) {
        const char *const a4[] = {"route", "-n", "get", server_ip, NULL};
        const char *const a6[] = {"route", "-n", "get", "-inet6", server_ip, NULL};
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(127);
        close(fds[1]);
        execvp("route", (char *const *)((af == AF_INET6) ? a6 : a4));
        _exit(127);
    }

    close(fds[1]);
    char out[1024];
    ssize_t nread = read(fds[0], out, sizeof(out) - 1);
    close(fds[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR) return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || nread <= 0) return -1;

    out[nread] = '\0';
    return mqvpn_parse_route_get_output(out, gateway, gw_len, iface, if_len);
}

int
setup_routes(platform_ctx_t *p)
{
    sa_family_t af = p->server_addr.ss_family;
    int prefix = mqvpn_sa_host_prefix(&p->server_addr);
    mqvpn_sa_ntop(&p->server_addr, p->server_ip_str, sizeof(p->server_ip_str));

    if (discover_route(p->server_ip_str, af, p->orig_gateway, sizeof(p->orig_gateway),
                       p->orig_iface, sizeof(p->orig_iface)) < 0) {
        LOG_WRN("could not determine original iface for %s", p->server_ip_str);
        return -1;
    }

    char host_cidr[INET6_ADDRSTRLEN + 5];
    snprintf(host_cidr, sizeof(host_cidr), "%s/%d", p->server_ip_str, prefix);

    if (p->orig_gateway[0] != '\0') {
        LOG_INF("split tunnel: server %s via %s dev %s", p->server_ip_str,
                p->orig_gateway, p->orig_iface);

        /* macOS route(8) has no `replace` verb (unlike Linux `ip route
         * replace`); the twin behavior is add, and on failure retry with
         * `change`. UNVERIFIED on real macOS. run_route_cmd only observes
         * the child's exit status, so this fallback fires on ANY add
         * failure (route already exists, bad gateway, permission, ...),
         * not only the "route already exists" case — a genuinely bad
         * gateway/iface fails both add and change and falls through to
         * the LOG_WRN below, same as canon. */
        int pin_ok;
        if (af == AF_INET6) {
            const char *const add6[] = {"route",         "-n", "add", "-inet6", host_cidr,
                                        p->orig_gateway, NULL};
            const char *const chg6[] = {
                "route", "-n", "change", "-inet6", host_cidr, p->orig_gateway, NULL};
            pin_ok = (run_route_cmd(add6) == 0) || (run_route_cmd(chg6) == 0);
        } else {
            const char *const add4[] = {"route",         "-n", "add", host_cidr,
                                        p->orig_gateway, NULL};
            const char *const chg4[] = {"route",         "-n", "change", host_cidr,
                                        p->orig_gateway, NULL};
            pin_ok = (run_route_cmd(add4) == 0) || (run_route_cmd(chg4) == 0);
        }
        if (!pin_ok) {
            LOG_WRN("failed to pin server route");
            return -1;
        }
    } else {
        LOG_INF("split tunnel: server %s on-link dev %s", p->server_ip_str,
                p->orig_iface);
    }

    /* `-interface` catch-all routes on a utun point-to-point interface are
     * UNVERIFIED on real macOS hardware. */
    const char *const low[] = {"route",     "-n",         "add",       "-net",
                               "0.0.0.0/1", "-interface", p->tun.name, NULL};
    const char *const high[] = {"route",       "-n",         "add",       "-net",
                                "128.0.0.0/1", "-interface", p->tun.name, NULL};
    if (run_route_cmd(low) < 0 || run_route_cmd(high) < 0) {
        LOG_WRN("failed to set catch-all routes via %s", p->tun.name);
        const char *u1[] = {"route",     "-n",         "delete",    "-net",
                            "0.0.0.0/1", "-interface", p->tun.name, NULL};
        const char *u2[] = {"route",       "-n",         "delete",    "-net",
                            "128.0.0.0/1", "-interface", p->tun.name, NULL};
        (void)run_route_cmd(u1);
        (void)run_route_cmd(u2);
        if (p->orig_gateway[0]) {
            if (af == AF_INET6) {
                const char *u3[] = {"route",         "-n", "delete", "-inet6", host_cidr,
                                    p->orig_gateway, NULL};
                (void)run_route_cmd(u3);
            } else {
                const char *u3[] = {"route",         "-n", "delete", host_cidr,
                                    p->orig_gateway, NULL};
                (void)run_route_cmd(u3);
            }
        }
        return -1;
    }
    p->routing_configured = 1;

    /* IPv6 catch-all routes */
    if (p->has_v6) {
        const char *v6l[] = {"route", "-n",         "add",       "-inet6",
                             "::/1",  "-interface", p->tun.name, NULL};
        const char *v6h[] = {"route",    "-n",         "add",       "-inet6",
                             "8000::/1", "-interface", p->tun.name, NULL};
        if (run_route_cmd(v6l) == 0 && run_route_cmd(v6h) == 0) {
            p->routing6_configured = 1;
            LOG_INF("IPv6 catch-all routes set via %s", p->tun.name);
        } else {
            LOG_WRN("failed to set IPv6 catch-all routes (continuing IPv4-only)");
        }
    }
    return 0;
}

void
cleanup_routes(platform_ctx_t *p)
{
    if (!p->routing_configured) return;

    if (p->routing6_configured) {
        const char *d1[] = {"route", "-n",         "delete",    "-inet6",
                            "::/1",  "-interface", p->tun.name, NULL};
        const char *d2[] = {"route",    "-n",         "delete",    "-inet6",
                            "8000::/1", "-interface", p->tun.name, NULL};
        (void)run_route_cmd(d1);
        (void)run_route_cmd(d2);
        p->routing6_configured = 0;
    }

    const char *d3[] = {"route",     "-n",         "delete",    "-net",
                        "0.0.0.0/1", "-interface", p->tun.name, NULL};
    const char *d4[] = {"route",       "-n",         "delete",    "-net",
                        "128.0.0.0/1", "-interface", p->tun.name, NULL};
    (void)run_route_cmd(d3);
    (void)run_route_cmd(d4);

    if (p->orig_gateway[0]) {
        int pfx = mqvpn_sa_host_prefix(&p->server_addr);
        char hc[INET6_ADDRSTRLEN + 5];
        snprintf(hc, sizeof(hc), "%s/%d", p->server_ip_str, pfx);
        if (p->server_addr.ss_family == AF_INET6) {
            const char *d5[] = {"route",         "-n", "delete", "-inet6", hc,
                                p->orig_gateway, NULL};
            (void)run_route_cmd(d5);
        } else {
            const char *d5[] = {"route", "-n", "delete", hc, p->orig_gateway, NULL};
            (void)run_route_cmd(d5);
        }
    }
    p->routing_configured = 0;
    LOG_INF("split tunnel routes cleaned up");
}
