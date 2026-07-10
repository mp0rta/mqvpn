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
 * Verified on macOS 26.5 (arm64). Real `route -n get <off-link server>`
 * output is indented "key: value" lines plus a trailing colon-free metrics
 * table (skipped), e.g.:
 *
 *      route to: 160.251.143.149
 *   destination: default
 *          mask: default
 *       gateway: 192.168.1.1
 *     interface: en0
 *         flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 *      recvpipe  sendpipe  ...
 *             0         0  ...
 *
 * For an on-link destination the gateway is rendered as "link#N" or an
 * lladdr MAC instead of an IP (no gateway hop — the caller must not pin a
 * route via it); those are handled by the IP-vs-non-IP filter below.
 * (The exact captured vector is tests/test_route_parse_darwin.c case (a).)
 *
 * The gateway filter is non-IP-rejecting by design: `-n` forces numeric
 * output, so a usable gateway can only ever be an IPv4/IPv6 literal.
 * Any other rendering — "link#N", an lladdr MAC sockaddr (e.g.
 * "gateway: a4:83:e7:xx:xx:xx" from an LLINFO cloned route), or anything
 * else — is unusable as a `route add` gateway argument regardless of its
 * exact format, so any value that fails inet_pton for both families is
 * treated as on-link (gateway left empty). This holds independently of
 * the actual macOS output format. Hardware verify item: confirm real
 * on-link outputs are covered (link#N / lladdr) and that zoned v6
 * gateways round-trip.
 *
 * Input beyond 1023 bytes is silently truncated by the internal buffer
 * (the production caller discover_route reads <= 1023 bytes, so this
 * only matters for unit tests).
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
            /* Accept only IPv4/IPv6 literals as a gateway; any non-IP
             * rendering (link#N, an lladdr MAC, ...) is on-link — see the
             * -n rationale in the block comment above. Zone-scoped v6
             * gateways ("fe80::1%en0") fail inet_pton because of the
             * %zone suffix: test the address part with the zone stripped,
             * but keep the FULL zoned value in `gateway` — route(8)
             * accepts zoned gateway args. A '%' at position 0 leaves an
             * empty address part → rejected as non-IP. */
            const char *zone = strchr(value, '%');
            size_t ip_len = zone ? (size_t)(zone - value) : strlen(value);
            char ip_part[INET6_ADDRSTRLEN];
            if (ip_len > 0 && ip_len < sizeof(ip_part)) {
                memcpy(ip_part, value, ip_len);
                ip_part[ip_len] = '\0';
                unsigned char scratch[sizeof(struct in6_addr)];
                if (inet_pton(AF_INET, ip_part, scratch) == 1 ||
                    inet_pton(AF_INET6, ip_part, scratch) == 1)
                    snprintf(gateway, gw_len, "%s", value);
            }
        } else if (strcmp(key, "interface") == 0) {
            snprintf(iface, if_len, "%s", value);
        }
    }
    return iface[0] ? 0 : -1;
}

/* Run a `route -n get ...` command and parse its stdout into gateway/iface.
 * Factored out of discover_route so discover_scoped_gateway can issue the
 * -ifscope variant through the identical fork/pipe/parse path. */
static int
route_get_and_parse(const char *const argv[], char *gateway, size_t gw_len,
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
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(127);
        close(fds[1]);
        execvp("route", (char *const *)argv);
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

static int
discover_route(const char *server_ip, sa_family_t af, char *gateway, size_t gw_len,
               char *iface, size_t if_len)
{
    const char *const a4[] = {"route", "-n", "get", server_ip, NULL};
    const char *const a6[] = {"route", "-n", "get", "-inet6", server_ip, NULL};
    return route_get_and_parse((af == AF_INET6) ? a6 : a4, gateway, gw_len, iface,
                               if_len);
}

/* ── Per-interface scoped server pins (multipath, follow-up #F1) ──
 *
 * setup_routes()'s unscoped server pin goes via ONE gateway — whichever
 * interface owned the primary default route at connect time. When THAT
 * interface goes down, the kernel flushes the pin together with the
 * interface's routes, and nothing restores it. From then on the server IP
 * resolves through the utun catch-all (128.0.0.0/1), and xnu's scoped
 * route lookup (what an IP_BOUND_IF path socket does on every send)
 * rejects that more-specific route on ifp mismatch WITHOUT backtracking
 * to the interface's own default route: every sendto() on a recovered
 * path fails ENETUNREACH, the PATH_CHALLENGE never reaches the wire, and
 * the path parks in VALIDATING forever (watchdog shows the public
 * projection: "stuck in PENDING"). Hardware-verified on macOS 26.5
 * (arm64, Wi-Fi en0 + USB ethernet en6): after a churn flap the recovered
 * path retransmitted PATH_CHALLENGE for minutes with 14k+ socket errors,
 * and manually adding the scoped host route flipped it to ACTIVE within
 * 40 ms.
 *
 * Invariant maintained here: every multipath interface carries its own
 * RTF_IFSCOPE host route to the server via its own gateway, so a path
 * socket's scoped lookup never depends on which interface currently owns
 * the unscoped primary default (configd reshuffles that on every
 * interface arrival/departure). The kernel flushes a scoped pin with its
 * interface on down; try_readd_removed_path / try_reactivate_by_ifname
 * (route_mon.c) re-install it before handing the recovered socket back
 * to xquic. */

/* Gateway of ifname's own (scoped) default route, via
 * `route -n get [-inet6] -ifscope <if> default`. Empty gateway = on-link
 * upstream (link#N / lladdr rendering, same filter as discover_route).
 * Returns 0 on success, -1 if the interface has no default route. */
static int
discover_scoped_gateway(const char *ifname, sa_family_t af, char *gateway,
                        size_t gw_len)
{
    char gw_iface[IFNAMSIZ];
    const char *const a4[] = {"route", "-n",      "get",     "-ifscope",
                              ifname,  "default", NULL};
    const char *const a6[] = {"route",    "-n",   "get",     "-inet6",
                              "-ifscope", ifname, "default", NULL};
    if (route_get_and_parse((af == AF_INET6) ? a6 : a4, gateway, gw_len, gw_iface,
                            sizeof(gw_iface)) < 0)
        return -1;
    /* A scoped default get answers for exactly this interface; a reply
     * naming another iface means there is no usable default via ifname. */
    if (strcmp(gw_iface, ifname) != 0) return -1;
    return 0;
}

int
darwin_scoped_server_pin(platform_ctx_t *p, const char *ifname)
{
    if (!p->routing_configured) return -1;

    sa_family_t af = p->server_addr.ss_family;
    char host_cidr[INET6_ADDRSTRLEN + 5];
    snprintf(host_cidr, sizeof(host_cidr), "%s/%d", p->server_ip_str,
             mqvpn_sa_host_prefix(&p->server_addr));

    char gw[INET6_ADDRSTRLEN];
    if (discover_scoped_gateway(ifname, af, gw, sizeof(gw)) < 0) {
        LOG_WRN("scoped server pin: no default route via %s", ifname);
        return -1;
    }

    /* add, then retry as change — same no-`replace`-verb idiom (and the
     * same fires-on-any-failure caveat) as setup_routes' unscoped pin. */
    const char *argv[10];
    int n = 0;
    argv[n++] = "route";
    argv[n++] = "-n";
    argv[n++] = "add";
    if (af == AF_INET6) argv[n++] = "-inet6";
    argv[n++] = "-ifscope";
    argv[n++] = ifname;
    argv[n++] = host_cidr;
    if (gw[0] != '\0') {
        argv[n++] = gw;
    } else {
        /* On-link upstream: pin via the interface itself, mirroring
         * setup_routes' on-link branch. */
        argv[n++] = "-interface";
        argv[n++] = ifname;
    }
    argv[n] = NULL;

    int ok = (run_route_cmd(argv) == 0);
    if (!ok) {
        argv[2] = "change";
        ok = (run_route_cmd(argv) == 0);
    }
    if (!ok) {
        LOG_WRN("scoped server pin for %s failed", ifname);
        return -1;
    }
    LOG_INF("scoped server pin: %s via %s dev %s", p->server_ip_str,
            gw[0] ? gw : "on-link", ifname);
    return 0;
}

/* Best-effort teardown twin of darwin_scoped_server_pin. Deleting a pin
 * the kernel already flushed with its interface fails silently — fine. */
static void
scoped_server_pin_delete(platform_ctx_t *p, const char *ifname)
{
    sa_family_t af = p->server_addr.ss_family;
    char host_cidr[INET6_ADDRSTRLEN + 5];
    snprintf(host_cidr, sizeof(host_cidr), "%s/%d", p->server_ip_str,
             mqvpn_sa_host_prefix(&p->server_addr));

    const char *argv[8];
    int n = 0;
    argv[n++] = "route";
    argv[n++] = "-n";
    argv[n++] = "delete";
    if (af == AF_INET6) argv[n++] = "-inet6";
    argv[n++] = "-ifscope";
    argv[n++] = ifname;
    argv[n++] = host_cidr;
    argv[n] = NULL;
    (void)run_route_cmd(argv);
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

    /* Multipath: give every path interface its own scoped pin so a path
     * socket's reachability never depends on the single unscoped pin above
     * (follow-up #F1; doc block at darwin_scoped_server_pin). Best-effort:
     * an interface without upstream right now gets its pin from route_mon
     * at re-add/reactivate time instead. */
    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        if (p->path_mgr.paths[i].iface[0] == '\0') continue;
        (void)darwin_scoped_server_pin(p, p->path_mgr.paths[i].iface);
    }
    return 0;
}

void
cleanup_routes(platform_ctx_t *p)
{
    if (!p->routing_configured) return;

    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        if (p->path_mgr.paths[i].iface[0] == '\0') continue;
        scoped_server_pin_delete(p, p->path_mgr.paths[i].iface);
    }

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
