// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * platform_linux.c — Linux platform layer for libmqvpn
 *
 * Bridges libmqvpn (sans-I/O) with Linux-specific I/O:
 *   - libevent event loop driving tick()
 *   - TUN device creation and I/O
 *   - UDP socket creation via path_mgr
 *   - Signal handling (SIGINT/SIGTERM)
 *
 * Routing and killswitch are in separate files (routing.c, killswitch.c).
 */

#include "platform_internal.h"
#include "platform_linux.h"
#include "control_socket.h"
#include "log.h"
#include "mqvpn_internal.h" /* mqvpn_config_apply_reorder (INI reorder bridge) */

#include <stdio.h>
#include <inttypes.h>

#define STATUS_INTERVAL_SEC        30
#define RECOVER_INTERVAL_SEC       3
#define PATH_RECOVER_FAILURE_LIMIT 5
#define BULK_READ_COUNT            64
#define NETLINK_BUF_SIZE           8192
#define TUN_BUF_SIZE               65536
#define SOCK_BUF_SIZE              65536
static void status_log_cb(evutil_socket_t fd, short what, void *arg);
static void recover_dropped_paths_cb(evutil_socket_t fd, short what, void *arg);
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>

/* ================================================================
 *  Socket pinning to a specific egress interface
 * ================================================================ */

/* Pin an outgoing UDP socket to the given interface via SO_BINDTODEVICE.
 * Symmetric to win_pin_socket_to_iface() in platform_windows.c.
 * Returns 0 on success, -1 on failure. The caller decides whether
 * failure is fatal. */
static int
linux_pin_socket_to_iface(int fd, const char *ifname)
{
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
                   (socklen_t)(strlen(ifname) + 1)) < 0) {
        LOG_WRN("setsockopt(SO_BINDTODEVICE, '%s'): %s", ifname, strerror(errno));
        return -1;
    }
    return 0;
}

/* ================================================================
 *  libmqvpn callbacks
 * ================================================================ */

/* Forward declarations for event handlers */
static void on_tun_read(evutil_socket_t fd, short what, void *arg);
static void on_socket_read(evutil_socket_t fd, short what, void *arg);

static void
cb_tun_output(const uint8_t *pkt, size_t len, void *user_ctx)
{
    platform_ctx_t *p = (platform_ctx_t *)user_ctx;
    if (p->tun_up && p->tun.fd >= 0) mqvpn_tun_write(&p->tun, pkt, len);
}

static void
cb_tunnel_config_ready(const mqvpn_tunnel_info_t *info, void *user_ctx)
{
    platform_ctx_t *p = (platform_ctx_t *)user_ctx;

    /* Clean up stale TUN event from previous connection (reconnect case) */
    if (p->ev_tun) {
        event_del(p->ev_tun);
        event_free(p->ev_tun);
        p->ev_tun = NULL;
    }
    if (p->tun.fd >= 0) {
        mqvpn_tun_destroy(&p->tun);
        p->tun.fd = -1;
        p->tun_up = 0;
    }

    /* Create TUN device — use tun_name_cfg which survives destroy/recreate */
    if (mqvpn_tun_create(&p->tun, p->tun_name_cfg) < 0) {
        LOG_ERR("TUN create failed");
        goto fail;
    }

    /* Set IPv4 address */
    char local_ip[INET_ADDRSTRLEN];
    snprintf(local_ip, sizeof(local_ip), "%d.%d.%d.%d", info->assigned_ip[0],
             info->assigned_ip[1], info->assigned_ip[2], info->assigned_ip[3]);
    char peer_ip[INET_ADDRSTRLEN];
    snprintf(peer_ip, sizeof(peer_ip), "%d.%d.%d.%d", info->server_ip[0],
             info->server_ip[1], info->server_ip[2], info->server_ip[3]);

    if (mqvpn_tun_set_addr(&p->tun, local_ip, peer_ip, 32) < 0) goto fail;
    if (mqvpn_tun_set_mtu(&p->tun, info->mtu) < 0) goto fail;
    if (mqvpn_tun_up(&p->tun) < 0) goto fail;

    /* Set IPv6 address if available */
    if (info->has_v6) {
        p->has_v6 = 1;
        char v6str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, info->assigned_ip6, v6str, sizeof(v6str));
        if (mqvpn_tun_set_addr6(&p->tun, v6str, info->assigned_prefix6) < 0)
            LOG_WRN("failed to set IPv6 address on TUN (continuing IPv4-only)");
    }

    LOG_INF("TUN %s configured: %s → %s (mtu=%d)", p->tun.name, local_ip, peer_ip,
            info->mtu);

    /* Set up routes, killswitch, DNS.
     *
     * manage_routes=false skips setup_routes() entirely. TUN is still
     * created + addressed + UP and the kernel auto-adds the connected
     * route for the tunnel subnet (e.g. 10.0.0.0/24 dev mqvpn0).
     *
     * Skipped: server-pin (<server_ip>/32 via orig gateway) + catch-all
     * redirect (0.0.0.0/1 + 128.0.0.0/1 + IPv6 ::/1 + 8000::/1 into
     * mqvpn0). Without these, traffic outside the tunnel subnet uses
     * the existing default route — the integrator must add `ip route`
     * / `ip rule` externally (router/embedded use case). killswitch
     * and DNS overrides remain independently controllable.
     */
    if (p->manage_routes) {
        if (setup_routes(p) < 0) {
            LOG_ERR("route setup failed, aborting tunnel");
            goto fail;
        }
    } else {
        LOG_INF("manage_routes=off: host routing table left untouched");
    }
    if (setup_killswitch(p) < 0) {
        LOG_ERR("killswitch setup failed, aborting tunnel");
        goto fail;
    }
    if (p->dns.n_servers > 0) {
        if (mqvpn_dns_apply(&p->dns) < 0)
            LOG_WRN("DNS override failed (continuing without DNS override)");
    }

    /* Register TUN read event */
    p->ev_tun = event_new(p->eb, p->tun.fd, EV_READ | EV_PERSIST, on_tun_read, p);
    if (!p->ev_tun) {
        LOG_ERR("failed to create TUN event");
        goto fail;
    }
    event_add(p->ev_tun, NULL);
    p->tun_up = 1;

    /* Tell library the TUN is active */
    mqvpn_client_set_tun_active(p->client, 1, p->tun.fd);

    /* Start periodic status log */
    if (!p->ev_status) p->ev_status = evtimer_new(p->eb, status_log_cb, p);
    if (p->ev_status) {
        struct timeval tv = {.tv_sec = STATUS_INTERVAL_SEC};
        event_add(p->ev_status, &tv);
    }

    /* Start periodic dropped-path re-add timer. Carrier-up netlink events
     * fire only once and `try_readd_removed_path()` can fail synchronously
     * (e.g. xqc_conn_create_path returning -XQC_EMP_NO_AVAIL_PATH_ID before
     * the server has distributed enough CIDs). Without this timer the slot
     * would sit in CLOSED_DROPPED indefinitely — no further netlink event
     * arrives because IP and link state never change again. The library's
     * tick_drive_retry_timer only services CREATE_WAIT/DEGRADED, not
     * CLOSED_DROPPED, so a platform-side timer is needed. */
    if (!p->ev_recover) p->ev_recover = evtimer_new(p->eb, recover_dropped_paths_cb, p);
    if (p->ev_recover) {
        struct timeval tv = {.tv_sec = RECOVER_INTERVAL_SEC};
        event_add(p->ev_recover, &tv);
    }

    return;

fail:
    cleanup_killswitch(p);
    if (p->manage_routes) cleanup_routes(p);
    mqvpn_dns_restore(&p->dns);
    if (p->tun.fd >= 0) mqvpn_tun_destroy(&p->tun);
    p->tun.fd = -1;
    p->tun_up = 0;
    mqvpn_client_disconnect(p->client);
}

static void
cb_tunnel_closed(mqvpn_error_t reason, void *user_ctx)
{
    (void)user_ctx;
    LOG_INF("tunnel closed: %s", mqvpn_error_string(reason));
}

static void
cb_ready_for_tun(void *user_ctx)
{
    /* Backpressure cleared — TUN reading will resume on next tick */
    (void)user_ctx;
}

static void
cb_state_changed(mqvpn_client_state_t old_state, mqvpn_client_state_t new_state,
                 void *user_ctx)
{
    platform_ctx_t *p = (platform_ctx_t *)user_ctx;
    static const char *names[] = {"IDLE",         "CONNECTING",  "AUTHENTICATING",
                                  "TUNNEL_READY", "ESTABLISHED", "RECONNECTING",
                                  "CLOSED"};
    const char *os = (old_state < 7) ? names[old_state] : "?";
    const char *ns = (new_state < 7) ? names[new_state] : "?";
    LOG_INF("state: %s → %s", os, ns);

    /* On RECONNECTING or CLOSED, tear down TUN and platform resources so
     * that stale fd events don't fire ("tun read: Bad file descriptor").
     * The TUN will be recreated in cb_tunnel_config_ready on reconnect. */
    if (new_state == MQVPN_STATE_RECONNECTING || new_state == MQVPN_STATE_CLOSED) {
        /* PR5: path lifecycle state is owned by libmqvpn — no state mirror
         * to reset here. Library handles slot recycling across reconnects.
         * path_recover_failures IS reset — Level-2 reconnect creates a
         * fresh xquic conn with fresh path_id namespace, so prior failures
         * (e.g. -XQC_EMP_NO_AVAIL_PATH_ID due to CID lag) shouldn't count
         * against the new connection's retry budget. */
        memset(p->path_recover_failures, 0, sizeof(p->path_recover_failures));
        if (p->ev_status) event_del(p->ev_status); /* pause — reused on reconnect */
        if (p->ev_recover) event_del(p->ev_recover);
        cleanup_killswitch(p);
        if (p->manage_routes) cleanup_routes(p);
        mqvpn_dns_restore(&p->dns);
        if (p->tun_up) {
            if (p->ev_tun) {
                event_del(p->ev_tun);
                event_free(p->ev_tun);
                p->ev_tun = NULL;
            }
            mqvpn_tun_destroy(&p->tun);
            p->tun.fd = -1;
            p->tun_up = 0;
            mqvpn_client_set_tun_active(p->client, 0, -1);
        }
        if (new_state == MQVPN_STATE_CLOSED && p->shutting_down)
            event_base_loopbreak(p->eb);
    }
}

static void
cb_path_event(mqvpn_path_handle_t path, mqvpn_path_status_t status, void *user_ctx)
{
    (void)user_ctx;
    /* PR5: path lifecycle state is owned entirely by libmqvpn. Platform
     * no longer mirrors recoverable / removed state — try_reactivate_by_ifname
     * queries lib state directly via mqvpn_client_get_paths(). */
    const char *sn = mqvpn_path_status_string(status);
    LOG_INF("path %lld -> %s", (long long)path, sn);
}

static void
cb_mtu_updated(int mtu, void *user_ctx)
{
    platform_ctx_t *p = (platform_ctx_t *)user_ctx;
    if (p->tun_up) mqvpn_tun_set_mtu(&p->tun, mtu);
    LOG_INF("TUN MTU updated to %d", mtu);
}

static void
cb_log(mqvpn_log_level_t level, const char *msg, void *user_ctx)
{
    (void)user_ctx;
    switch (level) {
    case MQVPN_LOG_DEBUG: LOG_DBG("[lib] %s", msg); break;
    case MQVPN_LOG_INFO: LOG_INF("[lib] %s", msg); break;
    case MQVPN_LOG_WARN: LOG_WRN("[lib] %s", msg); break;
    case MQVPN_LOG_ERROR: LOG_ERR("[lib] %s", msg); break;
    }
}

static void
cb_reconnect_scheduled(int delay_sec, void *user_ctx)
{
    (void)user_ctx;
    LOG_INF("reconnect scheduled in %d seconds", delay_sec);
}

static void
status_log_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;
    if (!p->client) return;

    mqvpn_client_state_t state = mqvpn_client_get_state(p->client);
    if (state != MQVPN_STATE_ESTABLISHED) return;

    mqvpn_stats_t stats;
    if (mqvpn_client_get_stats(p->client, &stats) != MQVPN_OK) return;

    mqvpn_path_info_t paths[MQVPN_MAX_PATHS];
    int n_paths = 0;
    mqvpn_client_get_paths(p->client, paths, MQVPN_MAX_PATHS, &n_paths);

    LOG_INF("[STATUS] state=established paths=%d tx=%" PRIu64 " rx=%" PRIu64
            " srtt=%dms dgram_lost=%" PRIu64 " lanes tcp/dgram/raw=%" PRIu64 "/%" PRIu64
            "/%" PRIu64,
            n_paths, stats.bytes_tx, stats.bytes_rx, stats.srtt_ms, stats.dgram_lost,
            stats.pkts_lane_tcp, stats.pkts_lane_dgram, stats.pkts_lane_raw);

    for (int i = 0; i < n_paths; i++) {
        const char *st_str = mqvpn_path_status_string(paths[i].status);
        LOG_INF("[STATUS]   path%d=%s srtt=%dms tx=%" PRIu64 " rx=%" PRIu64 " %s", i,
                paths[i].name, paths[i].srtt_ms, paths[i].bytes_tx, paths[i].bytes_rx,
                st_str);
    }

    /* Re-arm timer */
    if (p->ev_status) {
        struct timeval tv = {.tv_sec = STATUS_INTERVAL_SEC};
        event_add(p->ev_status, &tv);
    }
}

/* ================================================================
 *  Event handlers
 * ================================================================ */

static void on_tick_timer(evutil_socket_t fd, short what, void *arg);

static void
schedule_next_tick(platform_ctx_t *p)
{
    mqvpn_interest_t interest;
    mqvpn_client_get_interest(p->client, &interest);

    int ms = interest.next_timer_ms;
    struct timeval tv = {
        .tv_sec = ms / 1000,
        .tv_usec = (ms % 1000) * 1000,
    };
    event_add(p->ev_tick, &tv);

    /* Enable/disable TUN read based on interest */
    if (p->tun_up && p->tun.fd >= 0) {
        if (interest.tun_readable && !event_pending(p->ev_tun, EV_READ, NULL))
            event_add(p->ev_tun, NULL);
        else if (!interest.tun_readable && event_pending(p->ev_tun, EV_READ, NULL))
            event_del(p->ev_tun);
    }
}

static void
on_tick_timer(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;

    mqvpn_client_tick(p->client);
    schedule_next_tick(p);
}

static void
on_tun_read(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;
    uint8_t buf[TUN_BUF_SIZE];

    for (int i = 0; i < BULK_READ_COUNT; i++) {
        int n = mqvpn_tun_read(&p->tun, buf, sizeof(buf));
        if (n <= 0) break;

        int ret = mqvpn_client_on_tun_packet(p->client, buf, (size_t)n);
        if (ret == MQVPN_ERR_AGAIN) {
            /* Backpressure — stop reading TUN until ready_for_tun callback */
            event_del(p->ev_tun);
            break;
        }
    }
}

static void
on_socket_read(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;
    uint8_t buf[SOCK_BUF_SIZE];
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);

    for (int i = 0; i < BULK_READ_COUNT; i++) {
        // codeql[cpp/uncontrolled-allocation-size] buf is stack-allocated and bounded by
        // sizeof(buf); xquic validates internally
        ssize_t n =
            recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peer_len);
        if (n <= 0 || (size_t)n > sizeof(buf)) break;

        /* Find which library path handle matches this fd */
        mqvpn_path_handle_t handle = -1;
        for (int j = 0; j < p->path_mgr.n_paths; j++) {
            if (p->path_mgr.paths[j].fd == fd) {
                handle = p->lib_path_handles[j];
                break;
            }
        }
        if (handle < 0) break;

        mqvpn_client_on_socket_recv(p->client, handle, buf, (size_t)n,
                                    (struct sockaddr *)&peer, peer_len);
    }
    /* Drive engine after receiving packets */
    mqvpn_client_tick(p->client);
    schedule_next_tick(p);
}

static void
on_signal(evutil_socket_t sig, short what, void *arg)
{
    (void)sig;
    (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;

    LOG_INF("received signal, shutting down...");
    p->shutting_down = 1;
    mqvpn_client_disconnect(p->client);
    /* state_changed callback will call event_base_loopbreak on CLOSED */
}

/* ================================================================
 *  Netlink path recovery accelerator
 * ================================================================ */

/* Extract interface name from IFLA_IFNAME attribute in netlink message.
 * Required for RTM_DELLINK where if_indextoname() fails (interface gone). */
static const char *
nlmsg_get_ifname(struct nlmsghdr *nh)
{
    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nh);
    struct rtattr *rta = IFLA_RTA(ifi);
    int rtl = (int)IFLA_PAYLOAD(nh);
    for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
        if (rta->rta_type == IFLA_IFNAME) return (const char *)RTA_DATA(rta);
    }
    return NULL;
}

/* Extract IFLA_OPERSTATE (RFC 2863 operational state) from a netlink message.
 * Returns the IF_OPER_* enum value (0..7), or -1 if the attribute is missing. */
static int
nlmsg_get_operstate(struct nlmsghdr *nh)
{
    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nh);
    struct rtattr *rta = IFLA_RTA(ifi);
    int rtl = (int)IFLA_PAYLOAD(nh);
    for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
        if (rta->rta_type == IFLA_OPERSTATE && RTA_PAYLOAD(rta) >= 1)
            return *(const uint8_t *)RTA_DATA(rta);
    }
    return -1;
}

/* Remove a path because the kernel says it's no longer usable.
 * Two callers: RTM_DELLINK (interface gone) and RTM_NEWLINK with IFLA_OPERSTATE
 * = IF_OPER_DOWN / IF_OPER_LOWERLAYERDOWN (carrier lost — cable unplugged etc).
 * Both share cleanup; only the log message differs.
 *
 * Cleans up: library path, libevent, fd. Preserves iface name for re-add. */
static void
remove_path_by_index(platform_ctx_t *p, int idx, const char *reason)
{
    if (p->path_mgr.paths[idx].fd < 0) return; /* already removed */

    LOG_WRN("netlink: interface %s %s, closing path %d", p->path_mgr.paths[idx].iface,
            reason, idx);

    /* PR5: emit PLATFORM_DROP via new public API with diagnostic info.
     * Library transitions slot to CLOSED_DROPPED; fd close is reported
     * via mqvpn_client_on_platform_fd_closed() below. */
    mqvpn_platform_path_event_info_t info = {0};
    snprintf(info.iface, sizeof(info.iface), "%s", p->path_mgr.paths[idx].iface);
    info.reason = MQVPN_PLATFORM_REASON_RTM_DELLINK;
    mqvpn_client_on_platform_path_dropped(p->client, p->lib_path_handles[idx], &info);

    /* Remove libevent watcher */
    if (p->ev_udp[idx]) {
        event_del(p->ev_udp[idx]);
        event_free(p->ev_udp[idx]);
        p->ev_udp[idx] = NULL;
    }

    /* Close dead socket + notify lib so CLOSED_DROPPED -> CLOSED_FREE
     * cleanup can complete (once xquic-side also clears). */
    close(p->path_mgr.paths[idx].fd);
    p->path_mgr.paths[idx].fd = -1;
    p->path_mgr.paths[idx].platform_attached = 0;
    mqvpn_client_on_platform_fd_closed(p->client, p->lib_path_handles[idx]);
}

/* Check whether `ifname` is admin-up AND has carrier (IFF_UP & IFF_RUNNING).
 * Used by the periodic recovery timer to skip retries on a still-down link. */
static int
iface_is_up_and_running(const char *ifname)
{
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return 0;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    int ok = 0;
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0)
        ok = (ifr.ifr_flags & IFF_UP) && (ifr.ifr_flags & IFF_RUNNING);
    close(s);
    return ok;
}

/* Check if interface has an IP address (v4 or v6) */
static int
iface_has_ip(const char *ifname)
{
    struct ifaddrs *ifa_list = NULL, *ifa;
    int found = 0;
    if (getifaddrs(&ifa_list) < 0) return 0;
    for (ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (strcmp(ifa->ifa_name, ifname) != 0) continue;
        if (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6) {
            found = 1;
            break;
        }
    }
    freeifaddrs(ifa_list);
    return found;
}

static void
try_reactivate_by_ifname(platform_ctx_t *p, const char *ifname)
{
    /* PR5: query lib state instead of platform-tracked path_recoverable[].
     * Reactivate is valid for slots in DEGRADED / CREATE_WAIT /
     * CLOSED_RECOVERABLE (per lib's reactivate_slot_eligible gate added
     * in 433272f). Public projection collapses these to MQVPN_PATH_DEGRADED
     * (for DEGRADED+CREATE_WAIT) and MQVPN_PATH_CLOSED (for CLOSED_RECOVERABLE),
     * so both warrant attempting reactivate. The lib's gate rejects bad
     * states with MQVPN_ERR_INVALID_STATE which we silently swallow. */
    mqvpn_path_info_t pinfo[MQVPN_MAX_PATHS];
    int n = 0;
    if (mqvpn_client_get_paths(p->client, pinfo, MQVPN_MAX_PATHS, &n) != MQVPN_OK) return;

    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        if (strcmp(p->path_mgr.paths[i].iface, ifname) != 0) continue;
        mqvpn_path_handle_t h = p->lib_path_handles[i];
        if (h < 0) continue;

        int found = 0;
        mqvpn_path_status_t st = MQVPN_PATH_PENDING;
        for (int j = 0; j < n; j++) {
            if (pinfo[j].handle == h) {
                found = 1;
                st = pinfo[j].status;
                break;
            }
        }
        if (!found) continue;
        if (st != MQVPN_PATH_DEGRADED && st != MQVPN_PATH_CLOSED) continue;

        int ret = mqvpn_client_reactivate_path(p->client, h);
        if (ret == MQVPN_OK) {
            LOG_INF("netlink: reactivated path %s", ifname);
        } else if (ret == MQVPN_ERR_INVALID_STATE) {
            /* slot not in 3-state acceptance window (e.g. already VALIDATING) */
        } else {
            LOG_WRN("netlink: reactivate %s failed: %s", ifname, mqvpn_error_string(ret));
        }
    }
}

/* Create a UDP socket bound to the wildcard address and pinned to ifname.
 * Updates mp->local_addr / mp->local_addrlen on success.
 * Returns the new fd, or -1 (already logged). */
static int
recovery_socket_create(sa_family_t af, const char *ifname, mqvpn_path_t *mp)
{
    int fd = (int)socket(af, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_WRN("netlink: socket() for re-add %s: %s", ifname, strerror(errno));
        return -1;
    }
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        LOG_WRN("netlink: fcntl() for re-add %s: %s", ifname, strerror(errno));
        goto fail;
    }

    /* Socket buffers are set by mqvpn_client_add_path_fd() (7 MiB) */

    memset(&mp->local_addr, 0, sizeof(mp->local_addr));
    if (af == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&mp->local_addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = in6addr_any;
        mp->local_addrlen = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *sin4 = (struct sockaddr_in *)&mp->local_addr;
        sin4->sin_family = AF_INET;
        sin4->sin_addr.s_addr = htonl(INADDR_ANY);
        mp->local_addrlen = sizeof(struct sockaddr_in);
    }
    if (bind(fd, (struct sockaddr *)&mp->local_addr, mp->local_addrlen) < 0) {
        LOG_WRN("netlink: bind() for re-add %s: %s", ifname, strerror(errno));
        goto fail;
    }

    /* Pin AFTER bind, matching startup-loop order. */
    if (linux_pin_socket_to_iface(fd, ifname) < 0) {
        LOG_WRN("netlink: iface pin for re-add %s failed", ifname);
        goto fail;
    }

    return fd;
fail:
    close(fd);
    return -1;
}

/* Register a freshly-created socket with the library and capture the
 * synchronous activation outcome via the with_outcome API. Returns the
 * new handle and writes *outcome (MQVPN_ADD_PATH_OK / TRANSIENT / PERMANENT);
 * returns -1 on handle-allocation failure (already logged). */
static mqvpn_path_handle_t
recovery_register_with_lib(platform_ctx_t *p, int slot, int fd, const char *ifname,
                           mqvpn_add_path_outcome_t *outcome)
{
    mqvpn_path_t *mp = &p->path_mgr.paths[slot];

    mqvpn_path_desc_t desc = {0};
    desc.struct_size = sizeof(desc);
    desc.fd = fd;
    snprintf(desc.iface, sizeof(desc.iface), "%s", mp->iface);
    if (mp->local_addrlen > 0 && mp->local_addrlen <= sizeof(desc.local_addr)) {
        memcpy(desc.local_addr, &mp->local_addr, mp->local_addrlen);
        desc.local_addr_len = mp->local_addrlen;
    }

    mqvpn_path_handle_t handle =
        mqvpn_client_add_path_fd_with_outcome(p->client, fd, &desc, outcome);
    if (handle < 0) {
        LOG_WRN("netlink: add_path_fd() for re-add %s failed", ifname);
        return -1;
    }
    p->lib_path_handles[slot] = handle;
    return handle;
}

/* Roll back a failed re-add so the next attempt starts from a clean slate.
 *
 * Safe ordering: remove_path() first, then close(fd). The xquic_path_live=0
 * invariant (enforced by apply_path_activation_failure /
 * apply_path_create_permanent_failure) makes remove_path() skip
 * xqc_conn_close_path(), so xquic never touches this fd during teardown.
 * Do NOT remove that defensive clear — it's what makes this rollback safe. */
static void
recovery_rollback(platform_ctx_t *p, int slot, mqvpn_add_path_outcome_t outcome)
{
    mqvpn_path_t *mp = &p->path_mgr.paths[slot];
    const char *ifname = mp->iface;

    mqvpn_client_remove_path(p->client, p->lib_path_handles[slot]);
    close(mp->fd);
    mp->fd = -1;
    mp->platform_attached = 0;

    if (outcome == MQVPN_ADD_PATH_PERMANENT_FAIL) {
        /* Saturate the per-slot counter — recover_dropped_paths_cb will
         * skip this slot until a fresh Level-2 reconnect resets the limit. */
        p->path_recover_failures[slot] = PATH_RECOVER_FAILURE_LIMIT;
        LOG_WRN("netlink: path %s recovery abandoned (xquic budget exhausted; "
                "reconnect required)",
                ifname);
        return;
    }

    /* Transient failure (most commonly -XQC_EMP_NO_AVAIL_PATH_ID during
     * WiFi reassoc CID-lag burst). Bump the consecutive-failure counter so
     * the 3s recovery timer eventually gives up and waits for reconnect. */
    p->path_recover_failures[slot]++;
    if (p->path_recover_failures[slot] >= PATH_RECOVER_FAILURE_LIMIT) {
        LOG_WRN("netlink: path %s recovery abandoned after %d consecutive "
                "failures (will resume on reconnect)",
                ifname, PATH_RECOVER_FAILURE_LIMIT);
    } else {
        LOG_WRN("netlink: re-add %s not activated, will retry (%d/%d)", ifname,
                p->path_recover_failures[slot], PATH_RECOVER_FAILURE_LIMIT);
    }
}

/* PR5: replace path_removed_by_platform[] polling with lib state query.
 * The slot is considered "ready for re-add" if its public status is
 * MQVPN_PATH_CLOSED — i.e., lib has fully cleaned up the previous incarnation
 * (CLOSED_FREE) OR is mid-cleanup (CLOSED_DROPPED with all xquic-side fields
 * drained). add_path_fd_with_outcome will refuse to reuse a non-CLOSED slot;
 * if cleanup hasn't completed we get TRANSIENT_FAIL and bail — next netlink
 * event will retry. */
static int
try_readd_removed_path(platform_ctx_t *p, const char *ifname)
{
    mqvpn_path_info_t pinfo[MQVPN_MAX_PATHS];
    int n = 0;
    if (mqvpn_client_get_paths(p->client, pinfo, MQVPN_MAX_PATHS, &n) != MQVPN_OK)
        return 0;

    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        if (strcmp(p->path_mgr.paths[i].iface, ifname) != 0) continue;
        if (p->path_recover_failures[i] >= PATH_RECOVER_FAILURE_LIMIT) continue;
        mqvpn_path_handle_t h = p->lib_path_handles[i];

        int found = 0;
        mqvpn_path_status_t st = MQVPN_PATH_PENDING;
        for (int j = 0; j < n; j++) {
            if (pinfo[j].handle == h) {
                found = 1;
                st = pinfo[j].status;
                break;
            }
        }
        /* Re-add candidate: slot exists in lib as CLOSED (DROPPED or FREE),
         * or slot was never tracked (handle invalid / removed before lib saw it). */
        if (found && st != MQVPN_PATH_CLOSED) continue;

        mqvpn_path_t *mp = &p->path_mgr.paths[i];
        int fd = recovery_socket_create(p->server_addr.ss_family, ifname, mp);
        if (fd < 0) return 0;

        mp->fd = fd;
        mp->platform_attached = 1;
        mp->xquic_path_live = 0;
        mp->path_id = 0;

        mqvpn_add_path_outcome_t outcome = MQVPN_ADD_PATH_OK;
        mqvpn_path_handle_t new_h =
            recovery_register_with_lib(p, i, fd, ifname, &outcome);
        if (new_h < 0) {
            close(fd);
            mp->fd = -1;
            mp->platform_attached = 0;
            return 0;
        }

        if (outcome != MQVPN_ADD_PATH_OK) {
            recovery_rollback(p, i, outcome);
            return 0;
        }

        /* Activation confirmed — register libevent so packets are read from
         * the new socket. */
        p->ev_udp[i] = event_new(p->eb, fd, EV_READ | EV_PERSIST, on_socket_read, p);
        event_add(p->ev_udp[i], NULL);

        p->path_recover_failures[i] = 0; /* success resets the budget */
        LOG_INF("netlink: path %s re-added (handle=%lld)", ifname, (long long)new_h);
        return 1;
    }
    return 0;
}

/* Periodically re-add platform slots whose library state is CLOSED but
 * whose interface is currently up. Fires every RECOVER_INTERVAL_SEC.
 *
 * Spec sec 3.4 "Stateless Platforms" compliance: this handler holds NO
 * lifecycle state — it queries the library via mqvpn_client_get_paths()
 * each tick (in try_readd_removed_path) and acts based on the public
 * MQVPN_PATH_CLOSED status. path_recover_failures[] is pure backpressure
 * to bound the busy-loop on transient xquic errors during a WiFi
 * reassoc CID-lag burst — not a state mirror.
 *
 * Why this timer is necessary: on carrier loss/restore the kernel emits
 * a single RTM_NEWLINK with IFF_RUNNING toggled — IP/admin state don't
 * change, so no RTM_NEWADDR follows. If the one-shot
 * try_readd_removed_path() driven by that single event fails
 * synchronously (e.g. xqc_conn_create_path returns
 * -XQC_EMP_NO_AVAIL_PATH_ID because the server hasn't replenished CIDs
 * yet, or the previous CLOSED_DROPPED slot hasn't drained xquic-side
 * fields), there is no further event to retry on. The library's
 * tick_drive_retry_timer only services CREATE_WAIT/DEGRADED, not
 * CLOSED_DROPPED — so a platform-side periodic poll is the only way
 * to recover.
 *
 * Pre-filters on link state + IP so we don't burn syscalls
 * (socket/bind/IP_BOUND_IF) when the interface is still down. */
static void
recover_dropped_paths_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;

    mqvpn_path_info_t pinfo[MQVPN_MAX_PATHS];
    int n = 0;
    if (mqvpn_client_get_paths(p->client, pinfo, MQVPN_MAX_PATHS, &n) != MQVPN_OK)
        goto rearm;

    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        if (p->path_recover_failures[i] >= PATH_RECOVER_FAILURE_LIMIT) continue;
        if (p->path_mgr.paths[i].platform_attached) continue; /* already live */

        mqvpn_path_handle_t h = p->lib_path_handles[i];
        int is_closed = 0;
        for (int j = 0; j < n; j++) {
            if (pinfo[j].handle == h) {
                is_closed = (pinfo[j].status == MQVPN_PATH_CLOSED);
                break;
            }
        }
        if (!is_closed) continue;

        const char *ifname = p->path_mgr.paths[i].iface;
        if (!iface_is_up_and_running(ifname)) continue;
        if (!iface_has_ip(ifname)) continue;

        /* try_readd_removed_path scans by ifname, finds this slot via
         * lib state, and either succeeds (resets the counter via line
         * above) or fails through recovery_rollback (which bumps the
         * counter). Multiple slots sharing one ifname are handled by
         * try_readd's internal loop. */
        if (try_readd_removed_path(p, ifname))
            LOG_INF("netlink: timer re-added path %s after carrier-up failure", ifname);
    }

rearm:
    if (p->ev_recover) {
        struct timeval tv = {.tv_sec = RECOVER_INTERVAL_SEC};
        event_add(p->ev_recover, &tv);
    }
}

/* RTM_NEWADDR: an interface gained an IP address.
 * Try re-add first because RTM_DELLINK invalidates the fd; only fall back
 * to reactivate if this slot wasn't fully dropped (fd still valid). */
static void
handle_rtm_newaddr(platform_ctx_t *p, struct nlmsghdr *nh)
{
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
    char ifname[IFNAMSIZ];
    if (!if_indextoname(ifa->ifa_index, ifname)) return;
    if (!try_readd_removed_path(p, ifname)) try_reactivate_by_ifname(p, ifname);
}

/* RTM_DELLINK: interface gone. remove_path_by_index() uses drop_path
 * semantics (not orderly close) so surviving paths aren't blocked by
 * xquic shutdown handshakes. */
static void
handle_rtm_dellink(platform_ctx_t *p, struct nlmsghdr *nh)
{
    const char *ifname = nlmsg_get_ifname(nh);
    if (!ifname) return;
    for (int i = 0; i < p->path_mgr.n_paths; i++) {
        if (strcmp(p->path_mgr.paths[i].iface, ifname) == 0)
            remove_path_by_index(p, i, "removed");
    }
}

/* Decide whether this RTM_NEWLINK is a carrier-loss event we should drop on.
 *
 * Gate on IFLA_OPERSTATE rather than !IFF_RUNNING. IFF_RUNNING also clears
 * during wifi association / dormant transitions, so an !IFF_RUNNING-based
 * gate would burn one path_id slot per wifi roam — defeating the very
 * XQC_MAX_PATHS_COUNT budget the drop is meant to preserve.
 *
 * Drop only on a definite operational-down report (RFC 2863): IF_OPER_DOWN
 * (link admin/peer down) or IF_OPER_LOWERLAYERDOWN (e.g. underlying ethernet
 * of a vlan/bridge went away). IF_OPER_DORMANT (wifi associating),
 * IF_OPER_UNKNOWN (driver doesn't report; common on virtual interfaces) and
 * IF_OPER_TESTING are tolerated — the carrier-up handler / recovery timer
 * will still re-add once IFF_RUNNING + has_ip become true. */
static int
is_carrier_loss(struct ifinfomsg *ifi, int operstate)
{
    return (ifi->ifi_flags & IFF_UP) &&
           (operstate == IF_OPER_DOWN || operstate == IF_OPER_LOWERLAYERDOWN);
}

/* RTM_NEWLINK: link state changed. Either drop on carrier loss, or attempt
 * recovery if the link is now usable. */
static void
handle_rtm_newlink(platform_ctx_t *p, struct nlmsghdr *nh)
{
    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nh);
    const char *ifname = nlmsg_get_ifname(nh);
    if (!ifname) return;

    if (is_carrier_loss(ifi, nlmsg_get_operstate(nh))) {
        for (int i = 0; i < p->path_mgr.n_paths; i++) {
            if (strcmp(p->path_mgr.paths[i].iface, ifname) == 0)
                remove_path_by_index(p, i, "carrier lost");
        }
        return;
    }

    if (!(ifi->ifi_flags & IFF_UP) || !(ifi->ifi_flags & IFF_RUNNING)) return;
    if (!iface_has_ip(ifname)) return;

    /* First: try to re-add paths removed by RTM_DELLINK (dead fd).
     * Otherwise: reactivate degraded/closed paths (fd still valid). */
    if (try_readd_removed_path(p, ifname)) return;
    try_reactivate_by_ifname(p, ifname);
}

static void
on_netlink_event(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    platform_ctx_t *p = (platform_ctx_t *)arg;
    char buf[NETLINK_BUF_SIZE];

    for (;;) {
        ssize_t len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (len <= 0) break;

        int nlen = (int)len;
        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, nlen);
             nh = NLMSG_NEXT(nh, nlen)) {
            switch (nh->nlmsg_type) {
            case RTM_NEWADDR: handle_rtm_newaddr(p, nh); break;
            case RTM_DELLINK: handle_rtm_dellink(p, nh); break;
            case RTM_NEWLINK: handle_rtm_newlink(p, nh); break;
            }
        }
    }
}

static int
setup_netlink(platform_ctx_t *p)
{
    p->nl_fd =
        socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (p->nl_fd < 0) {
        LOG_WRN("netlink socket failed: %s (path recovery via timer only)",
                strerror(errno));
        return -1;
    }

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
        .nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
    };
    if (bind(p->nl_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOG_WRN("netlink bind failed: %s (path recovery via timer only)",
                strerror(errno));
        close(p->nl_fd);
        p->nl_fd = -1;
        return -1;
    }

    p->ev_netlink = event_new(p->eb, p->nl_fd, EV_READ | EV_PERSIST, on_netlink_event, p);
    if (!p->ev_netlink) {
        LOG_WRN("netlink event_new failed (OOM?)");
        close(p->nl_fd);
        p->nl_fd = -1;
        return -1;
    }
    event_add(p->ev_netlink, NULL);
    LOG_INF("netlink path recovery accelerator active");
    return 0;
}

/* ================================================================
 *  Main entry point: linux_platform_run_client
 * ================================================================ */

int
linux_platform_run_client(const mqvpn_client_cfg_t *cfg)
{
    int rc = 1;
    platform_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.tun.fd = -1;
    ctx.nl_fd = -1;
    ctx.server_port = cfg->server_port;
    ctx.killswitch_enabled = cfg->kill_switch;
    ctx.manage_routes = cfg->manage_routes;

    /* Pre-set TUN name (save to tun_name_cfg too — survives TUN destroy/recreate) */
    if (cfg->tun_name) {
        snprintf(ctx.tun.name, sizeof(ctx.tun.name), "%s", cfg->tun_name);
        snprintf(ctx.tun_name_cfg, sizeof(ctx.tun_name_cfg), "%s", cfg->tun_name);
    } else {
        snprintf(ctx.tun_name_cfg, sizeof(ctx.tun_name_cfg), "mqvpn0");
    }

    /* DNS setup */
    mqvpn_dns_init(&ctx.dns);
    snprintf(ctx.dns.tun_name, sizeof(ctx.dns.tun_name), "%s", ctx.tun_name_cfg);
    for (int i = 0; i < cfg->n_dns; i++)
        mqvpn_dns_add_server(&ctx.dns, cfg->dns_servers[i]);

    /* Resolve server address */
    if (mqvpn_resolve_host(cfg->server_addr, &ctx.server_addr, &ctx.server_addrlen) < 0) {
        LOG_ERR("could not resolve server address: %s", cfg->server_addr);
        return 1;
    }
    mqvpn_sa_set_port(&ctx.server_addr, (uint16_t)cfg->server_port);

    /* Create libmqvpn config */
    mqvpn_config_t *lib_cfg = mqvpn_config_new();
    if (!lib_cfg) {
        LOG_ERR("failed to allocate config");
        return 1;
    }

    mqvpn_config_set_server(lib_cfg, cfg->server_addr, cfg->server_port);
    if (cfg->tls_server_name)
        mqvpn_config_set_tls_server_name(lib_cfg, cfg->tls_server_name);
    if (cfg->auth_key) mqvpn_config_set_auth_key(lib_cfg, cfg->auth_key);
    mqvpn_config_set_insecure(lib_cfg, cfg->insecure);
    mqvpn_config_set_multipath(lib_cfg, cfg->n_paths > 1 ? 1 : 0);
    mqvpn_config_set_reconnect(lib_cfg, cfg->reconnect,
                               cfg->reconnect_interval > 0 ? cfg->reconnect_interval : 5);
    mqvpn_config_set_killswitch_hint(lib_cfg, cfg->kill_switch);

    mqvpn_config_set_log_level(lib_cfg, (mqvpn_log_level_t)cfg->log_level);

    mqvpn_scheduler_t lib_sched;
    switch (cfg->scheduler) {
    case 1: lib_sched = MQVPN_SCHED_WLB; break;
    case 2: lib_sched = MQVPN_SCHED_BACKUP_FEC; break;
    case 3: lib_sched = MQVPN_SCHED_WLB_UDP_PIN; break;
    default: lib_sched = MQVPN_SCHED_MINRTT; break;
    }
    mqvpn_config_set_scheduler(lib_cfg, lib_sched);
    mqvpn_config_set_cc(lib_cfg, (mqvpn_cc_t)cfg->cc);
    mqvpn_config_set_init_max_path_id(lib_cfg, cfg->init_max_path_id);
    mqvpn_config_set_tun_mtu(lib_cfg, cfg->tun_mtu);
    mqvpn_config_apply_reorder(lib_cfg,
                               &cfg->reorder); /* INI [Reorder]/[ReorderRule] bridge */
    mqvpn_config_apply_hybrid(lib_cfg, &cfg->hybrid); /* INI [Hybrid] bridge */

    /* Create callbacks */
    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output = cb_tun_output;
    cbs.tunnel_config_ready = cb_tunnel_config_ready;
    cbs.send_packet = NULL; /* fd-only mode */
    cbs.tunnel_closed = cb_tunnel_closed;
    cbs.ready_for_tun = cb_ready_for_tun;
    cbs.state_changed = cb_state_changed;
    cbs.path_event = cb_path_event;
    cbs.mtu_updated = cb_mtu_updated;
    cbs.log = cb_log;
    cbs.reconnect_scheduled = cb_reconnect_scheduled;

    /* Create client */
    ctx.client = mqvpn_client_new(lib_cfg, &cbs, &ctx);
    mqvpn_config_free(lib_cfg);
    if (!ctx.client) {
        LOG_ERR("failed to create mqvpn client");
        return 1;
    }

    /* Set server address on client */
    mqvpn_client_set_server_addr(ctx.client, (struct sockaddr *)&ctx.server_addr,
                                 ctx.server_addrlen);

    /* Create event base */
    ctx.eb = event_base_new();
    if (!ctx.eb) {
        LOG_ERR("event_base_new failed");
        goto cleanup;
    }

    /* Create UDP sockets */
    mqvpn_path_mgr_init(&ctx.path_mgr);
    if (cfg->n_paths > 0) {
        for (int i = 0; i < cfg->n_paths; i++) {
            if (mqvpn_path_mgr_add(&ctx.path_mgr, cfg->path_ifaces[i], &ctx.server_addr) <
                0) {
                LOG_ERR("failed to create UDP socket for path[%d] '%s'", i,
                        cfg->path_ifaces[i]);
                goto cleanup;
            }
        }
    } else {
        if (mqvpn_path_mgr_add(&ctx.path_mgr, NULL, &ctx.server_addr) < 0) {
            LOG_ERR("failed to create UDP socket");
            goto cleanup;
        }
    }

    /* Register paths with library and create socket events */
    for (int i = 0; i < ctx.path_mgr.n_paths; i++) {
        mqvpn_path_t *mp = &ctx.path_mgr.paths[i];

        if (mp->iface[0]) {
            if (linux_pin_socket_to_iface(mp->fd, mp->iface) < 0) {
                LOG_ERR("path[%d] iface pin failed for '%s'; --path values must "
                        "be valid interface names (see `ip link`)",
                        i, mp->iface);
                goto cleanup;
            }
        }

        mqvpn_path_desc_t desc = {0};
        desc.struct_size = sizeof(desc);
        desc.fd = mp->fd;
        snprintf(desc.iface, sizeof(desc.iface), "%s", mp->iface);
        if (mp->local_addrlen > 0 && mp->local_addrlen <= sizeof(desc.local_addr)) {
            memcpy(desc.local_addr, &mp->local_addr, mp->local_addrlen);
            desc.local_addr_len = mp->local_addrlen;
        }

        ctx.lib_path_handles[i] = mqvpn_client_add_path_fd(ctx.client, mp->fd, &desc);
        if (ctx.lib_path_handles[i] < 0) {
            LOG_ERR("failed to register path %d with library", i);
            goto cleanup;
        }

        ctx.ev_udp[i] =
            event_new(ctx.eb, mp->fd, EV_READ | EV_PERSIST, on_socket_read, &ctx);
        event_add(ctx.ev_udp[i], NULL);
    }

    /* Netlink path recovery accelerator (non-fatal if fails) */
    setup_netlink(&ctx);

    /* Signal handlers */
    ctx.ev_sigint = evsignal_new(ctx.eb, SIGINT, on_signal, &ctx);
    ctx.ev_sigterm = evsignal_new(ctx.eb, SIGTERM, on_signal, &ctx);
    event_add(ctx.ev_sigint, NULL);
    event_add(ctx.ev_sigterm, NULL);

    /* Tick timer */
    ctx.ev_tick = event_new(ctx.eb, -1, 0, on_tick_timer, &ctx);

    /* Connect */
    if (mqvpn_client_connect(ctx.client) != MQVPN_OK) {
        LOG_ERR("client connect failed");
        goto cleanup;
    }

    /* Schedule initial tick */
    schedule_next_tick(&ctx);

    LOG_INF("entering event loop...");
    event_base_dispatch(ctx.eb);
    rc = 0;

cleanup:
    /* Clean up platform resources */
    cleanup_killswitch(&ctx);
    if (ctx.manage_routes) cleanup_routes(&ctx);
    mqvpn_dns_restore(&ctx.dns);

    if (ctx.tun_up) {
        if (ctx.ev_tun) {
            event_del(ctx.ev_tun);
            event_free(ctx.ev_tun);
        }
        mqvpn_tun_destroy(&ctx.tun);
    }

    for (int i = 0; i < ctx.path_mgr.n_paths; i++) {
        if (ctx.ev_udp[i]) {
            event_del(ctx.ev_udp[i]);
            event_free(ctx.ev_udp[i]);
        }
    }

    if (ctx.ev_netlink) {
        event_del(ctx.ev_netlink);
        event_free(ctx.ev_netlink);
    }
    if (ctx.nl_fd >= 0) close(ctx.nl_fd);

    if (ctx.ev_tick) {
        event_del(ctx.ev_tick);
        event_free(ctx.ev_tick);
    }
    if (ctx.ev_sigint) {
        event_del(ctx.ev_sigint);
        event_free(ctx.ev_sigint);
    }
    if (ctx.ev_sigterm) {
        event_del(ctx.ev_sigterm);
        event_free(ctx.ev_sigterm);
    }
    if (ctx.ev_status) {
        event_del(ctx.ev_status);
        event_free(ctx.ev_status);
    }
    if (ctx.ev_recover) {
        event_del(ctx.ev_recover);
        event_free(ctx.ev_recover);
    }

    mqvpn_path_mgr_destroy(&ctx.path_mgr);
    mqvpn_client_destroy(ctx.client);

    if (ctx.eb) event_base_free(ctx.eb);

    return rc;
}

/* ================================================================
 *  Server platform layer
 * ================================================================ */

/* Registry entry tracking readiness interest for one egress TCP fd that
 * the core (src/hybrid/tcp_egress.c) opened and manages itself — the
 * platform only maps the fd to the libevent event multiplexing it.
 * libevent events aren't individually mutable, so a want_read/want_write
 * change means tearing down and recreating the event (see
 * platform_egress_fd_register()). */
typedef struct {
    int fd; /* -1 = empty slot */
    struct event *ev;
    void *fd_ctx;
    struct server_platform_ctx_s *sp; /* backpointer for the event callback */
} egress_fd_slot_t;

typedef struct server_platform_ctx_s {
    mqvpn_server_t *server;
    struct event_base *eb;
    struct event *ev_tick;
    struct event *ev_tun;
    struct event *ev_socket;
    struct event *ev_sigint;
    struct event *ev_sigterm;
    mqvpn_tun_t tun;
    int tun_up;
    int udp_fd;
    int shutting_down;
    ctrl_socket_t *ctrl;

    /* Egress fd registry (hybrid TCP lane, D1). Sized once at server start
     * from mqvpn_server_egress_fd_budget() so the platform's registry and
     * the core's own fd cap can never drift apart. */
    egress_fd_slot_t *egress_fds;
    int n_egress_fds;
} server_platform_ctx_t;

static void svr_on_tick(evutil_socket_t fd, short what, void *arg);
static void svr_on_tun_read(evutil_socket_t fd, short what, void *arg);

static void
svr_schedule_next_tick(server_platform_ctx_t *sp)
{
    mqvpn_interest_t interest;
    mqvpn_server_get_interest(sp->server, &interest);

    int ms = interest.next_timer_ms;
    struct timeval tv = {
        .tv_sec = ms / 1000,
        .tv_usec = (ms % 1000) * 1000,
    };
    event_add(sp->ev_tick, &tv);

    /* Enable/disable TUN read based on interest */
    if (sp->tun_up && sp->tun.fd >= 0 && sp->ev_tun) {
        if (interest.tun_readable && !event_pending(sp->ev_tun, EV_READ, NULL))
            event_add(sp->ev_tun, NULL);
        else if (!interest.tun_readable && event_pending(sp->ev_tun, EV_READ, NULL))
            event_del(sp->ev_tun);
    }
}

static void
svr_on_tick(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    server_platform_ctx_t *sp = (server_platform_ctx_t *)arg;
    mqvpn_server_tick(sp->server);
    svr_schedule_next_tick(sp);
}

static void
svr_cb_tun_output(const uint8_t *pkt, size_t len, void *user_ctx)
{
    server_platform_ctx_t *sp = (server_platform_ctx_t *)user_ctx;
    if (sp->tun_up && sp->tun.fd >= 0) mqvpn_tun_write(&sp->tun, pkt, len);
}

static void
svr_cb_tunnel_config_ready(const mqvpn_tunnel_info_t *info, void *user_ctx)
{
    server_platform_ctx_t *sp = (server_platform_ctx_t *)user_ctx;

    /* Create TUN device */
    const char *tun_name = sp->tun.name[0] ? sp->tun.name : "mqvpn0";
    if (mqvpn_tun_create(&sp->tun, tun_name) < 0) {
        LOG_ERR("TUN create failed");
        return;
    }

    /* Set IPv4 address — server gets assigned_ip (the .1 address) */
    char srv_ip[INET_ADDRSTRLEN], base_ip[INET_ADDRSTRLEN];
    snprintf(srv_ip, sizeof(srv_ip), "%d.%d.%d.%d", info->assigned_ip[0],
             info->assigned_ip[1], info->assigned_ip[2], info->assigned_ip[3]);
    snprintf(base_ip, sizeof(base_ip), "%d.%d.%d.%d", info->server_ip[0],
             info->server_ip[1], info->server_ip[2], info->server_ip[3]);

    if (mqvpn_tun_set_addr(&sp->tun, srv_ip, base_ip, info->assigned_prefix) < 0) return;
    if (mqvpn_tun_set_mtu(&sp->tun, info->mtu) < 0) return;
    if (mqvpn_tun_up(&sp->tun) < 0) return;

    /* IPv6 if available */
    if (info->has_v6) {
        char v6str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, info->assigned_ip6, v6str, sizeof(v6str));
        if (mqvpn_tun_set_addr6(&sp->tun, v6str, info->assigned_prefix6) < 0)
            LOG_WRN("failed to set IPv6 on TUN (continuing IPv4-only)");
    }

    LOG_INF("TUN %s configured: %s (mtu=%d)", sp->tun.name, srv_ip, info->mtu);

    /* Register TUN read event */
    sp->ev_tun = event_new(sp->eb, sp->tun.fd, EV_READ | EV_PERSIST, svr_on_tun_read, sp);
    if (sp->ev_tun) {
        event_add(sp->ev_tun, NULL);
        sp->tun_up = 1;
    }
}

static void
svr_cb_log(mqvpn_log_level_t level, const char *msg, void *user_ctx)
{
    (void)user_ctx;
    switch (level) {
    case MQVPN_LOG_DEBUG: LOG_DBG("[svr] %s", msg); break;
    case MQVPN_LOG_INFO: LOG_INF("[svr] %s", msg); break;
    case MQVPN_LOG_WARN: LOG_WRN("[svr] %s", msg); break;
    case MQVPN_LOG_ERROR: LOG_ERR("[svr] %s", msg); break;
    }
}

static void
svr_on_tun_read(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    server_platform_ctx_t *sp = (server_platform_ctx_t *)arg;
    uint8_t buf[TUN_BUF_SIZE];

    for (int i = 0; i < BULK_READ_COUNT; i++) {
        int n = mqvpn_tun_read(&sp->tun, buf, sizeof(buf));
        if (n <= 0) break;

        int ret = mqvpn_server_on_tun_packet(sp->server, buf, (size_t)n);
        if (ret == MQVPN_ERR_AGAIN) {
            /* Backpressure — stop reading TUN */
            event_del(sp->ev_tun);
            break;
        }
    }
    mqvpn_server_tick(sp->server);
    svr_schedule_next_tick(sp);
}

static void
svr_on_socket_read(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    server_platform_ctx_t *sp = (server_platform_ctx_t *)arg;
    uint8_t buf[SOCK_BUF_SIZE];
    struct sockaddr_in6 peer;
    socklen_t peer_len;

    for (int i = 0; i < BULK_READ_COUNT; i++) {
        peer_len = sizeof(peer);
        // codeql[cpp/uncontrolled-allocation-size] buf is stack-allocated and bounded by
        // sizeof(buf); xquic validates internally
        ssize_t n =
            recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peer_len);
        if (n <= 0 || (size_t)n > sizeof(buf)) break;

        mqvpn_server_on_socket_recv(sp->server, buf, (size_t)n, (struct sockaddr *)&peer,
                                    peer_len);
    }
    mqvpn_server_tick(sp->server);
    svr_schedule_next_tick(sp);
}

/* ─── Egress fd registry (hybrid TCP lane, D1) ───
 *
 * The core (src/hybrid/tcp_egress.c) owns every egress fd's socket()/
 * connect()/send()/recv()/close() syscalls directly; these callbacks only
 * (un)register the platform's interest in an already-open fd. Linear scan
 * is fine — register/unregister fire on state-change, not per-packet. */

static egress_fd_slot_t *
find_egress_slot(server_platform_ctx_t *sp, int fd)
{
    for (int i = 0; i < sp->n_egress_fds; i++) {
        if (sp->egress_fds[i].fd == fd) return &sp->egress_fds[i];
    }
    return NULL;
}

static egress_fd_slot_t *
find_or_alloc_egress_slot(server_platform_ctx_t *sp, int fd)
{
    egress_fd_slot_t *existing = find_egress_slot(sp, fd);
    if (existing) return existing;

    for (int i = 0; i < sp->n_egress_fds; i++) {
        if (sp->egress_fds[i].fd == -1) return &sp->egress_fds[i];
    }
    return NULL;
}

static void
on_egress_fd_event(evutil_socket_t fd, short what, void *arg)
{
    egress_fd_slot_t *slot = (egress_fd_slot_t *)arg;
    server_platform_ctx_t *sp = slot->sp;
    mqvpn_server_on_egress_fd_ready(sp->server, (int)fd, slot->fd_ctx,
                                    (what & EV_READ) != 0, (what & EV_WRITE) != 0);
    mqvpn_server_tick(sp->server);
    svr_schedule_next_tick(sp);
}

static void
platform_egress_fd_register(int fd, int want_read, int want_write, void *fd_ctx,
                            void *user_ctx)
{
    server_platform_ctx_t *sp = (server_platform_ctx_t *)user_ctx;
    egress_fd_slot_t *slot = find_or_alloc_egress_slot(sp, fd);
    if (!slot) {
        LOG_WRN("egress fd registry full, fd=%d not polled", fd);
        return;
    }

    /* Re-register: tear down the old event with stale want_read/want_write
     * flags first — libevent events aren't individually mutable. */
    if (slot->ev) {
        event_del(slot->ev);
        event_free(slot->ev);
        slot->ev = NULL;
    }

    short flags = EV_PERSIST | (want_read ? EV_READ : 0) | (want_write ? EV_WRITE : 0);
    slot->fd = fd;
    slot->fd_ctx = fd_ctx;
    slot->sp = sp;
    slot->ev = event_new(sp->eb, fd, flags, on_egress_fd_event, slot);
    if (!slot->ev) {
        LOG_WRN("event_new failed for egress fd=%d", fd);
        slot->fd = -1;
        slot->fd_ctx = NULL;
        return;
    }
    if (event_add(slot->ev, NULL) < 0) {
        LOG_WRN("event_add failed for egress fd=%d", fd);
        event_free(slot->ev);
        slot->ev = NULL;
        slot->fd = -1;
        slot->fd_ctx = NULL;
    }
}

static void
platform_egress_fd_unregister(int fd, void *user_ctx)
{
    server_platform_ctx_t *sp = (server_platform_ctx_t *)user_ctx;
    egress_fd_slot_t *slot = find_egress_slot(sp, fd);
    if (!slot) return;

    if (slot->ev) {
        event_del(slot->ev);
        event_free(slot->ev);
    }
    slot->ev = NULL;
    slot->fd = -1;
    slot->fd_ctx = NULL;
}

static void
svr_on_signal(evutil_socket_t sig, short what, void *arg)
{
    (void)sig;
    (void)what;
    server_platform_ctx_t *sp = (server_platform_ctx_t *)arg;
    LOG_INF("received signal, shutting down server...");
    sp->shutting_down = 1;
    event_base_loopbreak(sp->eb);
}

static int
svr_create_udp_socket(const char *addr, int port, struct sockaddr_storage *out_addr,
                      socklen_t *out_addrlen)
{
    sa_family_t af = AF_INET;
    struct in_addr addr4;
    struct in6_addr addr6;
    if (addr && addr[0]) {
        if (inet_pton(AF_INET6, addr, &addr6) == 1)
            af = AF_INET6;
        else if (inet_pton(AF_INET, addr, &addr4) == 1)
            af = AF_INET;
        else {
            LOG_ERR("invalid listen address: %s", addr);
            return -1;
        }
    }

    int fd = socket(af, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_ERR("socket: %s", strerror(errno));
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_ERR("fcntl: %s", strerror(errno));
        close(fd);
        return -1;
    }

    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    int bufsize = 1 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    memset(out_addr, 0, sizeof(*out_addr));
    if (af == AF_INET6) {
        int v6only = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out_addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)port);
        if (addr && addr[0])
            sin6->sin6_addr = addr6;
        else
            sin6->sin6_addr = in6addr_any;
        *out_addrlen = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)out_addr;
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)port);
        if (addr && addr[0])
            sin->sin_addr = addr4;
        else
            sin->sin_addr.s_addr = htonl(INADDR_ANY);
        *out_addrlen = sizeof(struct sockaddr_in);
    }

    if (bind(fd, (struct sockaddr *)out_addr, *out_addrlen) < 0) {
        LOG_ERR("bind %s:%d: %s", addr ? addr : (af == AF_INET6 ? "::" : "0.0.0.0"), port,
                strerror(errno));
        close(fd);
        return -1;
    }

    LOG_INF("UDP socket bound to %s:%d",
            addr ? addr : (af == AF_INET6 ? "::" : "0.0.0.0"), port);
    return fd;
}

int
linux_platform_run_server(const mqvpn_server_cfg_t *cfg)
{
    int rc = 1;
    server_platform_ctx_t sp;
    memset(&sp, 0, sizeof(sp));
    sp.tun.fd = -1;
    sp.udp_fd = -1;

    if (cfg->tun_name) snprintf(sp.tun.name, sizeof(sp.tun.name), "%s", cfg->tun_name);

    /* Create libmqvpn config */
    mqvpn_config_t *lib_cfg = mqvpn_config_new();
    if (!lib_cfg) {
        LOG_ERR("failed to allocate config");
        return 1;
    }

    mqvpn_config_set_listen(lib_cfg, cfg->listen_addr, cfg->listen_port);
    mqvpn_config_set_subnet(lib_cfg, cfg->subnet);
    if (cfg->subnet6) mqvpn_config_set_subnet6(lib_cfg, cfg->subnet6);
    if (cfg->cert_file && cfg->key_file)
        mqvpn_config_set_tls_cert(lib_cfg, cfg->cert_file, cfg->key_file);
    if (cfg->auth_key) mqvpn_config_set_auth_key(lib_cfg, cfg->auth_key);
    for (int i = 0; i < cfg->n_users; i++) {
        if (cfg->user_names[i] && cfg->user_keys[i]) {
            mqvpn_config_add_user(lib_cfg, cfg->user_names[i], cfg->user_keys[i]);
        }
    }
    mqvpn_config_set_max_clients(lib_cfg, cfg->max_clients);
    mqvpn_scheduler_t lib_sched;
    switch (cfg->scheduler) {
    case 1: lib_sched = MQVPN_SCHED_WLB; break;
    case 2: lib_sched = MQVPN_SCHED_BACKUP_FEC; break;
    case 3: lib_sched = MQVPN_SCHED_WLB_UDP_PIN; break;
    default: lib_sched = MQVPN_SCHED_MINRTT; break;
    }
    mqvpn_config_set_scheduler(lib_cfg, lib_sched);
    mqvpn_config_set_cc(lib_cfg, (mqvpn_cc_t)cfg->cc);
    mqvpn_config_set_init_max_path_id(lib_cfg, cfg->init_max_path_id);
    mqvpn_config_set_tun_mtu(lib_cfg, cfg->tun_mtu);
    mqvpn_config_apply_reorder(lib_cfg,
                               &cfg->reorder); /* INI [Reorder]/[ReorderRule] bridge */
    mqvpn_config_apply_hybrid(lib_cfg, &cfg->hybrid); /* INI [Hybrid] bridge */

    mqvpn_config_set_log_level(lib_cfg, (mqvpn_log_level_t)cfg->log_level);

    /* Create server callbacks */
    mqvpn_server_callbacks_t cbs = MQVPN_SERVER_CALLBACKS_INIT;
    cbs.tun_output = svr_cb_tun_output;
    cbs.tunnel_config_ready = svr_cb_tunnel_config_ready;
    cbs.send_packet = NULL; /* fd-only mode */
    cbs.log = svr_cb_log;
    cbs.egress_fd_register = platform_egress_fd_register;
    cbs.egress_fd_unregister = platform_egress_fd_unregister;

    /* Create server */
    sp.server = mqvpn_server_new(lib_cfg, &cbs, &sp);
    mqvpn_config_free(lib_cfg);
    if (!sp.server) {
        LOG_ERR("failed to create mqvpn server");
        return 1;
    }

    /* Egress fd registry (hybrid TCP lane, D1). Sized from the same budget
     * tcp_egress.c will itself enforce, so the two caps cannot drift. */
    sp.n_egress_fds = mqvpn_server_egress_fd_budget(sp.server);
    if (sp.n_egress_fds > 0) {
        sp.egress_fds = calloc((size_t)sp.n_egress_fds, sizeof(*sp.egress_fds));
        if (!sp.egress_fds) {
            LOG_ERR("failed to allocate egress fd registry");
            goto cleanup;
        }
        for (int i = 0; i < sp.n_egress_fds; i++)
            sp.egress_fds[i].fd = -1;
    } else {
        sp.n_egress_fds = 0;
    }

    /* Create UDP socket */
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    sp.udp_fd = svr_create_udp_socket(cfg->listen_addr, cfg->listen_port, &local_addr,
                                      &local_addrlen);
    if (sp.udp_fd < 0) goto cleanup;

    mqvpn_server_set_socket_fd(sp.server, sp.udp_fd, (struct sockaddr *)&local_addr,
                               local_addrlen);

    /* Create event base */
    sp.eb = event_base_new();
    if (!sp.eb) {
        LOG_ERR("event_base_new failed");
        goto cleanup;
    }

    /* Start server (triggers tunnel_config_ready → TUN creation) */
    if (mqvpn_server_start(sp.server) != MQVPN_OK) {
        LOG_ERR("server start failed");
        goto cleanup;
    }

    /* Register socket read event */
    sp.ev_socket =
        event_new(sp.eb, sp.udp_fd, EV_READ | EV_PERSIST, svr_on_socket_read, &sp);
    event_add(sp.ev_socket, NULL);

    /* Signal handlers */
    sp.ev_sigint = evsignal_new(sp.eb, SIGINT, svr_on_signal, &sp);
    sp.ev_sigterm = evsignal_new(sp.eb, SIGTERM, svr_on_signal, &sp);
    event_add(sp.ev_sigint, NULL);
    event_add(sp.ev_sigterm, NULL);

    /* Tick timer */
    sp.ev_tick = event_new(sp.eb, -1, 0, svr_on_tick, &sp);
    svr_schedule_next_tick(&sp);

    /* Control API (optional) */
    if (cfg->control_port > 0) {
        sp.ctrl =
            ctrl_socket_create(sp.eb, cfg->control_addr, cfg->control_port, sp.server);
        if (!sp.ctrl) LOG_WRN("control API setup failed — continuing without it");
    }

    LOG_INF("mqvpn server ready — listening on %s:%d, subnet %s",
            cfg->listen_addr ? cfg->listen_addr : "0.0.0.0", cfg->listen_port,
            cfg->subnet);

    event_base_dispatch(sp.eb);
    rc = 0;

cleanup:
    LOG_INF("server shutting down");
    ctrl_socket_destroy(sp.ctrl);
    if (sp.tun_up) {
        if (sp.ev_tun) {
            event_del(sp.ev_tun);
            event_free(sp.ev_tun);
        }
        mqvpn_tun_destroy(&sp.tun);
    }
    if (sp.ev_socket) {
        event_del(sp.ev_socket);
        event_free(sp.ev_socket);
    }
    if (sp.ev_tick) {
        event_del(sp.ev_tick);
        event_free(sp.ev_tick);
    }
    if (sp.ev_sigint) {
        event_del(sp.ev_sigint);
        event_free(sp.ev_sigint);
    }
    if (sp.ev_sigterm) {
        event_del(sp.ev_sigterm);
        event_free(sp.ev_sigterm);
    }
    if (sp.udp_fd >= 0) close(sp.udp_fd);
    mqvpn_server_destroy(sp.server);
    /* After server destroy: teardown may call egress_fd_unregister for any
     * still-open egress fds, which scans this registry — free it only once
     * the server is gone (but before the event base the events belong to). */
    if (sp.egress_fds) {
        for (int i = 0; i < sp.n_egress_fds; i++) {
            if (sp.egress_fds[i].ev) {
                event_del(sp.egress_fds[i].ev);
                event_free(sp.egress_fds[i].ev);
            }
        }
        free(sp.egress_fds);
        sp.egress_fds = NULL;
        sp.n_egress_fds = 0;
    }
    if (sp.eb) event_base_free(sp.eb);

    return rc;
}
