// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * platform_darwin.c — Darwin (macOS) platform layer for libmqvpn
 *
 * Bridges libmqvpn (sans-I/O) with Darwin-specific I/O:
 *   - libevent event loop driving tick()
 *   - utun device creation and I/O (tun_utun.c)
 *   - UDP socket creation via path_mgr
 *   - Signal handling (SIGINT/SIGTERM)
 *
 * Structurally cloned from platform_linux.c's client run loop. Routing,
 * killswitch, DNS and the control socket are not yet ported for Darwin
 * (foundation slice) — the calls below are kept as-is; they resolve once
 * those files land in a later change.
 */

#ifdef __APPLE__

#  include "platform_internal.h"
#  include "route_mon.h"
#  include "vpn_client.h"
#  include "log.h"
#  include "mqvpn_internal.h" /* mqvpn_config_apply_reorder (INI reorder bridge) */

#  include <stdio.h>
#  include <inttypes.h>
#  include <stdlib.h>
#  include <string.h>
#  include <unistd.h>
#  include <errno.h>
#  include <signal.h>
#  include <fcntl.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <net/if.h>

#  define STATUS_INTERVAL_SEC 30
#  define BULK_READ_COUNT     64
#  define TUN_BUF_SIZE        65536
#  define SOCK_BUF_SIZE       65536
static void status_log_cb(evutil_socket_t fd, short what, void *arg);

/* ================================================================
 *  Socket pinning to a specific egress interface
 * ================================================================ */

/* Pin an outgoing UDP socket to the given interface via IP_BOUND_IF /
 * IPV6_BOUND_IF. Symmetric to linux_pin_socket_to_iface() in
 * platform_linux.c / win_pin_socket_to_iface() in platform_windows.c.
 * Returns 0 on success, -1 on failure. The caller decides whether
 * failure is fatal. */
int
darwin_pin_socket_to_iface(int fd, const char *ifname, sa_family_t af)
{
    unsigned int idx = if_nametoindex(ifname);
    if (!idx) {
        LOG_WRN("if_nametoindex('%s'): %s", ifname, strerror(errno));
        return -1;
    }

    int opt = (af == AF_INET6) ? IPV6_BOUND_IF : IP_BOUND_IF;
    int lvl = (af == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IP;
    if (setsockopt(fd, lvl, opt, &idx, sizeof(idx)) < 0) {
        LOG_WRN("setsockopt(%s, '%s'): %s",
                (af == AF_INET6) ? "IPV6_BOUND_IF" : "IP_BOUND_IF", ifname,
                strerror(errno));
        return -1;
    }
    return 0;
}

/* ================================================================
 *  libmqvpn callbacks
 * ================================================================ */

/* Forward declarations for event handlers */
static void on_tun_read(evutil_socket_t fd, short what, void *arg);
void on_socket_read(evutil_socket_t fd, short what, void *arg);

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

    /* Darwin deviation: utun auto-allocation can hand back a name that
     * differs from what was requested (tun_name_cfg), discovered only now
     * by mqvpn_tun_create(). dns.tun_name was seeded from the requested
     * name at start-up, before the real name was knowable — reseed it here
     * from the kernel-discovered p->tun.name, before any of the DNS/route/
     * killswitch setup below runs. (Audited: routing.c/killswitch.c key off
     * p->tun.name directly at call time, not a pre-snapshot, so they need
     * no equivalent reseed once ported.) */
    snprintf(p->dns.tun_name, sizeof(p->dns.tun_name), "%s", p->tun.name);

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

    /* Start periodic dropped-path re-add timer. Carrier-up route events
     * fire only once and `try_readd_removed_path()` can fail synchronously
     * (e.g. xqc_conn_create_path returning -XQC_EMP_NO_AVAIL_PATH_ID before
     * the server has distributed enough CIDs). Without this timer the slot
     * would sit in CLOSED_DROPPED indefinitely — no further route event
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
            "/%" PRIu64 " tcp_dropped=%" PRIu64 " flows act/tot/rej=%" PRIu64 "/%" PRIu64
            "/%" PRIu64 " raw_markers=%" PRIu64,
            n_paths, stats.bytes_tx, stats.bytes_rx, stats.srtt_ms, stats.dgram_lost,
            stats.pkts_lane_tcp, stats.pkts_lane_dgram, stats.pkts_lane_raw,
            stats.pkts_lane_tcp_dropped, stats.tcp_flows_active, stats.tcp_flows_total,
            stats.tcp_flows_rejected, stats.raw_markers_active);

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

void
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

void
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
 *  Main entry point: darwin_platform_run_client
 * ================================================================ */

int
darwin_platform_run_client(const mqvpn_client_cfg_t *cfg)
{
    int rc = 1;
    platform_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.tun.fd = -1;
    ctx.rt_fd = -1; /* 0 is a valid fd — close(rt_fd) on a zero-init'd ctx
                     * would close stdin if this stayed 0 */
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
            sa_family_t af = (sa_family_t)ctx.server_addr.ss_family;
            if (darwin_pin_socket_to_iface(mp->fd, mp->iface, af) < 0) {
                LOG_ERR("path[%d] iface pin failed for '%s'; --path values must "
                        "be valid interface names (see `ifconfig`)",
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

    /* PF_ROUTE path recovery accelerator (non-fatal if fails) */
    setup_route_socket(&ctx);

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

    if (ctx.ev_route) {
        event_del(ctx.ev_route);
        event_free(ctx.ev_route);
    }
    if (ctx.rt_fd >= 0) close(ctx.rt_fd);

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

#endif /* __APPLE__ */
