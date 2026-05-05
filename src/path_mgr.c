#include "path_mgr.h"
#include "log.h"
#include "compat/socket_compat.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#ifndef _WIN32
#  include <arpa/inet.h> /* htonl */
#endif

void
mqvpn_path_mgr_init(mqvpn_path_mgr_t *mgr)
{
    memset(mgr, 0, sizeof(*mgr));
    for (int i = 0; i < MQVPN_MAX_PATHS; i++) {
        mgr->paths[i].fd = -1;
    }
}

int
mqvpn_path_mgr_add(mqvpn_path_mgr_t *mgr, const char *iface,
                   const struct sockaddr_storage *peer_addr)
{
    if (mgr->n_paths >= MQVPN_MAX_PATHS) {
        LOG_ERR("path_mgr: max paths (%d) reached", MQVPN_MAX_PATHS);
        return -1;
    }

    int idx = mgr->n_paths;
    mqvpn_path_t *p = &mgr->paths[idx];
    int af = peer_addr->ss_family;

    int fd = (int)socket(af, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_ERR("path_mgr: socket: %s", mqvpn_socket_strerror());
        return -1;
    }

    if (mqvpn_socket_set_nonblock(fd) < 0) {
        LOG_ERR("path_mgr: set_nonblock: %s", mqvpn_socket_strerror());
        mqvpn_socket_close(fd);
        return -1;
    }

    int bufsize = 1 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&bufsize, sizeof(bufsize));
#ifdef _WIN32
    {
        int actual_snd = 0, actual_rcv = 0;
        int optlen = sizeof(actual_snd);
        getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&actual_snd, &optlen);
        getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&actual_rcv, &optlen);
        LOG_INF("path_mgr: UDP socket buffers: SO_SNDBUF=%d SO_RCVBUF=%d", actual_snd,
                actual_rcv);
    }
#endif

    /* Store iface label only. Pinning egress to the named interface is
     * the platform layer's responsibility (linux_pin_socket_to_iface /
     * win_pin_socket_to_iface), called after this returns. */
    if (iface && iface[0]) {
        snprintf(p->iface, sizeof(p->iface), "%s", iface);
    }

    /* Bind to any local address (ephemeral port) */
    memset(&p->local_addr, 0, sizeof(p->local_addr));
    if (af == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&p->local_addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = in6addr_any;
        p->local_addrlen = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)&p->local_addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(INADDR_ANY);
        p->local_addrlen = sizeof(struct sockaddr_in);
    }

    if (bind(fd, (struct sockaddr *)&p->local_addr, p->local_addrlen) < 0) {
        LOG_ERR("path_mgr: bind(%s): %s", iface ? iface : "any", mqvpn_socket_strerror());
        mqvpn_socket_close(fd);
        return -1;
    }

    p->fd = fd;
    p->active = 1;
    p->in_use = 0;
    p->path_id = 0;

    mgr->n_paths++;
    LOG_INF("path_mgr: path[%d] created on %s (fd=%d)", idx, iface ? iface : "(any)", fd);
    return idx;
}

mqvpn_path_t *
mqvpn_path_mgr_find_by_fd(mqvpn_path_mgr_t *mgr, int fd)
{
    for (int i = 0; i < mgr->n_paths; i++) {
        if (mgr->paths[i].fd == fd) return &mgr->paths[i];
    }
    return NULL;
}

mqvpn_path_t *
mqvpn_path_mgr_find_by_path_id(mqvpn_path_mgr_t *mgr, uint64_t path_id)
{
    for (int i = 0; i < mgr->n_paths; i++) {
        if (mgr->paths[i].in_use && mgr->paths[i].path_id == path_id)
            return &mgr->paths[i];
    }
    return NULL;
}

int
mqvpn_path_mgr_get_fd(mqvpn_path_mgr_t *mgr, uint64_t path_id)
{
    mqvpn_path_t *p = mqvpn_path_mgr_find_by_path_id(mgr, path_id);
    if (p) return p->fd;
    /* Fallback to primary (path 0) */
    if (mgr->n_paths > 0) {
        LOG_WRN("path_mgr: path_id=%" PRIu64 " not found, falling back to path 0",
                path_id);
        return mgr->paths[0].fd;
    }
    return -1;
}

void
mqvpn_path_mgr_destroy(mqvpn_path_mgr_t *mgr)
{
    for (int i = 0; i < mgr->n_paths; i++) {
        mqvpn_socket_close(mgr->paths[i].fd);
        mgr->paths[i].fd = -1;
    }
    mgr->n_paths = 0;
}
