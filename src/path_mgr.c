#include "path_mgr.h"
#include "log.h"

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <event2/event.h>

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
    sa_family_t af = peer_addr->ss_family;

    int fd = socket(af, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_ERR("path_mgr: socket: %s", strerror(errno));
        return -1;
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        LOG_ERR("path_mgr: fcntl: %s", strerror(errno));
        close(fd);
        return -1;
    }

    int bufsize = 1 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    /* Bind to specific interface */
    if (iface && iface[0]) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                       iface, strlen(iface) + 1) < 0) {
            LOG_ERR("path_mgr: SO_BINDTODEVICE(%s): %s", iface, strerror(errno));
            close(fd);
            return -1;
        }
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
        LOG_ERR("path_mgr: bind(%s): %s", iface ? iface : "any", strerror(errno));
        close(fd);
        return -1;
    }

    p->fd = fd;
    p->active = 1;
    p->in_use = 0;
    p->path_id = 0;

    mgr->n_paths++;
    LOG_INF("path_mgr: path[%d] created on %s (fd=%d)",
            idx, iface ? iface : "(any)", fd);
    return idx;
}

mqvpn_path_t *
mqvpn_path_mgr_find_by_fd(mqvpn_path_mgr_t *mgr, int fd)
{
    for (int i = 0; i < mgr->n_paths; i++) {
        if (mgr->paths[i].fd == fd)
            return &mgr->paths[i];
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
    if (p)
        return p->fd;
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
        if (mgr->paths[i].ev_socket) {
            event_del(mgr->paths[i].ev_socket);
            event_free(mgr->paths[i].ev_socket);
            mgr->paths[i].ev_socket = NULL;
        }
        if (mgr->paths[i].fd >= 0) {
            close(mgr->paths[i].fd);
            mgr->paths[i].fd = -1;
        }
    }
    mgr->n_paths = 0;
}
