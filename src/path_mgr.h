#ifndef MQVPN_PATH_MGR_H
#define MQVPN_PATH_MGR_H

#include <netinet/in.h>
#include <net/if.h>
#include <stdint.h>

#define MQVPN_MAX_PATHS  4

typedef struct {
    int                  fd;
    char                 iface[IFNAMSIZ];
    struct sockaddr_storage local_addr;
    socklen_t            local_addrlen;
    uint64_t             path_id;
    int                  active;        /* socket created and registered */
    int                  in_use;        /* xquic path created */
    struct event        *ev_socket;
} mqvpn_path_t;

typedef struct {
    mqvpn_path_t    paths[MQVPN_MAX_PATHS];
    int             n_paths;
} mqvpn_path_mgr_t;

/* Initialize path manager (zeroes everything) */
void mqvpn_path_mgr_init(mqvpn_path_mgr_t *mgr);

/* Create a UDP socket bound to iface, add to path manager.
 * peer_addr is the server address to connect-like setup.
 * Returns path index (>=0) on success, -1 on error. */
int mqvpn_path_mgr_add(mqvpn_path_mgr_t *mgr, const char *iface,
                        const struct sockaddr_storage *peer_addr);

/* Find path by socket fd. Returns NULL if not found. */
mqvpn_path_t *mqvpn_path_mgr_find_by_fd(mqvpn_path_mgr_t *mgr, int fd);

/* Find path by xquic path_id. Returns NULL if not found. */
mqvpn_path_t *mqvpn_path_mgr_find_by_path_id(mqvpn_path_mgr_t *mgr,
                                               uint64_t path_id);

/* Get socket fd for path by xquic path_id. Returns primary fd if not found. */
int mqvpn_path_mgr_get_fd(mqvpn_path_mgr_t *mgr, uint64_t path_id);

/* Cleanup: close all sockets */
void mqvpn_path_mgr_destroy(mqvpn_path_mgr_t *mgr);

#endif /* MQVPN_PATH_MGR_H */
