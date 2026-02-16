#ifndef MPVPN_PATH_MGR_H
#define MPVPN_PATH_MGR_H

#include <netinet/in.h>
#include <net/if.h>
#include <stdint.h>

#define MPVPN_MAX_PATHS  4

typedef struct {
    int                  fd;
    char                 iface[IFNAMSIZ];
    struct sockaddr_in   local_addr;
    socklen_t            local_addrlen;
    uint64_t             path_id;
    int                  active;        /* socket created and registered */
    int                  in_use;        /* xquic path created */
    struct event        *ev_socket;
} mpvpn_path_t;

typedef struct {
    mpvpn_path_t    paths[MPVPN_MAX_PATHS];
    int             n_paths;
} mpvpn_path_mgr_t;

/* Initialize path manager (zeroes everything) */
void mpvpn_path_mgr_init(mpvpn_path_mgr_t *mgr);

/* Create a UDP socket bound to iface, add to path manager.
 * peer_addr is the server address to connect-like setup.
 * Returns path index (>=0) on success, -1 on error. */
int mpvpn_path_mgr_add(mpvpn_path_mgr_t *mgr, const char *iface,
                        const struct sockaddr_in *peer_addr);

/* Find path by socket fd. Returns NULL if not found. */
mpvpn_path_t *mpvpn_path_mgr_find_by_fd(mpvpn_path_mgr_t *mgr, int fd);

/* Find path by xquic path_id. Returns NULL if not found. */
mpvpn_path_t *mpvpn_path_mgr_find_by_path_id(mpvpn_path_mgr_t *mgr,
                                               uint64_t path_id);

/* Get socket fd for path by xquic path_id. Returns primary fd if not found. */
int mpvpn_path_mgr_get_fd(mpvpn_path_mgr_t *mgr, uint64_t path_id);

/* Cleanup: close all sockets */
void mpvpn_path_mgr_destroy(mpvpn_path_mgr_t *mgr);

#endif /* MPVPN_PATH_MGR_H */
