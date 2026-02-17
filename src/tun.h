#ifndef MPVPN_TUN_H
#define MPVPN_TUN_H

#include <stdint.h>
#include <stddef.h>
#include <net/if.h>
#include <netinet/in.h>

/* mpvpn_tun_write() returns this when the kernel buffer is full (EAGAIN). */
#define MPVPN_TUN_EAGAIN (-2)

typedef struct {
    int             fd;
    char            name[IFNAMSIZ];
    struct in_addr  addr;
    struct in_addr  peer_addr;
    int             mtu;
} mpvpn_tun_t;

/* Create a TUN device. dev_name may be NULL for auto-naming. */
int  mpvpn_tun_create(mpvpn_tun_t *tun, const char *dev_name);

/* Assign point-to-point addresses and prefix length. */
int  mpvpn_tun_set_addr(mpvpn_tun_t *tun, const char *addr,
                         const char *peer_addr, int prefix_len);

/* Set MTU on the TUN device. */
int  mpvpn_tun_set_mtu(mpvpn_tun_t *tun, int mtu);

/* Bring the TUN interface up. */
int  mpvpn_tun_up(mpvpn_tun_t *tun);

/* Read a single IP packet from the TUN device (non-blocking safe). */
int  mpvpn_tun_read(mpvpn_tun_t *tun, uint8_t *buf, size_t buf_len);

/* Write a single IP packet to the TUN device. */
int  mpvpn_tun_write(mpvpn_tun_t *tun, const uint8_t *buf, size_t len);

/* Close the TUN device. */
void mpvpn_tun_destroy(mpvpn_tun_t *tun);

#endif /* MPVPN_TUN_H */
