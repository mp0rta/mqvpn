#ifndef MQVPN_TUN_H
#define MQVPN_TUN_H

#include <stdint.h>
#include <stddef.h>
#include <net/if.h>
#include <netinet/in.h>

/* mqvpn_tun_write() returns this when the kernel buffer is full (EAGAIN). */
#define MQVPN_TUN_EAGAIN (-2)

typedef struct {
    int             fd;
    char            name[IFNAMSIZ];
    struct in_addr  addr;
    struct in_addr  peer_addr;
    struct in6_addr addr6;
    int             has_v6;
    int             mtu;
} mqvpn_tun_t;

/* Create a TUN device. dev_name may be NULL for auto-naming. */
int  mqvpn_tun_create(mqvpn_tun_t *tun, const char *dev_name);

/* Assign point-to-point addresses and prefix length. */
int  mqvpn_tun_set_addr(mqvpn_tun_t *tun, const char *addr,
                         const char *peer_addr, int prefix_len);

/* Set MTU on the TUN device. */
int  mqvpn_tun_set_mtu(mqvpn_tun_t *tun, int mtu);

/* Bring the TUN interface up. */
int  mqvpn_tun_up(mqvpn_tun_t *tun);

/* Read a single IP packet from the TUN device (non-blocking safe). */
int  mqvpn_tun_read(mqvpn_tun_t *tun, uint8_t *buf, size_t buf_len);

/* Write a single IP packet to the TUN device. */
int  mqvpn_tun_write(mqvpn_tun_t *tun, const uint8_t *buf, size_t len);

/* Assign an IPv6 address to the TUN device. */
int  mqvpn_tun_set_addr6(mqvpn_tun_t *tun, const char *addr6, int prefix_len);

/* Close the TUN device. */
void mqvpn_tun_destroy(mqvpn_tun_t *tun);

#endif /* MQVPN_TUN_H */
