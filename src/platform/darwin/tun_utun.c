// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifdef __APPLE__

#  include "tun.h"
#  include "log.h"

#  include <ctype.h>
#  include <fcntl.h>
#  include <unistd.h>
#  include <string.h>
#  include <errno.h>
#  include <stdio.h>
#  include <stdlib.h>
#  include <sys/ioctl.h>
#  include <sys/socket.h>
#  include <sys/sys_domain.h>
#  include <sys/kern_control.h>
#  include <sys/sockio.h> /* SIOC{A,S,G}IFADDR/MTU/FLAGS, SIOCAIFADDR_IN6 — BSD, not net/if.h */
#  include <sys/uio.h>
#  include <net/if.h>
#  include <net/if_utun.h>
#  include <netinet/in.h>
#  include <netinet/in_var.h>
#  include <netinet6/in6_var.h>
#  include <arpa/inet.h>

#  ifndef ND6_INFINITE_LIFETIME
#    define ND6_INFINITE_LIFETIME 0xffffffff
#  endif

/*
 * Map a requested device name to the sc_unit the kernel expects:
 *   "utunN"        -> sc_unit = N+1 (request that specific unit)
 *   NULL/empty/any
 *   other string   -> sc_unit = 0 (kernel auto-allocates the next free unit)
 */
static uint32_t
utun_requested_unit(const char *name)
{
    if (!name || !name[0] || strncmp(name, "utun", 4) != 0) return 0;

    const char *digits = name + 4;
    if (!isdigit((unsigned char)digits[0])) return 0;

    char *end = NULL;
    long n = strtol(digits, &end, 10);
    if (*end != '\0' || n < 0 || n > (long)UINT32_MAX - 1) return 0;

    return (uint32_t)(n + 1);
}

int
mqvpn_tun_create(mqvpn_tun_t *tun, const char *dev_name)
{
    /* Copy dev_name before memset — caller may pass tun->name which aliases tun */
    char name_buf[IFNAMSIZ] = "";
    if (dev_name && dev_name[0]) snprintf(name_buf, sizeof(name_buf), "%s", dev_name);

    memset(tun, 0, sizeof(*tun));
    tun->fd = -1;

    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        LOG_ERR("socket(PF_SYSTEM utun): %s", strerror(errno));
        return -1;
    }

    struct ctl_info ci;
    memset(&ci, 0, sizeof(ci));
    snprintf(ci.ctl_name, sizeof(ci.ctl_name), "%s", UTUN_CONTROL_NAME);
    if (ioctl(fd, CTLIOCGINFO, &ci) < 0) {
        LOG_ERR("ioctl CTLIOCGINFO: %s", strerror(errno));
        close(fd);
        return -1;
    }

    struct sockaddr_ctl sc;
    memset(&sc, 0, sizeof(sc));
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_id = ci.ctl_id;
    sc.sc_unit = utun_requested_unit(name_buf);

    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
        LOG_ERR("connect(utun control): %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Discover the kernel-assigned utunX name. Every downstream addr/MTU/
     * up/route/DNS call keys off tun->name, and auto-allocation (sc_unit=0)
     * means the name cannot be predicted in advance — it must come from
     * the kernel. */
    char ifname[IFNAMSIZ] = "";
    socklen_t ifname_len = sizeof(ifname);
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) < 0) {
        LOG_ERR("getsockopt UTUN_OPT_IFNAME: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_ERR("fcntl O_NONBLOCK: %s", strerror(errno));
        close(fd);
        return -1;
    }

    tun->fd = fd;
    strncpy(tun->name, ifname, IFNAMSIZ - 1);
    tun->name[IFNAMSIZ - 1] = '\0';
    if (name_buf[0] && strcmp(name_buf, tun->name) != 0)
        LOG_WRN("requested TUN name '%s' not usable on Darwin; kernel assigned %s",
                name_buf, tun->name);
    LOG_INF("TUN device %s created (fd=%d)", tun->name, tun->fd);
    return 0;
}

int
mqvpn_tun_set_addr(mqvpn_tun_t *tun, const char *addr, const char *peer_addr,
                   int prefix_len)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG_ERR("socket: %s", strerror(errno));
        return -1;
    }

    /* utun addressing is a single ioctl on BSD: SIOCAIFADDR takes local
     * addr + point-to-point dest + mask together (struct in_aliasreq),
     * unlike Linux's three separate SIOCSIFADDR/SIOCSIFDSTADDR/
     * SIOCSIFNETMASK ioctls. */
    struct in_aliasreq ifra;
    memset(&ifra, 0, sizeof(ifra));
    strncpy(ifra.ifra_name, tun->name, IFNAMSIZ - 1);

    ifra.ifra_addr.sin_family = AF_INET;
    ifra.ifra_addr.sin_len = sizeof(struct sockaddr_in);
    if (inet_pton(AF_INET, addr, &ifra.ifra_addr.sin_addr) != 1) {
        LOG_ERR("invalid address: %s", addr);
        close(sock);
        return -1;
    }
    tun->addr = ifra.ifra_addr.sin_addr;

    ifra.ifra_dstaddr.sin_family = AF_INET;
    ifra.ifra_dstaddr.sin_len = sizeof(struct sockaddr_in);
    if (inet_pton(AF_INET, peer_addr, &ifra.ifra_dstaddr.sin_addr) != 1) {
        LOG_ERR("invalid peer address: %s", peer_addr);
        close(sock);
        return -1;
    }
    tun->peer_addr = ifra.ifra_dstaddr.sin_addr;

    uint32_t mask = prefix_len ? htonl(~((1U << (32 - prefix_len)) - 1)) : 0;
    ifra.ifra_mask.sin_family = AF_INET;
    ifra.ifra_mask.sin_len = sizeof(struct sockaddr_in);
    ifra.ifra_mask.sin_addr.s_addr = mask;

    if (ioctl(sock, SIOCAIFADDR, &ifra) < 0) {
        LOG_ERR("ioctl SIOCAIFADDR: %s", strerror(errno));
        close(sock);
        return -1;
    }

    close(sock);
    LOG_INF("TUN %s: addr=%s peer=%s/%d", tun->name, addr, peer_addr, prefix_len);
    return 0;
}

int
mqvpn_tun_set_mtu(mqvpn_tun_t *tun, int mtu)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ - 1);
    ifr.ifr_mtu = mtu;

    if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
        LOG_ERR("ioctl SIOCSIFMTU: %s", strerror(errno));
        close(sock);
        return -1;
    }

    close(sock);
    tun->mtu = mtu;
    LOG_INF("TUN %s: MTU=%d", tun->name, mtu);
    return 0;
}

int
mqvpn_tun_up(mqvpn_tun_t *tun)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        LOG_ERR("ioctl SIOCGIFFLAGS: %s", strerror(errno));
        close(sock);
        return -1;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        LOG_ERR("ioctl SIOCSIFFLAGS: %s", strerror(errno));
        close(sock);
        return -1;
    }

    close(sock);
    LOG_INF("TUN %s: interface UP", tun->name);
    return 0;
}

int
mqvpn_tun_set_addr6(mqvpn_tun_t *tun, const char *addr6_str, int prefix_len)
{
    struct in6_addr addr;
    if (inet_pton(AF_INET6, addr6_str, &addr) != 1) {
        LOG_ERR("invalid IPv6 address: %s", addr6_str);
        return -1;
    }

    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG_ERR("socket: %s", strerror(errno));
        return -1;
    }

    struct in6_aliasreq ifra6;
    memset(&ifra6, 0, sizeof(ifra6));
    strncpy(ifra6.ifra_name, tun->name, IFNAMSIZ - 1);

    ifra6.ifra_addr.sin6_family = AF_INET6;
    ifra6.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
    ifra6.ifra_addr.sin6_addr = addr;

    ifra6.ifra_prefixmask.sin6_family = AF_INET6;
    ifra6.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
    for (int i = 0; i < prefix_len && i < 128; i++)
        ifra6.ifra_prefixmask.sin6_addr.s6_addr[i / 8] |= (uint8_t)(0x80 >> (i % 8));

    ifra6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
    ifra6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

    if (ioctl(sock, SIOCAIFADDR_IN6, &ifra6) < 0) {
        LOG_ERR("ioctl SIOCAIFADDR_IN6: %s", strerror(errno));
        close(sock);
        return -1;
    }

    close(sock);
    tun->addr6 = addr;
    tun->has_v6 = 1;
    LOG_INF("TUN %s: IPv6 addr=%s/%d", tun->name, addr6_str, prefix_len);
    return 0;
}

int
mqvpn_tun_read(mqvpn_tun_t *tun, uint8_t *buf, size_t buf_len)
{
    /* utun frames are prefixed with a 4-byte network-order address-family
     * header (htonl(AF_INET)/htonl(AF_INET6)); the mqvpn packet path expects
     * bare IP packets. Scatter the header into a throwaway local so the
     * payload lands directly in the caller's buffer with no extra copy. */
    uint32_t af_hdr;
    struct iovec iov[2] = {
        {.iov_base = &af_hdr, .iov_len = sizeof(af_hdr)},
        {.iov_base = buf, .iov_len = buf_len},
    };

    ssize_t n = readv(tun->fd, iov, 2);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        LOG_ERR("tun read: %s", strerror(errno));
        return -1;
    }
    /* Defensive only: utun I/O is atomic per-packet, so a frame shorter
     * than the AF header should not occur (also covers n==0). */
    if (n < (ssize_t)sizeof(af_hdr)) return 0;
    return (int)(n - (ssize_t)sizeof(af_hdr));
}

int
mqvpn_tun_write(mqvpn_tun_t *tun, const uint8_t *buf, size_t len)
{
    if (len < 1) return 0;

    /* Prepend the 4-byte address-family header utun requires. The IP
     * version nibble in the first byte tells us which family to announce. */
    uint8_t ip_ver = (uint8_t)(buf[0] >> 4);
    uint32_t af_hdr = htonl(ip_ver == 6 ? AF_INET6 : AF_INET);
    struct iovec iov[2] = {
        {.iov_base = &af_hdr, .iov_len = sizeof(af_hdr)},
        {.iov_base = (void *)buf, .iov_len = len},
    };

    ssize_t n = writev(tun->fd, iov, 2);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MQVPN_TUN_EAGAIN;
        }
        LOG_ERR("tun write: %s", strerror(errno));
        return -1;
    }
    /* Defensive only: utun I/O is atomic per-packet, so a partial write
     * of the AF header should not occur. */
    if (n < (ssize_t)sizeof(af_hdr)) return 0;
    return (int)(n - (ssize_t)sizeof(af_hdr));
}

void
mqvpn_tun_destroy(mqvpn_tun_t *tun)
{
    if (tun->fd >= 0) {
        LOG_INF("TUN %s: destroying", tun->name);
        close(tun->fd);
        tun->fd = -1;
    }
}

#endif /* __APPLE__ */
