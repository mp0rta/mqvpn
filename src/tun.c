#include "tun.h"
#include "log.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

int
mpvpn_tun_create(mpvpn_tun_t *tun, const char *dev_name)
{
    memset(tun, 0, sizeof(*tun));
    tun->fd = -1;

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        LOG_ERR("open /dev/net/tun: %s", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (dev_name && dev_name[0]) {
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        LOG_ERR("ioctl TUNSETIFF: %s", strerror(errno));
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
    strncpy(tun->name, ifr.ifr_name, IFNAMSIZ - 1);
    LOG_INF("TUN device %s created (fd=%d)", tun->name, tun->fd);
    return 0;
}

int
mpvpn_tun_set_addr(mpvpn_tun_t *tun, const char *addr,
                    const char *peer_addr, int prefix_len)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG_ERR("socket: %s", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tun->name, IFNAMSIZ - 1);

    /* Local address */
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, addr, &sin->sin_addr) != 1) {
        LOG_ERR("invalid address: %s", addr);
        close(sock);
        return -1;
    }
    tun->addr = sin->sin_addr;
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        LOG_ERR("ioctl SIOCSIFADDR: %s", strerror(errno));
        close(sock);
        return -1;
    }

    /* Point-to-point destination */
    sin = (struct sockaddr_in *)&ifr.ifr_dstaddr;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, peer_addr, &sin->sin_addr) != 1) {
        LOG_ERR("invalid peer address: %s", peer_addr);
        close(sock);
        return -1;
    }
    tun->peer_addr = sin->sin_addr;
    if (ioctl(sock, SIOCSIFDSTADDR, &ifr) < 0) {
        LOG_ERR("ioctl SIOCSIFDSTADDR: %s", strerror(errno));
        close(sock);
        return -1;
    }

    /* Netmask from prefix_len */
    uint32_t mask = prefix_len ? htonl(~((1U << (32 - prefix_len)) - 1)) : 0;
    sin = (struct sockaddr_in *)&ifr.ifr_netmask;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = mask;
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        LOG_ERR("ioctl SIOCSIFNETMASK: %s", strerror(errno));
        close(sock);
        return -1;
    }

    close(sock);
    LOG_INF("TUN %s: addr=%s peer=%s/%d", tun->name, addr, peer_addr, prefix_len);
    return 0;
}

int
mpvpn_tun_set_mtu(mpvpn_tun_t *tun, int mtu)
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
mpvpn_tun_up(mpvpn_tun_t *tun)
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
mpvpn_tun_read(mpvpn_tun_t *tun, uint8_t *buf, size_t buf_len)
{
    ssize_t n = read(tun->fd, buf, buf_len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        LOG_ERR("tun read: %s", strerror(errno));
        return -1;
    }
    return (int)n;
}

int
mpvpn_tun_write(mpvpn_tun_t *tun, const uint8_t *buf, size_t len)
{
    ssize_t n = write(tun->fd, buf, len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        LOG_ERR("tun write: %s", strerror(errno));
        return -1;
    }
    return (int)n;
}

void
mpvpn_tun_destroy(mpvpn_tun_t *tun)
{
    if (tun->fd >= 0) {
        LOG_INF("TUN %s: destroying", tun->name);
        close(tun->fd);
        tun->fd = -1;
    }
}
