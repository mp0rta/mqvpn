#include "tun.h"
#include "log.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

int
mqvpn_tun_create(mqvpn_tun_t *tun, const char *dev_name)
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
    tun->name[IFNAMSIZ - 1] = '\0';
    LOG_INF("TUN device %s created (fd=%d)", tun->name, tun->fd);
    return 0;
}

int
mqvpn_tun_set_addr(mqvpn_tun_t *tun, const char *addr,
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

/*
 * Resolve an interface name to its index.
 */
static unsigned int
tun_ifindex(const char *ifname)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return 0;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    unsigned int idx = 0;
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == 0)
        idx = (unsigned int)ifr.ifr_ifindex;

    close(sock);
    return idx;
}

/*
 * Send RTM_NEWADDR via netlink to add an IPv6 address to an interface.
 *
 * TUN devices (ARPHRD_NONE) do not get an inet6_dev at NETDEV_REGISTER time,
 * so the legacy ioctl(SIOCSIFADDR) for AF_INET6 silently fails.  Netlink
 * RTM_NEWADDR triggers inet6_dev creation via __inet6_bind() → ipv6_add_addr()
 * in the kernel, which is what `ip addr add` uses internally.
 *
 * On network namespaces where disable_ipv6=1, the first RTM_NEWADDR may fail
 * with EACCES but still causes inet6_dev + procfs creation as a side effect.
 * We then disable ipv6 via procfs and retry.
 */
static int
tun_netlink_add_addr6(unsigned int ifindex, const struct in6_addr *addr,
                      int prefix_len)
{
    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd < 0) {
        LOG_ERR("socket(NETLINK_ROUTE): %s", strerror(errno));
        return -1;
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOG_ERR("bind(netlink): %s", strerror(errno));
        close(fd);
        return -1;
    }

    /*
     * Build the netlink message:
     *   nlmsghdr + ifaddrmsg + RTA(IFA_LOCAL, 16 bytes) + RTA(IFA_ADDRESS, 16 bytes)
     */
    struct {
        struct nlmsghdr  nlh;
        struct ifaddrmsg ifa;
        /* RTA_SPACE(16) for IFA_LOCAL + RTA_SPACE(16) for IFA_ADDRESS */
        char             buf[RTA_SPACE(16) + RTA_SPACE(16)];
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nlh.nlmsg_type  = RTM_NEWADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    req.nlh.nlmsg_seq   = 1;

    req.ifa.ifa_family    = AF_INET6;
    req.ifa.ifa_prefixlen = (unsigned char)prefix_len;
    req.ifa.ifa_index     = ifindex;
    req.ifa.ifa_scope     = 0; /* RT_SCOPE_UNIVERSE */

    /* Append IFA_LOCAL attribute */
    struct rtattr *rta = (struct rtattr *)
        ((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len  = RTA_LENGTH(16);
    memcpy(RTA_DATA(rta), addr, 16);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_SPACE(16);

    /* Append IFA_ADDRESS attribute */
    rta = (struct rtattr *)
        ((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = IFA_ADDRESS;
    rta->rta_len  = RTA_LENGTH(16);
    memcpy(RTA_DATA(rta), addr, 16);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_SPACE(16);

    /* Send */
    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        LOG_ERR("send(netlink RTM_NEWADDR): %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Receive ACK */
    char resp[4096];
    ssize_t n = recv(fd, resp, sizeof(resp), 0);
    close(fd);

    if (n < 0) {
        LOG_ERR("recv(netlink): %s", strerror(errno));
        return -1;
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *)resp;
    if (!NLMSG_OK(nlh, (size_t)n) || nlh->nlmsg_type != NLMSG_ERROR) {
        LOG_ERR("netlink: unexpected response type %d", nlh->nlmsg_type);
        return -1;
    }

    struct nlmsgerr *nlerr = (struct nlmsgerr *)NLMSG_DATA(nlh);
    if (nlerr->error == 0)
        return 0;  /* success */

    /* Return the negated errno (kernel sends negative errno) */
    errno = -nlerr->error;
    return -1;
}

/*
 * Write a value to a procfs sysctl path (best-effort).
 */
static int
tun_write_proc(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, value, strlen(value));
    close(fd);
    return (n > 0) ? 0 : -1;
}

int
mqvpn_tun_set_addr6(mqvpn_tun_t *tun, const char *addr6_str, int prefix_len)
{
    struct in6_addr addr;
    if (inet_pton(AF_INET6, addr6_str, &addr) != 1) {
        LOG_ERR("invalid IPv6 address: %s", addr6_str);
        return -1;
    }

    unsigned int ifindex = tun_ifindex(tun->name);
    if (ifindex == 0) {
        LOG_ERR("cannot resolve ifindex for %s", tun->name);
        return -1;
    }

    /*
     * First, try to enable IPv6 globally and on this interface via procfs.
     * These writes may fail if the procfs entries don't exist yet — that's OK,
     * the netlink call below will create inet6_dev as a side effect.
     */
    tun_write_proc("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0");
    tun_write_proc("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0");

    char path[128];
    snprintf(path, sizeof(path),
             "/proc/sys/net/ipv6/conf/%s/disable_ipv6", tun->name);
    tun_write_proc(path, "0");

    /* Try to add the address via netlink */
    int rc = tun_netlink_add_addr6(ifindex, &addr, prefix_len);
    if (rc == 0)
        goto done;

    /*
     * The first attempt may fail with EACCES if disable_ipv6 was 1,
     * but it has a crucial side effect: the kernel's inet6_addr_add() calls
     * ipv6_find_idev() which creates the inet6_dev structure and procfs
     * entries for the interface.  Now the procfs write should work.
     */
    if (errno == EACCES) {
        LOG_DBG("RTM_NEWADDR got EACCES, retrying after enabling IPv6");

        /* The procfs entry should exist now — try again */
        if (tun_write_proc(path, "0") < 0) {
            LOG_ERR("failed to enable IPv6 on %s via procfs", tun->name);
            return -1;
        }

        rc = tun_netlink_add_addr6(ifindex, &addr, prefix_len);
        if (rc == 0)
            goto done;
    }

    LOG_ERR("netlink RTM_NEWADDR %s/%d dev %s: %s",
            addr6_str, prefix_len, tun->name, strerror(errno));
    return -1;

done:
    tun->addr6 = addr;
    tun->has_v6 = 1;
    LOG_INF("TUN %s: IPv6 addr=%s/%d", tun->name, addr6_str, prefix_len);
    return 0;
}

int
mqvpn_tun_read(mqvpn_tun_t *tun, uint8_t *buf, size_t buf_len)
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
mqvpn_tun_write(mqvpn_tun_t *tun, const uint8_t *buf, size_t len)
{
    ssize_t n = write(tun->fd, buf, len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MQVPN_TUN_EAGAIN;
        }
        LOG_ERR("tun write: %s", strerror(errno));
        return -1;
    }
    return (int)n;
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
