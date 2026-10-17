// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#include "tun.h"
#include "tun_offload.h"
#include "log.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

/* TUN_F_USO4/6 and IFF_VNET_HDR come from <linux/if_tun.h>; older headers
 * (before 6.2) lack the USO flags. */
#ifndef TUN_F_USO4
#  define TUN_F_USO4 0x20
#endif
#ifndef TUN_F_USO6
#  define TUN_F_USO6 0x40
#endif

/* Room for one kernel read: a 64 KiB super-packet plus slack. A TUN read
 * that does not fit is truncated silently, so stay above the IP maximum. */
#define OFFLOAD_RX_CAP (65536 + 256)

/* State of a TUN opened with IFF_VNET_HDR. */
struct mqvpn_tun_offload {
    uint8_t rx[OFFLOAD_RX_CAP]; /* the packet of the last kernel read */
    mqvpn_gso_iter_t it;        /* segments of rx still to hand out */
    int active;                 /* it has segments left */
    int warned;                 /* logged a malformed vnet packet already */
    uint64_t gso_pkts;          /* super-packets split */
    uint64_t gso_segs;          /* segments they produced */
    uint64_t csum_pkts;         /* plain packets whose checksum we finished */
    uint64_t drops;             /* malformed vnet packets dropped */
    int fd;                     /* the TUN, for the GRO emit callback */
    mqvpn_gro_t *gro;           /* write-side TCP GRO, NULL when off */
};

static int
env_off(const char *name)
{
    const char *e = getenv(name);
    return e && (strcmp(e, "0") == 0 || strcmp(e, "off") == 0);
}

/* MQVPN_TUN_OFFLOAD=0 (or "off") keeps the plain one-packet-per-read TUN. */
static int
tun_offload_wanted(void)
{
    return !env_off("MQVPN_TUN_OFFLOAD");
}

/* MQVPN_TUN_GRO=0 keeps the offloaded reads but writes packets one by one. */
static int
tun_gro_wanted(void)
{
    return !env_off("MQVPN_TUN_GRO");
}

/* GRO sink: one packet (or one coalesced super-packet) to the TUN. */
static int
tun_gro_emit(void *ctx, const struct virtio_net_hdr *vh, const uint8_t *pkt, size_t len)
{
    struct mqvpn_tun_offload *off = ctx;
    struct iovec iov[2] = {{(void *)vh, sizeof(*vh)}, {(void *)pkt, len}};
    ssize_t n = writev(off->fd, iov, 2);
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        LOG_ERR("tun write: %s", strerror(errno));
    return n < 0 ? -1 : 0;
}

/*
 * Turn on the offloads on a TUN fd opened with IFF_VNET_HDR. TUN_F_CSUM is
 * what lets the kernel leave checksums unfinished, and TSO needs it. USO is
 * newer than the rest, so retry without it when the kernel rejects it.
 * Returns 0 on success, -1 when the kernel accepts none of it.
 */
static int
tun_enable_offloads(int fd, unsigned int *flags_out)
{
    int hdrsz = (int)sizeof(struct virtio_net_hdr);
    if (ioctl(fd, TUNSETVNETHDRSZ, &hdrsz) < 0) {
        LOG_DBG("TUNSETVNETHDRSZ: %s", strerror(errno));
        return -1;
    }

    unsigned int flags = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_USO4 | TUN_F_USO6;
    if (ioctl(fd, TUNSETOFFLOAD, flags) < 0) {
        flags &= ~(unsigned int)(TUN_F_USO4 | TUN_F_USO6);
        if (ioctl(fd, TUNSETOFFLOAD, flags) < 0) {
            LOG_DBG("TUNSETOFFLOAD: %s", strerror(errno));
            return -1;
        }
    }
    *flags_out = flags;
    return 0;
}

/* Open /dev/net/tun and attach it to dev_name. With vnet set, request the
 * virtio header and enable the offloads; returns -1 if any step fails so the
 * caller can fall back to a plain TUN. quiet suppresses the error logs of the
 * vnet attempt. */
static int
tun_open(const char *name_buf, int vnet, struct ifreq *ifr, unsigned int *off_flags)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        LOG_ERR("open /dev/net/tun: %s", strerror(errno));
        return -1;
    }

    memset(ifr, 0, sizeof(*ifr));
    ifr->ifr_flags = IFF_TUN | IFF_NO_PI | (vnet ? IFF_VNET_HDR : 0);
    if (name_buf[0]) strncpy(ifr->ifr_name, name_buf, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, ifr) < 0) {
        if (vnet)
            LOG_DBG("ioctl TUNSETIFF (IFF_VNET_HDR): %s", strerror(errno));
        else
            LOG_ERR("ioctl TUNSETIFF: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (vnet && tun_enable_offloads(fd, off_flags) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int
mqvpn_tun_create(mqvpn_tun_t *tun, const char *dev_name)
{
    /* Copy dev_name before memset — caller may pass tun->name which aliases tun */
    char name_buf[IFNAMSIZ] = "";
    if (dev_name && dev_name[0]) snprintf(name_buf, sizeof(name_buf), "%s", dev_name);

    memset(tun, 0, sizeof(*tun));
    tun->fd = -1;

    struct ifreq ifr;
    unsigned int off_flags = 0;
    struct mqvpn_tun_offload *off = NULL;
    int fd = -1;

    /* Prefer a TUN with the virtio header and TSO/USO offloads; if the
     * kernel refuses any part of it, fall back to the plain TUN. */
    if (tun_offload_wanted()) {
        off = calloc(1, sizeof(*off));
        if (off) fd = tun_open(name_buf, 1, &ifr, &off_flags);
        if (fd < 0) {
            free(off);
            off = NULL;
            LOG_INF("TUN offloads unavailable, using the plain TUN");
        }
    }
    if (fd < 0) fd = tun_open(name_buf, 0, &ifr, &off_flags);
    if (fd < 0) return -1;

    /* Set non-blocking */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_ERR("fcntl O_NONBLOCK: %s", strerror(errno));
        close(fd);
        free(off);
        return -1;
    }

    tun->fd = fd;
    tun->offload = off;
    if (off) {
        off->fd = fd;
        if (tun_gro_wanted()) off->gro = mqvpn_gro_new(tun_gro_emit, off);
    }
    strncpy(tun->name, ifr.ifr_name, IFNAMSIZ - 1);
    tun->name[IFNAMSIZ - 1] = '\0';
    if (off)
        LOG_INF("TUN device %s created (fd=%d, offloads: csum tso4 tso6%s)", tun->name,
                tun->fd, (off_flags & TUN_F_USO4) ? " uso4 uso6" : "");
    else
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
    if (sock < 0) return 0;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    unsigned int idx = 0;
    if (ioctl(sock, SIOCGIFINDEX, &ifr) == 0) idx = (unsigned int)ifr.ifr_ifindex;

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
tun_netlink_add_addr6(unsigned int ifindex, const struct in6_addr *addr, int prefix_len)
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
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
        /* RTA_SPACE(16) for IFA_LOCAL + RTA_SPACE(16) for IFA_ADDRESS */
        char buf[RTA_SPACE(16) + RTA_SPACE(16)];
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nlh.nlmsg_type = RTM_NEWADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    req.nlh.nlmsg_seq = 1;

    req.ifa.ifa_family = AF_INET6;
    req.ifa.ifa_prefixlen = (unsigned char)prefix_len;
    req.ifa.ifa_index = ifindex;
    req.ifa.ifa_scope = 0; /* RT_SCOPE_UNIVERSE */

    /* Append IFA_LOCAL attribute */
    struct rtattr *rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = RTA_LENGTH(16);
    memcpy(RTA_DATA(rta), addr, 16);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_SPACE(16);

    /* Append IFA_ADDRESS attribute */
    rta = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = IFA_ADDRESS;
    rta->rta_len = RTA_LENGTH(16);
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
    if (nlerr->error == 0) return 0; /* success */

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
    if (fd < 0) return -1;
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
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/disable_ipv6", tun->name);
    tun_write_proc(path, "0");

    /* Try to add the address via netlink */
    int rc = tun_netlink_add_addr6(ifindex, &addr, prefix_len);
    if (rc == 0) goto done;

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
        if (rc == 0) goto done;
    }

    LOG_ERR("netlink RTM_NEWADDR %s/%d dev %s: %s", addr6_str, prefix_len, tun->name,
            strerror(errno));
    return -1;

done:
    tun->addr6 = addr;
    tun->has_v6 = 1;
    LOG_INF("TUN %s: IPv6 addr=%s/%d", tun->name, addr6_str, prefix_len);
    return 0;
}

/*
 * Read one IP packet. On a TUN with the virtio header each kernel read is
 * [vnet header | packet]; a plain packet is copied out as is (after finishing
 * its checksum if the kernel left it partial), a GSO super-packet is cut into
 * MTU-sized packets that come back one per call, the later ones without a
 * syscall.
 */
int
mqvpn_tun_read(mqvpn_tun_t *tun, uint8_t *buf, size_t buf_len)
{
    struct mqvpn_tun_offload *off = tun->offload;

    if (!off) {
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

    if (off->active) {
        int n = mqvpn_gso_next(&off->it, buf, buf_len);
        if (n > 0) {
            off->gso_segs++;
            off->active = !off->it.done;
            return n;
        }
        off->active = 0; /* buf too small: drop the rest */
        if (n < 0) off->drops++;
    }

    struct virtio_net_hdr vh;
    struct iovec iov[2] = {{&vh, sizeof(vh)}, {off->rx, sizeof(off->rx)}};
    ssize_t n = readv(tun->fd, iov, 2);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        LOG_ERR("tun read: %s", strerror(errno));
        return -1;
    }
    if (n < (ssize_t)sizeof(vh)) return 0;
    size_t len = (size_t)n - sizeof(vh);
    if (len == 0) return 0;

    int rc = 0;
    if ((vh.gso_type & (uint8_t)~VIRTIO_NET_HDR_GSO_ECN) == VIRTIO_NET_HDR_GSO_NONE) {
        if (len > buf_len) {
            rc = -1;
        } else {
            memcpy(buf, off->rx, len);
            /* The kernel sets NEEDS_CSUM on every CHECKSUM_PARTIAL skb, GSO or
             * not (virtio_net_hdr_from_skb()), so finish all of them: a plain
             * TUN would hand the partial checksum on unfinished. */
            if (vh.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
                rc = mqvpn_vnet_finish_csum(buf, len, &vh);
                off->csum_pkts++;
            }
            if (rc == 0) return (int)len;
        }
    } else {
        rc = mqvpn_gso_begin(&off->it, off->rx, len, &vh);
        if (rc == 0) {
            off->active = 1;
            off->gso_pkts++;
            int seg = mqvpn_gso_next(&off->it, buf, buf_len);
            if (seg > 0) {
                off->gso_segs++;
                off->active = !off->it.done;
                return seg;
            }
            off->active = 0;
            rc = -1;
        }
    }

    /* Malformed header from the kernel: drop the packet, say so once. */
    off->drops++;
    if (!off->warned) {
        off->warned = 1;
        LOG_WRN("tun read: dropped a packet with an unusable vnet header (flags=0x%x "
                "gso_type=%u gso_size=%u csum_start=%u csum_offset=%u len=%zu)",
                vh.flags, vh.gso_type, vh.gso_size, vh.csum_start, vh.csum_offset, len);
    }
    return 0;
}

int
mqvpn_tun_has_pending(const mqvpn_tun_t *tun)
{
    return tun->offload && tun->offload->active;
}

int
mqvpn_tun_write(mqvpn_tun_t *tun, const uint8_t *buf, size_t len)
{
    ssize_t n;

    if (tun->offload && tun->offload->gro) {
        /* Held until mqvpn_tun_flush(); a failed write is logged there. */
        mqvpn_gro_push(tun->offload->gro, buf, len);
        return (int)len;
    }
    if (tun->offload) {
        /* All-zero header: no checksum to finish, no segmentation. */
        struct virtio_net_hdr vh;
        memset(&vh, 0, sizeof(vh));
        struct iovec iov[2] = {{&vh, sizeof(vh)}, {(void *)buf, len}};
        n = writev(tun->fd, iov, 2);
        if (n >= (ssize_t)sizeof(vh)) n -= (ssize_t)sizeof(vh);
    } else {
        n = write(tun->fd, buf, len);
    }
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
mqvpn_tun_flush(mqvpn_tun_t *tun)
{
    if (tun->offload && tun->offload->gro && tun->fd >= 0)
        mqvpn_gro_flush(tun->offload->gro);
}

int
mqvpn_tun_gro_pending(const mqvpn_tun_t *tun)
{
    return tun->offload && tun->offload->gro && mqvpn_gro_pending(tun->offload->gro);
}

void
mqvpn_tun_destroy(mqvpn_tun_t *tun)
{
    if (tun->offload) {
        if (tun->offload->gro) {
            uint64_t pushed, supers, merged;
            if (tun->fd >= 0) mqvpn_gro_flush(tun->offload->gro);
            mqvpn_gro_stats(tun->offload->gro, &pushed, &supers, &merged);
            LOG_INF("TUN %s: GRO: %llu packets written, %llu super-packets from %llu "
                    "of them",
                    tun->name, (unsigned long long)pushed, (unsigned long long)supers,
                    (unsigned long long)merged);
            mqvpn_gro_free(tun->offload->gro);
        }
        LOG_INF("TUN %s: offload stats: %llu GSO packets split into %llu segments, %llu "
                "checksums finished, %llu dropped",
                tun->name, (unsigned long long)tun->offload->gso_pkts,
                (unsigned long long)tun->offload->gso_segs,
                (unsigned long long)tun->offload->csum_pkts,
                (unsigned long long)tun->offload->drops);
        free(tun->offload);
        tun->offload = NULL;
    }
    if (tun->fd >= 0) {
        LOG_INF("TUN %s: destroying", tun->name);
        close(tun->fd);
        tun->fd = -1;
    }
}
