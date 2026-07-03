// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* H2a micro-benchmark harness (throwaway test rig — NOT part of mqvpn_lib):
 * TUN → classifier → lwIP TCP termination → /dev/null byte sink. No QUIC,
 * no relay — isolates raw classifier+lwIP termination throughput (spec H2a
 * gate: >= 10 Gbit/s single flow at MTU 8500).
 *
 * Usage:
 *   tcp_lane_microbench <tun-name>                      (iface pre-configured)
 *   tcp_lane_microbench <tun-name> <ip4> <prefix> <mtu> (self-configure via
 *       ioctl — no iproute2 needed; also brings lo up. Lets the rig run in
 *       any isolated netns: ip-netns, unshare, or a NET_ADMIN container.)
 *
 * Measurement is receiver-side: bytes accepted by the lwIP recv callback
 * between the flow's first and last payload byte. A RESULT line goes to
 * stdout at every flow close (and on SIGINT/SIGTERM); run.sh parses it.
 *
 * Tick-loop note: mqvpn_lwip_tick() runs once per TUN read. Under load
 * reads dominate, so the 250 ms tcp_tmr cadence is easily met; when idle
 * the loop blocks in read() and timers stall — fine for a benchmark (no
 * retransmit/keepalive work exists while no packets flow to a local peer),
 * wrong for production (the real integration drives tick() off
 * mqvpn_lwip_next_timeout_ms()).
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>

#include "hybrid/classifier.h"
#include "hybrid/lwip_glue.h"
#include "lwip/tcp.h"

static volatile sig_atomic_t g_stop;

/* Receiver-side accounting (single-threaded rig — globals are fine). */
static uint64_t g_bytes_sunk_total;
static uint64_t g_first_byte_us;
static uint64_t g_last_byte_us;

static uint64_t
wall_clock_us(void *unused)
{
    (void)unused;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

static void
print_result(const char *why)
{
    double secs = (g_last_byte_us > g_first_byte_us)
                      ? (double)(g_last_byte_us - g_first_byte_us) / 1e6
                      : 0.0;
    double gbps = secs > 0.0 ? (double)g_bytes_sunk_total * 8.0 / secs / 1e9 : 0.0;
    printf("RESULT reason=%s bytes=%" PRIu64 " elapsed_s=%.3f gbps=%.2f\n", why,
           g_bytes_sunk_total, secs, gbps);
    fflush(stdout);
}

static err_t
on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    (void)arg;
    if (err != ERR_OK) {
        if (p) pbuf_free(p);
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    if (!p) { /* peer closed — flow done */
        print_result("flow_close");
        tcp_close(pcb);
        return ERR_OK;
    }
    if (g_first_byte_us == 0) g_first_byte_us = wall_clock_us(NULL);
    g_last_byte_us = wall_clock_us(NULL);
    g_bytes_sunk_total += p->tot_len;
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t
on_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    (void)arg;
    if (err != ERR_OK || !newpcb) return ERR_VAL;
    tcp_recv(newpcb, on_recv);
    return ERR_OK;
}

static int g_tun_fd_for_output;

static void
harness_tun_output(const uint8_t *pkt, size_t len, void *output_ctx)
{
    (void)output_ctx;
    /* Writes lwIP-generated SYN-ACK/ACK/window-update segments back into
     * the SAME TUN device the traffic arrived on — without this the
     * handshake stalls (Task 4's netif->output fix, wired to a raw fd). */
    ssize_t w = write(g_tun_fd_for_output, pkt, len);
    (void)w; /* benchmark rig: a dropped ACK just retransmits */
}

static void
on_signal(int sig)
{
    (void)sig;
    g_stop = 1; /* read() returns EINTR (no SA_RESTART) → main loop exits */
}

/* Optional iface self-configuration (ioctl-only, no iproute2): addr/prefix/
 * mtu/up on the tun, plus lo up. Kernel adds the connected /prefix route
 * itself when the address is set on an UP interface. */
static int
setup_iface(const char *name, const char *ip4, int prefix, int mtu)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket(AF_INET)");
        return -1;
    }

    struct ifreq ifr;
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;

#define IOCTL_OR_DIE(req, what)          \
    do {                                 \
        if (ioctl(s, (req), &ifr) < 0) { \
            perror(what);                \
            close(s);                    \
            return -1;                   \
        }                                \
    } while (0)

    /* up first, then address — so the connected route is installed */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    ifr.ifr_mtu = mtu;
    IOCTL_OR_DIE(SIOCSIFMTU, "SIOCSIFMTU");

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    IOCTL_OR_DIE(SIOCGIFFLAGS, "SIOCGIFFLAGS");
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    IOCTL_OR_DIE(SIOCSIFFLAGS, "SIOCSIFFLAGS(tun)");

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (inet_pton(AF_INET, ip4, &sin.sin_addr) != 1) {
        fprintf(stderr, "bad ip4: %s\n", ip4);
        close(s);
        return -1;
    }
    memcpy(&ifr.ifr_addr, &sin, sizeof(sin));
    IOCTL_OR_DIE(SIOCSIFADDR, "SIOCSIFADDR");

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    sin.sin_addr.s_addr = prefix == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - (unsigned)prefix));
    memcpy(&ifr.ifr_netmask, &sin, sizeof(sin));
    IOCTL_OR_DIE(SIOCSIFNETMASK, "SIOCSIFNETMASK");

    /* lo up (harmless if already up; some fresh netns leave it down) */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        (void)ioctl(s, SIOCSIFFLAGS, &ifr);
    }
#undef IOCTL_OR_DIE
    close(s);
    return 0;
}

int
main(int argc, char **argv)
{
    if (argc != 2 && argc != 5) {
        fprintf(stderr, "usage: %s <tun-name> [<ip4> <prefix> <mtu>]\n", argv[0]);
        return 1;
    }
    int mtu = (argc == 5) ? atoi(argv[4]) : 8500;

    int tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd < 0) {
        perror("open /dev/net/tun");
        return 1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
    if (ioctl(tun_fd, TUNSETIFF, &ifr) < 0) {
        perror("TUNSETIFF");
        return 1;
    }
    g_tun_fd_for_output = tun_fd;

    if (argc == 5 && setup_iface(argv[1], argv[2], atoi(argv[3]), mtu) != 0) return 1;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal; /* deliberately no SA_RESTART: interrupt read() */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    mqvpn_lwip_ctx_t *ctx =
        mqvpn_lwip_ctx_new(wall_clock_us, NULL, harness_tun_output, NULL, mtu);
    if (!ctx) {
        fprintf(stderr, "mqvpn_lwip_ctx_new failed\n");
        return 1;
    }
    mqvpn_lwip_ctx_set_accept_cb(ctx, on_accept, NULL);
    fprintf(stderr, "harness: ready on %s (mtu %d)\n", argv[1], mtu);

    mqvpn_hybrid_config_t pol;
    mqvpn_hybrid_config_default(&pol);
    pol.enabled = 1;
    pol.tcp_mode = MQVPN_HYBRID_TCP_STREAM;

    uint8_t buf[9500];
    uint64_t next_progress_us = 0;
    uint64_t prev_bytes = 0;
    while (!g_stop) {
        ssize_t n = read(tun_fd, buf, sizeof(buf));
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue; /* g_stop check */
            if (n < 0) {
                perror("read(tun)");
                break;
            }
            continue;
        }
        mqvpn_hybrid_lane_t lane = mqvpn_hybrid_classify(buf, (size_t)n, &pol, NULL);
        if (lane == MQVPN_LANE_TCP) (void)mqvpn_lwip_input(ctx, buf, (size_t)n);
        /* non-TCP (e.g. kernel-generated ICMP/IGMP noise) is dropped — this
         * rig has no RAW/DGRAM lane behind it */
        mqvpn_lwip_tick(ctx);

        uint64_t now = wall_clock_us(NULL);
        if (now >= next_progress_us) {
            if (next_progress_us != 0)
                fprintf(stderr, "progress: %.2f Gbit/s\n",
                        (double)(g_bytes_sunk_total - prev_bytes) * 8.0 / 1e9);
            prev_bytes = g_bytes_sunk_total;
            next_progress_us = now + 1000000;
        }
    }

    print_result("shutdown");
    /* Benchmark rig: skip mqvpn_lwip_ctx_free() teardown ceremony (accepted
     * pcbs may still be live; the process exits anyway). */
    return 0;
}
