// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* Contract tests for the bundled POSIX bind: constructor failure classes,
 * borrowed-fd rule, opts prefix copy / non-retention, per-scope sticky state,
 * get_stats struct_size prefix, RX budget accounting, and the once-per-process
 * "udp-gso: " marker (checked by the ctest wrapper on this binary's output). */
#define _GNU_SOURCE
#undef NDEBUG
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "mqvpn_bind_posix.h"
#include "bind/posix_offload.h"
#include "log.h"

#ifndef UDP_GRO
#  define UDP_GRO 104
#endif

/* ── seam: fake kernel ── */
static int seam_fail_errno;    /* 0 = succeed */
static int seam_fail_once_gso; /* fail the next sendmsg that carries a cmsg */
static int seam_sendmsg_calls, seam_sendmmsg_calls, seam_recvmsg_calls;
static int seam_recv_queue;  /* how many datagrams recvmsg still returns */
static size_t seam_recv_len; /* bytes per fake datagram */
static int seam_recv_seg;    /* UDP_GRO segment size to report, 0 = none */

ssize_t
mqvpn_seam_sendmsg(int fd, const struct msghdr *msg, int flags)
{
    (void)fd;
    (void)flags;
    seam_sendmsg_calls++;
    if (seam_fail_once_gso && msg->msg_controllen != 0) {
        seam_fail_once_gso = 0;
        errno = EMSGSIZE;
        return -1;
    }
    if (seam_fail_errno) {
        errno = seam_fail_errno;
        return -1;
    }
    size_t n = 0;
    for (size_t i = 0; i < msg->msg_iovlen; i++)
        n += msg->msg_iov[i].iov_len;
    return (ssize_t)n;
}

int
mqvpn_seam_sendmmsg(int fd, struct mmsghdr *mv, unsigned int vlen, int flags)
{
    (void)fd;
    (void)flags;
    seam_sendmmsg_calls++;
    if (seam_fail_errno) {
        errno = seam_fail_errno;
        return -1;
    }
    for (unsigned i = 0; i < vlen; i++)
        mv[i].msg_len = (unsigned)mv[i].msg_hdr.msg_iov[0].iov_len;
    return (int)vlen;
}

ssize_t
mqvpn_seam_recvmsg(int fd, struct msghdr *msg, int flags)
{
    (void)fd;
    (void)flags;
    seam_recvmsg_calls++;
    if (seam_recv_queue <= 0) {
        errno = EAGAIN;
        return -1;
    }
    seam_recv_queue--;
    struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(4433);
    msg->msg_namelen = sizeof(*sin);
    memset(msg->msg_iov[0].iov_base, 0x5A, seam_recv_len);
    msg->msg_flags = 0;
    if (seam_recv_seg > 0) {
        struct cmsghdr *cm = CMSG_FIRSTHDR(msg);
        cm->cmsg_level = SOL_UDP;
        cm->cmsg_type = UDP_GRO;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm), &seam_recv_seg, sizeof(int));
        msg->msg_controllen = CMSG_SPACE(sizeof(int));
    } else {
        msg->msg_controllen = 0;
    }
    return (ssize_t)seam_recv_len;
}

static int seam_calloc_fail_next; /* 1 = the next calloc returns NULL */

void *
mqvpn_seam_calloc(size_t n, size_t sz)
{
    if (seam_calloc_fail_next) {
        seam_calloc_fail_next = 0;
        return NULL;
    }
    return calloc(n, sz);
}

static void
seam_reset(void)
{
    seam_calloc_fail_next = 0;
    seam_fail_errno = 0;
    seam_fail_once_gso = 0;
    seam_sendmsg_calls = seam_sendmmsg_calls = seam_recvmsg_calls = 0;
    seam_recv_queue = 0;
    seam_recv_len = 100;
    seam_recv_seg = 0;
}

static int
make_udp_fd(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    return fd;
}

static mqvpn_bind_posix_opts_t
opts_default(int gso, int gro)
{
    mqvpn_bind_posix_opts_t o;
    memset(&o, 0, sizeof(o));
    o.struct_size = sizeof(o);
    o.udp_gso = gso;
    o.udp_gro = gro;
    o.socket_buf_bytes = -1; /* keep the unit test independent of rmem_max */
    return o;
}

static struct sockaddr_in
peer4(void)
{
    struct sockaddr_in p;
    memset(&p, 0, sizeof(p));
    p.sin_family = AF_INET;
    p.sin_port = htons(4433);
    p.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return p;
}

static void
noop_tun_output(const uint8_t *p, size_t l, void *u)
{
    (void)p;
    (void)l;
    (void)u;
}

static void
noop_config_ready(const mqvpn_tunnel_info_t *i, void *u)
{
    (void)i;
    (void)u;
}

/* ── tests ── */

static void
test_ctor_invalid_args_leave_fd_open(void)
{
    int fd = make_udp_fd();
    void *ctx = (void *)0x1;
    mqvpn_bind_posix_opts_t o = opts_default(1, 0);
    assert(mqvpn_bind_posix_path_new(-1, &o, &ctx) == MQVPN_ERR_INVALID_ARG);
    assert(mqvpn_bind_posix_path_new(fd, NULL, &ctx) == MQVPN_ERR_INVALID_ARG);
    assert(mqvpn_bind_posix_path_new(fd, &o, NULL) == MQVPN_ERR_INVALID_ARG);
    o.struct_size = 2; /* does not cover udp_gso */
    assert(mqvpn_bind_posix_path_new(fd, &o, &ctx) == MQVPN_ERR_INVALID_ARG);
    assert(ctx == (void *)0x1);      /* *out_ctx untouched */
    assert(fcntl(fd, F_GETFD) >= 0); /* fd still open */
    assert(mqvpn_bind_posix_server_new(-1, &o, &ctx) == MQVPN_ERR_INVALID_ARG);
    close(fd);
    printf("  test_ctor_invalid_args_leave_fd_open: OK\n");
}

static void
test_ctor_no_memory_leaves_fd_open_and_out_ctx_untouched(void)
{
    int fd = make_udp_fd();
    void *ctx = (void *)0x1;
    mqvpn_bind_posix_opts_t o = opts_default(0, 0);
    seam_reset();
    seam_calloc_fail_next = 1;
    assert(mqvpn_bind_posix_path_new(fd, &o, &ctx) == MQVPN_ERR_NO_MEMORY);
    assert(ctx == (void *)0x1);
    assert(fcntl(fd, F_GETFD) >= 0);
    seam_calloc_fail_next = 1;
    assert(mqvpn_bind_posix_server_new(fd, &o, &ctx) == MQVPN_ERR_NO_MEMORY);
    assert(ctx == (void *)0x1);
    assert(fcntl(fd, F_GETFD) >= 0);
    /* scope-table growth failure degrades to bind-wide sticky, never crashes */
    void *sctx = NULL;
    mqvpn_bind_posix_opts_t og = opts_default(1, 0);
    assert(mqvpn_bind_posix_server_new(fd, &og, &sctx) == MQVPN_OK);
    if (mqvpn_udp_gso_probe()) {
        struct sockaddr_in p = peer4();
        uint8_t pkt[100] = {0};
        mqvpn_datagram_t d[2] = {{pkt, 100}, {pkt, 100}};
        seam_reset();
        seam_fail_once_gso = 1;
        seam_calloc_fail_next = 1; /* the first insert grows the table → fails */
        assert(mqvpn_bind_posix_server_ops()->send(sctx, 5, d, 2, (struct sockaddr *)&p,
                                                   sizeof(p)) == 2);
        seam_reset();
        assert(mqvpn_bind_posix_server_ops()->send(sctx, 6, d, 2, (struct sockaddr *)&p,
                                                   sizeof(p)) == 2);
        assert(seam_sendmmsg_calls == 1 &&
               seam_sendmsg_calls == 0); /* every scope sticky now */
    }
    mqvpn_bind_posix_server_free(sctx);
    close(fd);
    printf("  test_ctor_no_memory_leaves_fd_open_and_out_ctx_untouched: OK\n");
}

static void
test_ctor_copies_opts_and_larger_struct_size_accepted(void)
{
    int fd = make_udp_fd();
    void *ctx = NULL;
    /* udp_gso = 0 here so this ctx never triggers the once-per-process marker;
     * the marker test below relies on exactly one GSO-allowed ctx in main(). */
    mqvpn_bind_posix_opts_t *heap = malloc(sizeof(*heap) + 64);
    *heap = opts_default(0, 0);
    heap->struct_size = sizeof(*heap) + 64; /* newer caller: prefix copy */
    snprintf(heap->tag, sizeof(heap->tag), "eth0");
    assert(mqvpn_bind_posix_path_new(fd, heap, &ctx) == MQVPN_OK);
    assert(ctx != NULL);
    memset(heap, 0xFF, sizeof(*heap) + 64);
    free(heap); /* ASan: any retained pointer use below is a UAF */
    seam_reset();
    uint8_t pkt[100] = {0};
    mqvpn_datagram_t d[2] = {{pkt, sizeof(pkt)}, {pkt, sizeof(pkt)}};
    struct sockaddr_in p = peer4();
    assert(mqvpn_bind_posix_path_ops()->send(ctx, d, 2, (struct sockaddr *)&p,
                                             sizeof(p)) == 2);
    mqvpn_bind_posix_path_ops()->release(ctx);
    assert(fcntl(fd, F_GETFD) >= 0); /* release never closes the borrowed fd */
    close(fd);
    printf("  test_ctor_copies_opts_and_larger_struct_size_accepted: OK\n");
}

static void
test_gro_unsupported_still_constructs(void)
{
    /* A TCP socket has no UDP_GRO: enable fails with ENOPROTOOPT/EOPNOTSUPP. */
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(fd >= 0);
    void *ctx = NULL;
    mqvpn_bind_posix_opts_t o = opts_default(0, 1);
    assert(mqvpn_bind_posix_path_new(fd, &o, &ctx) == MQVPN_OK);
    assert(mqvpn_bind_posix_path_gro_enabled(ctx) == 0);
    assert(mqvpn_bind_posix_path_gro_errno(ctx) != 0);
    mqvpn_bind_posix_path_free(ctx);
    close(fd);
    printf("  test_gro_unsupported_still_constructs: OK\n");
}

static void
test_gro_on_udp_socket_is_consistent(void)
{
    int fd = make_udp_fd();
    void *ctx = NULL;
    mqvpn_bind_posix_opts_t o = opts_default(0, 1);
    assert(mqvpn_bind_posix_path_new(fd, &o, &ctx) == MQVPN_OK);
    /* Kernels < 5.0 lack UDP_GRO; accept either outcome but require the flag
     * and the errno accessor to agree. */
    if (mqvpn_bind_posix_path_gro_enabled(ctx))
        assert(mqvpn_bind_posix_path_gro_errno(ctx) == 0);
    else
        assert(mqvpn_bind_posix_path_gro_errno(ctx) == ENOPROTOOPT ||
               mqvpn_bind_posix_path_gro_errno(ctx) == EOPNOTSUPP);
    mqvpn_bind_posix_path_free(ctx);
    close(fd);
    printf("  test_gro_on_udp_socket_is_consistent: OK\n");
}

static void
test_send_contract_prefix_and_codes(void)
{
    int fd = make_udp_fd();
    void *ctx = NULL;
    mqvpn_bind_posix_opts_t o = opts_default(0, 0); /* GSO off: sendmmsg path */
    assert(mqvpn_bind_posix_path_new(fd, &o, &ctx) == MQVPN_OK);
    const mqvpn_path_ops_t *ops = mqvpn_bind_posix_path_ops();
    struct sockaddr_in p = peer4();
    uint8_t pkt[100] = {0};
    mqvpn_datagram_t d[40];
    for (int i = 0; i < 40; i++)
        d[i] = (mqvpn_datagram_t){pkt, sizeof(pkt)};

    seam_reset();
    assert(ops->send(ctx, d, 3, (struct sockaddr *)&p, sizeof(p)) == 3);
    /* n > 32 is clamped: the accepted prefix is 32, the core re-offers the rest */
    assert(ops->send(ctx, d, 40, (struct sockaddr *)&p, sizeof(p)) == 32);
    /* n == 1 without GSO is a real sendto() (not seam-interceptable): use n == 2
     * for the error-code cases so the seam decides. */
    seam_fail_errno = EAGAIN;
    assert(ops->send(ctx, d, 2, (struct sockaddr *)&p, sizeof(p)) ==
           MQVPN_TX_WOULD_BLOCK);
    seam_fail_errno = ENETUNREACH;
    assert(ops->send(ctx, d, 2, (struct sockaddr *)&p, sizeof(p)) == MQVPN_TX_FAILED);
    assert(ops->send(ctx, d, 0, (struct sockaddr *)&p, sizeof(p)) ==
           MQVPN_TX_FAILED); /* n==0 */
    mqvpn_transport_stats_t st = {0};
    assert(ops->get_stats(ctx, &st) == MQVPN_OK);
    assert(st.tx_sends == 2 && st.tx_datagrams == 35); /* failed calls count nothing */
    /* n == 1, GSO off: the real sendto() to 127.0.0.1:4433 on an unconnected
     * UDP socket succeeds (nobody listens; ICMP unreachable is asynchronous). */
    assert(ops->send(ctx, d, 1, (struct sockaddr *)&p, sizeof(p)) == 1);
    assert(ops->get_stats(ctx, &st) == MQVPN_OK);
    assert(st.tx_sends == 3 && st.tx_datagrams == 36);
    mqvpn_bind_posix_path_free(ctx);
    close(fd);
    printf("  test_send_contract_prefix_and_codes: OK\n");
}

/* Drives the sticky-scope logic. The process-wide probe + marker already
 * fired in the NO_MEMORY test (first GSO-allowed ctx); the ctest wrapper
 * asserts exactly one marker for the whole binary. The probe is a real
 * kernel property, so the sticky assertions are conditional on UDP_SEGMENT. */
static void
test_server_scope_sticky_state(void)
{
    int fd = make_udp_fd();
    void *ctx = NULL;
    mqvpn_bind_posix_opts_t o = opts_default(1, 0);
    assert(mqvpn_bind_posix_server_new(fd, &o, &ctx) == MQVPN_OK);
    const mqvpn_server_transport_ops_t *ops = mqvpn_bind_posix_server_ops();
    struct sockaddr_in p = peer4();
    uint8_t pkt[100] = {0};
    mqvpn_datagram_t d[2] = {{pkt, 100}, {pkt, 100}};
    int gso_avail = mqvpn_udp_gso_probe();

    seam_reset();
    seam_fail_once_gso = 1;
    /* in-call retry */
    assert(ops->send(ctx, 7, d, 2, (struct sockaddr *)&p, sizeof(p)) == 2);
    seam_reset();
    assert(ops->send(ctx, 7, d, 2, (struct sockaddr *)&p, sizeof(p)) == 2);
    int scope7_sticky = (seam_sendmmsg_calls == 1 && seam_sendmsg_calls == 0);
    seam_reset();
    assert(ops->send(ctx, 8, d, 2, (struct sockaddr *)&p, sizeof(p)) == 2);
    int scope8_uses_gso = (seam_sendmsg_calls == 1);
    seam_reset();
    seam_fail_once_gso = 1;
    assert(ops->send(ctx, 0, d, 2, (struct sockaddr *)&p, sizeof(p)) == 2);
    seam_reset();
    assert(ops->send(ctx, 0, d, 2, (struct sockaddr *)&p, sizeof(p)) == 2);
    int scope0_not_sticky = (seam_sendmsg_calls == 1);
    ops->release_scope(ctx, 7);
    seam_reset();
    assert(ops->send(ctx, 7, d, 2, (struct sockaddr *)&p, sizeof(p)) == 2);
    int scope7_gso_again = (seam_sendmsg_calls == 1);
    ops->release_scope(ctx, 0); /* harmless no-op */
    if (gso_avail) {
        assert(scope7_sticky);
        assert(scope8_uses_gso);
        assert(scope0_not_sticky);
        assert(scope7_gso_again);
    } else {
        printf("  (UDP_SEGMENT unavailable on this kernel: sticky checks skipped)\n");
    }
    mqvpn_bind_posix_server_free(ctx);
    close(fd);
    printf("  test_server_scope_sticky_state: OK\n");
}

/* O(1) scope table under load: 300 scopes sticky-disabled, odd ones released,
 * every state re-verified through the seam's syscall choice. Conditional on
 * UDP_SEGMENT (the sticky path only exists when GSO is available). Expect
 * ~300 "udp-gso: runtime GSO failure" WARN lines on stderr: one per scope
 * (the WARN is one-shot per sticky slot) — noise, not a failure. */
static void
test_server_scope_table_many(void)
{
    if (!mqvpn_udp_gso_probe()) {
        printf("  test_server_scope_table_many: skipped (no UDP_SEGMENT)\n");
        return;
    }
    int fd = make_udp_fd();
    void *ctx = NULL;
    mqvpn_bind_posix_opts_t o = opts_default(1, 0);
    assert(mqvpn_bind_posix_server_new(fd, &o, &ctx) == MQVPN_OK);
    const mqvpn_server_transport_ops_t *ops = mqvpn_bind_posix_server_ops();
    struct sockaddr_in p = peer4();
    uint8_t pkt[100] = {0};
    mqvpn_datagram_t d[2] = {{pkt, 100}, {pkt, 100}};
    for (uint64_t sc = 1; sc <= 300; sc++) {
        seam_reset();
        seam_fail_once_gso = 1;
        assert(ops->send(ctx, sc, d, 2, (struct sockaddr *)&p, sizeof(p)) == 2);
    }
    for (uint64_t sc = 1; sc <= 300; sc += 2)
        ops->release_scope(ctx, sc);
    for (uint64_t sc = 1; sc <= 300; sc++) {
        seam_reset();
        assert(ops->send(ctx, sc, d, 2, (struct sockaddr *)&p, sizeof(p)) == 2);
        if (sc % 2 == 0)
            assert(seam_sendmmsg_calls == 1 &&
                   seam_sendmsg_calls == 0); /* still sticky */
        else
            assert(seam_sendmsg_calls == 1); /* released: GSO again */
    }
    for (uint64_t sc = 2; sc <= 300; sc += 2)
        ops->release_scope(ctx, sc);
    ops->release_scope(ctx, 4242); /* unknown scope: harmless */
    mqvpn_bind_posix_server_free(ctx);
    close(fd);
    printf("  test_server_scope_table_many: OK\n");
}

static void
test_get_stats_struct_size_prefix(void)
{
    int fd = make_udp_fd();
    void *ctx = NULL;
    mqvpn_bind_posix_opts_t o = opts_default(0, 0);
    assert(mqvpn_bind_posix_path_new(fd, &o, &ctx) == MQVPN_OK);
    mqvpn_bind_posix_stats_t st;
    memset(&st, 0xEE, sizeof(st));
    st.struct_size =
        (uint32_t)offsetof(mqvpn_bind_posix_stats_t, rx_receives); /* older caller */
    mqvpn_bind_posix_path_get_stats(ctx, &st);
    assert(st.struct_size == offsetof(mqvpn_bind_posix_stats_t, rx_receives));
    assert(st.rx_receives == 0xEEEEEEEEEEEEEEEEull); /* beyond the prefix: untouched */
    /* Below the size field itself: nothing may be written at all. */
    for (uint32_t tiny = 1; tiny <= 3; tiny++) {
        memset(&st, 0xEE, sizeof(st));
        st.struct_size = tiny;
        mqvpn_bind_posix_path_get_stats(ctx, &st);
        assert(st.struct_size == tiny); /* untouched, not written back */
    }
    mqvpn_bind_posix_path_free(ctx);
    close(fd);
    printf("  test_get_stats_struct_size_prefix: OK\n");
}

/* RX: a client with an engine but no connection; xquic discards the fake
 * datagrams, which is all the counter test needs. */
static void
test_rx_drain_budget_and_counters(void)
{
    int fd = make_udp_fd();
    void *ctx = NULL;
    mqvpn_bind_posix_opts_t o = opts_default(0, 0);
    assert(mqvpn_bind_posix_path_new(fd, &o, &ctx) == MQVPN_OK);
    mqvpn_config_t *cfg = mqvpn_config_new();
    mqvpn_config_set_server(cfg, "1.2.3.4", 443);
    mqvpn_client_callbacks_t cbs = MQVPN_CLIENT_CALLBACKS_INIT;
    cbs.tun_output = noop_tun_output;
    cbs.tunnel_config_ready = noop_config_ready;
    mqvpn_client_t *c = mqvpn_client_new(cfg, &cbs, NULL);
    mqvpn_config_free(cfg);
    assert(c);
    mqvpn_path_handle_t h =
        mqvpn_client_add_path(c, NULL, mqvpn_bind_posix_path_ops(), ctx, NULL);
    assert(h >= 0);

    /* 5 aggregates of 4 segments each queued, budget 10: the third receive
     * overshoots the soft threshold (never stops mid-aggregate) → 3 receives,
     * 12 datagrams; the remaining 2 aggregates come out on the next drain. */
    seam_reset();
    seam_recv_queue = 5;
    seam_recv_len = 400;
    seam_recv_seg = 100;
    assert(mqvpn_bind_posix_path_drain(ctx, c, h, 10) == 3);
    mqvpn_bind_posix_stats_t st = {.struct_size = sizeof(st)};
    mqvpn_bind_posix_path_get_stats(ctx, &st);
    assert(st.rx_receives == 3 && st.rx_datagrams == 12);
    assert(mqvpn_bind_posix_path_drain(ctx, c, h, 64) == 2);
    mqvpn_bind_posix_path_get_stats(ctx, &st);
    assert(st.rx_receives == 5 && st.rx_datagrams == 20);

    /* budget 1 with 5 single datagrams queued: exactly one receive */
    seam_reset();
    seam_recv_queue = 5;
    assert(mqvpn_bind_posix_path_drain(ctx, c, h, 1) == 1);
    /* drained: 0 */
    seam_reset();
    assert(mqvpn_bind_posix_path_drain(ctx, c, h, 64) == 0);
    /* handle < 0: consumed but not counted */
    seam_reset();
    seam_recv_queue = 2;
    mqvpn_bind_posix_path_get_stats(ctx, &st);
    uint64_t before = st.rx_receives;
    assert(mqvpn_bind_posix_path_drain(ctx, c, -1, 64) == 2);
    mqvpn_bind_posix_path_get_stats(ctx, &st);
    assert(st.rx_receives == before);

    mqvpn_client_destroy(c); /* finalises ctx */
    close(fd);
    printf("  test_rx_drain_budget_and_counters: OK\n");
}

int
main(void)
{
    /* the marker is INFO; the ctest wrapper counts it */
    mqvpn_log_set_level(MQVPN_LOG_INFO);
    printf("test_bind_posix:\n");
    test_ctor_invalid_args_leave_fd_open();
    /* GSO-allowed server ctx: may emit the marker first — still exactly one
     * per process */
    test_ctor_no_memory_leaves_fd_open_and_out_ctx_untouched();
    test_ctor_copies_opts_and_larger_struct_size_accepted();
    test_gro_unsupported_still_constructs();
    test_gro_on_udp_socket_is_consistent();
    test_send_contract_prefix_and_codes();
    /* GSO-allowed; the probe/marker already ran in the NO_MEMORY test */
    test_server_scope_sticky_state();
    test_server_scope_table_many(); /* also GSO-allowed; no 2nd marker */
    test_get_stats_struct_size_prefix();
    test_rx_drain_budget_and_counters();
    printf("test_bind_posix: all OK\n");
    return 0;
}
