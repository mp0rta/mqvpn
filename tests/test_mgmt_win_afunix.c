// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* tests/test_mgmt_win_afunix.c — Windows only. One plain event_base (the
 * win32 select() backend, as mqvpn uses it) carries a UDP socket, the
 * AF_INET wake pair and an AF_UNIX listener with a bufferevent echo; all
 * three must fire within 2 seconds. Own CHECK, not assert(): the Windows job
 * builds Release. Elsewhere the test is skipped. */

#include <stdio.h>

#ifndef _WIN32

int
main(void)
{
    printf("skipped\n");
    return 0;
}

#else

#  include <winsock2.h>
#  include <windows.h>
#  include <ws2tcpip.h>
#  include <afunix.h>

#  include <event2/buffer.h>
#  include <event2/bufferevent.h>
#  include <event2/event.h>
#  include <event2/listener.h>
#  include <event2/util.h>

#  include <string.h>

static int g_failed;

#  define CHECK(c)                                                                  \
      do {                                                                          \
          if (!(c)) {                                                               \
              fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); \
              g_failed = 1;                                                         \
          }                                                                         \
      } while (0)

static int g_udp_ok, g_wake_ok, g_afunix_ok;
static struct event_base *g_eb;
static struct bufferevent *g_server_bev;

static void
udp_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    (void)arg;
    char buf[16];
    int n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
    if (n == 5 && memcmp(buf, "hello", 5) == 0) g_udp_ok = 1;
}

static void
wake_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    (void)arg;
    char c = 0;
    if (recv(fd, &c, 1, 0) == 1 && c == 'w') g_wake_ok = 1;
}

static void
server_read_cb(struct bufferevent *bev, void *arg)
{
    (void)arg;
    evbuffer_add_buffer(bufferevent_get_output(bev), bufferevent_get_input(bev));
}

static void
accept_cb(struct evconnlistener *l, evutil_socket_t fd, struct sockaddr *sa, int len,
          void *arg)
{
    (void)l;
    (void)sa;
    (void)len;
    (void)arg;
    g_server_bev = bufferevent_socket_new(g_eb, fd, BEV_OPT_CLOSE_ON_FREE);
    CHECK(g_server_bev != NULL);
    if (!g_server_bev) return;
    bufferevent_setcb(g_server_bev, server_read_cb, NULL, NULL, NULL);
    bufferevent_enable(g_server_bev, EV_READ | EV_WRITE);
}

static void
client_read_cb(struct bufferevent *bev, void *arg)
{
    (void)arg;
    char buf[16];
    size_t n = bufferevent_read(bev, buf, sizeof(buf));
    if (n == 5 && memcmp(buf, "ping\n", 5) == 0) g_afunix_ok = 1;
}

static void
timeout_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    (void)arg;
    event_base_loopbreak(g_eb);
}

int
main(void)
{
    WSADATA wsa;
    CHECK(WSAStartup(MAKEWORD(2, 2), &wsa) == 0);

    g_eb = event_base_new();
    CHECK(g_eb != NULL);
    if (!g_eb) return 1;

    /* (a) UDP: two loopback sockets, one datagram */
    evutil_socket_t u[2];
    struct sockaddr_in a;
    int alen = sizeof(a);
    for (int i = 0; i < 2; i++) {
        u[i] = socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(u[i] != INVALID_SOCKET);
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(bind(u[i], (struct sockaddr *)&a, sizeof(a)) == 0);
        CHECK(evutil_make_socket_nonblocking(u[i]) == 0);
    }
    CHECK(getsockname(u[0], (struct sockaddr *)&a, &alen) == 0);
    struct event *udp_ev = event_new(g_eb, u[0], EV_READ | EV_PERSIST, udp_cb, NULL);
    CHECK(udp_ev && event_add(udp_ev, NULL) == 0);
    CHECK(sendto(u[1], "hello", 5, 0, (struct sockaddr *)&a, sizeof(a)) == 5);

    /* (b) wake pair */
    evutil_socket_t pair[2];
    CHECK(evutil_socketpair(AF_INET, SOCK_STREAM, 0, pair) == 0);
    CHECK(evutil_make_socket_nonblocking(pair[0]) == 0);
    struct event *wake_ev = event_new(g_eb, pair[0], EV_READ | EV_PERSIST, wake_cb, NULL);
    CHECK(wake_ev && event_add(wake_ev, NULL) == 0);
    CHECK(send(pair[1], "w", 1, 0) == 1);

    /* (c) AF_UNIX listener, already listening when handed to libevent */
    char tmp[MAX_PATH];
    struct sockaddr_un un;
    DWORD tl = GetTempPathA(sizeof(tmp), tmp);
    CHECK(tl > 0 && tl < sizeof(tmp));
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    int pl = snprintf(un.sun_path, sizeof(un.sun_path), "%smqvpn-afunix-%lu.sock", tmp,
                      (unsigned long)GetCurrentProcessId());
    CHECK(pl > 0 && (size_t)pl < sizeof(un.sun_path));
    DeleteFileA(un.sun_path);

    evutil_socket_t lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(lfd != INVALID_SOCKET);
    CHECK(bind(lfd, (struct sockaddr *)&un, sizeof(un)) == 0);
    CHECK(listen(lfd, 4) == 0);
    CHECK(evutil_make_socket_nonblocking(lfd) == 0);
    struct evconnlistener *lis = evconnlistener_new(g_eb, accept_cb, NULL, 0, 0, lfd);
    CHECK(lis != NULL);

    evutil_socket_t cfd = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(cfd != INVALID_SOCKET);
    CHECK(connect(cfd, (struct sockaddr *)&un, sizeof(un)) == 0);
    CHECK(evutil_make_socket_nonblocking(cfd) == 0);
    struct bufferevent *cbev = bufferevent_socket_new(g_eb, cfd, BEV_OPT_CLOSE_ON_FREE);
    CHECK(cbev != NULL);
    if (cbev) {
        bufferevent_setcb(cbev, client_read_cb, NULL, NULL, NULL);
        bufferevent_enable(cbev, EV_READ | EV_WRITE);
        CHECK(bufferevent_write(cbev, "ping\n", 5) == 0);
    }

    struct timeval tv = {2, 0};
    struct event *tm = evtimer_new(g_eb, timeout_cb, NULL);
    CHECK(tm && evtimer_add(tm, &tv) == 0);

    event_base_dispatch(g_eb);

    printf("udp=%d wake=%d afunix=%d\n", g_udp_ok, g_wake_ok, g_afunix_ok);
    CHECK(g_udp_ok && g_wake_ok && g_afunix_ok);

    if (tm) event_free(tm);
    if (cbev) bufferevent_free(cbev);
    if (g_server_bev) bufferevent_free(g_server_bev);
    if (lis) evconnlistener_free(lis);
    evutil_closesocket(lfd);
    if (wake_ev) event_free(wake_ev);
    if (udp_ev) event_free(udp_ev);
    evutil_closesocket(pair[0]);
    evutil_closesocket(pair[1]);
    evutil_closesocket(u[0]);
    evutil_closesocket(u[1]);
    DeleteFileA(un.sun_path);
    event_base_free(g_eb);
    WSACleanup();
    return g_failed ? 1 : 0;
}

#endif /* _WIN32 */
