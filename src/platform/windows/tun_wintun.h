/*
 * tun_wintun.h — Wintun-based TUN device for Windows
 *
 * Provides the same logical interface as the Linux tun.h but backed
 * by the Wintun ring-buffer driver. A dedicated reader thread feeds
 * packets to the libevent loop through a socketpair.
 */

#ifndef MQVPN_TUN_WINTUN_H
#define MQVPN_TUN_WINTUN_H

#ifdef _WIN32

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stddef.h>

#include <event2/util.h>

/* Wintun opaque handles */
typedef void *WINTUN_ADAPTER_HANDLE;
typedef void *WINTUN_SESSION_HANDLE;

/* mqvpn_tun_write() returns this when the ring is full. */
#define MQVPN_TUN_EAGAIN (-2)

typedef struct {
    /* Wintun handles */
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;
    HANDLE                read_event;

    /* Adapter identification */
    NET_LUID              luid;
    DWORD                 if_index;
    char                  name[256];
    int                   mtu;

    /* Reader thread → libevent bridge (socketpair) */
    HANDLE                reader_thread;
    evutil_socket_t       pipe_rd;   /* libevent monitors this */
    evutil_socket_t       pipe_wr;   /* reader thread writes here */
    volatile LONG         stop;      /* InterlockedExchange flag */

    /* Address state */
    struct in_addr        addr;
    struct in_addr        peer_addr;
    struct in6_addr       addr6;
    int                   has_v6;
} mqvpn_tun_win_t;

/* Load wintun.dll and resolve function pointers. Call once at startup. */
int  mqvpn_wintun_load(void);

/* Create a Wintun adapter and start a session. */
int  mqvpn_tun_win_create(mqvpn_tun_win_t *tun, const char *dev_name);

/* Assign IPv4 point-to-point address. */
int  mqvpn_tun_win_set_addr(mqvpn_tun_win_t *tun, const char *addr,
                             const char *peer_addr, int prefix_len);

/* Assign IPv6 address. */
int  mqvpn_tun_win_set_addr6(mqvpn_tun_win_t *tun, const char *addr6,
                              int prefix_len);

/* Set MTU on the adapter. */
int  mqvpn_tun_win_set_mtu(mqvpn_tun_win_t *tun, int mtu);

/* Start the reader thread that bridges Wintun → socketpair. */
int  mqvpn_tun_win_start_reader(mqvpn_tun_win_t *tun);

/* Write a single IP packet to Wintun (called from main thread). */
int  mqvpn_tun_win_write(mqvpn_tun_win_t *tun, const uint8_t *buf, size_t len);

/* Destroy adapter, stop reader, close socketpair. */
void mqvpn_tun_win_destroy(mqvpn_tun_win_t *tun);

#endif /* _WIN32 */
#endif /* MQVPN_TUN_WINTUN_H */
