// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * socket_compat.h — Thin wrappers over Berkeley/Winsock differences.
 *
 * Header-only inline. No .c file. Each TU that includes this gets its
 * own internal-linkage copy of the inline functions.
 *
 * Why header-only: the wrappers are tiny enough that -O2 fully inlines
 * them at every call site, so no per-TU bloat lands in release builds.
 *
 * Consider splitting into a .c file when:
 *   - A function grows beyond a trivial wrapper (e.g. switching to
 *     FormatMessageA for proper Windows error stringification).
 *   - State is introduced that must be shared across TUs (a single
 *     buffer rather than per-TU TLS, lazy init, etc.).
 *   - The header is included from many TUs (~5+) and debug builds
 *     start showing measurable per-TU duplication in nm output.
 */
#ifndef COMPAT_SOCKET_COMPAT_H
#define COMPAT_SOCKET_COMPAT_H

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <unistd.h>
#  include <fcntl.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#endif

#if defined(_MSC_VER)
#  define MQVPN_TLS __declspec(thread)
#else
#  define MQVPN_TLS _Thread_local
#endif

/* MSG_NOSIGNAL is Linux/POSIX-2008-only. Darwin has no such send() flag —
 * SIGPIPE suppression there is per-socket via SO_NOSIGPIPE, applied in
 * mqvpn_socket_tcp_nonblock_new() below. Windows has no SIGPIPE at all.
 * Callers pass MQVPN_MSG_NOSIGNAL in send() flags unconditionally. */
#ifdef MSG_NOSIGNAL
#  define MQVPN_MSG_NOSIGNAL MSG_NOSIGNAL
#else
#  define MQVPN_MSG_NOSIGNAL 0
#endif

/* Set socket to non-blocking mode. Returns 0 on success, -1 on failure.
 * The caller logs and decides what to do; this helper is silent. */
static inline int
mqvpn_socket_set_nonblock(int fd)
{
#ifdef _WIN32
    u_long nb = 1;
    return (ioctlsocket((SOCKET)fd, FIONBIO, &nb) == 0) ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

/* Send with DF set and never fragment locally, so a datagram that does not
 * fit the path is lost instead of fragmented: what PMTUD probes rely on.
 * On Linux the kernel's cached path MTU is ignored (PMTUDISC_PROBE): QUIC
 * sizes its own packets. Returns 0 on success, -1 on failure. */
static inline int
mqvpn_socket_set_dontfrag(int fd, int af)
{
#if defined(__linux__)
    if (af == AF_INET6) {
        int v = IPV6_PMTUDISC_PROBE;
        /* also for IPv4-mapped traffic on a dual-stack socket; a socket
         * that cannot take it is IPv6 only anyway */
        int v4 = IP_PMTUDISC_PROBE;
        (void)setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &v4, sizeof(v4));
        return setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &v, sizeof(v));
    }
    int v = IP_PMTUDISC_PROBE;
    return setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &v, sizeof(v));
#elif defined(__APPLE__)
    int on = 1;
    if (af == AF_INET6)
        return setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &on, sizeof(on));
    return setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &on, sizeof(on));
#elif defined(_WIN32)
    DWORD on = 1;
    if (af == AF_INET6)
        return setsockopt((SOCKET)fd, IPPROTO_IPV6, IPV6_DONTFRAG, (const char *)&on,
                          sizeof(on)) == 0
                   ? 0
                   : -1;
    return setsockopt((SOCKET)fd, IPPROTO_IP, IP_DONTFRAGMENT, (const char *)&on,
                      sizeof(on)) == 0
               ? 0
               : -1;
#else
    (void)fd;
    (void)af;
    return -1;
#endif
}

/* Close a socket. Idempotent for fd<0. Errors are not reported. */
static inline void
mqvpn_socket_close(int fd)
{
    if (fd < 0) return;
#ifdef _WIN32
    closesocket((SOCKET)fd);
#else
    close(fd);
#endif
}

/* Create a non-blocking TCP socket, or -1 on failure (errno set by the
 * failing syscall). Uses SOCK_NONBLOCK atomically where the platform has
 * it (Linux); falls back to socket() + fcntl elsewhere (Darwin, Windows).
 * On Darwin additionally sets SO_NOSIGPIPE — the per-socket counterpart
 * of the MQVPN_MSG_NOSIGNAL send() flag above, and the only SIGPIPE
 * suppression available there. */
static inline int
mqvpn_socket_tcp_nonblock_new(int domain)
{
#ifdef SOCK_NONBLOCK
    int fd = socket(domain, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
#else
    int fd = (int)socket(domain, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (mqvpn_socket_set_nonblock(fd) < 0) {
        int saved = errno;
        mqvpn_socket_close(fd);
        errno = saved;
        return -1;
    }
#endif
#ifdef SO_NOSIGPIPE
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    return fd;
}

/* Return a printable string for the most recent socket error.
 *
 * Linux: strerror(errno).
 * Windows: thread-local buffer formatted as "WSA <code>" so the caller
 * can use a uniform "%s" format.
 *
 * The returned pointer is valid until the next call from the same
 * thread. Do NOT use it twice in the same expression — both
 * arguments would resolve to the same buffer with the latter call's
 * contents (e.g. `LOG("%s %s", strerr(), strerr())` is undefined). */
static inline const char *
mqvpn_socket_strerror(void)
{
#ifdef _WIN32
    static MQVPN_TLS char buf[32];
    snprintf(buf, sizeof(buf), "WSA %d", WSAGetLastError());
    return buf;
#else
    return strerror(errno);
#endif
}

#endif /* COMPAT_SOCKET_COMPAT_H */
