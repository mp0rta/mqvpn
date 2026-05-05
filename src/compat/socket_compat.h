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

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <unistd.h>
#  include <fcntl.h>
#  include <sys/socket.h>
#  include <errno.h>
#endif

#if defined(_MSC_VER)
#  define MQVPN_TLS __declspec(thread)
#else
#  define MQVPN_TLS _Thread_local
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
