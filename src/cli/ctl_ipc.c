// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/cli/ctl_ipc.c — mqvpnctl management-client IPC implementation. */
#include "ctl_ipc.h"

#include "cmp_json.h"
#include "cmp_types.h"
#include "json_mini.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* Absolute monotonic deadline, `ms` from now (ms <= 0 means "already due"). */
static void
deadline_set(struct timespec *dl, int ms)
{
    clock_gettime(CLOCK_MONOTONIC, dl);
    if (ms < 0) ms = 0;
    dl->tv_sec += ms / 1000;
    dl->tv_nsec += (long)(ms % 1000) * 1000000L;
    if (dl->tv_nsec >= 1000000000L) {
        dl->tv_sec++;
        dl->tv_nsec -= 1000000000L;
    }
}

/* Milliseconds remaining until `dl`, clamped to >= 0 (poll(2) timeout unit). */
static int
deadline_remaining_ms(const struct timespec *dl)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long ms = (dl->tv_sec - now.tv_sec) * 1000L + (dl->tv_nsec - now.tv_nsec) / 1000000L;
    return ms < 0 ? 0 : (int)ms;
}

int
ctl_connect(ctl_conn_t *c, const char *endpoint, int timeout_ms, char *err, size_t errlen)
{
    c->fd = -1;
    c->rlen = 0;
    c->next_id = 1;
    c->timeout_ms = timeout_ms;

    int op_timeout = timeout_ms > 0 ? timeout_ms : CTL_TIMEOUT_CONNECT_MS;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(endpoint) >= sizeof(addr.sun_path)) {
        snprintf(err, errlen, "endpoint path too long: %s", endpoint);
        return CTL_E_UNAVAILABLE;
    }
    memcpy(addr.sun_path, endpoint, strlen(endpoint) + 1);

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        snprintf(err, errlen, "socket(): %s", strerror(errno));
        return CTL_E_UNAVAILABLE;
    }

    int orig_flags = fcntl(fd, F_GETFL, 0);
    if (orig_flags < 0 || fcntl(fd, F_SETFL, orig_flags | O_NONBLOCK) < 0) {
        snprintf(err, errlen, "fcntl(O_NONBLOCK): %s", strerror(errno));
        close(fd);
        return CTL_E_UNAVAILABLE;
    }

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        snprintf(err, errlen, "connect(%s): %s", endpoint, strerror(errno));
        close(fd);
        return CTL_E_UNAVAILABLE;
    }

    if (rc < 0) {
        /* EINPROGRESS: wait for the connect to complete. POLLOUT fires on
         * both success and failure — SO_ERROR is the only way to tell them
         * apart; skipping it would treat e.g. ECONNREFUSED as success. */
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        int pr = poll(&pfd, 1, op_timeout);
        if (pr == 0) {
            snprintf(err, errlen, "connect(%s): timed out", endpoint);
            close(fd);
            return CTL_E_TIMEOUT;
        }
        if (pr < 0) {
            snprintf(err, errlen, "poll(): %s", strerror(errno));
            close(fd);
            return CTL_E_UNAVAILABLE;
        }

        int soerr = 0;
        socklen_t sl = sizeof(soerr);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) < 0) {
            snprintf(err, errlen, "getsockopt(SO_ERROR): %s", strerror(errno));
            close(fd);
            return CTL_E_UNAVAILABLE;
        }
        if (soerr != 0) {
            snprintf(err, errlen, "connect(%s): %s", endpoint, strerror(soerr));
            close(fd);
            return CTL_E_UNAVAILABLE;
        }
    }

    /* Revert to blocking mode: every subsequent send/recv is guarded by its
     * own poll() call first (see ctl_do_request), so a plain blocking
     * syscall afterward will not actually block past the deadline. */
    if (fcntl(fd, F_SETFL, orig_flags) < 0) {
        snprintf(err, errlen, "fcntl(restore blocking): %s", strerror(errno));
        close(fd);
        return CTL_E_UNAVAILABLE;
    }

    c->fd = fd;
    return CTL_OK;
}

/* poll(POLLOUT)-guarded send loop; MSG_NOSIGNAL on the write side means a
 * peer that has already closed/RST the connection yields EPIPE instead of
 * SIGPIPE (the alternative — installing SIG_IGN for SIGPIPE — is also
 * required in ctl_main.c because a mid-response peer close can still raise
 * SIGPIPE on some libc/kernel combinations for reasons other than send(2);
 * this file's own contribution is MSG_NOSIGNAL on every send). */
static int
send_all(int fd, const char *buf, size_t len, const struct timespec *dl, char *err,
         size_t errlen)
{
    size_t sent = 0;
    struct pollfd pfd = {.fd = fd, .events = POLLOUT};

    while (sent < len) {
        int remain = deadline_remaining_ms(dl);
        if (remain == 0) {
            snprintf(err, errlen, "request send timed out");
            return CTL_E_TIMEOUT;
        }
        int pr = poll(&pfd, 1, remain);
        if (pr == 0) {
            snprintf(err, errlen, "request send timed out");
            return CTL_E_TIMEOUT;
        }
        if (pr < 0) {
            if (errno == EINTR) continue;
            snprintf(err, errlen, "poll(): %s", strerror(errno));
            return CTL_E_IO;
        }
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            snprintf(err, errlen, "send(): %s", strerror(errno));
            return CTL_E_IO;
        }
        sent += (size_t)n;
    }
    return CTL_OK;
}

/* poll(POLLIN)-guarded recv loop that fills c->rbuf until a LF appears,
 * then hands back a NUL-terminated line (LF stripped) and compacts any
 * remaining buffered bytes to the front of c->rbuf. */
static int
recv_line(ctl_conn_t *c, const struct timespec *dl, char **out_line, char *err,
          size_t errlen)
{
    struct pollfd pfd = {.fd = c->fd, .events = POLLIN};

    for (;;) {
        char *nl = memchr(c->rbuf, '\n', c->rlen);
        if (nl) {
            *nl = '\0';
            *out_line = c->rbuf;
            size_t consumed = (size_t)(nl - c->rbuf) + 1;
            size_t remaining = c->rlen - consumed;
            if (remaining > 0) {
                memmove(c->rbuf, c->rbuf + consumed, remaining);
            }
            c->rlen = remaining;
            return CTL_OK;
        }

        if (c->rlen >= sizeof(c->rbuf)) {
            snprintf(err, errlen, "response exceeded buffer without a newline");
            c->rlen = 0;
            return CTL_E_PROTOCOL;
        }

        int remain = deadline_remaining_ms(dl);
        if (remain == 0) {
            snprintf(err, errlen, "response timed out");
            return CTL_E_TIMEOUT;
        }
        int pr = poll(&pfd, 1, remain);
        if (pr == 0) {
            snprintf(err, errlen, "response timed out");
            return CTL_E_TIMEOUT;
        }
        if (pr < 0) {
            if (errno == EINTR) continue;
            snprintf(err, errlen, "poll(): %s", strerror(errno));
            return CTL_E_IO;
        }

        ssize_t n = recv(c->fd, c->rbuf + c->rlen, sizeof(c->rbuf) - c->rlen, 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            snprintf(err, errlen, "recv(): %s", strerror(errno));
            return CTL_E_IO;
        }
        if (n == 0) {
            /* EOF: mid-line (bytes buffered but no LF yet) is a protocol
             * violation; a clean EOF with nothing buffered is plain I/O. */
            snprintf(err, errlen,
                     c->rlen > 0 ? "connection closed mid-response"
                                 : "connection closed by endpoint");
            return c->rlen > 0 ? CTL_E_PROTOCOL : CTL_E_IO;
        }
        c->rlen += (size_t)n;
    }
}

/* Shared request/response round trip used by both ctl_request and
 * ctl_hello. Builds the request envelope, sends it, reads back the matching
 * response line into `resp`, and classifies ok:false responses. */
static int
ctl_do_request(ctl_conn_t *c, const char *method, const char *params_json, int timeout_ms,
               char *resp, size_t resp_cap, char *err, size_t errlen)
{
    uint64_t id = c->next_id++;

    char req[CMP_MAX_REQUEST_BYTES];
    cmp_buf_t rb;
    cmp_buf_init(&rb, req, sizeof(req));
    cmp_buf_appendf(&rb, "{\"id\":%llu,\"protocol\":\"%s\",\"method\":",
                    (unsigned long long)id, CMP_PROTOCOL_VERSION);
    cmp_json_append_str(&rb, method);
    cmp_buf_appendf(&rb, ",\"params\":%s}\n", params_json);
    if (rb.overflow) {
        snprintf(err, errlen, "request too large to build");
        return CTL_E_IO;
    }

    struct timespec dl;
    deadline_set(&dl, timeout_ms);

    int rc = send_all(c->fd, req, rb.len, &dl, err, errlen);
    if (rc != CTL_OK) return rc;

    for (;;) {
        char *line;
        rc = recv_line(c, &dl, &line, err, errlen);
        if (rc != CTL_OK) return rc;

        size_t linelen = strlen(line);
        if (linelen >= resp_cap) {
            snprintf(err, errlen, "response too large for caller buffer (%zu bytes)",
                     linelen);
            return CTL_E_PROTOCOL;
        }
        memcpy(resp, line, linelen + 1);

        uint64_t rid = 0;
        int has_rid = 0;
        const char *idv = json_find_key(resp, "id");
        if (idv) {
            uint64_t v;
            if (json_read_u64_strict(idv, &v) == 0) {
                rid = v;
                has_rid = 1;
            }
        }

        int ok = 0;
        const char *okv = json_find_key(resp, "ok");
        if (!okv || json_read_bool(okv, &ok) != 0) {
            snprintf(err, errlen, "malformed response (missing/invalid ok)");
            return CTL_E_PROTOCOL;
        }

        if (has_rid && rid != id) {
            /* Not the response to the request we just sent (should not
             * happen over a fresh connection with one in-flight request at
             * a time, but do not silently accept it). Keep reading in case
             * a stale/duplicate line precedes the real one. */
            continue;
        }
        if (!has_rid && ok) {
            snprintf(err, errlen, "malformed response (missing id on success)");
            return CTL_E_PROTOCOL;
        }
        /* An id-less ok:false response (the dispatcher omits id when it
         * could not parse one out of the request) is accepted as the
         * response to the current request per the CMP contract. */

        if (!ok) {
            char code[64] = "";
            char msg[192] = "";
            const char *errv = json_find_key(resp, "error");
            if (errv && *errv == '{') {
                const char *errend = json_object_end(errv);
                if (errend) {
                    const char *codev = json_find_key_bounded(errv, errend, "code");
                    if (codev) json_read_string(codev, code, sizeof(code));
                    const char *msgv = json_find_key_bounded(errv, errend, "message");
                    if (msgv) json_read_string(msgv, msg, sizeof(msg));
                }
            }
            snprintf(err, errlen, "%s: %s",
                     code[0] ? code : "MQVPN_CLIENT_INTERNAL_ERROR",
                     msg[0] ? msg : "(no message)");
            if (strcmp(code, "MQVPN_CLIENT_PROTOCOL_INCOMPATIBLE") == 0) {
                return CTL_E_PROTOCOL;
            }
            return CTL_E_REMOTE;
        }

        return CTL_OK;
    }
}

int
ctl_request(ctl_conn_t *c, const char *method, const char *params_json, char *resp,
            size_t resp_cap, char *err, size_t errlen)
{
    int timeout = c->timeout_ms ? c->timeout_ms : CTL_TIMEOUT_DEFAULT_MS;
    return ctl_do_request(c, method, params_json, timeout, resp, resp_cap, err, errlen);
}

int
ctl_hello(ctl_conn_t *c, char *resp, size_t resp_cap, char *err, size_t errlen)
{
    char params[256];
    cmp_buf_t pb;
    cmp_buf_init(&pb, params, sizeof(params));
    cmp_buf_appendf(&pb, "{\"client_name\":");
    cmp_json_append_str(&pb, "mqvpnctl");
    cmp_buf_appendf(&pb, ",\"client_version\":");
    cmp_json_append_str(&pb, CTL_VERSION_STR);
    cmp_buf_appendf(&pb, ",\"supported_protocols\":[\"%s\"]}", CMP_PROTOCOL_VERSION);
    if (pb.overflow) {
        snprintf(err, errlen, "internal: hello params buffer overflow");
        return CTL_E_IO;
    }

    int timeout = c->timeout_ms ? c->timeout_ms : CTL_TIMEOUT_HELLO_MS;
    return ctl_do_request(c, "system.hello", params, timeout, resp, resp_cap, err,
                          errlen);
}

void
ctl_close(ctl_conn_t *c)
{
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}
