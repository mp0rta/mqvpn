// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/cli/ctl_ipc.h — mqvpnctl management-client IPC: connect + NDJSON
 * request/response over AF_UNIX.
 *
 * Deliberately libevent-free: a blocking fd + poll(2) timeouts + memchr
 * framing (the fd is switched to non-blocking only transiently, for the
 * duration of the connect(2) call, so that failure can be observed via
 * poll(POLLOUT) instead of blocking indefinitely — see ctl_ipc.c).
 *
 * This header may include libmqvpn.h for MQVPN_VERSION_{MAJOR,MINOR,PATCH}
 * only (a compile-time macro, not a linked symbol) — mqvpnctl must never
 * link libmqvpn/xquic/libevent (machine-verified by
 * scripts/ci_e2e/run_client_mgmt_ipc_phase1_test.sh, T9).
 */
#ifndef MQVPN_CTL_IPC_H
#define MQVPN_CTL_IPC_H

#include "cmp_types.h"
#include "libmqvpn.h"

#include <stddef.h>
#include <stdint.h>

/* mqvpnctl's own version string, shared by ctl_main.c's `version` output and
 * ctl_ipc.c's system.hello client_version field. */
#define CTL_STRINGIFY2(x) #x
#define CTL_STRINGIFY(x)  CTL_STRINGIFY2(x)
#define CTL_VERSION_STR                \
    CTL_STRINGIFY(MQVPN_VERSION_MAJOR) \
    "." CTL_STRINGIFY(MQVPN_VERSION_MINOR) "." CTL_STRINGIFY(MQVPN_VERSION_PATCH)

/* Per-operation default timeouts (ms), used when ctl_conn_t.timeout_ms == 0
 * (no --timeout override). A non-zero timeout_ms overrides ALL of them. */
#define CTL_TIMEOUT_CONNECT_MS 2000
#define CTL_TIMEOUT_HELLO_MS   2000
#define CTL_TIMEOUT_DEFAULT_MS 5000

typedef enum {
    CTL_OK = 0,
    CTL_E_UNAVAILABLE, /* connect refused/ENOENT/socket error */
    CTL_E_TIMEOUT,     /* poll(2) deadline exceeded */
    CTL_E_PROTOCOL,    /* malformed response, id mismatch, or
                        * MQVPN_CLIENT_PROTOCOL_INCOMPATIBLE */
    CTL_E_IO,          /* send/recv error, or EOF mid-response */
    CTL_E_REMOTE,      /* endpoint returned ok:false, any other error code */
} ctl_err_t;

typedef struct {
    int fd;
    char rbuf[CMP_MAX_RESPONSE_BYTES];
    size_t rlen;
    uint64_t next_id;
    /* 0 == use the per-operation defaults above; non-zero overrides all of
     * them (set from --timeout N). */
    int timeout_ms;
} ctl_conn_t;

/* Non-blocking connect(2) + poll(POLLOUT) + getsockopt(SO_ERROR) — POLLOUT
 * fires on failure too; skipping SO_ERROR would treat ECONNREFUSED as
 * success. `endpoint` is a filesystem path (any "unix://" prefix must
 * already be stripped by the caller). `timeout_ms` is the --timeout
 * override (0 = use CTL_TIMEOUT_CONNECT_MS) and is stashed in *c for later
 * ctl_request/ctl_hello calls. On success *c is fully initialized (fd,
 * rlen=0, next_id=1) and the fd is left in blocking mode. Returns CTL_OK or
 * a ctl_err_t; on error, `err` holds a human-readable reason. */
int ctl_connect(ctl_conn_t *c, const char *endpoint, int timeout_ms, char *err,
                size_t errlen);

/* Send one CMP request (method + a raw JSON object literal for params) and
 * read back the matching response line. `resp` receives the raw response
 * JSON (NUL-terminated, no trailing LF); the caller parses it with
 * json_mini.h helpers. Uses c->timeout_ms if set, else
 * CTL_TIMEOUT_DEFAULT_MS. Returns CTL_OK, or a ctl_err_t with `err` filled
 * in (for CTL_E_REMOTE/CTL_E_PROTOCOL, `err` includes the endpoint's error
 * code and message). */
int ctl_request(ctl_conn_t *c, const char *method, const char *params_json, char *resp,
                size_t resp_cap, char *err, size_t errlen);

/* Sends system.hello with {client_name:"mqvpnctl", client_version,
 * supported_protocols:["1.0"]}. Uses c->timeout_ms if set, else
 * CTL_TIMEOUT_HELLO_MS. On ok:true, Phase 1 does not need anything from the
 * result body (resp still receives the raw response for callers that want
 * it). On error.code == MQVPN_CLIENT_PROTOCOL_INCOMPATIBLE, returns
 * CTL_E_PROTOCOL. */
int ctl_hello(ctl_conn_t *c, char *resp, size_t resp_cap, char *err, size_t errlen);

void ctl_close(ctl_conn_t *c);

#endif
