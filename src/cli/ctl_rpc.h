// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef CTL_RPC_H
#define CTL_RPC_H

#include "ctl_sock.h"
#include "json_util.h"
#include "libmqvpn.h"

#define CTL_STR_(x) #x
#define CTL_STR(x)  CTL_STR_(x)
#define CTL_VERSION_STR          \
    CTL_STR(MQVPN_VERSION_MAJOR) \
    "." CTL_STR(MQVPN_VERSION_MINOR) "." CTL_STR(MQVPN_VERSION_PATCH)

#define CTL_TIMEOUT_CONNECT_MS 2000
#define CTL_TIMEOUT_HELLO_MS   2000
#define CTL_TIMEOUT_DEFAULT_MS 5000

typedef struct {
    yyjson_doc *doc;
    yyjson_val *result;
    yyjson_val *error;
    int error_code;
} ctl_reply_t;

/* E_CONNECT: connect stage failed (sock_err: NOENT/ACCESS/REFUSED/TIMEOUT/IO).
 * E_SOCK: send/receive failed after connecting (EOF/IO/TOO_LONG).
 * E_TIMEOUT: no reply in time. E_PROTOCOL: reply is not valid JSON-RPC.
 * E_REMOTE: the endpoint answered with an error (reply->error is set). */
typedef enum {
    CTL_RPC_OK = 0,
    CTL_RPC_E_CONNECT,
    CTL_RPC_E_SOCK,
    CTL_RPC_E_TIMEOUT,
    CTL_RPC_E_PROTOCOL,
    CTL_RPC_E_REMOTE
} ctl_rpc_status_t;

/* 0 or CTL_RPC_E_CONNECT. */
int ctl_rpc_connect(ctl_sock_t *s, const char *path, int timeout_ms,
                    ctl_sock_err_t *sock_err);
/* Sends one request line and validates one reply line. params (owned by pdoc)
 * may be NULL, in which case no "params" member is sent and pdoc may be NULL.
 * sock_err is filled for E_SOCK and E_TIMEOUT. On OK/E_REMOTE the caller
 * releases the reply with ctl_reply_free(). */
int ctl_rpc_call(ctl_sock_t *s, int id, const char *method, yyjson_mut_doc *pdoc,
                 yyjson_mut_val *params, int timeout_ms, ctl_reply_t *reply,
                 ctl_sock_err_t *sock_err);
void ctl_reply_free(ctl_reply_t *r);
int ctl_rpc_hello(ctl_sock_t *s, int timeout_ms, ctl_reply_t *reply,
                  ctl_sock_err_t *sock_err);

int ctl_exit_code_for(ctl_rpc_status_t st, ctl_sock_err_t sock_err, int remote_code);

#endif /* CTL_RPC_H */
