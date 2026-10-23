// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef CMP_ERROR_H
#define CMP_ERROR_H

#include <stddef.h>

/* Single source of truth: the enum, names and default messages are all
 * generated from this list. */
#define CMP_ERROR_LIST(X)                                       \
    X(PARSE_ERROR, -32700, "parse error")                       \
    X(INVALID_REQUEST, -32600, "invalid request")               \
    X(METHOD_NOT_FOUND, -32601, "method not found")             \
    X(INVALID_PARAMS, -32602, "invalid params")                 \
    X(INTERNAL_ERROR, -32603, "internal error")                 \
    X(RESPONSE_TOO_LARGE, -32000, "response too large")         \
    X(HANDSHAKE_REQUIRED, -32001, "handshake required")         \
    X(PROTOCOL_INCOMPATIBLE, -32002, "protocol incompatible")   \
    X(PERMISSION_DENIED, -32003, "permission denied")           \
    X(BUSY, -32004, "busy")                                     \
    X(TIMEOUT, -32005, "timeout")                               \
    X(UNSUPPORTED, -32006, "unsupported")                       \
    X(UNAVAILABLE, 1000, "unavailable")                         \
    X(NOT_CONNECTED, 1001, "not connected")                     \
    X(CONFIG_INVALID, 1002, "config invalid")                   \
    X(TUN_UNAVAILABLE, 1003, "tun unavailable")                 \
    X(SERVER_UNREACHABLE, 1004, "server unreachable")           \
    X(DNS_RESOLUTION_FAILED, 1005, "dns resolution failed")     \
    X(TLS_HANDSHAKE_FAILED, 1006, "tls handshake failed")       \
    X(AUTH_FAILED, 1007, "auth failed")                         \
    X(NO_ACTIVE_PATH, 1008, "no active path")                   \
    X(PATH_NOT_FOUND, 1009, "path not found")                   \
    X(PATH_VALIDATION_TIMEOUT, 1010, "path validation timeout") \
    X(MTU_TOO_LARGE, 1011, "mtu too large")

typedef enum {
#define CMP_X(name, code, msg) CMP_E_##name = (code),
    CMP_ERROR_LIST(CMP_X)
#undef CMP_X
} cmp_error_code_t;

/* "MQVPN_CLIENT_<name>"; NULL for an unknown code. */
const char *cmp_error_name(int code);
/* Default message; NULL for an unknown code. */
const char *cmp_error_message(int code);
/* 0 = found, -1 = unknown (or name NULL). */
int cmp_error_from_name(const char *name, int *code_out);
/* Number of table entries. */
size_t cmp_error_count(void);
/* i-th table entry; 0 = ok, -1 = out of range. Either out pointer may be NULL. */
int cmp_error_at(size_t i, int *code_out, const char **name_out);

#endif /* CMP_ERROR_H */
