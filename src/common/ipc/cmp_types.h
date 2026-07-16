// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/common/ipc/cmp_types.h — mqvpn Client Management Protocol (CMP) constants.
 * Shared by the management endpoint (client process) and management clients
 * (mqvpnctl). No OS / libevent / libmqvpn dependencies allowed here. */
#ifndef MQVPN_CMP_TYPES_H
#define MQVPN_CMP_TYPES_H

#include <stddef.h>

#define CMP_PROTOCOL_VERSION   "1.0"
#define CMP_ENDPOINT_NAME      "mqvpn-client"
#define CMP_MAX_REQUEST_BYTES  (64 * 1024)
#define CMP_MAX_RESPONSE_BYTES (1024 * 1024)
#define CMP_MIN_RESPONSE_BUF                           \
    256 /* mgmt_dispatch_request の out_cap 下限。 \
         * RESPONSE_TOO_LARGE 固定短文が必ず収まる */
#define CMP_MAX_CONNECTIONS      32
#define CMP_DEFAULT_SOCKET_PATH  "/run/mqvpn/client.sock"
#define CMP_FALLBACK_SOCKET_PATH "/var/run/mqvpn/client.sock"

#endif
