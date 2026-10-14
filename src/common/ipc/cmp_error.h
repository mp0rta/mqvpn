// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/common/ipc/cmp_error.h — stable CMP error codes.
 *
 * Wire strings are "MQVPN_CLIENT_" + the enumerator suffix (e.g.
 * CMP_E_NO_ACTIVE_PATH -> "MQVPN_CLIENT_NO_ACTIVE_PATH"). The enum order and
 * values are a compatibility surface for management clients (mqvpnctl,
 * OpenMPTCProuter integration): append new codes before CMP_E__COUNT, never
 * renumber existing ones.
 */
#ifndef MQVPN_CMP_ERROR_H
#define MQVPN_CMP_ERROR_H

typedef enum {
    CMP_E_OK = 0,
    CMP_E_INTERNAL_ERROR,
    CMP_E_INVALID_ARGUMENT,
    CMP_E_METHOD_NOT_FOUND,
    CMP_E_PROTOCOL_INCOMPATIBLE,
    CMP_E_HANDSHAKE_REQUIRED,
    CMP_E_PERMISSION_DENIED,
    CMP_E_UNAVAILABLE,
    CMP_E_NOT_CONNECTED,
    CMP_E_CONFIG_INVALID,
    CMP_E_TUN_UNAVAILABLE,
    CMP_E_SERVER_UNREACHABLE,
    CMP_E_DNS_RESOLUTION_FAILED,
    CMP_E_TLS_HANDSHAKE_FAILED,
    CMP_E_AUTH_FAILED,
    CMP_E_NO_ACTIVE_PATH,
    CMP_E_PATH_NOT_FOUND,
    CMP_E_PATH_VALIDATION_TIMEOUT,
    CMP_E_MTU_TOO_LARGE,
    CMP_E_TIMEOUT,
    CMP_E_BUSY,
    CMP_E_UNSUPPORTED,
    CMP_E_RESPONSE_TOO_LARGE,
    CMP_E__COUNT
} cmp_error_code_t;

/* Stable wire string for a CMP error code. Out-of-range values (should never
 * occur) map to "MQVPN_CLIENT_INTERNAL_ERROR" rather than crashing. */
const char *cmp_error_code_str(cmp_error_code_t code);

#endif
