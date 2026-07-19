// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* src/common/ipc/cmp_error.c — CMP error code -> wire string table. */
#include "cmp_error.h"

#include <stddef.h>

static const char *const tbl[CMP_E__COUNT] = {
    [CMP_E_OK] = "MQVPN_CLIENT_OK",
    [CMP_E_INTERNAL_ERROR] = "MQVPN_CLIENT_INTERNAL_ERROR",
    [CMP_E_INVALID_ARGUMENT] = "MQVPN_CLIENT_INVALID_ARGUMENT",
    [CMP_E_METHOD_NOT_FOUND] = "MQVPN_CLIENT_METHOD_NOT_FOUND",
    [CMP_E_PROTOCOL_INCOMPATIBLE] = "MQVPN_CLIENT_PROTOCOL_INCOMPATIBLE",
    [CMP_E_HANDSHAKE_REQUIRED] = "MQVPN_CLIENT_HANDSHAKE_REQUIRED",
    [CMP_E_PERMISSION_DENIED] = "MQVPN_CLIENT_PERMISSION_DENIED",
    [CMP_E_UNAVAILABLE] = "MQVPN_CLIENT_UNAVAILABLE",
    [CMP_E_NOT_CONNECTED] = "MQVPN_CLIENT_NOT_CONNECTED",
    [CMP_E_CONFIG_INVALID] = "MQVPN_CLIENT_CONFIG_INVALID",
    [CMP_E_TUN_UNAVAILABLE] = "MQVPN_CLIENT_TUN_UNAVAILABLE",
    [CMP_E_SERVER_UNREACHABLE] = "MQVPN_CLIENT_SERVER_UNREACHABLE",
    [CMP_E_DNS_RESOLUTION_FAILED] = "MQVPN_CLIENT_DNS_RESOLUTION_FAILED",
    [CMP_E_TLS_HANDSHAKE_FAILED] = "MQVPN_CLIENT_TLS_HANDSHAKE_FAILED",
    [CMP_E_AUTH_FAILED] = "MQVPN_CLIENT_AUTH_FAILED",
    [CMP_E_NO_ACTIVE_PATH] = "MQVPN_CLIENT_NO_ACTIVE_PATH",
    [CMP_E_PATH_NOT_FOUND] = "MQVPN_CLIENT_PATH_NOT_FOUND",
    [CMP_E_PATH_VALIDATION_TIMEOUT] = "MQVPN_CLIENT_PATH_VALIDATION_TIMEOUT",
    [CMP_E_MTU_TOO_LARGE] = "MQVPN_CLIENT_MTU_TOO_LARGE",
    [CMP_E_TIMEOUT] = "MQVPN_CLIENT_TIMEOUT",
    [CMP_E_BUSY] = "MQVPN_CLIENT_BUSY",
    [CMP_E_UNSUPPORTED] = "MQVPN_CLIENT_UNSUPPORTED",
    [CMP_E_RESPONSE_TOO_LARGE] = "MQVPN_CLIENT_RESPONSE_TOO_LARGE",
};

_Static_assert(sizeof(tbl) / sizeof(tbl[0]) == CMP_E__COUNT,
               "cmp_error tbl must have exactly CMP_E__COUNT entries");

const char *
cmp_error_code_str(cmp_error_code_t code)
{
    if ((int)code < 0 || (int)code >= CMP_E__COUNT) {
        return "MQVPN_CLIENT_INTERNAL_ERROR";
    }
    /* A future enum value without a matching table row would be NULL here;
     * never return NULL (callers pass this straight to the JSON writer). */
    return tbl[code] ? tbl[code] : "MQVPN_CLIENT_INTERNAL_ERROR";
}
