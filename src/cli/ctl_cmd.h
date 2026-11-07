// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef CTL_CMD_H
#define CTL_CMD_H

#include "ctl_rpc.h"

typedef struct {
    const char *endpoint;
    int timeout_ms_override; /* 0 = per-stage defaults */
    int json;
} ctl_opts_t;

/* Return value = process exit code. */
int ctl_cmd_version(const ctl_opts_t *o);

/* Failure output shared by every command. json: one {"error":{...}} line on
 * stdout, nothing on stderr. text: "mqvpnctl: <message>" on stderr. With
 * remote_error the endpoint's code, message and data are passed through. */
void ctl_emit_error(const ctl_opts_t *o, int code, const char *message,
                    yyjson_val *remote_error);

#endif /* CTL_CMD_H */
