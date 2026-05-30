// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and contributors

/*
 * mqvpn_conn_settings.h — single source of truth for mqvpn's xquic
 * connection settings construction. To add a knob, extend the input
 * struct, the helper body, and tests/test_conn_settings.c in lock-step.
 */

#ifndef MQVPN_CONN_SETTINGS_H
#define MQVPN_CONN_SETTINGS_H

#include "mqvpn_internal.h"
#include <stdbool.h>
#include <stdint.h>
#include <xquic/xquic.h>

/* Caller-driven inputs. The bools are parameterised (not a single
 * `is_server` flag) so each call site documents its intent. */
typedef struct {
    bool is_server;
    bool enable_multipath; /* server callers pass true */
    mqvpn_scheduler_t scheduler;
    mqvpn_cc_t cc;             /* congestion control algorithm */
    uint64_t init_max_path_id; /* 0 = leave xquic default */
} mqvpn_conn_settings_input_t;

/* Populates *out with mqvpn-canonical xquic conn settings. Always begins
 * with memset(0), so the caller is not required to zero `out` first. */
MQVPN_INTERNAL void mqvpn_build_conn_settings(const mqvpn_conn_settings_input_t *in,
                                              xqc_conn_settings_t *out);

#endif /* MQVPN_CONN_SETTINGS_H */
