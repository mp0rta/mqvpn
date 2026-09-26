// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_POC_BRIDGING_H
#define MQVPN_POC_BRIDGING_H
#include <libmqvpn.h>
#include <mqvpn_bind_posix.h>
#include "mqvpn_clock_shim.h"

// Global library log sink (src/log.h, an internal symbol of the static
// archive — like mqvpn_client_get_reorder_stats below): routes every global
// libmqvpn line to os_log. mqvpn_log_fn comes from libmqvpn.h. Set it once
// per process, before any client exists; the sink must be thread-safe (it
// runs on whichever thread logged) and must not log through mqvpn_log
// itself. It gets the message without the timestamp/level prefix or a
// trailing newline.
void mqvpn_log_set_sink(mqvpn_log_fn fn, void *user_ctx);

// Internal reorder stats API. reorder.h supplies mqvpn_reorder_stats_t + the
// percentile helpers; mqvpn_client_get_reorder_stats is internal but linkable
// from the static archive. Declared here (rather than pulling the full
// internal headers) to keep the bridged surface minimal. mqvpn_client_t stays
// opaque via libmqvpn.h.
#include "reorder.h"
int mqvpn_client_get_reorder_stats(const mqvpn_client_t *c, mqvpn_reorder_stats_t *out);

// Extension-side layout fingerprint (reorder_layout_shim.c).
uint64_t mqvpn_ext_reorder_layout_id(void);

#endif
