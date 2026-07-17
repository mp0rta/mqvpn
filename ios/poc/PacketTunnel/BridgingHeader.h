// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_POC_BRIDGING_H
#define MQVPN_POC_BRIDGING_H
#include <libmqvpn.h>
#include "mqvpn_clock_shim.h"

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
