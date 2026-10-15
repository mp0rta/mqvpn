// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
//
// Extension-side companion to the library's mqvpn_reorder_stats_layout_id():
// returns the layout fingerprint as computed from the reorder.h THIS extension
// compiled against. MqvpnEngine compares the two at init; a mismatch means the
// linked libmqvpn.a was built against a different struct definition, so the
// monitor is disabled (never read).
#include <stdint.h>
#include "reorder.h"

uint64_t
mqvpn_ext_reorder_layout_id(void)
{
    return MQVPN_REORDER_STATS_LAYOUT_ID;
}

// Secondary compile-time guard: pin the struct size so an accidental local
// reorder.h edit that changes the layout fails the build here.
_Static_assert(sizeof(mqvpn_reorder_stats_t) == 27 * sizeof(uint64_t),
               "mqvpn_reorder_stats_t layout changed — update the monitor + this assert");
