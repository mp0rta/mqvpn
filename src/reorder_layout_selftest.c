// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
#include <stdint.h>
#include "reorder.h"

/* The fingerprint must be well-formed (non-zero) and the struct size must be
 * exactly the 14 scalar counters + 12-entry residence histogram +
 * residence_max_us = 27 * 8 bytes. If this fails, the struct changed: verify
 * the five consumed offsets still exist, update the monitor, and update this
 * assert. */
_Static_assert(MQVPN_REORDER_STATS_LAYOUT_ID != 0, "layout id must be non-zero");
_Static_assert(sizeof(mqvpn_reorder_stats_t) == 27 * sizeof(uint64_t),
               "mqvpn_reorder_stats_t layout changed");
int
main(void)
{
    return 0;
}
