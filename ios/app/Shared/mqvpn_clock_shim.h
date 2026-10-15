// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_CLOCK_SHIM_H
#define MQVPN_CLOCK_SHIM_H
#include <stdint.h>
/* Non-capturing C function with the mqvpn_clock_fn signature.
 * Returns microseconds from mach_continuous_time, which keeps advancing
 * during device sleep (the Darwin analogue of Android CLOCK_BOOTTIME). */
uint64_t mqvpn_ios_clock_us(void *ctx);
#endif
