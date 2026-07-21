// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* iOS lwIP profile switch — single definition point for the sweep
 * parameter so lwipopts.h and tcp_lane.h derive from the SAME value.
 * MQVPN_LWIP_IOS_PROFILE (CMake option) selects the profile;
 * MQVPN_LWIP_IOS_RCV_SCALE (default 2 = ~256 KiB window) is the ONLY
 * per-value override allowed — everything else derives. */

#ifndef MQVPN_LWIP_PROFILE_H
#define MQVPN_LWIP_PROFILE_H

#ifdef MQVPN_LWIP_IOS_PROFILE
#  ifndef MQVPN_LWIP_IOS_RCV_SCALE
#    define MQVPN_LWIP_IOS_RCV_SCALE 2
#  endif
/* MEMP_NUM_TCP_SEG(512) >= TCP_SND_QUEUELEN (lwIP init.c #error) caps the
 * sweep at scale<=4; the 2 MiB reference point uses the default profile. */
#  if MQVPN_LWIP_IOS_RCV_SCALE > 4
#    error "iOS profile: scale > 4 violates MEMP_NUM_TCP_SEG >= TCP_SND_QUEUELEN"
#  endif
#endif

#endif /* MQVPN_LWIP_PROFILE_H */
