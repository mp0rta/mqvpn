// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* lwIP TCP-lane sizing profile — single definition point for the values
 * lwipopts.h and tcp_lane.h must derive from the SAME source.
 *
 * Two independent axes:
 *   - WINDOW sizing (TCP_RCV_SCALE / TCP_SND_BUF / PBUF_POOL_SIZE), a
 *     two-way iOS-vs-rest split kept in lwipopts.h. MQVPN_LWIP_IOS_PROFILE
 *     (CMake option) selects it; MQVPN_LWIP_IOS_RCV_SCALE (default 2 =
 *     ~256 KiB window) is the ONLY per-value override allowed.
 *   - POOL sizing (the two pool constants below), a three-way split, because
 *     the pcb pool is what bounds the concurrent-flow cap: tcp_lane.c clamps
 *     hybrid.tcp_max_flows to MQVPN_LWIP_TCP_PCB_POOL / 2.
 *
 * The pool axis keys on __ANDROID__ rather than a CMake option on purpose.
 * The profile constants are consumed by lwip_core AND by every tcp_lane.h
 * includer (mqvpn_lib, tests, fuzz, microbench); a toolchain predefine is
 * uniform across all of them by construction, so no build script can wire
 * the flag into one target and forget another and silently split the
 * profile across TUs. */

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
/* iOS NE (~50 MB resident ceiling): flow cap 64. */
#  define MQVPN_LWIP_TCP_PCB_POOL 128
#  define MQVPN_LWIP_TCP_SEG_POOL 512
#elif defined(__ANDROID__)
/* Android: flow cap 256 — a handset multiplexes far fewer inner flows than a
 * router, and the pools are .bss touched at lwip_init(), so the desktop
 * profile's larger pcb pool would be resident cost with no matching demand. */
#  define MQVPN_LWIP_TCP_PCB_POOL 512
#  define MQVPN_LWIP_TCP_SEG_POOL 2048
#else
/* Desktop / router (Linux, Windows, macOS): flow cap 4096. The OpenMPTCProuter
 * integration aggregates a whole LAN behind one tunnel, where 256 concurrent
 * inner TCP flows is a real ceiling. Cost of the headroom over the 512/2048
 * this profile used through v0.13.0 is ~2.5 MiB of .bss (pcb 312 B, seg 32 B
 * on LP64), faulted in only when a lane is actually created — lwip_init()
 * runs lazily from the glue, so hybrid-disabled builds pay nothing resident.
 *
 * The seg pool tracks the pcb pool rather than staying at 2048: it is GLOBAL
 * across flows, so 2048 segments against a 4096-flow cap could not hold even
 * one segment per flow, and tcp_write() would return ERR_MEM (relay
 * backpressure — correct, but a throughput cliff) at full occupancy. */
#  define MQVPN_LWIP_TCP_PCB_POOL 8192
#  define MQVPN_LWIP_TCP_SEG_POOL 8192
#endif

#endif /* MQVPN_LWIP_PROFILE_H */
