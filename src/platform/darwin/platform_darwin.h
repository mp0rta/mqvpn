// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * platform_darwin.h — Darwin (macOS) platform layer for libmqvpn
 *
 * Provides libevent-based tick() driver and utun TUN management.
 * This is the glue between the sans-I/O libmqvpn and the macOS CLI binary.
 * Server mode is not ported to Darwin (client-only platform layer).
 */

#ifndef MQVPN_PLATFORM_DARWIN_H
#define MQVPN_PLATFORM_DARWIN_H

#include "vpn_client.h"

/*
 * Run the VPN client using the libmqvpn API + Darwin platform layer.
 * Blocks until shutdown (SIGINT/SIGTERM). Returns 0 on clean exit.
 */
int darwin_platform_run_client(const mqvpn_client_cfg_t *cfg);

#endif /* MQVPN_PLATFORM_DARWIN_H */
