/*
 * platform_linux.h — Linux platform layer for libmqvpn
 *
 * Provides libevent-based tick() driver, TUN/routing/killswitch/DNS management.
 * This is the glue between the sans-I/O libmqvpn and the Linux CLI binary.
 */

#ifndef MQVPN_PLATFORM_LINUX_H
#define MQVPN_PLATFORM_LINUX_H

#include "vpn_client.h"
#include "vpn_server.h"

/*
 * Run the VPN client using the libmqvpn API + Linux platform layer.
 * Blocks until shutdown (SIGINT/SIGTERM). Returns 0 on clean exit.
 *
 * Replaces the old mqvpn_client_run() which used global state.
 */
int linux_platform_run_client(const mqvpn_client_cfg_t *cfg);

/*
 * Run the VPN server using the libmqvpn API + Linux platform layer.
 * Blocks until shutdown (SIGINT/SIGTERM). Returns 0 on clean exit.
 *
 * For now, delegates to the existing mqvpn_server_run().
 */
int linux_platform_run_server(const mqvpn_server_cfg_t *cfg);

#endif /* MQVPN_PLATFORM_LINUX_H */
