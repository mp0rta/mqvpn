/*
 * platform_windows.h — Windows platform layer for libmqvpn
 *
 * Provides libevent-based tick() driver, Wintun TUN, IPHLPAPI routing,
 * WFP killswitch, and DNS management.
 */

#ifndef MQVPN_PLATFORM_WINDOWS_H
#define MQVPN_PLATFORM_WINDOWS_H

#include "vpn_client.h"
#include "vpn_server.h"

/*
 * Run the VPN client using the libmqvpn API + Windows platform layer.
 * Blocks until shutdown (Ctrl+C). Returns 0 on clean exit.
 */
int win_platform_run_client(const mqvpn_client_cfg_t *cfg);

/*
 * Run the VPN server using the libmqvpn API + Windows platform layer.
 * Blocks until shutdown (Ctrl+C). Returns 0 on clean exit.
 */
int win_platform_run_server(const mqvpn_server_cfg_t *cfg);

#endif /* MQVPN_PLATFORM_WINDOWS_H */
