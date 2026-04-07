#ifndef MQVPN_STATUS_H
#define MQVPN_STATUS_H

/* Connect to control API at addr:port, send get_status, print formatted output.
 * Returns 0 on success, 1 on error. */
int run_status(const char *addr, int port);

#endif
