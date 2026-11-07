// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef CMP_ENDPOINT_H
#define CMP_ENDPOINT_H

#include <stddef.h>

#define CMP_ENDPOINT_MAX 280

/* OS default path (UTF-8).
 * Linux: "/run/mqvpn/client.sock" if /run exists, else "/var/run/mqvpn/client.sock".
 * macOS: "/var/run/mqvpn/client.sock".
 * Windows: "%ProgramData%\mqvpn\client.sock" ("C:\ProgramData" if unset).
 * 0 = ok, -1 = out_len too small (out is then set to ""). */
int cmp_endpoint_default(char *out, size_t out_len);

/* NULL / "" -> default; a "unix://" prefix is stripped ("unix://" alone = default).
 * 0 = ok, -1 = too long (>= CMP_ENDPOINT_MAX) or does not fit out_len. On -1 an
 * explicit path leaves out untouched; the default branch sets out to "". */
int cmp_endpoint_resolve(const char *configured, char *out, size_t out_len);

#endif /* CMP_ENDPOINT_H */
