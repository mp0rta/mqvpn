// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
//
// Windows platform certificate verifier for libmqvpn (mqvpn_cert_verify_fn).
// Identity: the shared rule in cert_identity.c. Trust: CryptoAPI chain
// building against the Windows stores with network retrieval disabled, and
// CERT_CHAIN_POLICY_SSL with its own name check turned off.
#ifndef MQVPN_CERT_VERIFY_H
#define MQVPN_CERT_VERIFY_H

#include <winsock2.h> /* before windows.h, as platform_internal_win.h does */
#include <windows.h>
#include <wincrypt.h>
#include <stddef.h>
#include <stdint.h>

#include "cert_identity.h"

/* mqvpn_cert_verify_fn-compatible. ctx: an HCERTCHAINENGINE, or NULL for the
 * default engine (the user's and machine's Root/CA stores). Tests pass an
 * engine whose hExclusiveRoot holds only a test root. Returns 0 only when
 * every step succeeded; every other outcome is -1. */
int mqvpn_win_cert_verify(const uint8_t *const certs[], const size_t cert_len[],
                          size_t n_certs, const char *hostname, void *ctx);

/* Identity of a certificate context by the shared rule (CertFindExtension →
 * mqvpn_win_identity_match_san). Unit-tested by the Windows test binary. */
mqvpn_win_id_result_t mqvpn_win_cert_identity_match(PCCERT_CONTEXT leaf,
                                                    const char *host);

#endif
