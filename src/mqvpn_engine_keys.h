// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * mqvpn_engine_keys.h — secret keys of the xquic engine
 *
 * xquic falls back to a key published in its source for address validation
 * tokens and to an empty key for stateless reset tokens, which RFC 9000
 * Sections 8.1.4 and 10.3.2 require to be difficult to guess.
 */
#ifndef MQVPN_ENGINE_KEYS_H
#define MQVPN_ENGINE_KEYS_H

#include <xquic/xquic.h>

#include "mqvpn_internal.h"

/* Sets a random stateless reset key: a client sends no stateless reset, so
 * the key need not outlive the engine. Returns 0, or -1 on failure. */
MQVPN_INTERNAL int mqvpn_engine_keys_set_client(xqc_config_t *xconfig);

/* Sets random token keys, in every slot since a token names the slot that
 * decrypts it, and a stateless reset key derived from the TLS private key
 * file: a reset has to work after a restart, when it is most needed. Returns
 * 0, or -1 when the file cannot be read or a key cannot be made. */
MQVPN_INTERNAL int mqvpn_engine_keys_set_server(xqc_config_t *xconfig,
                                                const char *tls_key_file);

#endif /* MQVPN_ENGINE_KEYS_H */
