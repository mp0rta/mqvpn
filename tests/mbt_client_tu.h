// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/* tests/mbt_client_tu.h — read-only accessors into the private copy of
 * src/mqvpn_client.c that tests/mbt_client_tu.c compiles against the fake
 * xquic. The slot layout comes from path_entry_internal.h, which a caller
 * that reads slot fields reaches through formal/oracle/oracle_abs.h. */
#ifndef MQVPN_MBT_CLIENT_TU_H
#define MQVPN_MBT_CLIENT_TU_H

#include "libmqvpn.h"

typedef struct path_entry_s path_entry_t;

const path_entry_t *mbt_slot(const mqvpn_client_t *c, int idx);
int mbt_n_paths(const mqvpn_client_t *c);
int mbt_multipath_ready(const mqvpn_client_t *c);
int mbt_hold(const mqvpn_client_t *c);
/* The assert canary: IDLE -> ESTABLISHED, an invalid transition that must
 * abort in this TU. */
void mbt_canary_bad_transition(mqvpn_client_t *c);

#endif /* MQVPN_MBT_CLIENT_TU_H */
