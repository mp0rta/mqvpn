// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef CMP_PROTO_H
#define CMP_PROTO_H

#define CMP_VERSION                      "1.0"
#define CMP_ENDPOINT_NAME                "mqvpn-client"
#define CMP_MAX_REQUEST_LINE             (64u * 1024u)
#define CMP_MAX_RESPONSE_LINE            (256u * 1024u)
#define CMP_MAX_CONNECTIONS_PER_LISTENER 32u
#define CMP_HANDSHAKE_DEADLINE_MS        5000u
#define CMP_DRAIN_DEADLINE_MS            5000u
#define CMP_REQUEST_BUDGET_PER_LOOP      4u
#define CMP_ACCEPT_BUDGET_PER_LOOP       8u
#define CMP_LOG_INTERVAL_MS              60000u
#define CMP_LISTEN_BACKLOG               16

#endif /* CMP_PROTO_H */
