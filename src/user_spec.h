// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * user_spec.h — the "NAME:KEY[:IPV4]" user form shared by --user, the INI
 * User= key and the JSON "users" strings (static inline)
 */
#ifndef MQVPN_USER_SPEC_H
#define MQVPN_USER_SPEC_H

#include <string.h>
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#endif

/* Split "NAME:KEY" or "NAME:KEY:IPV4" in place. NAME ends at the first ':'. The text
 * after the last ':' is the IP only when it parses as IPv4 and a non-empty KEY remains
 * before it; otherwise the rest is the KEY (keys may contain ':'). *ip = NULL when
 * absent. Returns 0, or -1 when there is no ':' or NAME or KEY is empty. */
static inline int
mqvpn_user_spec_split(char *spec, char **name, char **key, char **ip)
{
    char *sep = spec ? strchr(spec, ':') : NULL;
    if (!sep || sep == spec || !sep[1]) return -1;
    *sep = '\0';
    *name = spec;
    *key = sep + 1;
    *ip = NULL;

    char *last = strrchr(*key, ':');
    struct in_addr a;
    if (last && last > *key && inet_pton(AF_INET, last + 1, &a) == 1) {
        *last = '\0';
        *ip = last + 1;
    }
    return 0;
}

#endif /* MQVPN_USER_SPEC_H */
