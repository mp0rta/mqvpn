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
 * after the last ':' is the IP when it parses as IPv4 and a non-empty KEY remains
 * before it; otherwise the rest is the KEY (keys may contain ':'). *ip = NULL when
 * absent. Returns 0, -1 when there is no ':' or NAME or KEY is empty, or -2 when that
 * last part is a mistyped address (only digits and at least one '.', but not IPv4):
 * taking it into the KEY would lock the user out without a word. */
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
    if (!last || last == *key) return 0;
    struct in_addr a;
    if (inet_pton(AF_INET, last + 1, &a) == 1) {
        *last = '\0';
        *ip = last + 1;
    } else if (strchr(last + 1, '.') &&
               strspn(last + 1, "0123456789.") == strlen(last + 1)) {
        return -2;
    }
    return 0;
}

#endif /* MQVPN_USER_SPEC_H */
