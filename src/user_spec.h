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

static inline char *
mqvpn_user_spec_trim(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t'))
        *--end = '\0';
    return s;
}

/* Split "NAME:KEY" or "NAME:KEY:IPV4" in place at the first two ':'; spaces and
 * tabs around each part are dropped. *ip = NULL when there is no second ':'.
 * Returns 0, -1 when there is no ':' or NAME or KEY is empty, or -2 when the text
 * after the second ':' is not an IPv4 address. A KEY therefore cannot contain ':'
 * in this form: reading a mistyped address as part of the key would lock the user
 * out without a word. */
static inline int
mqvpn_user_spec_split(char *spec, char **name, char **key, char **ip)
{
    char *k = spec ? strchr(spec, ':') : NULL;
    if (!k) return -1;
    *k++ = '\0';
    char *i = strchr(k, ':');
    if (i) *i++ = '\0';
    *name = mqvpn_user_spec_trim(spec);
    *key = mqvpn_user_spec_trim(k);
    *ip = i ? mqvpn_user_spec_trim(i) : NULL;
    if (!**name || !**key) return -1;
    struct in_addr a;
    if (*ip && inet_pton(AF_INET, *ip, &a) != 1) return -2;
    return 0;
}

#endif /* MQVPN_USER_SPEC_H */
