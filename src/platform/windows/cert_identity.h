// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
//
// Portable core of the Windows certificate verifier: the reference-host
// parser, the subjectAltName DER walker and the identity match. No Win32
// headers, so it is unit-tested on Linux as well as in Windows CI. The
// Kotlin implementation for Android follows the same rules; the two must
// stay identical.
#ifndef MQVPN_CERT_IDENTITY_H
#define MQVPN_CERT_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    MQVPN_WIN_ID_UNSET = 0, /* never returned: a zeroed result must not read as OK */
    MQVPN_WIN_ID_OK = 1,
    MQVPN_WIN_ID_INVALID_HOST, /* empty, '*', brackets, non-printable, >=255 bytes,
                                  bad literal */
    MQVPN_WIN_ID_NO_SAN,       /* no SAN extension, or its DER does not walk */
    MQVPN_WIN_ID_NO_IP_SAN,    /* IP host, no matching iPAddress */
    MQVPN_WIN_ID_NO_DNS_SAN,   /* DNS host, no dNSName entries */
    MQVPN_WIN_ID_HOSTNAME_MISMATCH,
} mqvpn_win_id_result_t;

/* Normalise (ASCII fold, one trailing dot stripped) and classify `host`.
 * Returns 4 or 16 and writes the address bytes to out[] for a literal, 0 for
 * a DNS hostname (normalised name written to dns[], NUL-terminated, dns_cap
 * >= 254), or -1 for an invalid host. No resolver, no inet_pton. */
int mqvpn_win_parse_host_literal(const char *host, uint8_t out[16], char *dns,
                                 size_t dns_cap);

typedef struct {
    int kind;         /* 2 = dNSName, 7 = iPAddress */
    const uint8_t *p; /* points into the input DER */
    size_t len;
} mqvpn_win_san_entry_t;

#define MQVPN_WIN_SAN_MAX 64

/* Walk one GeneralNames SEQUENCE. Validates the ENTIRE input first; only then
 * fills out[] (pointers into der). Returns the number of usable entries
 * (>= 0), or -1 on any failure. More than max (or MQVPN_WIN_SAN_MAX)
 * elements is -1, never a partial result; skipped elements count too. */
int mqvpn_win_san_walk(const uint8_t *der, size_t len, mqvpn_win_san_entry_t *out,
                       size_t max);

/* The identity rule over a SAN extension value (the inner GeneralNames DER;
 * NULL/0 = no SAN extension). Returns the reason class; MQVPN_WIN_ID_OK means
 * the leaf may speak for host. */
mqvpn_win_id_result_t mqvpn_win_identity_match_san(const uint8_t *san_der, size_t san_len,
                                                   const char *host);

const char *mqvpn_win_id_result_str(mqvpn_win_id_result_t r);

#endif
