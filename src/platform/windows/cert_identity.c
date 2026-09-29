// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
//
// Portable identity core for the Windows verifier. See cert_identity.h.
// The rules here are the same as the Kotlin implementation on Android
// (SanDer / HostIdentifier / PlatformTrust.identity); change both or neither.
#include "cert_identity.h"

#include <string.h>

/* ---------- reference host ---------- */

static int
is_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

static int
hexval(char c)
{
    return c <= '9' ? c - '0' : c - 'a' + 10;
}

/* "0" or [1-9][0-9]{0,2}, <= 255. Returns -1 if not a label. */
static int
ipv4_label(const char *s, size_t n)
{
    if (n == 0 || n > 3) return -1;
    if (n > 1 && s[0] == '0') return -1;
    int v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
    }
    return v > 255 ? -1 : v;
}

/* Exactly four labels. */
static int
parse_ipv4(const char *s, size_t n, uint8_t out[4])
{
    size_t start = 0;
    int k = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || s[i] == '.') {
            if (k == 4) return 0;
            int v = ipv4_label(s + start, i - start);
            if (v < 0) return 0;
            out[k++] = (uint8_t)v;
            start = i + 1;
        }
    }
    return k == 4;
}

/* One colon-separated run [p, e) appended to groups[]; with allow4 the last
 * group may be a dotted quad standing for two groups. An empty run is valid
 * (either side of "::"); an empty group or a trailing ':' is not. */
static int
ipv6_run(const char *p, const char *e, int allow4, uint16_t groups[8], int *ng)
{
    while (p < e) {
        const char *q = p;
        while (q < e && *q != ':')
            q++;
        size_t len = (size_t)(q - p);
        if (len == 0) return 0;
        if (allow4 && q == e && memchr(p, '.', len)) {
            uint8_t v4[4];
            if (*ng > 6 || !parse_ipv4(p, len, v4)) return 0;
            groups[(*ng)++] = (uint16_t)((v4[0] << 8) | v4[1]);
            groups[(*ng)++] = (uint16_t)((v4[2] << 8) | v4[3]);
        } else {
            if (len > 4 || *ng > 7) return 0;
            uint16_t v = 0;
            for (size_t i = 0; i < len; i++) {
                if (!is_hex(p[i])) return 0;
                v = (uint16_t)((v << 4) | hexval(p[i]));
            }
            groups[(*ng)++] = v;
        }
        if (q < e) {
            q++;                  /* the separator */
            if (q == e) return 0; /* trailing ':' */
        }
        p = q;
    }
    return 1;
}

/* RFC 4291 text form: groups of 1-4 hex digits, at most one "::", optional
 * dotted-quad tail standing for the last two groups. Writes 16 bytes. */
static int
parse_ipv6(const char *s, size_t n, uint8_t out[16])
{
    const char *dbl = NULL;
    for (size_t i = 0; i + 1 < n; i++) {
        if (s[i] == ':' && s[i + 1] == ':') {
            if (dbl) return 0;
            dbl = s + i;
            i++;
        }
    }
    uint16_t groups[8];
    int ng = 0, head = 0;
    if (!dbl) {
        if (!ipv6_run(s, s + n, 1, groups, &ng) || ng != 8) return 0;
    } else {
        if (!ipv6_run(s, dbl, 0, groups, &ng)) return 0;
        head = ng;
        if (!ipv6_run(dbl + 2, s + n, 1, groups, &ng) || ng > 7) return 0;
    }
    memset(out, 0, 16);
    /* groups before "::" fill from the front, the rest from the back
     * (without "::", head is 0 and the eight groups land in order) */
    int tail = ng - head;
    for (int i = 0; i < ng; i++) {
        int idx = i < head ? i : 8 - tail + (i - head);
        out[idx * 2] = (uint8_t)(groups[i] >> 8);
        out[idx * 2 + 1] = (uint8_t)(groups[i] & 0xFF);
    }
    return 1;
}

/* LDH labels 1..63, no leading/trailing '-', total <= 253, not every label
 * numeric (decimal, or "0x" followed by hex digits). */
static int
is_ldh_hostname(const char *h, size_t n)
{
    if (n == 0 || n > 253) return 0;
    int all_numeric = 1;
    size_t start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i != n && h[i] != '.') continue;
        size_t len = i - start;
        const char *l = h + start;
        if (len == 0 || len > 63) return 0;
        if (l[0] == '-' || l[len - 1] == '-') return 0;
        int numeric = 1;
        int hexnum = len > 2 && l[0] == '0' && l[1] == 'x';
        for (size_t k = 0; k < len; k++) {
            char c = l[k];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return 0;
            if (c < '0' || c > '9') numeric = 0;
            if (k >= 2 && !is_hex(c)) hexnum = 0;
        }
        if (!numeric && !hexnum) all_numeric = 0;
        start = i + 1;
    }
    return !all_numeric;
}

int
mqvpn_win_parse_host_literal(const char *host, uint8_t out[16], char *dns, size_t dns_cap)
{
    if (!host || !out || !dns || dns_cap < 254) return -1;
    /* bounded length without strnlen (POSIX, not ISO C11) */
    const char *nul = memchr(host, 0, 256);
    size_t n = nul ? (size_t)(nul - host) : 256;
    if (n == 0 || n >= 255) return -1; /* 255+ = possibly truncated upstream */
    char h[256];
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)host[i];
        if (c < 0x21 || c > 0x7E) return -1;
        h[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c;
    }
    h[n] = 0;
    int trailing_dot = 0;
    if (h[n - 1] == '.') {
        h[--n] = 0;
        trailing_dot = 1;
    }
    if (n == 0) return -1;
    if (memchr(h, '*', n) || memchr(h, '[', n) || memchr(h, ']', n)) return -1;

    /* A literal with a trailing dot is invalid, never a DNS name: resolvers
     * treat it as a DNS query. */
    uint8_t v4[4];
    if (parse_ipv4(h, n, v4)) {
        if (trailing_dot) return -1;
        memcpy(out, v4, 4);
        return 4;
    }
    if (memchr(h, ':', n)) {
        uint8_t v6[16];
        if (trailing_dot || !parse_ipv6(h, n, v6)) return -1;
        memcpy(out, v6, 16);
        return 16;
    }
    /* Numeric-looking but not a strict literal is invalid, never a DNS name:
     * the transport resolves the original string with the platform resolver,
     * whose lenient parsers accept 0x7f000001, 0177.0.0.1, 127.1 and friends
     * as addresses. is_ldh_hostname covers the rest of that family. */
    int digits_only = 1;
    for (size_t i = 0; i < n; i++) {
        if (!((h[i] >= '0' && h[i] <= '9') || h[i] == '.')) {
            digits_only = 0;
            break;
        }
    }
    if (digits_only) return -1;
    if (!is_ldh_hostname(h, n)) return -1;
    memcpy(dns, h, n + 1);
    return 0;
}

/* ---------- SAN walker ---------- */

/* DER length at der[*pos]; short form or minimal long form with 1..4 octets.
 * 0 = failure. */
static int
der_len(const uint8_t *der, size_t len, size_t *pos, size_t *out)
{
    if (*pos >= len) return 0;
    uint8_t first = der[(*pos)++];
    if (first < 0x80) {
        *out = first;
        return 1;
    }
    size_t n = first & 0x7F;
    if (n == 0 || n > 4) return 0; /* 0x80 indefinite; 0x85+ too long */
    if (len - *pos < n) return 0;
    uint32_t v = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = der[(*pos)++];
        if (i == 0 && b == 0) return 0; /* leading zero octet: non-minimal */
        v = (v << 8) | b;
    }
    if (v < 0x80 || v > 0x7FFFFFFF) return 0; /* fits the short form; or absurd */
    *out = (size_t)v;
    return 1;
}

int
mqvpn_win_san_walk(const uint8_t *der, size_t len, mqvpn_win_san_entry_t *out, size_t max)
{
    if (!der || !out) return -1;
    size_t pos = 0, seq_len;
    if (len < 2 || der[pos++] != 0x30) return -1;
    if (!der_len(der, len, &pos, &seq_len)) return -1;
    if (seq_len != len - pos || seq_len == 0) return -1;
    /* Collect into a local array; out[] is written only after the whole
     * SEQUENCE validated (all-or-nothing: no partial result on failure). */
    mqvpn_win_san_entry_t tmp[MQVPN_WIN_SAN_MAX];
    size_t count = 0, nout = 0;
    while (pos < len) {
        uint8_t tag = der[pos++];
        size_t elen;
        if (!der_len(der, len, &pos, &elen)) return -1;
        if (elen == 0 || elen > len - pos) return -1;
        if (++count > MQVPN_WIN_SAN_MAX || count > max) return -1;
        switch (tag) {
        case 0x82: /* dNSName */
            for (size_t i = 0; i < elen; i++)
                if (der[pos + i] < 0x21 || der[pos + i] > 0x7E) return -1;
            tmp[nout].kind = 2;
            tmp[nout].p = der + pos;
            tmp[nout].len = elen;
            nout++;
            break;
        case 0x87: /* iPAddress */
            if (elen != 4 && elen != 16) return -1;
            tmp[nout].kind = 7;
            tmp[nout].p = der + pos;
            tmp[nout].len = elen;
            nout++;
            break;
        case 0xA0:
        case 0x81:
        case 0xA3:
        case 0xA4:
        case 0xA5:
        case 0x86:
        case 0x88: break; /* valid choice, content not interpreted */
        default: return -1;
        }
        pos += elen;
    }
    if (nout) memcpy(out, tmp, nout * sizeof(tmp[0]));
    return (int)nout;
}

/* ---------- identity ---------- */

/* Exact, or left-most whole-label '*' standing for exactly one non-empty host
 * label. Only the SAN side is normalised here; host is already lower-case,
 * dot-stripped LDH. */
static int
dns_matches(const uint8_t *e, size_t elen, const char *host, size_t hlen)
{
    char ent[256];
    if (elen == 0 || elen > 255) return 0;
    for (size_t i = 0; i < elen; i++)
        ent[i] = (e[i] >= 'A' && e[i] <= 'Z') ? (char)(e[i] + 32) : (char)e[i];
    if (ent[elen - 1] == '.') elen--;
    if (elen == hlen && memcmp(ent, host, hlen) == 0) return 1;
    if (elen < 2 || ent[0] != '*' || ent[1] != '.') return 0;
    if (memchr(ent + 1, '*', elen - 1)) return 0;
    const char *dot = memchr(host, '.', hlen);
    if (!dot || dot == host) return 0;
    size_t rest = hlen - (size_t)(dot - host); /* ".example.com" */
    return rest == elen - 1 && memcmp(dot, ent + 1, rest) == 0;
}

mqvpn_win_id_result_t
mqvpn_win_identity_match_san(const uint8_t *san_der, size_t san_len, const char *host)
{
    uint8_t addr[16];
    char dns[256];
    /* the host is judged before the SAN is looked at */
    int kind = mqvpn_win_parse_host_literal(host, addr, dns, sizeof(dns));
    if (kind < 0) return MQVPN_WIN_ID_INVALID_HOST;
    if (!san_der || san_len == 0) return MQVPN_WIN_ID_NO_SAN;
    mqvpn_win_san_entry_t ent[MQVPN_WIN_SAN_MAX];
    int n = mqvpn_win_san_walk(san_der, san_len, ent, MQVPN_WIN_SAN_MAX);
    if (n < 0) return MQVPN_WIN_ID_NO_SAN;
    if (kind > 0) {
        for (int i = 0; i < n; i++) {
            if (ent[i].kind == 7 && ent[i].len == (size_t)kind &&
                memcmp(ent[i].p, addr, (size_t)kind) == 0)
                return MQVPN_WIN_ID_OK;
        }
        return MQVPN_WIN_ID_NO_IP_SAN;
    }
    int have_dns = 0;
    size_t hlen = strlen(dns);
    for (int i = 0; i < n; i++) {
        if (ent[i].kind != 2) continue;
        have_dns = 1;
        if (dns_matches(ent[i].p, ent[i].len, dns, hlen)) return MQVPN_WIN_ID_OK;
    }
    return have_dns ? MQVPN_WIN_ID_HOSTNAME_MISMATCH : MQVPN_WIN_ID_NO_DNS_SAN;
}

/* Same wording as the Android verifier's rejection reasons. */
const char *
mqvpn_win_id_result_str(mqvpn_win_id_result_t r)
{
    switch (r) {
    case MQVPN_WIN_ID_OK: return "ok";
    case MQVPN_WIN_ID_INVALID_HOST: return "invalid host";
    case MQVPN_WIN_ID_NO_SAN: return "certificate has no subject alternative name";
    case MQVPN_WIN_ID_NO_IP_SAN: return "certificate has no IP address SAN for";
    case MQVPN_WIN_ID_NO_DNS_SAN: return "certificate has no DNS SAN for";
    case MQVPN_WIN_ID_HOSTNAME_MISMATCH: return "certificate hostname mismatch for";
    case MQVPN_WIN_ID_UNSET: break;
    }
    return "unset";
}
