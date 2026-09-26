// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
// Unit tests for src/platform/windows/cert_identity.c (portable; runs on Linux
// and Windows). The vectors mirror the Android suite (HostIdentifierTest,
// SanDerTest, PlatformTrustTest): change both or neither.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cert_identity.h"

static int g_run = 0, g_pass = 0;
#define TEST(name)                 \
    static void test_##name(void); \
    static void run_##name(void)   \
    {                              \
        g_run++;                   \
        printf("  %-60s ", #name); \
        test_##name();             \
        g_pass++;                  \
        printf("PASS\n");          \
    }                              \
    static void test_##name(void)
#define ASSERT_EQ(a, b)                                                                \
    do {                                                                               \
        long long _a = (long long)(a), _b = (long long)(b);                            \
        if (_a != _b) {                                                                \
            printf("FAIL\n    %s:%d: %s == %lld, expected %lld\n", __FILE__, __LINE__, \
                   #a, _a, _b);                                                        \
            exit(1);                                                                   \
        }                                                                              \
    } while (0)
#define ASSERT_MEM(p, q, n)                                                \
    do {                                                                   \
        if (memcmp((p), (q), (n)) != 0) {                                  \
            printf("FAIL\n    %s:%d: bytes differ\n", __FILE__, __LINE__); \
            exit(1);                                                       \
        }                                                                  \
    } while (0)

/* ---- fixtures ---- */
static uint8_t g_buf[8][8192];
static size_t g_len[8];
static int g_nbuf = 0;

static const uint8_t *
load(const char *name, size_t *len)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s.der", TEST_CERT_DIR, name);
    FILE *f = fopen(path, "rb");
    if (!f) {
        printf("FAIL: cannot open %s\n", path);
        exit(1);
    }
    int i = g_nbuf++ % 8;
    g_len[i] = fread(g_buf[i], 1, sizeof(g_buf[i]), f);
    fclose(f);
    *len = g_len[i];
    return g_buf[i];
}

/* SAN extension value of a DER certificate, or NULL. Minimal scan: the SAN OID
 * followed by an optional BOOLEAN and the OCTET STRING value (short or 1/2-octet
 * long length). */
static const uint8_t *
san_of(const uint8_t *der, size_t len, size_t *out_len)
{
    static const uint8_t oid[] = {0x06, 0x03, 0x55, 0x1D, 0x11};
    for (size_t i = 0; i + sizeof(oid) < len; i++) {
        if (memcmp(der + i, oid, sizeof(oid)) != 0) continue;
        size_t p = i + sizeof(oid);
        if (p < len && der[p] == 0x01) p += 3; /* BOOLEAN critical */
        if (p + 3 >= len || der[p] != 0x04) return NULL;
        p++;
        size_t l;
        if (der[p] < 0x80) {
            l = der[p];
            p++;
        } else if (der[p] == 0x81) {
            l = der[p + 1];
            p += 2;
        } else if (der[p] == 0x82) {
            l = ((size_t)der[p + 1] << 8) | der[p + 2];
            p += 3;
        } else {
            return NULL;
        }
        if (p + l > len) return NULL;
        *out_len = l;
        return der + p;
    }
    return NULL;
}

static mqvpn_win_id_result_t
idm(const char *fixture, const char *host)
{
    size_t n;
    const uint8_t *der = load(fixture, &n);
    size_t sl = 0;
    const uint8_t *san = san_of(der, n, &sl);
    return mqvpn_win_identity_match_san(san, sl, host);
}

static void
expect_invalid(const char *h)
{
    uint8_t o[16];
    char d[256];
    if (mqvpn_win_parse_host_literal(h, o, d, sizeof d) != -1) {
        printf("FAIL\n    '%s' should be invalid\n", h);
        exit(1);
    }
}

static void
expect_ip(const char *h, const char *bytes, int n)
{
    uint8_t o[16];
    char d[256];
    if (mqvpn_win_parse_host_literal(h, o, d, sizeof d) != n ||
        memcmp(o, bytes, (size_t)n) != 0) {
        printf("FAIL\n    '%s' should be a %d-byte literal with the given bytes\n", h, n);
        exit(1);
    }
}

static void
expect_dns(const char *h, const char *name)
{
    uint8_t o[16];
    char d[256];
    if (mqvpn_win_parse_host_literal(h, o, d, sizeof d) != 0 || strcmp(d, name) != 0) {
        printf("FAIL\n    '%s' should be the DNS name '%s'\n", h, name);
        exit(1);
    }
}

/* ---- host parser ---- */
TEST(parse_ipv4)
{
    expect_ip("192.0.2.10", "\xc0\x00\x02\x0a", 4);
    expect_ip("198.51.100.7", "\xc6\x33\x64\x07", 4);
}

TEST(parse_ipv6_forms)
{
    uint8_t o[16], p[16];
    char d[256];
    ASSERT_EQ(mqvpn_win_parse_host_literal("2001:db8::1", o, d, sizeof d), 16);
    ASSERT_MEM(o, "\x20\x01\x0d\xb8\0\0\0\0\0\0\0\0\0\0\0\x01", 16);
    ASSERT_EQ(mqvpn_win_parse_host_literal("2001:0DB8:0000:0000:0000:0000:0000:0001", p,
                                           d, sizeof d),
              16);
    ASSERT_MEM(o, p, 16);
    ASSERT_EQ(mqvpn_win_parse_host_literal("2001:0db8::1", p, d, sizeof d), 16);
    ASSERT_MEM(o, p, 16);
    expect_ip("::1", "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01", 16);
    ASSERT_EQ(mqvpn_win_parse_host_literal("::ffff:198.51.100.7", o, d, sizeof d), 16);
    ASSERT_MEM(o, "\0\0\0\0\0\0\0\0\0\0\xff\xff\xc6\x33\x64\x07", 16);
    ASSERT_EQ(mqvpn_win_parse_host_literal("::ffff:c633:6407", p, d, sizeof d), 16);
    ASSERT_MEM(o, p, 16);
    /* an IPv4-mapped literal stays 16 bytes: it never matches a 4-byte SAN */
    expect_ip("::ffff:192.0.2.10", "\0\0\0\0\0\0\0\0\0\0\xff\xff\xc0\x00\x02\x0a", 16);
}

TEST(parse_dns)
{
    uint8_t o[16];
    char d[256];
    expect_dns("A.EXAMPLE.COM.", "a.example.com");
    expect_dns("a.example.com", "a.example.com");
    char big[300];
    memset(big, 'a', 63);
    big[63] = '.';
    memset(big + 64, 'a', 63);
    big[127] = '.';
    memset(big + 128, 'a', 63);
    big[191] = '.';
    memset(big + 192, 'b', 61);
    big[253] = '.';
    big[254] = 0; /* 253 chars + trailing dot */
    ASSERT_EQ(mqvpn_win_parse_host_literal(big, o, d, sizeof d), 0);
    ASSERT_EQ((int)strlen(d), 253);
    /* "0x" with no hex digit is not numeric (glibc inet_aton rejects it too) */
    expect_dns("0x", "0x");
}

TEST(parse_accepted_shapes)
{
    expect_ip("1:2:3:4:5:6:1.2.3.4", "\0\1\0\2\0\3\0\4\0\5\0\6\1\2\3\4", 16);
    expect_ip("::", "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);
    expect_ip("1::", "\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);
    expect_ip("::1.2.3.4", "\0\0\0\0\0\0\0\0\0\0\0\0\1\2\3\4", 16);
    expect_ip("1:2:3:4:5:6:7::", "\0\1\0\2\0\3\0\4\0\5\0\6\0\7\0\0", 16);
    expect_dns("123.example", "123.example");
    expect_dns("a-b.example", "a-b.example");
    expect_dns("localhost", "localhost");
    expect_dns("0x1.example", "0x1.example");
    expect_dns("xn--bcher-kva.example", "xn--bcher-kva.example");
    expect_dns("A.B.C", "a.b.c");
    expect_dns("a.b.c.d.", "a.b.c.d");
}

TEST(parse_rejected_shapes)
{
    const char *bad[] = {"1.2.3.4.5",
                         "256.0.0.1",
                         "01.2.3.4",
                         ":::",
                         "::1::",
                         "1:2:3:4:5:6:7:8::",
                         "1:2:3:4:5:6:7:1.2.3.4",
                         "1.2.3.4::1",
                         "::1.2.3.4:1",
                         "::ffff:1.2.3",
                         "12345::1",
                         "g::1",
                         "1.2.3.0x1f",
                         "1:2:3:4:5:6::1.2.3.4",
                         "0xff.0xff.0xff.0xff",
                         "example.com..",
                         "a.example.com\t",
                         "127.0.0.1 ",
                         "1:2:3:4:5:6:7:",
                         ":1:2:3:4:5:6:7",
                         NULL};
    for (int i = 0; bad[i]; i++)
        expect_invalid(bad[i]);
}

TEST(parse_invalid)
{
    uint8_t o[16];
    char d[256];
    const char *bad[] = {"",
                         ".",
                         "192.0.2.10.",
                         "1.2.3",
                         "192.0.2.010",
                         "1:2",
                         "1:2:3:4:5:6:7:8:9",
                         "[2001:db8::1]",
                         "b\xc3\xbc"
                         "cher.example",
                         "*.example.com",
                         "0x7f000001",
                         "0x7f.0.0.1",
                         "0177.0.0.1",
                         "127.1",
                         "+127.0.0.1",
                         " 127.0.0.1",
                         "-a.example.com",
                         "a_b.example.com",
                         "a..example.com",
                         "2001:db8::1%eth0",
                         "1::2::3",
                         "2001:db8::1.",
                         NULL};
    for (int i = 0; bad[i]; i++)
        expect_invalid(bad[i]);
    char long255[256];
    memset(long255, 'a', 255);
    long255[255] = 0;
    expect_invalid(long255);
    char lbl64[70];
    memset(lbl64, 'a', 64);
    memcpy(lbl64 + 64, ".com", 5);
    expect_invalid(lbl64);
    /* 254 chars, raw < 255: falls to the "total <= 253" rule, not the raw guard */
    char long254[255];
    memset(long254, 'a', 63);
    long254[63] = '.';
    memset(long254 + 64, 'a', 63);
    long254[127] = '.';
    memset(long254 + 128, 'a', 63);
    long254[191] = '.';
    memset(long254 + 192, 'b', 62);
    long254[254] = 0;
    expect_invalid(long254);
    ASSERT_EQ(mqvpn_win_parse_host_literal(NULL, o, d, sizeof d), -1);
    ASSERT_EQ(mqvpn_win_parse_host_literal("a.example.com", o, d, 253), -1);
}

/* ---- SAN walker (byte vectors) ---- */
#define DNS13 0x82, 13, 'a', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
#define WALK_FAILS(...)                                       \
    do {                                                      \
        const uint8_t v[] = {__VA_ARGS__};                    \
        mqvpn_win_san_entry_t e[4];                           \
        ASSERT_EQ(mqvpn_win_san_walk(v, sizeof v, e, 4), -1); \
    } while (0)

TEST(walk_valid)
{
    const uint8_t v[] = {0x30, 21, DNS13, 0x87, 4, 192, 0, 2, 10};
    mqvpn_win_san_entry_t e[4];
    ASSERT_EQ(mqvpn_win_san_walk(v, sizeof v, e, 4), 2);
    ASSERT_EQ(e[0].kind, 2);
    ASSERT_EQ(e[0].len, 13);
    ASSERT_MEM(e[0].p, "a.example.com", 13);
    ASSERT_EQ(e[1].kind, 7);
    ASSERT_EQ(e[1].len, 4);
    ASSERT_MEM(e[1].p, "\xc0\x00\x02\x0a", 4);
}
TEST(walk_valid_then_nul_fails)
{
    WALK_FAILS(0x30, 20, DNS13, 0x82, 3, 'a', 0x00, 'b');
}
TEST(walk_trailing_byte)
{
    WALK_FAILS(0x30, 15, DNS13, 0x00);
}
TEST(walk_seq_longer_than_input)
{
    WALK_FAILS(0x30, 16, DNS13);
}
TEST(walk_element_overrun)
{
    WALK_FAILS(0x30, 15, 0x82, 14, 'a', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c',
               'o', 'm');
}
TEST(walk_lone_tag)
{
    WALK_FAILS(0x30, 1, 0x82);
}
TEST(walk_truncated_long_header)
{
    WALK_FAILS(0x30, 2, 0x82, 0x82);
    WALK_FAILS(0x30, 3, 0x82, 0x82, 0x05); /* 0x82 0x82 with one length octet present */
}
TEST(walk_indefinite)
{
    WALK_FAILS(0x30, 0x80);
}
TEST(walk_len_of_len_too_big)
{
    WALK_FAILS(0x30, 0x85, 0, 0, 0, 0, 1);
}
TEST(walk_non_minimal)
{
    WALK_FAILS(0x30, 0x81, 5, 0x82, 3, 'a', 'b', 'c');
}
TEST(walk_leading_zero_len)
{
    WALK_FAILS(0x30, 0x82, 0x00, 5, 0x82, 3, 'a', 'b', 'c');
}
TEST(walk_constructed_dns)
{
    WALK_FAILS(0x30, 5, 0xA2, 3, 'a', 'b', 'c');
}
TEST(walk_universal_tag)
{
    WALK_FAILS(0x30, 3, 0x04, 1, 'a');
}
TEST(walk_high_tag_number_form)
{
    WALK_FAILS(0x30, 3, 0x9F, 1, 'z');
    WALK_FAILS(0x30, 3, 0xBF, 1, 'z');
}
TEST(walk_empty_seq)
{
    WALK_FAILS(0x30, 0);
}
TEST(walk_empty_input)
{
    const uint8_t v[] = {0x30};
    mqvpn_win_san_entry_t e[4];
    ASSERT_EQ(mqvpn_win_san_walk(v, 0, e, 4), -1);
    ASSERT_EQ(mqvpn_win_san_walk(NULL, 0, e, 4), -1);
}
TEST(walk_ip_lengths)
{
    WALK_FAILS(0x30, 7, 0x87, 5, 1, 2, 3, 4, 5);
    WALK_FAILS(0x30, 2, 0x87, 0);
    WALK_FAILS(0x30, 5, 0x87, 3, 1, 2, 3);
    const uint8_t v[] = {0x30, 18, 0x87, 16, 0x20, 0x01, 0x0d, 0xb8, 0, 0,
                         0,    0,  0,    0,  0,    0,    0,    0,    0, 1};
    mqvpn_win_san_entry_t e[4];
    ASSERT_EQ(mqvpn_win_san_walk(v, sizeof v, e, 4), 1);
    ASSERT_EQ(e[0].kind, 7);
    ASSERT_EQ(e[0].len, 16);
    ASSERT_MEM(e[0].p, v + 4, 16);
}
TEST(walk_empty_dns)
{
    WALK_FAILS(0x30, 2, 0x82, 0);
}
TEST(walk_empty_rfc822)
{
    WALK_FAILS(0x30, 17, 0x81, 0, DNS13);
}
TEST(walk_dns_bad_octets)
{
    const uint8_t bad[] = {0x20, 0x00, 0x7F, 0x80};
    for (int i = 0; i < 4; i++) {
        uint8_t v[] = {0x30, 5, 0x82, 3, 'a', 0, 'b'};
        v[5] = bad[i];
        mqvpn_win_san_entry_t e[4];
        ASSERT_EQ(mqvpn_win_san_walk(v, sizeof v, e, 4), -1);
    }
}
TEST(walk_dns_boundary_octets)
{
    const uint8_t v[] = {0x30, 5, 0x82, 3, '!', 'b', '~'};
    mqvpn_win_san_entry_t e[4];
    ASSERT_EQ(mqvpn_win_san_walk(v, sizeof v, e, 4), 1);
    ASSERT_MEM(e[0].p, "!b~", 3);
}
TEST(walk_rfc822_skipped_and_not_interpreted)
{
    const uint8_t v[] = {0x30, 19, 0x81, 2, 0x80, 'y', DNS13};
    mqvpn_win_san_entry_t e[4];
    ASSERT_EQ(mqvpn_win_san_walk(v, sizeof v, e, 4), 1);
    ASSERT_EQ(e[0].kind, 2);
}
TEST(walk_valid_rfc822_ignored)
{
    const uint8_t v[] = {0x30, 20, 0x81, 3, 'x', '@', 'y', DNS13};
    mqvpn_win_san_entry_t e[4];
    ASSERT_EQ(mqvpn_win_san_walk(v, sizeof v, e, 4), 1);
    ASSERT_EQ(e[0].kind, 2);
}
TEST(walk_other_skipped_tags)
{
    const uint8_t tags[] = {0xA0, 0xA3, 0xA4, 0xA5, 0x86, 0x88};
    for (size_t i = 0; i < sizeof tags; i++) {
        uint8_t v[] = {0x30, 18, 0, 1, 'z', DNS13};
        v[2] = tags[i];
        mqvpn_win_san_entry_t e[4];
        ASSERT_EQ(mqvpn_win_san_walk(v, sizeof v, e, 4), 1);
        ASSERT_EQ(e[0].kind, 2);
    }
}
TEST(walk_count_limit)
{
    static uint8_t v[4 + 65 * 15];
    const uint8_t d[] = {DNS13};
    for (int k = 0; k < 65; k++)
        memcpy(v + 4 + k * 15, d, 15);
    v[0] = 0x30;
    v[1] = 0x82;
    v[2] = (uint8_t)((64 * 15) >> 8);
    v[3] = (uint8_t)((64 * 15) & 0xFF);
    mqvpn_win_san_entry_t e[MQVPN_WIN_SAN_MAX];
    ASSERT_EQ(mqvpn_win_san_walk(v, 4 + 64 * 15, e, MQVPN_WIN_SAN_MAX), 64);
    /* a caller array smaller than the element count is a failure, not a partial result */
    ASSERT_EQ(mqvpn_win_san_walk(v, 4 + 64 * 15, e, 63), -1);
    v[2] = (uint8_t)((65 * 15) >> 8);
    v[3] = (uint8_t)((65 * 15) & 0xFF);
    ASSERT_EQ(mqvpn_win_san_walk(v, 4 + 65 * 15, e, MQVPN_WIN_SAN_MAX), -1);
    /* 64 rfc822Name + 1 dNSName: the limit counts every element */
    for (int k = 0; k < 64; k++)
        v[4 + k * 15] = 0x81;
    ASSERT_EQ(mqvpn_win_san_walk(v, 4 + 65 * 15, e, MQVPN_WIN_SAN_MAX), -1);
    /* 64 rfc822Name alone: valid, no usable entry */
    v[2] = (uint8_t)((64 * 15) >> 8);
    v[3] = (uint8_t)((64 * 15) & 0xFF);
    ASSERT_EQ(mqvpn_win_san_walk(v, 4 + 64 * 15, e, MQVPN_WIN_SAN_MAX), 0);
}
TEST(walk_huge_long_form_fails_cleanly)
{
    WALK_FAILS(0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF);
    WALK_FAILS(0x30, 0x84, 0x80, 0, 0, 0);
    WALK_FAILS(0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF);
}
TEST(walk_long_form_element)
{
    /* 128 and 256 content octets need the long form; 127 in long form is non-minimal */
    static uint8_t v[4 + 4 + 256];
    mqvpn_win_san_entry_t e[4];
    memset(v, 'a', sizeof v);
    v[0] = 0x30, v[1] = 0x81, v[2] = 131, v[3] = 0x82, v[4] = 0x81, v[5] = 128;
    ASSERT_EQ(mqvpn_win_san_walk(v, 3 + 131, e, 4), 1);
    ASSERT_EQ(e[0].len, 128);
    v[0] = 0x30, v[1] = 0x82, v[2] = 0x01, v[3] = 0x04, v[4] = 0x82, v[5] = 0x82,
    v[6] = 0x01, v[7] = 0x00;
    ASSERT_EQ(mqvpn_win_san_walk(v, 4 + 260, e, 4), 1);
    ASSERT_EQ(e[0].len, 256);
    memset(v, 'a', sizeof v); /* so only the length encoding can fail the next one */
    v[0] = 0x30, v[1] = 0x81, v[2] = 130, v[3] = 0x82, v[4] = 0x81, v[5] = 127;
    ASSERT_EQ(mqvpn_win_san_walk(v, 3 + 130, e, 4), -1);
}

/* ---- identity over the fixtures ---- */
TEST(id_dns)
{
    ASSERT_EQ(idm("identity-dns", "a.example.com"), MQVPN_WIN_ID_OK);
    ASSERT_EQ(idm("identity-dns", "A.EXAMPLE.COM."), MQVPN_WIN_ID_OK);
    ASSERT_EQ(idm("identity-dns", "b.example.com"), MQVPN_WIN_ID_HOSTNAME_MISMATCH);
    ASSERT_EQ(idm("identity-dns", "127.0.0.1"), MQVPN_WIN_ID_NO_IP_SAN);
}
TEST(id_wildcard)
{
    ASSERT_EQ(idm("identity-wildcard", "a.example.com"), MQVPN_WIN_ID_OK);
    ASSERT_EQ(idm("identity-wildcard", "example.com"), MQVPN_WIN_ID_HOSTNAME_MISMATCH);
    ASSERT_EQ(idm("identity-wildcard", "a.b.example.com"),
              MQVPN_WIN_ID_HOSTNAME_MISMATCH);
    ASSERT_EQ(idm("identity-wildcard-partial", "fa.example.com"),
              MQVPN_WIN_ID_HOSTNAME_MISMATCH);
    ASSERT_EQ(idm("identity-wildcard-multi", "a.b.example.com"),
              MQVPN_WIN_ID_HOSTNAME_MISMATCH);
}
TEST(id_ip)
{
    ASSERT_EQ(idm("identity-ip", "192.0.2.10"), MQVPN_WIN_ID_OK);
    ASSERT_EQ(idm("identity-ip", "2001:0db8::1"), MQVPN_WIN_ID_OK);
    ASSERT_EQ(idm("identity-ip", "::ffff:198.51.100.7"), MQVPN_WIN_ID_OK);
    ASSERT_EQ(idm("identity-ip", "::ffff:c633:6407"), MQVPN_WIN_ID_OK);
    ASSERT_EQ(idm("identity-ip", "192.0.2.11"), MQVPN_WIN_ID_NO_IP_SAN);
    ASSERT_EQ(idm("identity-ip", "::ffff:192.0.2.10"), MQVPN_WIN_ID_NO_IP_SAN);
    ASSERT_EQ(idm("identity-ip", "198.51.100.7"), MQVPN_WIN_ID_NO_IP_SAN);
    ASSERT_EQ(idm("identity-ip", "a.example.com"), MQVPN_WIN_ID_NO_DNS_SAN);
}
TEST(id_invalid_host)
{
    const char *bad[] = {"192.0.2.10.",
                         "1.2.3",
                         "192.0.2.010",
                         "1:2",
                         "1:2:3:4:5:6:7:8:9",
                         "[2001:db8::1]",
                         "b\xc3\xbc"
                         "cher.example",
                         "*.example.com",
                         "",
                         "0x7f000001",
                         "0x7f.0.0.1",
                         "0177.0.0.1",
                         "127.1",
                         "+127.0.0.1",
                         " 127.0.0.1",
                         "-a.example.com",
                         "a_b.example.com",
                         "a..example.com",
                         NULL};
    for (int i = 0; bad[i]; i++) {
        if (idm("identity-dns", bad[i]) != MQVPN_WIN_ID_INVALID_HOST) {
            printf("FAIL\n    '%s'\n", bad[i]);
            exit(1);
        }
    }
    ASSERT_EQ(idm("identity-dns", NULL), MQVPN_WIN_ID_INVALID_HOST);
    /* the host is judged before the SAN is looked at */
    ASSERT_EQ(idm("identity-cn-only", "*.example.com"), MQVPN_WIN_ID_INVALID_HOST);
    ASSERT_EQ(idm("identity-dns", "0x"), MQVPN_WIN_ID_HOSTNAME_MISMATCH);
}
TEST(id_no_san)
{
    ASSERT_EQ(idm("identity-cn-only", "a.example.com"), MQVPN_WIN_ID_NO_SAN);
    ASSERT_EQ(idm("identity-san-malformed", "a.example.com"), MQVPN_WIN_ID_NO_SAN);
    ASSERT_EQ(idm("identity-san-nul", "a.example.com"), MQVPN_WIN_ID_NO_SAN);
    ASSERT_EQ(idm("identity-san-mixed", "a.example.com"), MQVPN_WIN_ID_NO_SAN);
}
TEST(id_result_strings)
{
    /* every returnable class has its own wording; UNSET is never returned */
    for (int r = MQVPN_WIN_ID_OK; r <= MQVPN_WIN_ID_HOSTNAME_MISMATCH; r++)
        ASSERT_EQ(strcmp(mqvpn_win_id_result_str((mqvpn_win_id_result_t)r), "unset") != 0,
                  1);
    ASSERT_EQ(strcmp(mqvpn_win_id_result_str(MQVPN_WIN_ID_UNSET), "unset"), 0);
}

int
main(void)
{
    run_parse_ipv4();
    run_parse_ipv6_forms();
    run_parse_dns();
    run_parse_accepted_shapes();
    run_parse_rejected_shapes();
    run_parse_invalid();
    run_walk_valid();
    run_walk_valid_then_nul_fails();
    run_walk_trailing_byte();
    run_walk_seq_longer_than_input();
    run_walk_element_overrun();
    run_walk_lone_tag();
    run_walk_truncated_long_header();
    run_walk_indefinite();
    run_walk_len_of_len_too_big();
    run_walk_non_minimal();
    run_walk_leading_zero_len();
    run_walk_constructed_dns();
    run_walk_universal_tag();
    run_walk_high_tag_number_form();
    run_walk_empty_seq();
    run_walk_empty_input();
    run_walk_ip_lengths();
    run_walk_empty_dns();
    run_walk_empty_rfc822();
    run_walk_dns_bad_octets();
    run_walk_dns_boundary_octets();
    run_walk_rfc822_skipped_and_not_interpreted();
    run_walk_valid_rfc822_ignored();
    run_walk_other_skipped_tags();
    run_walk_count_limit();
    run_walk_huge_long_form_fails_cleanly();
    run_walk_long_form_element();
    run_id_dns();
    run_id_wildcard();
    run_id_ip();
    run_id_invalid_host();
    run_id_no_san();
    run_id_result_strings();
    printf("\n  %d/%d tests passed\n", g_pass, g_run);
    return g_pass == g_run ? 0 : 1;
}
