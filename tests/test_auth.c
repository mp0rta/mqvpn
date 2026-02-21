/*
 * test_auth.c — unit tests for auth utilities (constant-time compare, base64)
 *
 * Build: cc -o tests/test_auth tests/test_auth.c src/auth.c src/log.c -Isrc
 */
#include "auth.h"
#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define ASSERT_EQ_INT(a, b, msg) do { \
    if ((a) == (b)) { g_pass++; } \
    else { g_fail++; fprintf(stderr, "FAIL [%s]: %d != %d\n", msg, (int)(a), (int)(b)); } \
} while(0)

#define ASSERT_EQ_STR(a, b, msg) do { \
    if (strcmp((a), (b)) == 0) { g_pass++; } \
    else { g_fail++; fprintf(stderr, "FAIL [%s]: '%s' != '%s'\n", msg, (a), (b)); } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; fprintf(stderr, "FAIL [%s]\n", msg); } \
} while(0)

static void test_ct_compare_equal(void)
{
    const char *a = "mysecretkey123";
    const char *b = "mysecretkey123";
    ASSERT_EQ_INT(mqvpn_auth_ct_compare(a, strlen(a), b, strlen(b)), 0,
                  "ct_compare equal strings");
}

static void test_ct_compare_different(void)
{
    const char *a = "mysecretkey123";
    const char *b = "mysecretkey124";
    ASSERT_TRUE(mqvpn_auth_ct_compare(a, strlen(a), b, strlen(b)) != 0,
                "ct_compare different strings");
}

static void test_ct_compare_length_mismatch(void)
{
    const char *a = "short";
    const char *b = "longerstring";
    ASSERT_TRUE(mqvpn_auth_ct_compare(a, strlen(a), b, strlen(b)) != 0,
                "ct_compare length mismatch");
}

static void test_ct_compare_empty(void)
{
    ASSERT_EQ_INT(mqvpn_auth_ct_compare("", 0, "", 0), 0,
                  "ct_compare empty strings");
}

static void test_ct_compare_single_byte_diff(void)
{
    const char *a = "AAAA";
    const char *b = "AABA";
    ASSERT_TRUE(mqvpn_auth_ct_compare(a, 4, b, 4) != 0,
                "ct_compare single byte diff");
}

static void test_b64_encode_known_vectors(void)
{
    char buf[128];

    /* RFC 4648 test vectors */
    mqvpn_auth_b64_encode(buf, sizeof(buf), (const unsigned char *)"", 0);
    ASSERT_EQ_STR(buf, "", "b64 empty");

    mqvpn_auth_b64_encode(buf, sizeof(buf), (const unsigned char *)"f", 1);
    ASSERT_EQ_STR(buf, "Zg==", "b64 'f'");

    mqvpn_auth_b64_encode(buf, sizeof(buf), (const unsigned char *)"fo", 2);
    ASSERT_EQ_STR(buf, "Zm8=", "b64 'fo'");

    mqvpn_auth_b64_encode(buf, sizeof(buf), (const unsigned char *)"foo", 3);
    ASSERT_EQ_STR(buf, "Zm9v", "b64 'foo'");

    mqvpn_auth_b64_encode(buf, sizeof(buf), (const unsigned char *)"foob", 4);
    ASSERT_EQ_STR(buf, "Zm9vYg==", "b64 'foob'");

    mqvpn_auth_b64_encode(buf, sizeof(buf), (const unsigned char *)"fooba", 5);
    ASSERT_EQ_STR(buf, "Zm9vYmE=", "b64 'fooba'");

    mqvpn_auth_b64_encode(buf, sizeof(buf), (const unsigned char *)"foobar", 6);
    ASSERT_EQ_STR(buf, "Zm9vYmFy", "b64 'foobar'");
}

static void test_b64_encode_padding(void)
{
    char buf[128];

    /* 1 byte → 4 chars with == padding */
    mqvpn_auth_b64_encode(buf, sizeof(buf), (const unsigned char *)"\x00", 1);
    ASSERT_EQ_STR(buf, "AA==", "b64 single zero byte");

    /* 2 bytes → 4 chars with = padding */
    mqvpn_auth_b64_encode(buf, sizeof(buf), (const unsigned char *)"\xff\xfe", 2);
    ASSERT_EQ_STR(buf, "//4=", "b64 0xff 0xfe");

    /* 3 bytes → 4 chars no padding */
    mqvpn_auth_b64_encode(buf, sizeof(buf), (const unsigned char *)"\x01\x02\x03", 3);
    ASSERT_EQ_STR(buf, "AQID", "b64 1 2 3");
}

static void test_b64_encode_buffer_limit(void)
{
    char buf[5]; /* Only room for 4 chars + NUL */
    int ret = mqvpn_auth_b64_encode(buf, sizeof(buf), (const unsigned char *)"foo", 3);
    /* "Zm9v" = 4 chars, should fit in buf[5] */
    ASSERT_EQ_INT(ret, 0, "b64 buffer fits");
    ASSERT_EQ_STR(buf, "Zm9v", "b64 exact fit");

    /* Try too small buffer */
    char tiny[3];
    ret = mqvpn_auth_b64_encode(tiny, sizeof(tiny), (const unsigned char *)"foo", 3);
    ASSERT_TRUE(ret != 0, "b64 buffer too small returns error");
}

int main(void)
{
    test_ct_compare_equal();
    test_ct_compare_different();
    test_ct_compare_length_mismatch();
    test_ct_compare_empty();
    test_ct_compare_single_byte_diff();
    test_b64_encode_known_vectors();
    test_b64_encode_padding();
    test_b64_encode_buffer_limit();

    printf("\n=== test_auth: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
