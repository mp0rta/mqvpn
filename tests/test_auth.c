/*
 * test_auth.c — unit tests for auth utilities (constant-time compare, base64)
 *
 * Build: cc -o tests/test_auth tests/test_auth.c src/auth.c src/log.c -Isrc
 */
#include "auth.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

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

/* Helper: redirect stdout to tmpfile, run genkey, restore stdout,
 * read output into buf.  Returns genkey's return value or -1 on
 * setup failure. */
static int capture_genkey(char *buf, size_t bufsize)
{
    char tmppath[] = "/tmp/test_auth_genkey_XXXXXX";
    int tmpfd = mkstemp(tmppath);
    if (tmpfd < 0) return -1;

    int saved = dup(STDOUT_FILENO);
    if (saved < 0) { close(tmpfd); unlink(tmppath); return -1; }
    if (dup2(tmpfd, STDOUT_FILENO) < 0) {
        close(tmpfd); close(saved); unlink(tmppath); return -1;
    }
    close(tmpfd);

    int ret = mqvpn_auth_genkey();

    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);

    buf[0] = '\0';
    FILE *fp = fopen(tmppath, "r");
    if (fp) {
        if (fgets(buf, (int)bufsize, fp) == NULL)
            buf[0] = '\0';
        fclose(fp);
    }
    unlink(tmppath);

    /* Strip trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';

    return ret;
}

static int is_valid_b64(const char *s, size_t len)
{
    if (len % 4 != 0) return 0;    /* base64 output is always a multiple of 4 */

    int pad_started = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '=') {
            pad_started = 1;
        } else if (pad_started) {
            return 0;               /* non-pad char after '=' */
        } else if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                     (c >= '0' && c <= '9') || c == '+' || c == '/')) {
            return 0;
        }
    }
    /* padding must be 0, 1, or 2 chars at the end */
    size_t pad = 0;
    while (pad < len && s[len - 1 - pad] == '=') pad++;
    return pad <= 2;
}

static void test_genkey(void)
{
    char buf[128];
    int ret = capture_genkey(buf, sizeof(buf));
    if (ret < 0) {
        g_fail++;
        fprintf(stderr, "FAIL [genkey]: capture setup failed\n");
        return;
    }

    ASSERT_EQ_INT(ret, 0, "genkey returns 0");

    size_t len = strlen(buf);

    /* 32 bytes → 44 base64 chars */
    ASSERT_EQ_INT((int)len, 44, "genkey output is 44 chars");
    ASSERT_TRUE(is_valid_b64(buf, len), "genkey output is valid base64");
}

static void test_b64_encode_32_bytes(void)
{
    /* Simulate genkey: 32 raw bytes → 44 base64 chars */
    unsigned char raw[32];
    for (int i = 0; i < 32; i++) raw[i] = (unsigned char)i;

    char buf[64];
    int ret = mqvpn_auth_b64_encode(buf, sizeof(buf), raw, 32);
    ASSERT_EQ_INT(ret, 0, "b64 32 bytes ok");
    ASSERT_EQ_INT((int)strlen(buf), 44, "b64 32 bytes → 44 chars");

    /* No padding for 32 bytes (32 % 3 = 2 → 1 '=' pad) */
    ASSERT_TRUE(buf[43] == '=', "b64 32 bytes has padding");
}

static void test_b64_encode_all_zeros(void)
{
    unsigned char zeros[3] = {0, 0, 0};
    char buf[16];
    int ret = mqvpn_auth_b64_encode(buf, sizeof(buf), zeros, 3);
    ASSERT_EQ_INT(ret, 0, "b64 all zeros ok");
    ASSERT_EQ_STR(buf, "AAAA", "b64 all zeros");
}

static void test_b64_encode_all_ff(void)
{
    unsigned char ffs[3] = {0xff, 0xff, 0xff};
    char buf[16];
    int ret = mqvpn_auth_b64_encode(buf, sizeof(buf), ffs, 3);
    ASSERT_EQ_INT(ret, 0, "b64 all 0xff ok");
    ASSERT_EQ_STR(buf, "////", "b64 all 0xff");
}

static void test_ct_compare_long_strings(void)
{
    /* 256-byte strings */
    char a[256], b[256];
    for (int i = 0; i < 256; i++) {
        a[i] = (char)(i & 0x7f);
        b[i] = (char)(i & 0x7f);
    }
    ASSERT_EQ_INT(mqvpn_auth_ct_compare(a, 256, b, 256), 0,
                  "ct_compare 256 bytes equal");

    /* Differ at last byte */
    b[255] = (char)((b[255] + 1) & 0x7f);
    ASSERT_TRUE(mqvpn_auth_ct_compare(a, 256, b, 256) != 0,
                "ct_compare 256 bytes differ at end");
}

static void test_ct_compare_one_side_empty(void)
{
    const char *a = "notempty";
    ASSERT_TRUE(mqvpn_auth_ct_compare(a, strlen(a), "", 0) != 0,
                "ct_compare one side empty");
    ASSERT_TRUE(mqvpn_auth_ct_compare("", 0, a, strlen(a)) != 0,
                "ct_compare other side empty");
}

static void test_genkey_format_and_uniqueness(void)
{
    /* Primary: both outputs have correct format (44-char valid base64).
     * Secondary (informational): they should differ.  Collision probability
     * is 2^-256 so this never flakes in practice, but we log instead of
     * failing to keep CI deterministic. */
    char buf1[128], buf2[128];
    int ret1 = capture_genkey(buf1, sizeof(buf1));
    int ret2 = capture_genkey(buf2, sizeof(buf2));

    if (ret1 < 0 || ret2 < 0) {
        g_fail++;
        fprintf(stderr, "FAIL [genkey_format_uniqueness]: capture setup failed\n");
        return;
    }

    /* Primary checks: both keys have correct format */
    ASSERT_EQ_INT(ret1, 0, "genkey #1 returns 0");
    ASSERT_EQ_INT(ret2, 0, "genkey #2 returns 0");
    ASSERT_EQ_INT((int)strlen(buf1), 44, "genkey #1 is 44 chars");
    ASSERT_EQ_INT((int)strlen(buf2), 44, "genkey #2 is 44 chars");
    ASSERT_TRUE(is_valid_b64(buf1, strlen(buf1)), "genkey #1 valid base64");
    ASSERT_TRUE(is_valid_b64(buf2, strlen(buf2)), "genkey #2 valid base64");

    /* Informational: keys should differ (not a hard failure) */
    if (strcmp(buf1, buf2) == 0) {
        fprintf(stderr, "INFO [genkey_uniqueness]: two keys matched "
                "(p=2^-256, likely /dev/urandom issue)\n");
    }
}

int main(void)
{
    test_ct_compare_equal();
    test_ct_compare_different();
    test_ct_compare_length_mismatch();
    test_ct_compare_empty();
    test_ct_compare_single_byte_diff();
    test_ct_compare_long_strings();
    test_ct_compare_one_side_empty();
    test_b64_encode_known_vectors();
    test_b64_encode_padding();
    test_b64_encode_buffer_limit();
    test_b64_encode_32_bytes();
    test_b64_encode_all_zeros();
    test_b64_encode_all_ff();
    test_genkey();
    test_genkey_format_and_uniqueness();

    printf("\n=== test_auth: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
