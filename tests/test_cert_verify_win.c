// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
// Windows-only: the CryptoAPI half of the certificate verifier, driven with
// an exclusive-root chain engine so the runner's own stores never matter.
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cert_verify.h"

static int g_run = 0, g_pass = 0;
#define TEST(name)                 \
    static void test_##name(void); \
    static void run_##name(void)   \
    {                              \
        g_run++;                   \
        printf("  %-56s ", #name); \
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

static uint8_t g_buf[16][8192];
static size_t g_len[16];
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
    int i = g_nbuf++ % 16;
    g_len[i] = fread(g_buf[i], 1, sizeof(g_buf[i]), f);
    fclose(f);
    *len = g_len[i];
    return g_buf[i];
}

/* An engine whose only trust anchor is chain-root.der. Exclusive-root mode
 * still consults the CA stores for intermediates; the test intermediate is in
 * no store on the runner, and every case builds a fresh engine (no chain cache). */
static HCERTSTORE g_roots;
static HCERTCHAINENGINE
test_engine(void)
{
    size_t n;
    const uint8_t *root = load("chain-root", &n);
    HCERTSTORE roots =
        CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!roots ||
        !CertAddEncodedCertificateToStore(roots, X509_ASN_ENCODING, root, (DWORD)n,
                                          CERT_STORE_ADD_ALWAYS, NULL)) {
        printf("FAIL: root store\n");
        exit(1);
    }
    CERT_CHAIN_ENGINE_CONFIG cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.cbSize = sizeof(cfg);
    cfg.hExclusiveRoot = roots;
    HCERTCHAINENGINE eng = NULL;
    if (!CertCreateCertificateChainEngine(&cfg, &eng)) {
        printf("FAIL: engine 0x%08lx\n", GetLastError());
        exit(1);
    }
    g_roots = roots; /* kept open for the engine's lifetime; free_engine closes it */
    return eng;
}
static void
free_engine(HCERTCHAINENGINE eng)
{
    CertFreeCertificateChainEngine(eng);
    CertCloseStore(g_roots, 0);
    g_roots = NULL;
}
static int
verify2(HCERTCHAINENGINE eng, const char *leaf, const char *inter, const char *host)
{
    size_t l1 = 0, l2 = 0;
    const uint8_t *c1 = load(leaf, &l1);
    const uint8_t *c2 = inter ? load(inter, &l2) : NULL;
    const uint8_t *certs[2] = {c1, c2};
    size_t lens[2] = {l1, inter ? l2 : 0};
    return mqvpn_win_cert_verify(certs, lens, inter ? 2 : 1, host, eng);
}
static mqvpn_win_id_result_t
idm(const char *leaf, const char *host)
{
    size_t n;
    const uint8_t *der = load(leaf, &n);
    PCCERT_CONTEXT c = CertCreateCertificateContext(X509_ASN_ENCODING, der, (DWORD)n);
    if (!c) {
        printf("FAIL: context %s\n", leaf);
        exit(1);
    }
    mqvpn_win_id_result_t r = mqvpn_win_cert_identity_match(c, host);
    CertFreeCertificateContext(c);
    return r;
}

TEST(a_default_engine_rejects_unknown_root)
{
    ASSERT_EQ(verify2(NULL, "chain-leaf", "chain-intermediate", "mqvpn-test"), -1);
}
TEST(b_test_engine_accepts)
{
    HCERTCHAINENGINE e = test_engine();
    ASSERT_EQ(verify2(e, "chain-leaf", "chain-intermediate", "mqvpn-test"), 0);
    free_engine(e);
}
TEST(c_wrong_name_rejected_with_name_check_off)
{
    HCERTCHAINENGINE e = test_engine();
    ASSERT_EQ(verify2(e, "chain-leaf", "chain-intermediate", "other.example"), -1);
    free_engine(e);
}
/* The fixture leaf carries no AIA URI, so this proves "missing intermediate
 * → rejected", not that network retrieval is disabled; the two flags are
 * pinned by review of cert_verify.c. */
TEST(d_missing_intermediate_rejected)
{
    HCERTCHAINENGINE e = test_engine();
    ASSERT_EQ(verify2(e, "chain-leaf", NULL, "mqvpn-test"), -1);
    free_engine(e);
}
TEST(e_truncated_leaf)
{
    HCERTCHAINENGINE e = test_engine();
    size_t l1, l2;
    const uint8_t *c1 = load("chain-leaf", &l1);
    const uint8_t *c2 = load("chain-intermediate", &l2);
    const uint8_t *certs[2] = {c1, c2};
    size_t lens[2] = {l1 - 1, l2};
    ASSERT_EQ(mqvpn_win_cert_verify(certs, lens, 2, "mqvpn-test", e), -1);
    free_engine(e);
}
TEST(f_bad_hosts)
{
    HCERTCHAINENGINE e = test_engine();
    ASSERT_EQ(verify2(e, "chain-leaf", "chain-intermediate", ""), -1);
    ASSERT_EQ(verify2(e, "chain-leaf", "chain-intermediate", NULL), -1);
    char h[300];
    memset(h, 'a', 256);
    h[256] = 0;
    ASSERT_EQ(verify2(e, "chain-leaf", "chain-intermediate", h), -1);
    free_engine(e);
}
TEST(g_identity_end_to_end)
{
    HCERTCHAINENGINE e = test_engine();
    ASSERT_EQ(verify2(e, "identity-ip", "chain-intermediate", "192.0.2.10"), 0);
    ASSERT_EQ(verify2(e, "identity-ip", "chain-intermediate", "2001:0db8::1"), 0);
    ASSERT_EQ(verify2(e, "identity-ip", "chain-intermediate", "::ffff:198.51.100.7"), 0);
    ASSERT_EQ(verify2(e, "identity-ip", "chain-intermediate", "192.0.2.11"), -1);
    ASSERT_EQ(verify2(e, "identity-wildcard", "chain-intermediate", "a.example.com"), 0);
    ASSERT_EQ(verify2(e, "identity-wildcard", "chain-intermediate", "a.b.example.com"),
              -1);
    ASSERT_EQ(verify2(e, "identity-cn-only", "chain-intermediate", "a.example.com"), -1);
    ASSERT_EQ(verify2(e, "identity-dns", "chain-intermediate", "a.example.com"), 0);
    free_engine(e);
}
TEST(h_untrusted_second_chain)
{
    HCERTCHAINENGINE e = test_engine();
    ASSERT_EQ(verify2(e, "other-leaf", "other-intermediate", "a.example.com"), -1);
    free_engine(e);
}
TEST(i_identity_unit_via_context)
{
    ASSERT_EQ(idm("identity-dns", "A.EXAMPLE.COM."), MQVPN_WIN_ID_OK);
    ASSERT_EQ(idm("identity-dns", "127.0.0.1"), MQVPN_WIN_ID_NO_IP_SAN);
    ASSERT_EQ(idm("identity-ip", "::ffff:c633:6407"), MQVPN_WIN_ID_OK);
    ASSERT_EQ(idm("identity-ip", "198.51.100.7"), MQVPN_WIN_ID_NO_IP_SAN);
    ASSERT_EQ(idm("identity-san-nul", "a.example.com"), MQVPN_WIN_ID_NO_SAN);
    ASSERT_EQ(idm("identity-san-mixed", "a.example.com"), MQVPN_WIN_ID_NO_SAN);
    ASSERT_EQ(idm("identity-san-malformed", "a.example.com"), MQVPN_WIN_ID_NO_SAN);
    ASSERT_EQ(idm("identity-cn-only", "a.example.com"), MQVPN_WIN_ID_NO_SAN);
    ASSERT_EQ(idm("identity-wildcard-partial", "fa.example.com"),
              MQVPN_WIN_ID_HOSTNAME_MISMATCH);
    ASSERT_EQ(idm("identity-dns", "[2001:db8::1]"), MQVPN_WIN_ID_INVALID_HOST);
}

int
main(void)
{
    run_a_default_engine_rejects_unknown_root();
    run_b_test_engine_accepts();
    run_c_wrong_name_rejected_with_name_check_off();
    run_d_missing_intermediate_rejected();
    run_e_truncated_leaf();
    run_f_bad_hosts();
    run_g_identity_end_to_end();
    run_h_untrusted_second_chain();
    run_i_identity_unit_via_context();
    printf("\n  %d/%d tests passed\n", g_pass, g_run);
    return g_pass == g_run ? 0 : 1;
}
