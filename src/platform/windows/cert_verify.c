// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors
#include "cert_verify.h"

#include <string.h>

#include "log.h"

/* wininet.h constant; defined here rather than pulling in wininet.h. */
#ifndef SECURITY_FLAG_IGNORE_CERT_CN_INVALID
#  define SECURITY_FLAG_IGNORE_CERT_CN_INVALID 0x00001000
#endif

/* CryptoAPI takes DWORD lengths; nothing near this size is a certificate. */
#define CERT_LEN_MAX 0x7FFFFFFF

/* Words for the policy errors operators will meet; "" for the rest. */
static const char *
policy_error_hint(DWORD err)
{
    switch ((HRESULT)err) {
    case CERT_E_EXPIRED: return ": expired or not yet valid";
    case CERT_E_UNTRUSTEDROOT: return ": root not trusted by this machine";
    case CERT_E_CHAINING: return ": incomplete chain (server must send intermediates)";
    case CERT_E_WRONG_USAGE: return ": not valid for server authentication";
    default: return "";
    }
}

mqvpn_win_id_result_t
mqvpn_win_cert_identity_match(PCCERT_CONTEXT leaf, const char *host)
{
    if (!leaf || !leaf->pCertInfo) return MQVPN_WIN_ID_NO_SAN;
    /* 2.5.29.17 only, the same extension Android reads; the obsolete
     * 2.5.29.7 OID is deliberately not consulted. */
    PCERT_EXTENSION ext =
        CertFindExtension(szOID_SUBJECT_ALT_NAME2, leaf->pCertInfo->cExtension,
                          leaf->pCertInfo->rgExtension);
    if (!ext) return mqvpn_win_identity_match_san(NULL, 0, host);
    return mqvpn_win_identity_match_san(ext->Value.pbData, (size_t)ext->Value.cbData,
                                        host);
}

int
mqvpn_win_cert_verify(const uint8_t *const certs[], const size_t cert_len[],
                      size_t n_certs, const char *hostname, void *ctx)
{
    int rc = -1;
    PCCERT_CONTEXT leaf = NULL;
    HCERTSTORE extra = NULL;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    HCERTCHAINENGINE engine = (HCERTCHAINENGINE)ctx; /* NULL = default */

    /* 1. inputs. Every rejection logs a fixed reason; the host is printed
     * only once the identity step has accepted it as printable ASCII. */
    if (n_certs == 0 || !certs || !cert_len || !hostname) {
        LOG_ERR("TLS certificate rejected: empty chain or missing host");
        goto cleanup;
    }
    for (size_t i = 0; i < n_certs; i++) {
        if (!certs[i] || cert_len[i] == 0 || cert_len[i] > CERT_LEN_MAX) {
            LOG_ERR("TLS certificate rejected: certificate %zu has an unusable length",
                    i);
            goto cleanup;
        }
    }

    /* 2. contexts */
    leaf = CertCreateCertificateContext(X509_ASN_ENCODING, certs[0], (DWORD)cert_len[0]);
    if (!leaf) {
        LOG_ERR("TLS certificate rejected: leaf does not decode (0x%08lx)",
                (unsigned long)GetLastError());
        goto cleanup;
    }
    extra = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!extra) {
        LOG_ERR("TLS certificate rejected: memory store (0x%08lx)",
                (unsigned long)GetLastError());
        goto cleanup;
    }
    for (size_t i = 1; i < n_certs; i++) {
        if (!CertAddEncodedCertificateToStore(extra, X509_ASN_ENCODING, certs[i],
                                              (DWORD)cert_len[i],
                                              CERT_STORE_ADD_REPLACE_EXISTING, NULL)) {
            LOG_ERR("TLS certificate rejected: certificate %zu does not decode (0x%08lx)",
                    i, (unsigned long)GetLastError());
            goto cleanup;
        }
    }

    /* 3. identity (shared rule), before trust as on Android */
    {
        mqvpn_win_id_result_t id = mqvpn_win_cert_identity_match(leaf, hostname);
        if (id == MQVPN_WIN_ID_INVALID_HOST || id == MQVPN_WIN_ID_NO_SAN) {
            LOG_ERR("TLS certificate rejected: %s", mqvpn_win_id_result_str(id));
            goto cleanup;
        }
        if (id != MQVPN_WIN_ID_OK) {
            LOG_ERR("TLS certificate rejected: %s %s", mqvpn_win_id_result_str(id),
                    hostname);
            goto cleanup;
        }
    }

    /* 4. chain: no network retrieval of any kind (this runs synchronously on
     * the thread that drives tick(), and AIA/CRL retrieval can block for
     * seconds). Intermediates come from the server and the local CA stores. */
    {
        LPSTR usages[] = {(LPSTR)szOID_PKIX_KP_SERVER_AUTH};
        CERT_CHAIN_PARA para;
        memset(&para, 0, sizeof(para));
        para.cbSize = sizeof(para);
        para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
        para.RequestedUsage.Usage.cUsageIdentifier = 1;
        para.RequestedUsage.Usage.rgpszUsageIdentifier = usages;
        if (!CertGetCertificateChain(engine, leaf, NULL, extra, &para,
                                     CERT_CHAIN_DISABLE_AIA |
                                         CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
                                     NULL, &chain)) {
            LOG_ERR("TLS certificate rejected: chain building failed (0x%08lx)",
                    (unsigned long)GetLastError());
            goto cleanup;
        }
    }

    /* 5. policy: trust anchor, validity, EKU, constraints, signature. The
     * name check is off: identity was decided in step 3. */
    {
        SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl;
        CERT_CHAIN_POLICY_PARA ppara;
        CERT_CHAIN_POLICY_STATUS status;
        memset(&ssl, 0, sizeof(ssl));
        memset(&ppara, 0, sizeof(ppara));
        memset(&status, 0, sizeof(status));
        ssl.cbSize = sizeof(ssl);
        ssl.dwAuthType = AUTHTYPE_SERVER;
        ssl.fdwChecks =
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID; /* ignore CERT_E_CN_NO_MATCH */
        ssl.pwszServerName = NULL;                /* and nothing to compare against */
        ppara.cbSize = sizeof(ppara);
        ppara.pvExtraPolicyPara = &ssl;
        status.cbSize = sizeof(status);
        if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &ppara,
                                              &status)) {
            LOG_ERR("TLS certificate rejected: policy call failed (0x%08lx)",
                    (unsigned long)GetLastError());
            goto cleanup;
        }
        if (status.dwError != 0) {
            LOG_ERR(
                "TLS certificate rejected: chain policy error 0x%08lx (element %ld)%s",
                (unsigned long)status.dwError, (long)status.lElementIndex,
                policy_error_hint(status.dwError));
            goto cleanup;
        }
    }
    rc = 0; /* the only success */

cleanup:
    /* Release calls are not part of the verdict: a failure to release cannot
     * be acted on here and is logged only. */
    if (chain) CertFreeCertificateChain(chain);
    if (extra && !CertCloseStore(extra, 0))
        LOG_WRN("CertCloseStore failed (0x%08lx)", (unsigned long)GetLastError());
    if (leaf && !CertFreeCertificateContext(leaf))
        LOG_WRN("CertFreeCertificateContext failed (0x%08lx)",
                (unsigned long)GetLastError());
    return rc;
}
