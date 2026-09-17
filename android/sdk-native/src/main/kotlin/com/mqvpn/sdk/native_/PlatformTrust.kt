// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.native_

import android.net.http.X509TrustManagerExtensions
import androidx.annotation.Keep
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * The Android platform certificate verifier libmqvpn calls on every TLS
 * handshake (via mqvpn_jni.c). Identity is decided here (RFC 9525 rules for
 * ASCII identifiers: SAN only, no CN, no IDNA), then trust is delegated to
 * the platform's X509TrustManager (system CA store plus the app's network
 * security config). Stateless by design: nothing here can be swapped at run
 * time by other code in the process.
 *
 * Resolved from C by literal name ("verify"), so this object is public and
 * its JVM name must not be mangled — kept by @Keep and by consumer-rules.pro.
 */
object PlatformTrust {
    /** Trust step. Throws when the chain is not trusted for [host]. */
    internal fun interface TrustChecker {
        fun check(chain: Array<X509Certificate>, host: String)
    }

    private const val REASON_INVALID_HOST = "invalid host"
    private const val REASON_NO_SAN = "certificate has no subject alternative name"
    private const val REASON_NO_IP_SAN = "certificate has no IP address SAN for"
    private const val REASON_NO_DNS_SAN = "certificate has no DNS SAN for"
    private const val REASON_MISMATCH = "certificate hostname mismatch for"
    private const val REASON_MALFORMED_AT = "malformed certificate at index"
    private const val REASON_EMPTY_CHAIN = "malformed certificate chain: empty"
    private const val REASON_VERIFIER_ERROR = "verifier error"

    /** Returns null when the chain is trusted for [host], else a non-null one-line reason. */
    @JvmStatic
    @Keep
    fun verify(chainDer: Array<ByteArray>, host: String): String? = verifyWith(chainDer, host, PlatformChecker)

    /** Same as [verify] with the trust step supplied by the caller (JVM tests pass a fake). */
    internal fun verifyWith(chainDer: Array<ByteArray>, host: String, checker: TrustChecker): String? {
        try {
            if (chainDer.isEmpty()) return REASON_EMPTY_CHAIN
            val certs = Array(chainDer.size) { i -> parseCertificate(chainDer[i]) ?: return "$REASON_MALFORMED_AT $i" }
            identity(certs[0], host)?.let { return it }
            checker.check(certs, HostIdentifier.normalise(host))
            return null
        } catch (t: Throwable) {
            // A rejection reason is never null: null means trusted and nothing else may produce it.
            return "$REASON_VERIFIER_ERROR: ${(t.message ?: t.javaClass.name).replace('\n', ' ').take(512)}"
        }
    }

    /** Strict parse: the provider's re-encoding must equal the input byte-for-byte — rejects
     *  trailing bytes, PEM, and (on Conscrypt) any non-DER outer encoding. */
    internal fun parseCertificate(der: ByteArray): X509Certificate? = try {
        val c = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as? X509Certificate
        if (c != null && c.encoded.contentEquals(der)) c else null
    } catch (_: Exception) { null }

    /** The identity rule (RFC 9525 rules for ASCII identifiers, leaf SAN only): null = the leaf
     *  may speak for [host]; else a reason with a fixed prefix. */
    internal fun identity(leaf: X509Certificate, host: String): String? {
        val ref = HostIdentifier.classify(host)
        if (ref is HostIdentifier.Result.Invalid) return REASON_INVALID_HOST   // steps 1-2 come before the SAN lookup
        val ext = leaf.getExtensionValue("2.5.29.17") ?: return REASON_NO_SAN
        val inner = SanDer.unwrapOctetString(ext) ?: return REASON_NO_SAN
        val entries = SanDer.walk(inner) ?: return REASON_NO_SAN
        val shown = HostIdentifier.normalise(host)
        return when (ref) {
            is HostIdentifier.Result.Ip -> {
                if (entries.any { it.kind == SanDer.Kind.IP && it.bytes.contentEquals(ref.bytes) }) null
                else "$REASON_NO_IP_SAN $shown"
            }
            is HostIdentifier.Result.Dns -> {
                val names = entries.filter { it.kind == SanDer.Kind.DNS }
                if (names.isEmpty()) return "$REASON_NO_DNS_SAN $shown"
                if (names.any { dnsMatches(String(it.bytes, Charsets.US_ASCII), ref) }) null
                else "$REASON_MISMATCH $shown"
            }
            HostIdentifier.Result.Invalid -> REASON_INVALID_HOST   // exhaustiveness only: returned above
        }
    }

    /**
     * Exact match, or a left-most whole-label "*" standing for exactly one
     * non-empty host label. Only the SAN side is normalised here; [ref] is
     * already lower-case, dot-stripped LDH.
     */
    internal fun dnsMatches(sanEntry: String, ref: HostIdentifier.Result.Dns): Boolean {
        var e = HostIdentifier.asciiLower(sanEntry)
        if (e.endsWith('.')) e = e.dropLast(1)
        if (e == ref.name) return true
        if (!e.startsWith("*.")) return false
        val suffix = e.substring(1)                 // ".example.com"
        if (suffix.indexOf('*') >= 0) return false
        val dot = ref.name.indexOf('.')
        if (dot <= 0) return false                  // host needs a non-empty first label and a rest
        return ref.name.substring(dot) == suffix
    }

    // Exercised only on a device: under isReturnDefaultValues the android.net.http stub would
    // accept everything, so JVM tests must inject a fake through verifyWith.
    /** Created lazily on first use so JVM unit tests (which inject a fake) never touch android.net.http. */
    private object PlatformChecker : TrustChecker {
        private val ext: X509TrustManagerExtensions by lazy {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as KeyStore?)
            val tm = tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
            X509TrustManagerExtensions(tm)
        }
        override fun check(chain: Array<X509Certificate>, host: String) {
            // authType is a dummy: Android only requires it non-empty, and Chromium passes "RSA" too.
            // host selects the app's network-security-config <domain-config> (per-domain trust
            // anchors and pins), not identity (decided before this).
            ext.checkServerTrusted(chain, "RSA", host)
        }
    }
}
