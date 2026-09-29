// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.native_

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

class PlatformTrustTest {
    private fun fixture(name: String): ByteArray =
        PlatformTrustTest::class.java.getResourceAsStream("/$name.der")!!.use { it.readBytes() }
    private fun leaf(name: String): X509Certificate = PlatformTrust.parseCertificate(fixture(name)) ?: error("fixture $name did not parse")

    private class FakeChecker(private val throwable: Throwable? = null) : PlatformTrust.TrustChecker {
        var calls = 0; var host: String? = null
        override fun check(chain: Array<X509Certificate>, host: String) { calls++; this.host = host; throwable?.let { throw it } }
    }

    private fun idClass(name: String, host: String): String {
        val r = PlatformTrust.identity(leaf(name), host) ?: return "OK"
        // deliberately a second copy of the wording: the prefixes are an observable the C side and the instrumented tests rely on
        return listOf("invalid host", "certificate has no subject alternative name", "certificate has no IP address SAN for",
                      "certificate has no DNS SAN for", "certificate hostname mismatch for")
            .firstOrNull { r.startsWith(it) } ?: throw AssertionError("unexpected reason: $r")
    }

    // identity vectors, by outcome class
    @Test fun dns_vectors() {
        assertEquals("OK", idClass("identity-dns", "a.example.com"))
        assertEquals("OK", idClass("identity-dns", "A.EXAMPLE.COM."))
        assertEquals("certificate hostname mismatch for", idClass("identity-dns", "b.example.com"))
        assertEquals("certificate has no IP address SAN for", idClass("identity-dns", "127.0.0.1"))
    }
    @Test fun wildcard_vectors() {
        assertEquals("OK", idClass("identity-wildcard", "a.example.com"))
        assertEquals("certificate hostname mismatch for", idClass("identity-wildcard", "example.com"))
        assertEquals("certificate hostname mismatch for", idClass("identity-wildcard", "a.b.example.com"))
        assertEquals("certificate hostname mismatch for", idClass("identity-wildcard-partial", "fa.example.com"))
        assertEquals("certificate hostname mismatch for", idClass("identity-wildcard-multi", "a.b.example.com"))
    }
    @Test fun ip_vectors() {
        assertEquals("OK", idClass("identity-ip", "192.0.2.10"))
        assertEquals("OK", idClass("identity-ip", "2001:0db8::1"))
        assertEquals("OK", idClass("identity-ip", "::ffff:198.51.100.7"))
        assertEquals("OK", idClass("identity-ip", "::ffff:c633:6407"))
        assertEquals("certificate has no IP address SAN for", idClass("identity-ip", "192.0.2.11"))
        assertEquals("certificate has no IP address SAN for", idClass("identity-ip", "::ffff:192.0.2.10"))
        assertEquals("certificate has no IP address SAN for", idClass("identity-ip", "198.51.100.7"))
        assertEquals("certificate has no DNS SAN for", idClass("identity-ip", "a.example.com"))
    }
    @Test fun invalid_host_vectors() {
        for (h in listOf("192.0.2.10.", "1.2.3", "192.0.2.010", "1:2", "1:2:3:4:5:6:7:8:9", "[2001:db8::1]", "bücher.example",
                         "*.example.com", "", "a".repeat(255), "0x7f000001", "0x7f.0.0.1", "0177.0.0.1", "127.1",
                         "+127.0.0.1", " 127.0.0.1", "-a.example.com", "a_b.example.com", "a..example.com"))
            assertEquals(h, "invalid host", idClass("identity-dns", h))
    }
    @Test fun no_san_vectors() {
        assertEquals("certificate has no subject alternative name", idClass("identity-cn-only", "a.example.com"))
        assertEquals("certificate has no subject alternative name", idClass("identity-san-malformed", "a.example.com"))
        assertEquals("certificate has no subject alternative name", idClass("identity-san-nul", "a.example.com"))
        assertEquals("certificate has no subject alternative name", idClass("identity-san-mixed", "a.example.com"))
    }

    // pipeline
    @Test fun accept_with_fake_checker_receives_normalised_host() {
        val fake = FakeChecker()
        assertNull(PlatformTrust.verifyWith(arrayOf(fixture("identity-dns"), fixture("chain-intermediate")), "A.EXAMPLE.COM.", fake))
        assertEquals(1, fake.calls); assertEquals("a.example.com", fake.host)
    }
    @Test fun identity_failure_never_reaches_checker() {
        val fake = FakeChecker()
        assertNotNull(PlatformTrust.verifyWith(arrayOf(fixture("identity-dns")), "b.example.com", fake))
        assertEquals(0, fake.calls)
    }
    @Test fun checker_exception_is_a_non_null_reason() {
        val r = PlatformTrust.verifyWith(arrayOf(fixture("identity-dns")), "a.example.com", FakeChecker(CertificateException("untrusted")))
        assertTrue(r!!, r.contains("untrusted"))
        assertNotNull(PlatformTrust.verifyWith(arrayOf(fixture("identity-dns")), "a.example.com", FakeChecker(CertificateException())))
        assertNotNull(PlatformTrust.verifyWith(arrayOf(fixture("identity-dns")), "a.example.com", FakeChecker(object : Throwable() {})))
    }
    @Test fun empty_chain_and_malformed_der() {
        assertNotNull(PlatformTrust.verifyWith(emptyArray(), "a.example.com", FakeChecker()))
        val bad = fixture("chain-intermediate").copyOf(50)
        assertTrue(PlatformTrust.verifyWith(arrayOf(fixture("identity-dns"), bad), "a.example.com", FakeChecker())!!.startsWith("malformed certificate at index 1"))
        val trailing = fixture("identity-dns") + byteArrayOf(0)
        assertTrue(PlatformTrust.verifyWith(arrayOf(trailing), "a.example.com", FakeChecker())!!.startsWith("malformed certificate at index 0"))
    }
}
