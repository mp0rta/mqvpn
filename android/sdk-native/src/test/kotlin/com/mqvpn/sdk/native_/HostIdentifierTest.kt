// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.native_

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HostIdentifierTest {
    private fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
    private fun ip(h: String): ByteArray {
        val r = HostIdentifier.classify(h)
        assertTrue("'$h' should classify as Ip", r is HostIdentifier.Result.Ip)
        return (r as HostIdentifier.Result.Ip).bytes
    }
    private fun dns(h: String): String {
        val r = HostIdentifier.classify(h)
        assertTrue("'$h' should classify as Dns", r is HostIdentifier.Result.Dns)
        return (r as HostIdentifier.Result.Dns).name
    }
    private fun invalid(h: String) = assertTrue("'$h' should be Invalid", HostIdentifier.classify(h) is HostIdentifier.Result.Invalid)

    @Test fun ipv4() {
        assertArrayEquals(b(192, 0, 2, 10), ip("192.0.2.10"))
        assertArrayEquals(b(198, 51, 100, 7), ip("198.51.100.7"))
    }
    @Test fun ipv6_compressed() = assertArrayEquals(b(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), ip("2001:db8::1"))
    @Test fun ipv6_loopback() = assertArrayEquals(b(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1), ip("::1"))
    @Test fun ipv6_spellings_equal() {
        assertArrayEquals(ip("2001:db8::1"), ip("2001:0DB8:0000:0000:0000:0000:0000:0001"))
        assertArrayEquals(ip("2001:db8::1"), ip("2001:0db8::1"))
        assertArrayEquals(b(0,0,0,0,0,0,0,0,0,0,0xff,0xff,198,51,100,7), ip("::ffff:198.51.100.7"))
        assertArrayEquals(ip("::ffff:198.51.100.7"), ip("::ffff:c633:6407"))
    }
    @Test fun ipv4_mapped_stays_16_bytes() =
        assertArrayEquals(b(0,0,0,0,0,0,0,0,0,0,0xff,0xff,0xc0,0x00,0x02,0x0a), ip("::ffff:192.0.2.10"))
    @Test fun dns_normalised() { assertEquals("a.example.com", dns("A.EXAMPLE.COM.")); assertEquals("a.example.com", dns("a.example.com")) }
    @Test fun dns_max_length_with_trailing_dot_ok() {
        val name = ("a".repeat(63) + ".").repeat(3) + "b".repeat(61)   // 253 chars
        assertEquals(253, name.length); assertEquals(name, dns("$name."))
    }
    @Test fun dns_bare_0x_is_dns() =
        // "0x" with no hex digit is not numeric (glibc inet_aton rejects it too); the Windows grammar must agree
        assertEquals("0x", dns("0x"))

    @Test fun accepted_shapes() {
        val cases: List<Pair<String, Any>> = listOf(
            "1:2:3:4:5:6:1.2.3.4" to b(0,1, 0,2, 0,3, 0,4, 0,5, 0,6, 1,2,3,4),
            "::" to b(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0),
            "1::" to b(0,1, 0,0,0,0,0,0,0,0,0,0,0,0,0,0),
            "::1.2.3.4" to b(0,0,0,0,0,0,0,0,0,0,0,0, 1,2,3,4),
            "1:2:3:4:5:6:7::" to b(0,1, 0,2, 0,3, 0,4, 0,5, 0,6, 0,7, 0,0),
            "123.example" to "123.example",
            "a-b.example" to "a-b.example",
            "localhost" to "localhost",
            "0x1.example" to "0x1.example",
            "xn--bcher-kva.example" to "xn--bcher-kva.example",
            "A.B.C" to "a.b.c",
            "a.b.c.d." to "a.b.c.d",
        )
        for ((input, expected) in cases) {
            when (expected) {
                is ByteArray -> assertArrayEquals("'$input'", expected, ip(input))
                is String -> assertEquals("'$input'", expected, dns(input))
                else -> error("unreachable")
            }
        }
    }

    @Test fun rejected_shapes() {
        for (h in listOf("1.2.3.4.5", "256.0.0.1", "01.2.3.4", ":::", "::1::", "1:2:3:4:5:6:7:8::",
                         "1:2:3:4:5:6:7:1.2.3.4", "1.2.3.4::1", "::1.2.3.4:1", "::ffff:1.2.3", "12345::1",
                         "g::1", "1.2.3.0x1f", "1:2:3:4:5:6::1.2.3.4", "0xff.0xff.0xff.0xff", "example.com..",
                         "a.example.com\t", "127.0.0.1 ")) invalid(h)
    }

    @Test fun invalid_hosts() {
        for (h in listOf("", ".", "192.0.2.10.", "1.2.3", "192.0.2.010", "1:2", "1:2:3:4:5:6:7:8:9", "[2001:db8::1]",
                         "bücher.example", "*.example.com", "0x7f000001", "0x7f.0.0.1", "0177.0.0.1", "127.1",
                         "+127.0.0.1", " 127.0.0.1", "-a.example.com", "a_b.example.com", "a..example.com",
                         "2001:db8::1%eth0", "1::2::3", "2001:db8::1.", "a".repeat(255), "a".repeat(64) + ".com",
                         ("a".repeat(63) + ".").repeat(3) + "b".repeat(62))) invalid(h)
    }
}
