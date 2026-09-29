// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.native_

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class SanDerTest {
    private fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    /**
     * Emits tag + minimal DER length + body: short form under 128, one length octet for
     * 128..255, two for 256..65535. The non-minimal / leading-zero / indefinite / truncated
     * length vectors below stay hand-written bytes, because tlv() cannot produce them by design.
     */
    private fun tlv(tag: Int, body: ByteArray): ByteArray {
        require(body.size < 65536) { "test helper: tlv() supports lengths below 65536" }
        val header = when {
            body.size < 128 -> b(body.size)
            body.size < 256 -> b(0x81, body.size)
            else -> b(0x82, (body.size shr 8) and 0xFF, body.size and 0xFF)
        }
        return b(tag) + header + body
    }
    private fun dns(s: String) = tlv(0x82, s.toByteArray(Charsets.US_ASCII))
    private fun rfc(s: String) = tlv(0x81, s.toByteArray(Charsets.US_ASCII))
    private fun ip4() = tlv(0x87, b(192, 0, 2, 10))
    private fun seq(vararg parts: ByteArray): ByteArray {
        val body = parts.fold(ByteArray(0)) { a, p -> a + p }
        require(body.size < 128) { "test helper: short form only" }
        return tlv(0x30, body)
    }
    /** Like seq(), but emits a minimal long-form SEQUENCE length when the body needs one. */
    private fun seqL(vararg parts: ByteArray) = tlv(0x30, parts.fold(ByteArray(0)) { a, p -> a + p })

    @Test fun valid_dns_and_ip() {
        val e = requireNotNull(SanDer.walk(seq(dns("a.example.com"), ip4())))
        assertEquals(2, e.size)
        assertEquals(SanDer.Kind.DNS, e[0].kind); assertEquals("a.example.com", String(e[0].bytes, Charsets.US_ASCII))
        assertEquals(SanDer.Kind.IP, e[1].kind); assertArrayEquals(b(192, 0, 2, 10), e[1].bytes)
    }
    @Test fun valid_first_then_nul_fails() = assertNull(SanDer.walk(seq(dns("a.example.com"), b(0x82, 3, 'a'.code, 0x00, 'b'.code))))
    @Test fun trailing_byte_after_sequence() = assertNull(SanDer.walk(seq(dns("a.example.com")) + b(0x00)))
    @Test fun sequence_longer_than_input() { val s = seq(dns("a.example.com")); s[1] = (s[1] + 1).toByte(); assertNull(SanDer.walk(s)) }
    @Test fun element_overruns_sequence() { val s = seq(dns("a.example.com")); s[3] = (s[3] + 1).toByte(); assertNull(SanDer.walk(s)) }
    @Test fun lone_tag_at_end() = assertNull(SanDer.walk(b(0x30, 1, 0x82)))
    @Test fun long_form_header_truncated() {
        assertNull(SanDer.walk(b(0x30, 2, 0x82, 0x82)))
        assertNull(SanDer.walk(b(0x30, 3, 0x82, 0x82, 0x05)))   // 0x82 0x82 with only one length octet present
    }
    @Test fun indefinite_length() = assertNull(SanDer.walk(b(0x30, 0x80)))
    @Test fun length_of_length_too_big() = assertNull(SanDer.walk(b(0x30, 0x85, 0, 0, 0, 0, 1)))
    @Test fun length_above_int_max_fails() = assertNull(SanDer.walk(b(0x30, 0x84, 0x80, 0, 0, 0)))
    @Test fun non_minimal_long_form() = assertNull(SanDer.walk(b(0x30, 0x81, 0x05) + b(0x82, 3, 'a'.code, 'b'.code, 'c'.code)))
    @Test fun leading_zero_length_octet() = assertNull(SanDer.walk(b(0x30, 0x82, 0x00, 0x05) + b(0x82, 3, 'a'.code, 'b'.code, 'c'.code)))
    @Test fun constructed_dnsname_tag() = assertNull(SanDer.walk(seq(b(0xA2, 3, 'a'.code, 'b'.code, 'c'.code))))
    @Test fun universal_tag_element() = assertNull(SanDer.walk(seq(b(0x04, 1, 'a'.code))))
    @Test fun high_tag_number_form_fails() {
        assertNull(SanDer.walk(seq(tlv(0x9F, b('z'.code)))))
        assertNull(SanDer.walk(seq(tlv(0xBF, b('z'.code)))))
    }
    @Test fun empty_sequence() = assertNull(SanDer.walk(b(0x30, 0x00)))
    @Test fun empty_input_fails() {
        assertNull(SanDer.walk(ByteArray(0)))
        assertNull(SanDer.unwrapOctetString(ByteArray(0)))
    }
    @Test fun ip_length_5() = assertNull(SanDer.walk(seq(b(0x87, 5, 1, 2, 3, 4, 5))))
    @Test fun ip_length_0_fails() = assertNull(SanDer.walk(seq(tlv(0x87, ByteArray(0)))))
    @Test fun ip_length_3_fails() = assertNull(SanDer.walk(seq(tlv(0x87, b(1, 2, 3)))))
    @Test fun ip_length_16_succeeds() {
        val content = ByteArray(16) { (it + 1).toByte() }
        val e = requireNotNull(SanDer.walk(seq(tlv(0x87, content))))
        assertEquals(1, e.size)
        assertEquals(SanDer.Kind.IP, e[0].kind)
        assertArrayEquals(content, e[0].bytes)
    }
    @Test fun empty_dnsname() = assertNull(SanDer.walk(seq(b(0x82, 0))))
    @Test fun empty_rfc822name() = assertNull(SanDer.walk(seq(b(0x81, 0), dns("a.example.com"))))
    @Test fun dnsname_bad_octets() {
        for (bad in listOf(0x20, 0x00, 0x7F, 0x80)) assertNull("octet $bad", SanDer.walk(seq(b(0x82, 3, 'a'.code, bad, 'b'.code))))
    }
    @Test fun dnsname_boundary_octets_succeed() {
        val e = requireNotNull(SanDer.walk(seq(dns("!b~"))))
        assertEquals(1, e.size)
        assertEquals("!b~", String(e[0].bytes, Charsets.US_ASCII))
    }
    @Test fun rfc822name_skipped_before_dns() {
        val e = SanDer.walk(seq(b(0x81, 3, 'x'.code, '@'.code, 'y'.code), dns("a.example.com")))
        assertEquals(1, e!!.size); assertEquals(SanDer.Kind.DNS, e[0].kind)
    }
    @Test fun rfc822name_content_not_interpreted() {
        val e = SanDer.walk(seq(b(0x81, 2, 0x80, 'y'.code), dns("a.example.com")))
        assertEquals(1, e!!.size)
    }
    @Test fun other_skipped_tags_are_skipped() {
        for (tag in listOf(0xA0, 0xA3, 0xA4, 0xA5, 0x86, 0x88)) {
            val e = requireNotNull(SanDer.walk(seq(tlv(tag, b('z'.code)), dns("a.example.com")))) { "tag $tag" }
            assertEquals("tag $tag", 1, e.size)
            assertEquals("tag $tag", SanDer.Kind.DNS, e[0].kind)
        }
    }
    @Test fun sixty_four_ok_sixty_five_fail_counting_every_element() {
        fun many(n: Int, first: ByteArray): ByteArray {
            var body = first
            repeat(n - 1) { body += dns("a.example.com") }
            return tlv(0x30, body)
        }
        assertNotNull(SanDer.walk(many(64, dns("a.example.com"))))
        assertNull(SanDer.walk(many(65, dns("a.example.com"))))

        fun rfcThenTail(count: Int, tail: ByteArray = ByteArray(0)): ByteArray {
            var body = ByteArray(0)
            repeat(count) { body += rfc("x@y") }
            body += tail
            return tlv(0x30, body)
        }
        // 64 rfc822Name + 1 dNSName = 65 elements: a skipped element still counts.
        assertNull(SanDer.walk(rfcThenTail(64, dns("a.example.com"))))
        // 64 rfc822Name alone: skipped-only elements succeed with an empty list — "present but
        // no usable entry".
        val e = requireNotNull(SanDer.walk(rfcThenTail(64)))
        assertEquals(0, e.size)
    }
    @Test fun long_form_four_octets_at_boundary() {
        // 0x82 0x01 0x00 = 256 bytes of content is legal long form; a leading 0x00 length octet
        // is rejected (covered above); here: 0x84 with a leading non-zero octet but a value
        // larger than the input must fail cleanly, not throw.
        assertNull(SanDer.walk(b(0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF)))
    }
    @Test fun long_form_element_length_128_succeeds() {
        val e = requireNotNull(SanDer.walk(seqL(dns("a".repeat(128)))))
        assertEquals(1, e.size)
        assertEquals(SanDer.Kind.DNS, e[0].kind)
        assertEquals(128, e[0].bytes.size)
    }
    @Test fun long_form_element_length_256_succeeds() {
        val e = requireNotNull(SanDer.walk(seqL(dns("a".repeat(256)))))
        assertEquals(1, e.size)
        assertEquals(256, e[0].bytes.size)
    }
    @Test fun long_form_element_length_127_non_minimal_fails() {
        // Hand-written: 127 fits short form, so a long-form encoding of it is non-minimal.
        // tlv() always emits the minimal form and cannot produce this vector.
        val content = ByteArray(127) { 'a'.code.toByte() }
        val elem = b(0x82, 0x81, 0x7F) + content
        assertNull(SanDer.walk(seqL(elem)))
    }
    @Test fun unwrap_octet_string() {
        val inner = seq(dns("a.example.com"))
        val ext = b(0x04, inner.size) + inner
        assertArrayEquals(inner, SanDer.unwrapOctetString(ext))
        assertNull(SanDer.unwrapOctetString(b(0x04, inner.size + 1) + inner))   // input is one byte short of the declared length
        assertNull(SanDer.unwrapOctetString(ext + b(0x00)))                       // trailing byte
        assertNull(SanDer.unwrapOctetString(b(0x30, inner.size) + inner))         // wrong tag
    }
    @Test fun unwrap_octet_string_long_form_wrapper() {
        val innerBody = (1..9).fold(ByteArray(0)) { acc, _ -> acc + dns("a.example.com") }
        val inner = seqL(innerBody)
        val ext = tlv(0x04, inner)
        assertArrayEquals(inner, SanDer.unwrapOctetString(ext))
    }
}
