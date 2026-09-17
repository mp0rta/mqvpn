// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.native_

/**
 * Walker for the subjectAltName extension DER (RFC 5280 GeneralNames).
 *
 * The verifier decides identity from the raw extension bytes, never from the
 * provider's decoded view: Conscrypt silently drops a GeneralName it cannot
 * decode, so a poisoned entry next to a valid one would otherwise pass. Every
 * element is validated structurally; dNSName and iPAddress content is
 * validated; the other seven choices are skipped without interpretation.
 * Any structural or content failure returns null (all-or-nothing); callers
 * must not fall back to a partial view.
 */
internal object SanDer {
    enum class Kind { DNS, IP }

    /** [bytes] is the caller's to read, not to modify in place. */
    class Entry(val kind: Kind, val bytes: ByteArray) {
        override fun toString() = "$kind:" + bytes.joinToString("") { "%02x".format(it) }
    }

    /** Cap on GeneralName elements per SAN; skipped elements count against it. */
    const val MAX_ENTRIES = 64

    private const val TAG_SEQUENCE = 0x30
    private const val TAG_OCTET_STRING = 0x04
    private const val TAG_DNSNAME = 0x82
    private const val TAG_IPADDRESS = 0x87
    private val SKIPPED_TAGS = setOf(0xA0, 0x81, 0xA3, 0xA4, 0xA5, 0x86, 0x88)

    /** X509Certificate.getExtensionValue() returns the DER OCTET STRING wrapper; strip it. */
    fun unwrapOctetString(ext: ByteArray): ByteArray? {
        val r = Reader(ext)
        if (r.u8() != TAG_OCTET_STRING) return null
        val len = r.length() ?: return null
        if (len != r.remaining) return null
        return ext.copyOfRange(r.pos, r.pos + len)
    }

    /** Walks one GeneralNames SEQUENCE. null on any failure; an empty list is "no usable entry". */
    fun walk(generalNames: ByteArray): List<Entry>? {
        val r = Reader(generalNames)
        if (r.u8() != TAG_SEQUENCE) return null
        val seqLen = r.length() ?: return null
        if (seqLen != r.remaining || seqLen == 0) return null
        val out = ArrayList<Entry>()
        var count = 0
        while (r.remaining > 0) {
            val tag = r.u8() ?: return null
            val len = r.length() ?: return null
            if (len == 0 || len > r.remaining) return null
            if (++count > MAX_ENTRIES) return null
            when (tag) {
                TAG_DNSNAME -> {
                    val bytes = r.take(len) ?: return null
                    if (bytes.any { (it.toInt() and 0xFF) !in 0x21..0x7E }) return null
                    out.add(Entry(Kind.DNS, bytes))
                }
                TAG_IPADDRESS -> {
                    if (len != 4 && len != 16) return null
                    val bytes = r.take(len) ?: return null
                    out.add(Entry(Kind.IP, bytes))
                }
                in SKIPPED_TAGS -> if (!r.skip(len)) return null
                else -> return null
            }
        }
        return out
    }

    private class Reader(private val buf: ByteArray) {
        var pos = 0
        val remaining: Int get() = buf.size - pos
        fun u8(): Int? = if (remaining < 1) null else (buf[pos++].toInt() and 0xFF)
        /** DER length: short form, or minimal long form with 1..4 octets. null on any violation. */
        fun length(): Int? {
            val first = u8() ?: return null
            if (first < 0x80) return first
            val n = first and 0x7F
            if (n == 0 || n > 4) return null          // 0x80 indefinite; 0x85+ too long
            if (remaining < n) return null
            var v = 0L
            for (i in 0 until n) {
                val b = u8() ?: return null
                if (i == 0 && b == 0) return null    // leading zero octet: non-minimal
                v = (v shl 8) or b.toLong()
            }
            if (v < 0x80 || v > Int.MAX_VALUE) return null
            return v.toInt()
        }
        fun take(n: Int): ByteArray? {
            if (n > remaining) return null
            val b = buf.copyOfRange(pos, pos + n)
            pos += n
            return b
        }
        fun skip(n: Int): Boolean {
            if (n > remaining) return false
            pos += n
            return true
        }
    }
}
