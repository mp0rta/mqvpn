// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.native_

/**
 * The reference identifier the certificate must match, classified once, in
 * pure Kotlin. The Windows C port must mirror this grammar; change both or
 * neither.
 *
 * Normalise first (ASCII fold, one trailing dot stripped), then classify:
 * IPv4/IPv6 literal (bytes produced here, no resolver), LDH DNS hostname, or
 * INVALID. Anything numeric-looking that is not a strict literal is INVALID,
 * never a DNS name: the transport resolves the original string with the
 * platform resolver, whose lenient parsers accept 0x7f000001, 0177.0.0.1,
 * 127.1 and friends as addresses. A literal with a trailing dot is INVALID
 * for the same reason (resolvers treat it as a DNS query).
 */
internal object HostIdentifier {
    sealed class Result {
        data object Invalid : Result()
        class Ip(val bytes: ByteArray) : Result() {
            override fun toString() = "Ip:" + bytes.joinToString("") { "%02x".format(it) }
        }
        /** Normalised name (lower-case, no trailing dot). */
        class Dns(val name: String) : Result() {
            override fun toString() = "Dns:$name"
        }
    }

    fun classify(raw: String): Result {
        if (raw.length >= 255) return Result.Invalid            // 255+ = possibly truncated by the C setter
        if (raw.any { it.code !in 0x21..0x7E }) return Result.Invalid
        val folded = asciiLower(raw)
        val trailingDot = folded.endsWith('.')
        val h = if (trailingDot) folded.dropLast(1) else folded
        if (h.isEmpty() || h.indexOf('*') >= 0 || h.indexOf('[') >= 0 || h.indexOf(']') >= 0) return Result.Invalid

        parseIpv4(h)?.let { return if (trailingDot) Result.Invalid else Result.Ip(it) }
        if (h.indexOf(':') >= 0) {
            val v6 = parseIpv6(h) ?: return Result.Invalid
            return if (trailingDot) Result.Invalid else Result.Ip(v6)
        }
        if (h.all { it in '0'..'9' || it == '.' }) return Result.Invalid   // numeric-looking, not a literal (isLdhHostname would also reject; kept as the named rule)
        if (!isLdhHostname(h)) return Result.Invalid
        return Result.Dns(h)
    }

    /**
     * ASCII-only fold of A-Z; every other char is returned unchanged. Callers
     * pass printable ASCII (classify checks it; SAN dNSName entries are
     * checked by SanDer).
     */
    fun asciiLower(s: String): String {
        val sb = StringBuilder(s.length)
        for (c in s) sb.append(if (c in 'A'..'Z') (c + 32) else c)
        return sb.toString()
    }

    /** ASCII fold, then strip exactly one trailing dot (if present). Shared with [PlatformTrust]
     * for the identifier shown in a rejection reason and passed to the platform trust manager. */
    internal fun normalise(raw: String): String {
        val folded = asciiLower(raw)
        return if (folded.endsWith('.')) folded.dropLast(1) else folded
    }

    /** Exactly four labels, each "0" or [1-9][0-9]{0,2}, value <= 255. */
    private fun parseIpv4(s: String): ByteArray? {
        val parts = s.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for (i in 0 until 4) {
            val p = parts[i]
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return null
            if (p.length > 1 && p[0] == '0') return null
            val v = p.toInt()
            if (v > 255) return null
            out[i] = v.toByte()
        }
        return out
    }

    /** RFC 4291 text form: 1-4 hex digit groups, at most one "::", optional dotted-quad tail. */
    private fun parseIpv6(s: String): ByteArray? {
        if (s.isEmpty()) return null
        val dblColon = s.indexOf("::")
        if (dblColon >= 0 && s.indexOf("::", dblColon + 1) >= 0) return null
        val (head, tail) = when {
            dblColon < 0 -> s.split(':') to emptyList<String>()
            else -> {
                val h = if (dblColon == 0) emptyList() else s.substring(0, dblColon).split(':')
                val t = s.substring(dblColon + 2)
                h to (if (t.isEmpty()) emptyList() else t.split(':'))
            }
        }
        val groups = ArrayList<Int>(8)
        fun push(list: List<String>, allowDottedLast: Boolean): Boolean {
            for ((i, g) in list.withIndex()) {
                val last = i == list.size - 1
                if (allowDottedLast && last && g.indexOf('.') >= 0) {
                    val v4 = parseIpv4(g) ?: return false
                    groups.add(((v4[0].toInt() and 0xFF) shl 8) or (v4[1].toInt() and 0xFF))
                    groups.add(((v4[2].toInt() and 0xFF) shl 8) or (v4[3].toInt() and 0xFF))
                    continue
                }
                if (g.isEmpty() || g.length > 4 || !g.all { it in '0'..'9' || it in 'a'..'f' }) return false
                groups.add(g.toInt(16))
            }
            return true
        }
        if (!push(head, allowDottedLast = dblColon < 0)) return null
        val headCount = groups.size
        if (!push(tail, allowDottedLast = dblColon >= 0)) return null
        val tailCount = groups.size - headCount
        val out = ByteArray(16)
        fun put(idx: Int, v: Int) { out[idx * 2] = (v shr 8).toByte(); out[idx * 2 + 1] = v.toByte() }
        if (dblColon < 0) {
            if (groups.size != 8) return null
            for (i in 0 until 8) put(i, groups[i])
        } else {
            if (groups.size > 7) return null
            for (i in 0 until headCount) put(i, groups[i])
            for (i in 0 until tailCount) put(8 - tailCount + i, groups[headCount + i])
        }
        return out
    }

    /** LDH labels 1..63, no leading/trailing '-', total <= 253, and not every label numeric. */
    private fun isLdhHostname(h: String): Boolean {
        if (h.length > 253) return false
        val labels = h.split('.')
        var allNumeric = true
        for (l in labels) {
            if (l.isEmpty() || l.length > 63) return false
            if (l.first() == '-' || l.last() == '-') return false
            if (!l.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }) return false
            val numeric = l.all { it in '0'..'9' } ||
                (l.length > 2 && l.startsWith("0x") && l.drop(2).all { it in '0'..'9' || it in 'a'..'f' })
            if (!numeric) allNumeric = false
        }
        return !allNumeric
    }
}
