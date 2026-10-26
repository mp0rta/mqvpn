// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.data

/** Single "host[:port]" text field, as on desktop. Pure so it is unit-testable. */
object ServerAddressField {
    data class Parsed(val address: String, val port: Int)

    private const val DEFAULT_PORT = 443

    /** Accepts host | host:port | v6literal | [v6] | [v6]:port; null when malformed. */
    fun parse(text: String): Parsed? {
        val t = text.trim()
        if (t.isEmpty() || t.any { it.isWhitespace() }) return null
        if (t.startsWith("[")) {
            val close = t.indexOf(']')
            if (close < 0) return null
            val host = t.substring(1, close)
            if (!isV6(host)) return null
            val rest = t.substring(close + 1)
            if (rest.isEmpty()) return Parsed(host, DEFAULT_PORT)
            if (!rest.startsWith(":")) return null
            return port(rest.substring(1))?.let { Parsed(host, it) }
        }
        return when (t.count { it == ':' }) {
            0 -> Parsed(t, DEFAULT_PORT)
            1 -> {
                val host = t.substringBefore(':')
                val p = port(t.substringAfter(':'))
                if (host.isEmpty() || p == null) null else Parsed(host, p)
            }
            else -> if (isV6(t)) Parsed(t, DEFAULT_PORT) else null
        }
    }

    /** Always "host:port" (even :443); v6 literals are bracketed. */
    fun format(address: String, port: Int): String =
        if (address.contains(':')) "[$address]:$port" else "$address:$port"

    private fun isV6(s: String) = s.contains(':') && s.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }

    private fun port(s: String): Int? =
        if (s.isNotEmpty() && s.all { it in '0'..'9' } && s.length <= 5) s.toInt().takeIf { it in 1..65535 } else null
}
