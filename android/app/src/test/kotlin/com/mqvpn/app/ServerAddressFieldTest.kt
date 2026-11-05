// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import com.mqvpn.app.data.ServerAddressField
import com.mqvpn.app.data.ServerAddressField.Parsed
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ServerAddressFieldTest {
    @Test
    fun `round trips the grammar`() {
        for ((text, p) in listOf(
            "example.net" to Parsed("example.net", 443),
            "example.net:8443" to Parsed("example.net", 8443),
            "fd00::1" to Parsed("fd00::1", 443),
            "[fd00::1]" to Parsed("fd00::1", 443),
            "[fd00::1]:8443" to Parsed("fd00::1", 8443),
        )) {
            assertEquals(text, p, ServerAddressField.parse(text))
            assertEquals(p, ServerAddressField.parse(ServerAddressField.format(p.address, p.port)))
        }
    }

    @Test
    fun `format always emits host and port`() {
        assertEquals("203.0.113.10:443", ServerAddressField.format("203.0.113.10", 443))
        assertEquals("[fd00::1]:8443", ServerAddressField.format("fd00::1", 8443))
    }

    @Test
    fun `rejects malformed input`() {
        for (t in listOf("", "  ", "[fd00::1", "example.net:0", "example.net:65536", "example.net:", ":443", "a b", "[fd00::1]x", "[example]:1", "1:2:xyz"))
            assertNull(t, ServerAddressField.parse(t))
    }
}
