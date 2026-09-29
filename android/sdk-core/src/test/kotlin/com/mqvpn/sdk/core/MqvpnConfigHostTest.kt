// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import com.mqvpn.sdk.core.model.MqvpnConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MqvpnConfigHostTest {
    private fun cfg(addr: String, sni: String? = null) = MqvpnConfig(serverAddress = addr, tlsServerName = sni, authKey = "k")

    @Test fun bareIdentifiersAccepted() {
        assertNull(cfg("vpn.example.com").hostIdentifierError())
        assertNull(cfg("192.0.2.10", "vpn.example.com").hostIdentifierError())
        assertNull(cfg("2001:db8::1").hostIdentifierError())
        assertNull(cfg("a.example.com.").hostIdentifierError())                       // trailing dot on a DNS name
        assertNull(cfg(("a".repeat(63) + ".").repeat(3) + "b".repeat(61) + ".").hostIdentifierError())  // 253 + dot
    }
    @Test fun rejected() {
        assertEquals("serverAddress must be a bare host without brackets", cfg("[2001:db8::1]").hostIdentifierError())
        assertNotNull(cfg("").hostIdentifierError())
        assertEquals(
            "tlsServerName must be printable ASCII without spaces",
            cfg("vpn.example.com", "bücher.example").hostIdentifierError(),
        )
        assertEquals("serverAddress is longer than 253 characters", cfg("a".repeat(254)).hostIdentifierError())
        assertNotNull(cfg("vpn.example.com", "").hostIdentifierError())
        assertNotNull(cfg(" 127.0.0.1").hostIdentifierError())
        assertNotNull(cfg("a".repeat(254) + ".").hostIdentifierError())  // 254 after strip
    }
    @Test fun messagesNameTheField() {
        assertTrue(cfg("").hostIdentifierError()!!.startsWith("serverAddress"))
        assertTrue(cfg("vpn.example.com", "").hostIdentifierError()!!.startsWith("tlsServerName"))
    }
}
