package com.mqvpn.sdk.core

import com.mqvpn.sdk.core.model.MqvpnError
import org.junit.Assert.assertTrue
import org.junit.Test

class MqvpnErrorTest {

    @Test
    fun `fromNativeCode maps TLS error`() {
        val err = MqvpnError.fromNativeCode(-4)
        assertTrue(err is MqvpnError.TlsError)
    }

    @Test
    fun `fromNativeCode maps auth error`() {
        val err = MqvpnError.fromNativeCode(-5)
        assertTrue(err is MqvpnError.AuthFailed)
    }

    @Test
    fun `fromNativeCode maps timeout`() {
        val err = MqvpnError.fromNativeCode(-12)
        assertTrue(err is MqvpnError.Timeout)
    }

    @Test
    fun `fromNativeCode maps unknown code`() {
        val err = MqvpnError.fromNativeCode(-99)
        assertTrue(err is MqvpnError.Unknown)
        assertEquals(-99, (err as MqvpnError.Unknown).nativeCode)
    }

    private fun assertEquals(expected: Int, actual: Int) {
        org.junit.Assert.assertEquals(expected.toLong(), actual.toLong())
    }
}
