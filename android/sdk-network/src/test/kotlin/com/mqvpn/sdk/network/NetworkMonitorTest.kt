package com.mqvpn.sdk.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows
import org.robolectric.shadows.ShadowConnectivityManager
import org.robolectric.shadows.ShadowNetwork
import org.robolectric.shadows.ShadowNetworkCapabilities

@RunWith(RobolectricTestRunner::class)
class NetworkMonitorTest {

    @Test
    fun `classifyTransport returns WIFI for wifi transport`() {
        val caps = ShadowNetworkCapabilities.newInstance()
        Shadows.shadowOf(caps).addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
        assertEquals(PathType.WIFI, NetworkMonitor.classifyTransport(caps))
    }

    @Test
    fun `classifyTransport returns CELLULAR for cellular transport`() {
        val caps = ShadowNetworkCapabilities.newInstance()
        Shadows.shadowOf(caps).addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
        assertEquals(PathType.CELLULAR, NetworkMonitor.classifyTransport(caps))
    }

    @Test
    fun `classifyTransport returns ETHERNET for ethernet transport`() {
        val caps = ShadowNetworkCapabilities.newInstance()
        Shadows.shadowOf(caps).addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
        assertEquals(PathType.ETHERNET, NetworkMonitor.classifyTransport(caps))
    }

    @Test
    fun `classifyTransport returns OTHER for unknown transport`() {
        val caps = ShadowNetworkCapabilities.newInstance()
        Shadows.shadowOf(caps).addTransportType(NetworkCapabilities.TRANSPORT_BLUETOOTH)
        assertEquals(PathType.OTHER, NetworkMonitor.classifyTransport(caps))
    }

    @Test
    fun `networkName includes type and partial handle`() {
        val network = ShadowNetwork.newInstance(42)
        val name = NetworkMonitor.networkName(network, PathType.WIFI)
        assertTrue("name should start with 'wifi-', got: $name", name.startsWith("wifi-"))
    }

    @Test
    fun `activeNetworks is empty before start`() {
        val context = RuntimeEnvironment.getApplication()
        val monitor = NetworkMonitor(context)
        assertTrue(monitor.activeNetworks.isEmpty())
    }

    @Test
    fun `stop clears activeNetworks`() {
        val context = RuntimeEnvironment.getApplication()
        val monitor = NetworkMonitor(context)
        val events = mutableListOf<NetworkEvent>()
        monitor.start { events.add(it) }
        monitor.stop()
        assertTrue(monitor.activeNetworks.isEmpty())
    }
}
