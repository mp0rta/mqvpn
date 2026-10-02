// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

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
    fun `classifyTransport returns BLUETOOTH for bluetooth transport`() {
        val caps = ShadowNetworkCapabilities.newInstance()
        Shadows.shadowOf(caps).addTransportType(NetworkCapabilities.TRANSPORT_BLUETOOTH)
        assertEquals(PathType.BLUETOOTH, NetworkMonitor.classifyTransport(caps))
    }

    @Test
    fun `classifyTransport returns OTHER for unknown transport`() {
        val caps = ShadowNetworkCapabilities.newInstance()
        Shadows.shadowOf(caps).addTransportType(NetworkCapabilities.TRANSPORT_LOWPAN)
        assertEquals(PathType.OTHER, NetworkMonitor.classifyTransport(caps))
    }

    @Test
    fun `networkName includes type and partial handle`() {
        val network = ShadowNetwork.newInstance(42)
        val name = NetworkMonitor.networkName(network, PathType.WIFI)
        assertTrue("name should start with 'wifi-', got: $name", name.startsWith("wifi-"))
    }

    // The JNI copies a path name into char[16]; a longer one is cut short.
    // networkName appends "-" and at most four digits (handle and 0xFFF).
    @Test
    fun `every path type name fits the 15-character path name limit`() {
        for (type in PathType.entries) {
            val longest = "${type.name.lowercase()}-4095"
            assertTrue("$longest is longer than 15 characters", longest.length <= 15)
        }
    }

    @Test
    fun `holdTransports holds wifi, cellular and ethernet without bluetooth`() {
        assertEquals(
            listOf(
                NetworkCapabilities.TRANSPORT_WIFI,
                NetworkCapabilities.TRANSPORT_CELLULAR,
                NetworkCapabilities.TRANSPORT_ETHERNET,
            ),
            NetworkMonitor.holdTransports(holdBluetooth = false),
        )
    }

    @Test
    fun `holdTransports adds bluetooth when asked`() {
        assertEquals(
            listOf(
                NetworkCapabilities.TRANSPORT_WIFI,
                NetworkCapabilities.TRANSPORT_CELLULAR,
                NetworkCapabilities.TRANSPORT_ETHERNET,
                NetworkCapabilities.TRANSPORT_BLUETOOTH,
            ),
            NetworkMonitor.holdTransports(holdBluetooth = true),
        )
    }

    @Test
    fun `start registers the listener and one hold per transport`() {
        val context = RuntimeEnvironment.getApplication()
        val registered = registeredCallbacks(context)
        val monitor = NetworkMonitor(context)
        monitor.start {}
        assertEquals(1 + 3, registered.size)
        monitor.stop()
    }

    @Test
    fun `start adds the bluetooth hold when asked`() {
        val context = RuntimeEnvironment.getApplication()
        val registered = registeredCallbacks(context)
        val monitor = NetworkMonitor(context, holdBluetooth = true)
        monitor.start {}
        assertEquals(1 + 4, registered.size)
        monitor.stop()
    }

    @Test
    fun `stop releases the listener and every hold`() {
        val context = RuntimeEnvironment.getApplication()
        val registered = registeredCallbacks(context)
        val monitor = NetworkMonitor(context, holdBluetooth = true)
        monitor.start {}
        monitor.stop()
        assertTrue("still registered: $registered", registered.isEmpty())
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

    /** Live view of the callbacks registered with the shadow ConnectivityManager. */
    private fun registeredCallbacks(context: Context): Set<ConnectivityManager.NetworkCallback> =
        Shadows.shadowOf(context.getSystemService(ConnectivityManager::class.java)).networkCallbacks
}
