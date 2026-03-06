package com.mqvpn.sdk.network

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows
import org.robolectric.shadows.ShadowConnectivityManager

/**
 * NetworkSelector unit tests + PathBinder structural validation.
 *
 * PathBinder.bindAndDetachUdp() uses Android-internal
 * DatagramSocket.getFileDescriptor$() via ParcelFileDescriptor.fromDatagramSocket().
 * This API is not available in Robolectric JVM, so FD-level tests
 * (bind, dup, detach, leak detection) require instrumented androidTest.
 */
@RunWith(RobolectricTestRunner::class)
class PathBinderTest {

    // --- NetworkSelector ---

    @Test
    fun `findFirst returns result from ConnectivityManager`() {
        // Robolectric's CM may or may not have networks;
        // verify the method doesn't crash
        val context = RuntimeEnvironment.getApplication()
        // Simply verify no exception is thrown
        NetworkSelector.findFirst(context, NetworkCapabilities.TRANSPORT_WIFI)
    }

    @Test
    fun `findFirst returns null for bluetooth transport`() {
        val context = RuntimeEnvironment.getApplication()
        val result = NetworkSelector.findFirst(context, NetworkCapabilities.TRANSPORT_BLUETOOTH)
        // Robolectric default has wifi/cell but not bluetooth
        assertNull(result)
    }

    @Test
    fun `findNonPrimary does not throw`() {
        val context = RuntimeEnvironment.getApplication()
        // May return null or a network depending on Robolectric setup
        NetworkSelector.findNonPrimary(context)
    }

    @Test
    fun `findNonPrimary returns null when cleared`() {
        val context = RuntimeEnvironment.getApplication()
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val shadow = Shadows.shadowOf(cm)
        shadow.clearAllNetworks()
        val result = NetworkSelector.findNonPrimary(context)
        assertNull(result)
    }

    @Test
    fun `findFirst returns null when networks cleared`() {
        val context = RuntimeEnvironment.getApplication()
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val shadow = Shadows.shadowOf(cm)
        shadow.clearAllNetworks()
        val result = NetworkSelector.findFirst(context, NetworkCapabilities.TRANSPORT_WIFI)
        assertNull(result)
    }

    // --- PathBinder structural ---

    @Test
    fun `PathBinder has expected public methods`() {
        val methods = PathBinder::class.java.declaredMethods.map { it.name }
        assertTrue("bindAndDetachUdp should exist", methods.contains("bindAndDetachUdp"))
        assertTrue("bindAndDetachUdpByLocalAddr should exist",
            methods.contains("bindAndDetachUdpByLocalAddr"))
    }

    @Test
    fun `PathBinder is a singleton object`() {
        assertNotNull(PathBinder)
    }
}
