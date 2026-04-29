package com.mqvpn.sdk.core.internal

import android.net.Network
import com.mqvpn.sdk.core.MqvpnTunnel
import com.mqvpn.sdk.network.NetworkEvent
import com.mqvpn.sdk.network.NetworkMonitor
import com.mqvpn.sdk.network.NetworkPath
import com.mqvpn.sdk.network.PathType
import com.mqvpn.sdk.runtime.MqvpnExecutor
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Verifies the race-fix in [PathManager.handleEvent]:
 * if onLost fires while bindAndDetachUdp is running on Dispatchers.IO,
 * the post-bind executor block must NOT call addPathFd. Otherwise a path
 * slot would be leaked, bound to an already-dead Network handle.
 *
 * Tests use a synchronous [MqvpnExecutor], an injected [bindUdp] lambda
 * (so PathBinder is bypassed), and a real [NetworkMonitor] whose internal
 * map is manipulated via reflection to simulate the active set.
 *
 * [MqvpnTunnel] is reflectively constructed with handle=0 and never invoked
 * — the abort branch fires before any JNI call, so `libmqvpn_jni` does not
 * need to be loaded.
 */
@RunWith(RobolectricTestRunner::class)
class PathManagerRaceTest {

    private val syncExecutor = object : MqvpnExecutor {
        override suspend fun <T> call(block: () -> T): T = block()
        override fun enqueue(block: () -> Unit) { block() }
        override fun start() {}
        override fun stop() {}
    }

    @Test
    fun `Lost-during-bind aborts addPathFd and leaves pathHandles empty`() = runBlocking {
        val monitor = NetworkMonitor(RuntimeEnvironment.getApplication())  // start() is NOT called

        val bindCalls = AtomicInteger(0)
        val pm = PathManager(
            executor = syncExecutor,
            tunnel = createDummyTunnel(),
            udpReaderPool = UdpReaderPool(syncExecutor),
            networkMonitor = monitor,
            protector = { true },
            serverHost = "1.2.3.4",
            serverPort = 443,
            bindUdp = { _, _, _, _ ->
                bindCalls.incrementAndGet()
                FAKE_FD  // simulate successful bind
            },
        )

        // monitor.activeNetworks is empty → simulates "Lost fired during bind".
        val net = newNetwork(netId = 100)
        val path = NetworkPath(net, PathType.WIFI, "wifi-100", isMetered = false)

        pm.handleEvent(NetworkEvent.Available(path))

        assertEquals("bindUdp should be invoked exactly once", 1, bindCalls.get())
        val handles = readPathHandles(pm)
        assertTrue("pathHandles must be empty after abort, got: $handles", handles.isEmpty())
    }

    @Test
    fun `bind into active network reaches addPathFd (proves abort is not always taken)`() = runBlocking {
        val monitor = NetworkMonitor(RuntimeEnvironment.getApplication())

        val net = newNetwork(netId = 200)
        val path = NetworkPath(net, PathType.WIFI, "wifi-200", isMetered = false)
        injectActiveNetwork(monitor, net, path)

        val pm = PathManager(
            executor = syncExecutor,
            tunnel = createDummyTunnel(),
            udpReaderPool = UdpReaderPool(syncExecutor),
            networkMonitor = monitor,
            protector = { true },
            serverHost = "1.2.3.4",
            serverPort = 443,
            bindUdp = { _, _, _, _ -> FAKE_FD },
        )

        // Reaching addPathFd triggers NativeBridge <clinit> →
        // System.loadLibrary("mqvpn_jni") → UnsatisfiedLinkError in unit-test JVM.
        // Catching it proves the abort branch was NOT taken.
        var nativeReached = false
        try {
            pm.handleEvent(NetworkEvent.Available(path))
        } catch (e: UnsatisfiedLinkError) {
            nativeReached = true
        } catch (e: NoClassDefFoundError) {
            nativeReached = true
        } catch (e: ExceptionInInitializerError) {
            nativeReached = true
        }
        assertTrue("addPathFd JNI call should have been attempted", nativeReached)
    }

    private fun newNetwork(netId: Int): Network {
        // ShadowNetwork.newInstance(int) is the canonical way; fall back to
        // reflection on the (int) constructor for Robolectric versions that
        // don't expose it directly.
        val ctor = Network::class.java.getDeclaredConstructor(Int::class.javaPrimitiveType)
        ctor.isAccessible = true
        return ctor.newInstance(netId)
    }

    private fun createDummyTunnel(): MqvpnTunnel {
        val ctor = MqvpnTunnel::class.java.declaredConstructors.first()
        ctor.isAccessible = true
        return ctor.newInstance(0L, 0L) as MqvpnTunnel
    }

    @Suppress("UNCHECKED_CAST")
    private fun readPathHandles(pm: PathManager): Map<Network, Long> {
        val field = PathManager::class.java.getDeclaredField("pathHandles")
        field.isAccessible = true
        return field.get(pm) as Map<Network, Long>
    }

    @Suppress("UNCHECKED_CAST")
    private fun injectActiveNetwork(
        monitor: NetworkMonitor,
        network: Network,
        path: NetworkPath,
    ) {
        val field = NetworkMonitor::class.java.getDeclaredField("_activeNetworks")
        field.isAccessible = true
        val map = field.get(monitor) as ConcurrentHashMap<Network, NetworkPath>
        map[network] = path
    }

    companion object {
        private const val FAKE_FD = 999
    }
}
