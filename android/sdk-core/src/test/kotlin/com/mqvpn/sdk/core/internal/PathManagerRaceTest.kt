// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core.internal

import android.net.Network
import com.mqvpn.sdk.core.MqvpnTunnel
import com.mqvpn.sdk.core.TestReflection
import com.mqvpn.sdk.network.NetworkEvent
import com.mqvpn.sdk.network.NetworkMonitor
import com.mqvpn.sdk.network.NetworkPath
import com.mqvpn.sdk.network.PathType
import com.mqvpn.sdk.runtime.ExecutorStoppedException
import com.mqvpn.sdk.runtime.MqvpnExecutor
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Verifies the race-fix in [PathManager.handleEvent]:
 * if onLost fires while bindAndDetachUdp is running on Dispatchers.IO,
 * the post-bind executor block must NOT call addPath. Otherwise a path
 * slot would be leaked, bound to an already-dead Network handle.
 * Also the bad-fd chain: the ledger is cleared WITHOUT a close.
 *
 * Tests use a synchronous [MqvpnExecutor], injected [bindUdp] / [closeFd]
 * lambdas (so PathBinder and Os.close are bypassed), and a real
 * [NetworkMonitor] whose internal map is manipulated via reflection to
 * simulate the active set.
 *
 * [MqvpnTunnel] is reflectively constructed with handle=0 (= destroyed):
 * every method returns an error without a JNI call, so `libmqvpn_jni` is
 * never loaded here.
 */
@RunWith(RobolectricTestRunner::class)
class PathManagerRaceTest {

    private val syncExecutor = object : MqvpnExecutor {
        override suspend fun <T> call(block: () -> T): T = block()
        override fun enqueue(block: () -> Unit) { block() }
        override fun start() {}
        override fun stop(finalizer: () -> Unit) { finalizer() }
    }

    @Test
    fun `Lost-during-bind aborts addPath and leaves pathHandles empty`() = runBlocking {
        val monitor = NetworkMonitor(RuntimeEnvironment.getApplication())  // start() is NOT called

        val bindCalls = AtomicInteger(0)
        val closed = mutableListOf<Int>()
        val pm = PathManager(
            executor = syncExecutor,
            tunnel = createDummyTunnel(),
            networkMonitor = monitor,
            protector = { true },
            serverHost = "1.2.3.4",
            serverPort = 443,
            onFatal = { fail("no fatal expected: $it") },
            bindUdp = { _, _, _, _ ->
                bindCalls.incrementAndGet()
                FAKE_FD  // simulate successful bind
            },
            closeFd = { closed.add(it) },
        )

        // monitor.activeNetworks is empty → simulates "Lost fired during bind".
        val net = newNetwork(netId = 100)
        val path = NetworkPath(net, PathType.WIFI, "wifi-100", isMetered = false)

        pm.handleEvent(NetworkEvent.Available(path))

        assertEquals("bindUdp should be invoked exactly once", 1, bindCalls.get())
        val handles = readPathHandles(pm)
        assertTrue("pathHandles must be empty after abort, got: $handles", handles.isEmpty())
        assertEquals("the discarded fd is closed (it was never registered)", listOf(FAKE_FD), closed)
    }

    @Test
    fun `bind into active network reaches addPath (proves abort is not always taken)`() = runBlocking {
        val monitor = NetworkMonitor(RuntimeEnvironment.getApplication())

        val net = newNetwork(netId = 200)
        val path = NetworkPath(net, PathType.WIFI, "wifi-200", isMetered = false)
        injectActiveNetwork(monitor, net, path)

        val closed = mutableListOf<Int>()
        val pm = PathManager(
            executor = syncExecutor,
            tunnel = createDummyTunnel(),
            networkMonitor = monitor,
            protector = { true },
            serverHost = "1.2.3.4",
            serverPort = 443,
            onFatal = { fail("no fatal expected: $it") },
            bindUdp = { _, _, _, _ -> FAKE_FD },
            closeFd = { closed.add(it) },
        )

        // The abort branch is NOT taken: addPath is reached. The destroyed
        // dummy tunnel answers -1 without a JNI call, so the manager takes
        // the add-failure branch — the fd it still owns gets closed.
        pm.handleEvent(NetworkEvent.Available(path))
        assertEquals("addPath failed → the fd is closed by its owner", listOf(FAKE_FD), closed)
        assertTrue(readPathHandles(pm).isEmpty())
    }

    @Test
    fun `Lost removes the path, closes its fd and clears the ledger`() = runBlocking {
        val monitor = NetworkMonitor(RuntimeEnvironment.getApplication())
        val closed = mutableListOf<Int>()
        val pm = PathManager(
            executor = syncExecutor,
            tunnel = createDummyTunnel(),
            networkMonitor = monitor,
            protector = { true },
            serverHost = "1.2.3.4",
            serverPort = 443,
            onFatal = { fail("no fatal expected: $it") },
            bindUdp = { _, _, _, _ -> FAKE_FD },
            closeFd = { closed.add(it) },
        )
        val net = newNetwork(netId = 500)
        val path = NetworkPath(net, PathType.WIFI, "wifi-500", isMetered = false)
        // A registered path (ledger entries injected: the dummy tunnel cannot add one).
        injectLedger(pm, net, handle = 42L, fd = FAKE_FD)

        pm.handleEvent(NetworkEvent.Lost(path))

        assertEquals("the platform closes its own fd", listOf(FAKE_FD), closed)
        assertTrue("handle dropped from the ledger", readPathHandles(pm).isEmpty())
        assertTrue("fd dropped from the ledger", readPathFds(pm).isEmpty())
    }

    @Test
    fun `bad fd - ledger cleared without a close and no fatal`() = runBlocking {
        val monitor = NetworkMonitor(RuntimeEnvironment.getApplication())
        val closed = mutableListOf<Int>()
        val fatal = mutableListOf<String>()
        val pm = PathManager(
            executor = syncExecutor,
            tunnel = createDummyTunnel(),
            networkMonitor = monitor,
            protector = { true },
            serverHost = "1.2.3.4",
            serverPort = 443,
            onFatal = { fatal.add(it) },
            bindUdp = { _, _, _, _ -> FAKE_FD },
            closeFd = { closed.add(it) },
        )
        val net = newNetwork(netId = 300)
        // A registered path (ledger entries injected: the dummy tunnel cannot add one).
        injectLedger(pm, net, handle = 42L, fd = FAKE_FD)

        pm.handleBadFd(42L)

        assertTrue("handle dropped from the ledger", readPathHandles(pm).isEmpty())
        assertTrue("fd dropped from the ledger", readPathFds(pm).isEmpty())
        assertTrue("the number may belong to another socket: never closed here, got $closed", closed.isEmpty())
        // The destroyed dummy tunnel answers INVALID_STATE, not POISONED: no fatal.
        assertTrue("no fatal, got $fatal", fatal.isEmpty())
    }

    @Test
    fun `poisoned release ends the session`() = runBlocking {
        val monitor = NetworkMonitor(RuntimeEnvironment.getApplication())
        val fatal = mutableListOf<String>()
        val tunnel = createDummyTunnel()
        val pm = PathManager(
            executor = syncExecutor,
            tunnel = tunnel,
            networkMonitor = monitor,
            protector = { true },
            serverHost = "1.2.3.4",
            serverPort = 443,
            onFatal = { fatal.add(it) },
            bindUdp = { _, _, _, _ -> FAKE_FD },
            closeFd = { },
        )
        // checkReleased is the seam that maps the reactor's code to the policy.
        pm.checkReleased(com.mqvpn.sdk.native_.NativeBridge.REACTOR_POISONED, "wifi-1")
        assertEquals(1, fatal.size)
        assertTrue(fatal[0], fatal[0].contains("poisoned"))
        pm.checkReleased(0, "wifi-1")
        pm.checkReleased(-13, "wifi-1")
        assertEquals("only POISONED is fatal", 1, fatal.size)
    }

    @Test
    fun `executor stopped during bind - the fd is closed and nothing is registered`() = runBlocking {
        val monitor = NetworkMonitor(RuntimeEnvironment.getApplication())
        val net = newNetwork(netId = 400)
        val path = NetworkPath(net, PathType.WIFI, "wifi-400", isMetered = false)
        injectActiveNetwork(monitor, net, path)
        val stoppedExecutor = object : MqvpnExecutor {
            override suspend fun <T> call(block: () -> T): T = throw ExecutorStoppedException()
            override fun enqueue(block: () -> Unit) {}
            override fun start() {}
            override fun stop(finalizer: () -> Unit) { finalizer() }
        }
        val closed = mutableListOf<Int>()
        val pm = PathManager(
            executor = stoppedExecutor,
            tunnel = createDummyTunnel(),
            networkMonitor = monitor,
            protector = { true },
            serverHost = "1.2.3.4",
            serverPort = 443,
            onFatal = { fail("no fatal expected: $it") },
            bindUdp = { _, _, _, _ -> FAKE_FD },
            closeFd = { closed.add(it) },
        )
        pm.handleEvent(NetworkEvent.Available(path))   // must not throw
        assertEquals("the bound fd is still ours: closed", listOf(FAKE_FD), closed)
        assertTrue(readPathHandles(pm).isEmpty())
        pm.handleEvent(NetworkEvent.Lost(path))        // must not throw either
        assertEquals("a refused Lost closes nothing", listOf(FAKE_FD), closed)
    }

    private fun newNetwork(netId: Int): Network {
        // ShadowNetwork.newInstance(int) is the canonical way; fall back to
        // reflection on the (int) constructor for Robolectric versions that
        // don't expose it directly.
        val ctor = Network::class.java.getDeclaredConstructor(Int::class.javaPrimitiveType)
        ctor.isAccessible = true
        return ctor.newInstance(netId)
    }

    private fun createDummyTunnel(): MqvpnTunnel = TestReflection.createDummyTunnel()

    @Suppress("UNCHECKED_CAST")
    private fun readPathHandles(pm: PathManager): Map<Network, Long> {
        val field = PathManager::class.java.getDeclaredField("pathHandles")
        field.isAccessible = true
        return field.get(pm) as Map<Network, Long>
    }

    @Suppress("UNCHECKED_CAST")
    private fun readPathFds(pm: PathManager): Map<Long, Int> {
        val field = PathManager::class.java.getDeclaredField("pathFds")
        field.isAccessible = true
        return field.get(pm) as Map<Long, Int>
    }

    @Suppress("UNCHECKED_CAST")
    private fun injectLedger(pm: PathManager, network: Network, handle: Long, fd: Int) {
        (readPathHandles(pm) as MutableMap<Network, Long>)[network] = handle
        (readPathFds(pm) as MutableMap<Long, Int>)[handle] = fd
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
