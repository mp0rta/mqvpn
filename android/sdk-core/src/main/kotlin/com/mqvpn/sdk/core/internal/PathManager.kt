package com.mqvpn.sdk.core.internal

import android.net.Network
import android.system.Os
import android.util.Log
import com.mqvpn.sdk.core.MqvpnTunnel
import com.mqvpn.sdk.network.NetworkEvent
import com.mqvpn.sdk.network.NetworkMonitor
import com.mqvpn.sdk.network.PathBinder
import com.mqvpn.sdk.runtime.MqvpnExecutor

/**
 * Bridges [NetworkEvent]s from NetworkMonitor to libmqvpn path management.
 *
 * Execution context:
 * - handleEvent() runs on IO dispatcher (caller provides)
 * - Socket creation (blocking I/O) happens on calling thread
 * - tunnel.addPathFd/connect/removePath are serialized via executor.call
 */
internal class PathManager(
    private val executor: MqvpnExecutor,
    private val tunnel: MqvpnTunnel,
    private val udpReaderPool: UdpReaderPool,
    private val networkMonitor: NetworkMonitor,
    private val protector: (Int) -> Boolean,
    private val serverHost: String,
    private val serverPort: Int,
) {
    private var connected = false
    private val pathHandles = mutableMapOf<Network, Long>()  // network → pathHandle
    private val pathFds = mutableMapOf<Long, Int>()           // pathHandle → fd

    /**
     * Handle a network event. Must be called from IO dispatcher.
     *
     * Available: [IO] bindSocket → [executor] addPathFd + connect → startReader
     * Lost: [executor] removePath → stopReader → close(fd)
     */
    suspend fun handleEvent(event: NetworkEvent) {
        when (event) {
            is NetworkEvent.Available -> handleAvailable(event)
            is NetworkEvent.Lost -> handleLost(event)
        }
    }

    private suspend fun handleAvailable(event: NetworkEvent.Available) {
        val network = event.path.network
        val name = event.path.name

        // Step 1: Create socket (blocking I/O, runs on IO thread)
        val fd = PathBinder.bindAndDetachUdp(
            network, serverHost, serverPort, protector,
        )
        if (fd < 0) {
            Log.e(TAG, "Failed to bind socket for $name, will retry on next event")
            networkMonitor.removeNetwork(network)
            return
        }

        // Step 2: Add path + connect via executor (thread-safe)
        val handle = executor.call {
            val h = tunnel.addPathFd(fd, name)
            if (h < 0) {
                Log.e(TAG, "addPathFd failed for $name: $h")
                return@call h
            }
            pathHandles[network] = h
            pathFds[h] = fd

            if (!connected) {
                tunnel.setServerAddr(serverHost, serverPort)
                tunnel.connect()
                connected = true
            }
            h
        }

        if (handle < 0) {
            closeFdSafe(fd)
            return
        }

        // Step 3: Start UDP reader
        udpReaderPool.startReader(fd, handle, name, tunnel)
        Log.i(TAG, "Path added: $name (handle=$handle, fd=$fd)")
    }

    private suspend fun handleLost(event: NetworkEvent.Lost) {
        val network = event.path.network
        val name = event.path.name

        // Step 1: Remove path via executor (must happen before fd close)
        val (handle, fd) = executor.call {
            val h = pathHandles.remove(network) ?: return@call Pair(-1L, -1)
            val f = pathFds.remove(h) ?: return@call Pair(h, -1)
            tunnel.removePath(h)
            Pair(h, f)
        }

        if (handle < 0) return

        // Step 2: Stop reader (shutdown, NOT close)
        udpReaderPool.stopReader(handle)

        // Step 3: Close fd (last — after C and reader are done)
        if (fd >= 0) closeFdSafe(fd)
        Log.i(TAG, "Path removed: $name (handle=$handle)")
    }

    /** Close all remaining fds. Called from executor during cleanup. */
    fun closeAllFds() {
        for ((_, fd) in pathFds) {
            closeFdSafe(fd)
        }
        pathFds.clear()
        pathHandles.clear()
        connected = false
    }

    private fun closeFdSafe(fd: Int) {
        try {
            val fdObj = java.io.FileDescriptor()
            val field = java.io.FileDescriptor::class.java.getDeclaredField("descriptor")
            field.isAccessible = true
            field.setInt(fdObj, fd)
            Os.close(fdObj)
        } catch (e: Exception) {
            Log.w(TAG, "close fd=$fd failed: ${e.message}")
        }
    }

    companion object {
        private const val TAG = "PathManager"
    }
}
