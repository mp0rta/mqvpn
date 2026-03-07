package com.mqvpn.sdk.core

import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.util.Log
import com.mqvpn.sdk.runtime.MqvpnExecutor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileDescriptor
import java.io.FileInputStream
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

/**
 * TUN ↔ libmqvpn packet I/O bridge.
 *
 * Uplink (TUN → libmqvpn):
 *   TUN reader (IO) → frameChannel → sender (Default) → coalesce batch
 *   → executor.enqueue { onTunPacket() × N }
 *
 * Downlink (libmqvpn → TUN):
 *   Direct write(tun_fd) from C tun_output callback — no Kotlin involvement.
 */
internal class TunnelBridge(
    private val executor: MqvpnExecutor,
    private val tunnel: MqvpnTunnel,
) {
    private val framePool = ConcurrentLinkedQueue<ByteArray>()
    private val poolSize = AtomicInteger(0)
    private val frameChannel = Channel<Pair<ByteArray, Int>>(FRAME_POOL_CAPACITY)

    private var readerJob: Job? = null
    private var senderJob: Job? = null

    fun startTunReader(tunPfd: ParcelFileDescriptor, mtu: Int, scope: CoroutineScope) {
        val fis = FileInputStream(tunPfd.fileDescriptor)
        readerJob = scope.launch(Dispatchers.IO) {
            val bufSize = mtu + 4 // TUN header overhead
            try {
                while (isActive) {
                    val frame = acquireFrame(bufSize)
                    val n = fis.read(frame)
                    if (n <= 0) break
                    frameChannel.send(Pair(frame, n))
                }
            } catch (e: Exception) {
                if (isActive) Log.w(TAG, "TUN reader stopped: ${e.message}")
            }
        }
    }

    fun startSender(scope: CoroutineScope) {
        senderJob = scope.launch(Dispatchers.Default) {
            val batch = mutableListOf<Pair<ByteArray, Int>>()
            try {
                while (isActive) {
                    // Wait for first frame
                    val first = frameChannel.receiveCatching().getOrNull() ?: break
                    batch.add(first)

                    // Drain all immediately available frames (no waiting)
                    while (batch.size < MAX_BATCH_SIZE) {
                        val result = frameChannel.tryReceive()
                        if (result.isSuccess) {
                            batch.add(result.getOrThrow())
                        } else {
                            break
                        }
                    }

                    // Submit batch to executor
                    val frames = batch.toList()
                    batch.clear()
                    executor.enqueue {
                        for (i in frames.indices) {
                            val (frame, len) = frames[i]
                            val rc = tunnel.onTunPacket(frame, 0, len)
                            releaseFrame(frame)
                            if (rc == MqvpnTunnel.ERR_AGAIN) {
                                // Backpressure: release ALL remaining frames before stop
                                for (j in (i + 1) until frames.size) {
                                    releaseFrame(frames[j].first)
                                }
                                break
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                if (isActive) Log.w(TAG, "TUN sender stopped: ${e.message}")
            }
        }
    }

    fun stop() {
        readerJob?.cancel()
        senderJob?.cancel()
        readerJob = null
        senderJob = null
        frameChannel.close()
    }

    private fun acquireFrame(size: Int): ByteArray {
        val frame = framePool.poll()
        if (frame != null) {
            poolSize.decrementAndGet()
            return frame
        }
        return ByteArray(size)
    }

    private fun releaseFrame(frame: ByteArray) {
        if (poolSize.get() < FRAME_POOL_CAPACITY) {
            framePool.offer(frame)
            poolSize.incrementAndGet()
        }
        // else: let GC collect (pool full)
    }

    companion object {
        private const val TAG = "TunnelBridge"
        private const val FRAME_POOL_CAPACITY = 192
        private const val MAX_BATCH_SIZE = 64
    }
}
