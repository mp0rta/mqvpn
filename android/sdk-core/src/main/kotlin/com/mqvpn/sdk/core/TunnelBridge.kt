// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import android.system.Os
import android.system.OsConstants
import android.util.Log
import com.mqvpn.sdk.runtime.MqvpnExecutor
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.InputStream
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

/**
 * TUN ↔ libmqvpn packet I/O bridge.
 *
 * Uplink (TUN → libmqvpn):
 *   TUN reader (IO) → frameChannel → sender (Default) → coalesce batch
 *   → executor.call { onTunPacket() × N }, one batch at a time: while the
 *   engine thread is busy, frameChannel fills, the reader stalls and packets
 *   wait in the kernel's TUN queue. ERR_AGAIN drops that packet (the core's
 *   contract); the rest of the batch waits for [onTunReadable].
 *
 * Downlink (libmqvpn → TUN):
 *   Direct write(tun_fd) from C tun_output callback — no Kotlin involvement.
 */
internal class TunnelBridge(
    private val executor: MqvpnExecutor,
    private val onTunPacket: (ByteArray, Int, Int) -> Int, // MqvpnTunnel.onTunPacket
) {
    private val framePool = ConcurrentLinkedQueue<ByteArray>()
    private val poolSize = AtomicInteger(0)
    private val frameChannel = Channel<Pair<ByteArray, Int>>(FRAME_POOL_CAPACITY)

    private var readerJob: Job? = null
    private var senderJob: Job? = null

    // Engine thread only: what a sender held by ERR_AGAIN waits for.
    private var readable: CompletableDeferred<Unit>? = null

    fun startTunReader(tun: InputStream, mtu: Int, scope: CoroutineScope) {
        readerJob = scope.launch(Dispatchers.IO) {
            val bufSize = mtu + 4 // TUN header overhead
            try {
                while (isActive) {
                    val frame = acquireFrame(bufSize)
                    val n = tun.read(frame)
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

                    val frames = batch.toList()
                    batch.clear()
                    var next = 0
                    while (next < frames.size) {
                        val from = next
                        val (fed, wait) = executor.call { feed(frames, from) }
                        next = fed
                        wait?.await()
                    }
                }
            } catch (e: Exception) {
                if (isActive) Log.w(TAG, "TUN sender stopped: ${e.message}")
            }
        }
    }

    /**
     * Engine thread: feeds frames[from..] until the core returns ERR_AGAIN.
     * Returns where to go on and, after ERR_AGAIN, what to wait for first.
     */
    private fun feed(frames: List<Pair<ByteArray, Int>>, from: Int): Pair<Int, CompletableDeferred<Unit>?> {
        for (i in from until frames.size) {
            val (frame, len) = frames[i]
            val rc = onTunPacket(frame, 0, len)
            releaseFrame(frame)
            if (rc == MqvpnTunnel.ERR_AGAIN) {
                // the core dropped this packet and refuses every packet until tun_readable
                val wait = CompletableDeferred<Unit>()
                readable = wait
                return Pair(i + 1, wait)
            }
        }
        return Pair(frames.size, null)
    }

    /** Engine thread: the poller's interest reported tun_readable. */
    fun onTunReadable() {
        readable?.complete(Unit)
        readable = null
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
