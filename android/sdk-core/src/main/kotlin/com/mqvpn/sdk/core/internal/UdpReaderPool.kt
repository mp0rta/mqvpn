package com.mqvpn.sdk.core.internal

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.Log
import com.mqvpn.sdk.core.MqvpnTunnel
import com.mqvpn.sdk.native_.NativeBridge
import com.mqvpn.sdk.runtime.MqvpnExecutor
import java.io.FileDescriptor
import java.util.concurrent.ConcurrentHashMap

/**
 * Manages per-path UDP reader threads.
 *
 * Each path gets a dedicated thread doing blocking recvFrom() → executor.enqueue.
 * Threads survive reconnects (same fd + pathHandle remain valid).
 */
internal class UdpReaderPool(private val executor: MqvpnExecutor) {

    private data class ReaderEntry(val thread: Thread, val fd: Int)

    private val readers = ConcurrentHashMap<Long, ReaderEntry>()

    /**
     * Start a UDP reader thread for [pathHandle].
     *
     * Loop: recvFrom(fd, buf, peerAddr) → executor.enqueue { onSocketRecv(...) }
     */
    fun startReader(fd: Int, pathHandle: Long, name: String, tunnel: MqvpnTunnel) {
        val thread = Thread({
            val buf = ByteArray(65536)
            val peerAddr = ByteArray(128) // sockaddr_storage
            val peerAddrLen = IntArray(1)

            while (!Thread.currentThread().isInterrupted) {
                peerAddrLen[0] = peerAddr.size
                val n = NativeBridge.recvFrom(fd, buf, 0, buf.size, peerAddr, peerAddrLen)
                if (n <= 0) break // shutdown or error

                val pktCopy = buf.copyOf(n)
                val addrCopy = peerAddr.copyOf(peerAddrLen[0])
                val addrLen = peerAddrLen[0]

                executor.enqueue {
                    tunnel.onSocketRecv(pathHandle, pktCopy, 0, n, addrCopy, addrLen)
                }
            }
            Log.d(TAG, "UDP reader $name stopped")
        }, "mqvpn-udp-$name")

        readers[pathHandle] = ReaderEntry(thread, fd)
        thread.start()
    }

    /**
     * Stop a UDP reader thread.
     *
     * 1. shutdown(fd, SHUT_RD) — unblocks recvFrom()
     * 2. Thread.interrupt()
     * 3. join(1000ms)
     *
     * Does NOT close fd — caller (PathManager) closes fd after this returns.
     */
    fun stopReader(pathHandle: Long) {
        val entry = readers.remove(pathHandle) ?: return
        shutdownRead(entry.fd)
        entry.thread.interrupt()
        try {
            entry.thread.join(1000)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    /** Stop all readers (called during cleanup). */
    fun stopAll() {
        for ((_, entry) in readers) {
            shutdownRead(entry.fd)
            entry.thread.interrupt()
            try {
                entry.thread.join(1000)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
        readers.clear()
    }

    /**
     * Call shutdown(fd, SHUT_RD) to unblock a blocking recvfrom().
     * Thread.interrupt() does NOT interrupt native system calls.
     */
    private fun shutdownRead(rawFd: Int) {
        try {
            val fd = FileDescriptor()
            val field = FileDescriptor::class.java.getDeclaredField("descriptor")
            field.isAccessible = true
            field.setInt(fd, rawFd)
            Os.shutdown(fd, OsConstants.SHUT_RD)
        } catch (e: ErrnoException) {
            // Ignore — fd may already be closed or not connected
        } catch (e: Exception) {
            Log.w(TAG, "shutdown failed: ${e.message}")
        }
    }

    companion object {
        private const val TAG = "UdpReaderPool"
    }
}
