// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.runtime

import android.util.Log
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * tick()-driven [MqvpnExecutor] on ONE dedicated thread — the engine thread
 * libmqvpn's tick-thread contract needs (a coroutine on a shared dispatcher
 * gives mutual exclusion, not thread affinity).
 *
 * Each loop iteration:
 *   1. Drain the task queue — every enqueued API call, in order
 *   2. Call [tickFn] (clientTick)
 *   3. Call [interestFn] → [nextTimerMs, tunReadable, isIdle]
 *   4. [Waiter.await] until nextTimerMs, I/O or a wake — path receive
 *      happens inside, on this thread
 *   5. Report every bad fd the waiter found to [onBadFd]
 *
 * Idle: the wait extends to at most 25 s (power saving).
 *
 * Shutdown ([stop]) is atomic with the queue: the finalizer is the last task,
 * later tasks are refused, and the thread frees the waiter itself after the
 * loop, so a bounded join can never leave a use-after-free behind.
 *
 * If the engine thread dies from an uncaught Throwable, calls already queued
 * are not resumed and a later [stop] runs no finalizer; on Android an
 * uncaught throwable on any thread ends the process (the default handler),
 * as it did with the old coroutine poller.
 */
class MqvpnPoller(
    private val waiter: Waiter,
    private val tickFn: () -> Int = { 0 },
    private val interestFn: () -> IntArray = { intArrayOf(0, 0, 0) },
    private val clientFn: () -> Long = { 0L },
    private val onBadFd: (Long) -> Unit = {},
) : MqvpnExecutor {

    private val lock = Any()
    private val taskQueue = ArrayDeque<Runnable>() // guarded by lock
    private var accepting = false                  // guarded by lock
    private var thread: Thread? = null             // guarded by lock

    private var finished = false                   // engine thread only (set by the finalizer task)
    private var waitErrorLogged = false            // engine thread only

    override fun start() {
        val t = Thread({ loop() }, "mqvpn-engine")
        synchronized(lock) {
            check(thread == null) { "Poller started twice" }
            accepting = true
            thread = t
        }
        t.start()
    }

    private fun loop() {
        try {
            while (true) {
                drainTasks()
                if (finished) break

                tickFn()

                val interest = interestFn()
                val nextMs = interest[0]
                val isIdle = interest.getOrElse(2) { 0 } == 1
                val sleepMs = if (isIdle) {
                    nextMs.coerceIn(1, MAX_IDLE_SLEEP_MS)
                } else {
                    nextMs.coerceAtLeast(1)
                }

                if (waiter.await(clientFn(), sleepMs) < 0 && !waitErrorLogged) {
                    waitErrorLogged = true
                    Log.e(TAG, "waiter.await failed; continuing")
                }
                while (true) {
                    val h = waiter.takeBadFd()
                    if (h < 0) break
                    onBadFd(h)
                }
            }
        } finally {
            // Whatever ends the loop (the finalizer, or an Error nobody
            // catches), nothing may be offered to a queue this thread no
            // longer drains: later calls throw instead of suspending forever.
            synchronized(lock) { accepting = false }
            waiter.close()
        }
    }

    override suspend fun <T> call(block: () -> T): T {
        return suspendCancellableCoroutine { cont ->
            val task = Runnable {
                if (!cont.isActive) return@Runnable
                try {
                    cont.resume(block())
                } catch (e: Throwable) {
                    // The caller must never be left suspended, whatever the
                    // block threw; an Error is still fatal for this thread.
                    cont.resumeWithException(e)
                    if (e is Error) throw e
                }
            }
            if (!offer(task)) throw ExecutorStoppedException()
            waiter.wake()
            cont.invokeOnCancellation { /* task will check cont.isActive */ }
        }
    }

    override fun enqueue(block: () -> Unit) {
        val task = Runnable {
            try {
                block()
            } catch (e: Exception) {
                Log.e(TAG, "enqueue task failed", e)
            }
        }
        if (!offer(task)) {
            Log.w(TAG, "enqueue after stop: task dropped")
            return
        }
        waiter.wake()
    }

    /** Append under the lock; false once [stop] closed the queue. */
    private fun offer(task: Runnable): Boolean = synchronized(lock) {
        if (!accepting) return false
        taskQueue.addLast(task)
        true
    }

    override fun stop(finalizer: () -> Unit) {
        val t = synchronized(lock) {
            if (!accepting) return
            accepting = false
            taskQueue.addLast(Runnable {
                try {
                    finalizer()
                } catch (e: Exception) {
                    Log.e(TAG, "stop finalizer failed", e)
                } finally {
                    finished = true
                }
            })
            thread
        }
        // Until the finalizer has run the loop keeps the waiter open, so this
        // wake reaches it. If the thread already ran it and exited, or died,
        // the waiter is closed and the wake is a no-op (the Waiter contract;
        // NativeReactorWaiter's wake takes the lock its close() takes).
        waiter.wake()
        if (t != null && t !== Thread.currentThread()) {
            t.join(JOIN_TIMEOUT_MS)
            if (t.isAlive) Log.w(TAG, "engine thread still running ${JOIN_TIMEOUT_MS} ms after stop")
        }
    }

    private fun drainTasks() {
        while (true) {
            val task = synchronized(lock) { taskQueue.removeFirstOrNull() } ?: break
            task.run()
        }
    }

    companion object {
        private const val TAG = "MqvpnPoller"
        private const val MAX_IDLE_SLEEP_MS = 25_000
        private const val JOIN_TIMEOUT_MS = 2_000L
    }
}
