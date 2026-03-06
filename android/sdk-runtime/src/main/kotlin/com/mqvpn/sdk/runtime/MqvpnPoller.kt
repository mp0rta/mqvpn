package com.mqvpn.sdk.runtime

import android.util.Log
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * tick()-driven [MqvpnExecutor] implementation.
 *
 * Each poll loop iteration:
 *   1. Drain task queue (lock-free) — execute all enqueued API calls
 *   2. Call [tickFn] (clientTick)
 *   3. Call [interestFn] to get [nextTimerMs, tunReadable, isIdle]
 *   4. Sleep until nextTimerMs or wakeup signal (task arrival)
 *
 * Performance:
 *   - Lock-free ConcurrentLinkedQueue (no mutex)
 *   - CONFLATED Channel for instant wakeup
 *   - Idle: tick interval extends to max 25s (power saving)
 */
class MqvpnPoller(
    private val scope: CoroutineScope,
    private val tickFn: () -> Int = { 0 },
    private val interestFn: () -> IntArray = { intArrayOf(0, 0, 0) },
) : MqvpnExecutor {

    private val taskQueue = ConcurrentLinkedQueue<Runnable>()
    private val wakeup = Channel<Unit>(Channel.CONFLATED)

    @Volatile
    private var running = false

    override fun start() {
        running = true
        scope.launch(Dispatchers.Default) { pollLoop() }
    }

    private suspend fun CoroutineScope.pollLoop() {
        while (isActive) {
            drainTasks()

            tickFn()

            val interest = interestFn()
            val nextMs = interest[0]
            val isIdle = interest.getOrElse(2) { 0 } == 1

            val sleepMs = if (isIdle) {
                nextMs.coerceIn(1, MAX_IDLE_SLEEP_MS)
            } else {
                nextMs.coerceAtLeast(1)
            }

            withTimeoutOrNull(sleepMs.toLong()) { wakeup.receive() }
        }
    }

    override suspend fun <T> call(block: () -> T): T {
        if (!running || !scope.isActive) {
            throw IllegalStateException("Poller stopped")
        }
        return suspendCancellableCoroutine { cont ->
            taskQueue.add {
                if (!cont.isActive) return@add
                try {
                    cont.resume(block())
                } catch (e: Exception) {
                    cont.resumeWithException(e)
                }
            }
            wakeup.trySend(Unit)
            cont.invokeOnCancellation { /* task will check cont.isActive */ }
        }
    }

    override fun enqueue(block: () -> Unit) {
        taskQueue.add(Runnable {
            try {
                block()
            } catch (e: Exception) {
                Log.e(TAG, "enqueue task failed", e)
            }
        })
        wakeup.trySend(Unit)
    }

    override fun stop() {
        running = false
        scope.cancel()
    }

    private fun drainTasks() {
        while (true) {
            val task = taskQueue.poll() ?: break
            task.run()
        }
    }

    companion object {
        private const val TAG = "MqvpnPoller"
        private const val MAX_IDLE_SLEEP_MS = 25_000
    }
}
