// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.runtime

import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit

/**
 * Test [Waiter]: a semaphore instead of the native reactor. Records the
 * thread that closed it, counts [closed] down on close, and lets a test
 * inject bad-fd handles.
 */
class ParkWaiter : Waiter {
    private val sem = Semaphore(0)
    val badFds = ConcurrentLinkedQueue<Long>()

    @Volatile
    var closedOn: Thread? = null

    /** Counted down by [close]: a test's happens-after edge on the engine thread's exit. */
    val closed = CountDownLatch(1)

    @Volatile
    var awaitCount = 0

    override fun await(client: Long, timeoutMs: Int): Int {
        awaitCount++
        sem.tryAcquire(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
        sem.drainPermits()
        return 0
    }

    override fun takeBadFd(): Long = badFds.poll() ?: -1L

    override fun wake() {
        if (sem.availablePermits() == 0) sem.release()
    }

    override fun close() {
        closedOn = Thread.currentThread()
        closed.countDown()
    }
}
