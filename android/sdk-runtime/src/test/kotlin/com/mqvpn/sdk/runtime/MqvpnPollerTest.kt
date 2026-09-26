// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.runtime

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class MqvpnPollerTest {

    private fun poller(
        waiter: ParkWaiter = ParkWaiter(),
        tickFn: () -> Int = { 0 },
        interestFn: () -> IntArray = { intArrayOf(10, 0, 0) },
        onBadFd: (Long) -> Unit = {},
    ) = MqvpnPoller(waiter, tickFn = tickFn, interestFn = interestFn, onBadFd = onBadFd)

    @Test
    fun `call runs block and returns result`() = runBlocking {
        val tickCount = AtomicInteger(0)
        val p = poller(tickFn = { tickCount.incrementAndGet(); 0 })
        p.start()

        val result = withTimeout(5_000) { p.call { 42 } }
        assertEquals(42, result)
        assertTrue("tick should have run at least once", tickCount.get() >= 1)

        p.stop()
    }

    @Test
    fun `enqueue runs task on poller thread`() = runBlocking {
        val p = poller()
        p.start()

        val result = withTimeout(5_000) { p.call { Thread.currentThread().name } }
        assertEquals("mqvpn-engine", result)

        p.stop()
    }

    @Test
    fun `thread affinity holds across tasks ticks waits and wakes`() = runBlocking {
        // Every task, every tick, and the code after a timed-out wait and
        // after a cross-thread wake run on ONE thread: libmqvpn's tick-thread
        // contract (a shared-dispatcher coroutine would not give this).
        val tickThreads = mutableSetOf<Long>()
        val latch = CountDownLatch(5)
        val p = poller(
            tickFn = { synchronized(tickThreads) { tickThreads.add(Thread.currentThread().id) }; latch.countDown(); 0 },
            interestFn = { intArrayOf(30, 0, 0) }, // short waits: several timed-out waits
        )
        p.start()
        val taskThread = withTimeout(5_000) { p.call { Thread.currentThread().id } }
        assertTrue("five ticks", latch.await(5, TimeUnit.SECONDS))
        // cross-thread wake, then another task
        val afterWake = withTimeout(5_000) { p.call { Thread.currentThread().id } }
        assertEquals(setOf(taskThread), synchronized(tickThreads) { tickThreads.toSet() })
        assertEquals(taskThread, afterWake)
        p.stop()
    }

    @Test
    fun `call propagates exceptions without stopping poller`() = runBlocking {
        val p = poller()
        p.start()

        try {
            withTimeout(5_000) { p.call<Unit> { throw RuntimeException("test error") } }
            fail("should have thrown")
        } catch (e: RuntimeException) {
            assertEquals("test error", e.message)
        }

        val result = withTimeout(5_000) { p.call { 99 } }
        assertEquals(99, result)

        p.stop()
    }

    @Test
    fun `idle extends sleep interval`() {
        val tickCount = AtomicInteger(0)
        val p = poller(tickFn = { tickCount.incrementAndGet(); 0 }, interestFn = { intArrayOf(25_000, 0, 1) })
        p.start()

        Thread.sleep(300)
        val ticks = tickCount.get()
        assertTrue("expected few ticks during idle, got $ticks", ticks < 10)

        p.stop()
    }

    @Test
    fun `wakeup interrupts sleep`() = runBlocking {
        val p = poller(interestFn = { intArrayOf(10_000, 0, 0) }) // 10 s wait
        p.start()
        Thread.sleep(200) // let the loop enter the long wait

        val t0 = System.nanoTime()
        val result = withTimeout(5_000) { p.call { "woke up" } }
        val elapsedMs = (System.nanoTime() - t0) / 1_000_000
        assertEquals("woke up", result)
        assertTrue("call should complete quickly (<2s), took ${elapsedMs}ms", elapsedMs < 2_000)

        p.stop()
    }

    @Test
    fun `lost wake - a task enqueued before the loop waits still runs promptly`() {
        val ran = CountDownLatch(1)
        val p = poller(interestFn = { intArrayOf(10_000, 0, 0) })
        p.start()
        p.enqueue { ran.countDown() } // may land before the first wait
        assertTrue("task must not wait for the 10 s timer", ran.await(2, TimeUnit.SECONDS))
        p.stop()
    }

    @Test
    fun `spurious wake fires no task and no bad fd`() {
        val waiter = ParkWaiter()
        val badFds = AtomicInteger(0)
        val ticks = AtomicInteger(0)
        val p = poller(waiter, tickFn = { ticks.incrementAndGet(); 0 }, interestFn = { intArrayOf(10_000, 0, 0) }, onBadFd = { badFds.incrementAndGet() })
        p.start()
        Thread.sleep(100)
        val before = waiter.awaitCount
        waiter.wake() // nothing queued, no bad fd
        Thread.sleep(200)
        assertTrue("the loop went round", waiter.awaitCount > before)
        assertEquals(0, badFds.get())
        assertTrue("the next tick is allowed", ticks.get() >= 1)
        p.stop()
    }

    @Test
    fun `stop runs queued tasks then the finalizer last and closes the waiter on the poller thread`() {
        val waiter = ParkWaiter()
        val order = mutableListOf<String>()
        val p = poller(waiter, interestFn = { intArrayOf(10_000, 0, 0) })
        p.start()
        Thread.sleep(100)
        p.enqueue { synchronized(order) { order.add("task") } }
        var finalizerThread: Thread? = null
        p.stop {
            synchronized(order) { order.add("finalizer") }
            finalizerThread = Thread.currentThread()
        }
        assertEquals(listOf("task", "finalizer"), order)
        assertNotNull(waiter.closedOn)
        assertEquals("mqvpn-engine", waiter.closedOn!!.name)
        assertEquals(waiter.closedOn, finalizerThread)
    }

    @Test
    fun `a throwing finalizer still stops accepting and closes the waiter`() {
        val waiter = ParkWaiter()
        val p = poller(waiter, interestFn = { intArrayOf(10_000, 0, 0) })
        p.start()
        Thread.sleep(50)
        p.stop { throw RuntimeException("cleanup failed") }
        assertNotNull("the waiter is closed by the poller thread even so", waiter.closedOn)
        assertEquals("mqvpn-engine", waiter.closedOn!!.name)
        val e = assertThrows(IllegalStateException::class.java) {
            runBlocking { withTimeout(2_000) { p.call { 1 } } }
        }
        assertEquals("Poller stopped", e.message)
    }

    @Test
    fun `an Error inside a call reaches the caller instead of stranding it`() {
        val waiter = ParkWaiter()
        val p = poller(waiter)
        p.start()
        val e = assertThrows(OutOfMemoryError::class.java) {
            runBlocking { withTimeout(2_000) { p.call<Unit> { throw OutOfMemoryError("test") } } }
        }
        assertEquals("test", e.message)
        // The Error killed the engine thread (fatal by design); a later call is refused, not stranded.
        // The loop's finally stops accepting, then closes the waiter, on that thread.
        assertTrue("engine thread exited", waiter.closed.await(2, TimeUnit.SECONDS))
        val e2 = assertThrows(IllegalStateException::class.java) {
            runBlocking { withTimeout(2_000) { p.call { 1 } } }
        }
        assertEquals("Poller stopped", e2.message)
    }

    @Test
    fun `enqueue racing stop - nothing runs after the finalizer and nothing hangs`() {
        val waiter = ParkWaiter()
        val p = poller(waiter, interestFn = { intArrayOf(10_000, 0, 0) })
        p.start()
        val finalized = AtomicBoolean(false)
        val ranAfterFinalizer = AtomicInteger(0)
        val accepted = AtomicInteger(0)
        val ran = AtomicInteger(0)
        val stopRacers = CountDownLatch(1)
        val firstRan = CountDownLatch(1)
        val racers = (1..4).map {
            Thread {
                stopRacers.await()
                repeat(2_000) {
                    // Count tasks that ran; any that runs after the finalizer is a bug.
                    p.enqueue {
                        ran.incrementAndGet()
                        firstRan.countDown()
                        if (finalized.get()) ranAfterFinalizer.incrementAndGet()
                    }
                    accepted.incrementAndGet()
                }
            }.apply { start() }
        }
        stopRacers.countDown()
        assertTrue("a task ran before the stop", firstRan.await(2, TimeUnit.SECONDS))
        p.stop { finalized.set(true) }
        racers.forEach { it.join(5_000) }
        assertTrue(finalized.get())
        assertEquals("no task may run after the finalizer", 0, ranAfterFinalizer.get())
        assertTrue("some tasks ran before stop", ran.get() > 0)
        // A call after stop never hangs: it is refused (not a timeout, whose
        // exception would also be an IllegalStateException subclass).
        val e = assertThrows(IllegalStateException::class.java) {
            runBlocking { withTimeout(2_000) { p.call { 1 } } }
        }
        assertEquals("Poller stopped", e.message)
    }

    @Test
    fun `call after stop throws`() {
        val p = poller()
        p.start()
        p.stop()

        // A bounded wait: a call that neither throws nor completes (a task
        // appended to a dead queue) must fail this test, not hang it. The
        // timeout's exception is itself an IllegalStateException subclass
        // (CancellationException), so the refusal is checked by message.
        val e = assertThrows(IllegalStateException::class.java) {
            runBlocking { withTimeout(2_000) { p.call { 1 } } }
        }
        assertEquals("Poller stopped", e.message)
    }

    @Test
    fun `enqueue after stop is dropped`() {
        val p = poller()
        p.start()
        p.stop()
        val ran = AtomicBoolean(false)
        p.enqueue { ran.set(true) }
        assertFalse(ran.get())
        // Dropped, not parked in a queue nobody drains any more.
        val q = MqvpnPoller::class.java.getDeclaredField("taskQueue").apply { isAccessible = true }.get(p) as ArrayDeque<*>
        assertTrue("the task must not sit in the dead queue", q.isEmpty())
    }

    @Test
    fun `enqueue tasks are drained in order`() {
        val order = mutableListOf<Int>()
        val latch = CountDownLatch(3)
        val p = poller()
        p.start()

        p.enqueue { order.add(1); latch.countDown() }
        p.enqueue { order.add(2); latch.countDown() }
        p.enqueue { order.add(3); latch.countDown() }

        assertTrue("tasks should complete", latch.await(5, TimeUnit.SECONDS))
        assertEquals(listOf(1, 2, 3), order)

        p.stop()
    }

    @Test
    fun `bad fd handles are delivered once on the poller thread`() {
        val waiter = ParkWaiter()
        val seen = mutableListOf<Long>()
        val seenOn = AtomicLong(0)
        val latch = CountDownLatch(1)
        val p = poller(waiter, interestFn = { intArrayOf(10_000, 0, 0) }, onBadFd = { h ->
            synchronized(seen) { seen.add(h) }
            seenOn.set(Thread.currentThread().id)
            latch.countDown()
        })
        p.start()
        Thread.sleep(100)
        waiter.badFds.add(7L)
        waiter.wake()
        assertTrue(latch.await(2, TimeUnit.SECONDS))
        Thread.sleep(100)
        assertEquals(listOf(7L), seen)
        val engineId = runBlocking { withTimeout(2_000) { p.call { Thread.currentThread().id } } }
        assertEquals(engineId, seenOn.get())
        p.stop()
    }
}
