package com.mqvpn.sdk.runtime

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class MqvpnPollerTest {

    private lateinit var scope: CoroutineScope

    @Before
    fun setUp() {
        scope = CoroutineScope(Dispatchers.Default + Job())
    }

    @After
    fun tearDown() {
        scope.cancel()
    }

    @Test
    fun `call runs block and returns result`() = runBlocking {
        val tickCount = AtomicInteger(0)
        val poller = MqvpnPoller(
            scope,
            tickFn = { tickCount.incrementAndGet(); 0 },
            interestFn = { intArrayOf(10, 0, 0) },
        )
        poller.start()

        val result = withTimeout(5_000) { poller.call { 42 } }
        assertEquals(42, result)
        assertTrue("tick should have run at least once", tickCount.get() >= 1)

        poller.stop()
    }

    @Test
    fun `enqueue runs task on poller thread`() = runBlocking {
        val poller = MqvpnPoller(
            scope,
            tickFn = { 0 },
            interestFn = { intArrayOf(10, 0, 0) },
        )
        poller.start()

        val result = withTimeout(5_000) {
            poller.call { Thread.currentThread().name }
        }
        assertTrue(
            "expected a background thread, got: $result",
            result != Thread.currentThread().name,
        )

        poller.stop()
    }

    @Test
    fun `call propagates exceptions without stopping poller`() = runBlocking {
        val tickCount = AtomicInteger(0)
        val poller = MqvpnPoller(
            scope,
            tickFn = { tickCount.incrementAndGet(); 0 },
            interestFn = { intArrayOf(10, 0, 0) },
        )
        poller.start()

        // First call throws
        try {
            withTimeout(5_000) {
                poller.call<Unit> { throw RuntimeException("test error") }
            }
            fail("should have thrown")
        } catch (e: RuntimeException) {
            assertEquals("test error", e.message)
        }

        // Second call still works — poller is alive
        val result = withTimeout(5_000) { poller.call { 99 } }
        assertEquals(99, result)

        poller.stop()
    }

    @Test
    fun `idle extends sleep interval`() = runBlocking {
        val tickCount = AtomicInteger(0)
        val poller = MqvpnPoller(
            scope,
            tickFn = { tickCount.incrementAndGet(); 0 },
            interestFn = { intArrayOf(25_000, 0, 1) }, // isIdle = 1
        )
        poller.start()

        Thread.sleep(300)
        val ticks = tickCount.get()
        assertTrue("expected few ticks during idle, got $ticks", ticks < 10)

        poller.stop()
    }

    @Test
    fun `wakeup interrupts sleep`() = runBlocking {
        val tickCount = AtomicInteger(0)
        val poller = MqvpnPoller(
            scope,
            tickFn = { tickCount.incrementAndGet(); 0 },
            interestFn = { intArrayOf(10_000, 0, 0) }, // 10s sleep
        )
        poller.start()

        // Wait for initial tick
        Thread.sleep(100)
        val before = tickCount.get()

        // enqueue should wake up the poller immediately
        val result = withTimeout(5_000) { poller.call { "woke up" } }
        assertEquals("woke up", result)
        assertTrue("tick should have advanced", tickCount.get() > before)

        poller.stop()
    }

    @Test
    fun `call after stop throws`() {
        val poller = MqvpnPoller(
            scope,
            tickFn = { 0 },
            interestFn = { intArrayOf(10, 0, 0) },
        )
        poller.start()
        poller.stop()

        try {
            runBlocking {
                poller.call { 1 }
            }
            fail("should have thrown IllegalStateException")
        } catch (e: IllegalStateException) {
            // expected
        }
    }

    @Test
    fun `enqueue tasks are drained in order`() = runBlocking {
        val order = mutableListOf<Int>()
        val latch = CountDownLatch(3)
        val poller = MqvpnPoller(
            scope,
            tickFn = { 0 },
            interestFn = { intArrayOf(10, 0, 0) },
        )
        poller.start()

        poller.enqueue { order.add(1); latch.countDown() }
        poller.enqueue { order.add(2); latch.countDown() }
        poller.enqueue { order.add(3); latch.countDown() }

        assertTrue("tasks should complete", latch.await(5, TimeUnit.SECONDS))
        assertEquals(listOf(1, 2, 3), order)

        poller.stop()
    }
}
