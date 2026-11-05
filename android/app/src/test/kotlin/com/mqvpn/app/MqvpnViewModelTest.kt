// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import com.mqvpn.app.data.DemoSettings
import com.mqvpn.app.service.MyVpnService
import com.mqvpn.app.ui.LogEvent
import com.mqvpn.app.ui.MqvpnViewModel
import com.mqvpn.sdk.network.TransportAvailability
import com.mqvpn.sdk.core.MqvpnManager
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.ReconnectInfo
import com.mqvpn.sdk.core.model.ReorderStats
import com.mqvpn.sdk.core.model.TunnelInfo
import com.mqvpn.sdk.core.model.VpnStats
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class MqvpnViewModelTest {

    private val testDispatcher = StandardTestDispatcher()

    private val stateFlow = MutableStateFlow<MqvpnState>(MqvpnState.Disconnected)
    private val statsFlow = MutableStateFlow(VpnStats())
    private val pathsFlow = MutableStateFlow<List<PathInfo>>(emptyList())
    private val reorderStatsFlow = MutableStateFlow(ReorderStats())

    private val mockManager = mockk<MqvpnManager>(relaxed = true).also {
        every { it.vpnState } returns stateFlow
        every { it.stats } returns statsFlow
        every { it.paths } returns pathsFlow
        every { it.reorderStats } returns reorderStatsFlow
    }

    private val testSettings = DemoSettings(serverAddress = "repo.example.com", serverPort = 1234)
    private val mockAvailability = mockk<TransportAvailability>(relaxed = true).also {
        every { it.available } returns MutableStateFlow(emptySet())
    }

    private val fixedClock: () -> Long = { 42L }

    private var fakeNanos = 0L
    private val fakeNanoClock: () -> Long = { fakeNanos }

    private lateinit var viewModel: MqvpnViewModel

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        viewModel = MqvpnViewModel(mockManager, mockAvailability, fixedClock, fakeNanoClock)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `init re-attaches the manager to a running service`() {
        // a ViewModel recreated while the VPN kept running must restore the
        // manager-service binding, or the UI stays frozen
        verify { mockManager.attach(MyVpnService::class.java) }
    }

    @Test
    fun `onCleared must not sever the singleton manager`() {
        // regression guard: onCleared() used to call manager.destroy(), which
        // froze the dashboard and broke disconnect once the activity died
        // while the VPN kept running
        val onCleared = androidx.lifecycle.ViewModel::class.java.getDeclaredMethod("onCleared")
        onCleared.isAccessible = true
        onCleared.invoke(viewModel)

        verify(exactly = 0) { mockManager.destroy() }
        verify(exactly = 0) { mockManager.disconnect() }
    }

    /** runTest cleanup drains the scheduler to empty; a live ticker never idles it. */
    private fun TestScope.stopTicker() {
        stateFlow.value = MqvpnState.Disconnected
        runCurrent()
    }

    /**
     * runTest wrapper for tests that may leave the ticker running: stops it even
     * when an assertion throws, so a failing test reports instead of hanging the
     * suite in runTest's scheduler-drain cleanup.
     */
    private fun tickerTest(block: suspend TestScope.() -> Unit) = runTest(testDispatcher) {
        try {
            block()
        } finally {
            stopTicker()
        }
    }

    private fun connectedInfo() = TunnelInfo(
        assignedIp = "10.0.0.2",
        prefix = 24,
        serverIp = "1.2.3.4",
        serverPrefix = 24,
        mtu = 1400,
    )

    @Test
    fun `initial state is Disconnected`() {
        assertEquals(MqvpnState.Disconnected, viewModel.vpnState.value)
    }

    @Test
    fun `initial stats are zero`() {
        val stats = viewModel.stats.value
        assertEquals(0L, stats.bytesTx)
        assertEquals(0L, stats.bytesRx)
    }

    @Test
    fun `initial paths are empty`() {
        assertTrue(viewModel.paths.value.isEmpty())
    }

    @Test
    fun `disconnect delegates to manager`() {
        viewModel.disconnect()
        verify { mockManager.disconnect() }
    }

    @Test
    fun `state updates propagate`() = tickerTest {
        val job = launch { viewModel.vpnState.collect {} }
        advanceUntilIdle()

        val info = TunnelInfo(
            assignedIp = "10.0.0.2",
            prefix = 24,
            serverIp = "1.2.3.4",
            serverPrefix = 24,
            mtu = 1400,
        )
        stateFlow.value = MqvpnState.Connected(info)
        runCurrent()

        assertTrue(viewModel.vpnState.value is MqvpnState.Connected)
        job.cancel()
    }

    @Test
    fun `stats updates propagate`() = runTest(testDispatcher) {
        val job = launch { viewModel.stats.collect {} }
        advanceUntilIdle()

        statsFlow.value = VpnStats(bytesTx = 1024, bytesRx = 2048, srttMs = 15)
        advanceUntilIdle()

        assertEquals(1024L, viewModel.stats.value.bytesTx)
        assertEquals(2048L, viewModel.stats.value.bytesRx)
        assertEquals(15, viewModel.stats.value.srttMs)
        job.cancel()
    }

    @Test
    fun `paths updates propagate`() = runTest(testDispatcher) {
        val job = launch { viewModel.paths.collect {} }
        advanceUntilIdle()

        val path = PathInfo(
            handle = 1L,
            status = 1,
            iface = "wlan0",
            bytesTx = 100,
            bytesRx = 200,
            srttMs = 12,
        )
        pathsFlow.value = listOf(path)
        advanceUntilIdle()

        assertEquals(1, viewModel.paths.value.size)
        assertEquals("wlan0", viewModel.paths.value[0].iface)
        job.cancel()
    }

    @Test
    fun `reorderStats updates propagate`() = runTest(testDispatcher) {
        val job = launch { viewModel.reorderStats.collect {} }
        advanceUntilIdle()

        reorderStatsFlow.value = ReorderStats(
            delivered = 500, gapCount = 10, gapFilled = 8,
            gapTimeout = 2, ackDemote = 0, bufferedP50Ms = 5, bufferedP99Ms = 22,
        )
        advanceUntilIdle()

        assertEquals(500L, viewModel.reorderStats.value.delivered)
        assertEquals(10L, viewModel.reorderStats.value.gapCount)
        assertEquals(8L, viewModel.reorderStats.value.gapFilled)
        job.cancel()
    }

    @Test
    fun `prepareVpn delegates to manager`() {
        every { mockManager.prepareVpn() } returns null
        val result = viewModel.prepareVpn()
        assertEquals(null, result)
        verify { mockManager.prepareVpn() }
    }

    @Test
    fun `connect builds the config from the passed settings`() = runTest(testDispatcher) {
        viewModel.connect(testSettings)
        advanceUntilIdle()

        verify(exactly = 1) { mockManager.connect(testSettings.toMqvpnConfig(), MyVpnService::class.java) }
        assertEquals(false, viewModel.connectPending.value)
        assertNull(viewModel.connectError.value)
    }

    @Test
    fun `repeated connect calls while one is pending only connect once`() = runTest(testDispatcher) {
        viewModel.connect(testSettings)
        viewModel.connect(testSettings)
        viewModel.connect(testSettings)
        advanceUntilIdle()

        verify(exactly = 1) { mockManager.connect(any(), any()) }
        assertEquals(false, viewModel.connectPending.value)
    }

    @Test
    fun `connect surfaces a manager failure and a later attempt clears it`() = runTest(testDispatcher) {
        every { mockManager.connect(any(), any()) } throws IllegalStateException("boom")
        viewModel.connect(testSettings)
        advanceUntilIdle()

        assertEquals("Connect failed: boom", viewModel.connectError.value)
        assertEquals(false, viewModel.connectPending.value)

        every { mockManager.connect(any(), any()) } returns Unit
        viewModel.connect(testSettings)
        advanceUntilIdle()

        assertNull(viewModel.connectError.value)
    }

    @Test
    fun `state and path emissions feed events`() = tickerTest {
        // No collectors on vpnState/paths here: event feeding is wired
        // directly off manager.vpnState/manager.paths in init{}, independent
        // of the stateIn-backed UI-facing flows, so events flow without UI
        // subscribers.
        advanceUntilIdle()

        val info = TunnelInfo(
            assignedIp = "10.0.0.2",
            prefix = 24,
            serverIp = "1.2.3.4",
            serverPrefix = 24,
            mtu = 1400,
        )
        stateFlow.value = MqvpnState.Connected(info)
        runCurrent()

        assertTrue(
            viewModel.events.value.any { it.kind == LogEvent.Kind.CoreState("Connected") },
        )

        val path = PathInfo(
            handle = 1L,
            status = 1,
            iface = "wlan0",
            bytesTx = 100,
            bytesRx = 200,
            srttMs = 12,
        )
        pathsFlow.value = listOf(path)
        runCurrent()

        assertTrue(
            viewModel.events.value.any { it.kind == LogEvent.Kind.PathAdded("wlan0", 1) },
        )
    }

    @Test
    fun `bandwidth history emits one sample per second while connected even with idle paths`() = tickerTest {
        pathsFlow.value = listOf(PathInfo(1L, 0, "wlan0", 100L, 100L, 10L))
        stateFlow.value = MqvpnState.Connected(connectedInfo())
        runCurrent() // vpnState collector starts the ticker
        repeat(3) {
            fakeNanos += 1_000_000_000L
            advanceTimeBy(1_000)
            runCurrent()
        }
        assertEquals(3, viewModel.bandwidthHistory.value.samples.size)
        // idle counters -> all-zero samples, but they still flow
        assertTrue(viewModel.bandwidthHistory.value.samples.all { it.dlBps + it.ulBps == 0L })
    }

    @Test
    fun `bandwidth history keeps sampling through reconnecting`() = tickerTest {
        pathsFlow.value = listOf(PathInfo(1L, 0, "wlan0", 0L, 0L, 10L))
        stateFlow.value = MqvpnState.Connected(connectedInfo())
        runCurrent()
        fakeNanos += 1_000_000_000L; advanceTimeBy(1_000); runCurrent()
        stateFlow.value = MqvpnState.Reconnecting(ReconnectInfo(3))
        runCurrent()
        fakeNanos += 1_000_000_000L; advanceTimeBy(1_000); runCurrent()
        assertEquals(2, viewModel.bandwidthHistory.value.samples.size)
    }

    @Test
    fun `bandwidth history clears on disconnect and stays empty while disconnected`() = tickerTest {
        pathsFlow.value = listOf(PathInfo(1L, 0, "wlan0", 0L, 0L, 10L))
        stateFlow.value = MqvpnState.Connected(connectedInfo())
        runCurrent()
        fakeNanos += 1_000_000_000L; advanceTimeBy(1_000); runCurrent()
        assertEquals(1, viewModel.bandwidthHistory.value.samples.size)
        stateFlow.value = MqvpnState.Disconnected
        runCurrent()
        assertTrue(viewModel.bandwidthHistory.value.samples.isEmpty())
        assertTrue(viewModel.bandwidthHistory.value.ifaceSlots.isEmpty())
        fakeNanos += 1_000_000_000L; advanceTimeBy(1_000); runCurrent()
        assertTrue(viewModel.bandwidthHistory.value.samples.isEmpty())
    }

    @Test
    fun `bandwidth ticker pauses during mid-session connecting and resumes with history kept`() = tickerTest {
        pathsFlow.value = listOf(PathInfo(1L, 0, "wlan0", 0L, 0L, 10L))
        stateFlow.value = MqvpnState.Connected(connectedInfo())
        runCurrent()
        fakeNanos += 1_000_000_000L; advanceTimeBy(1_000); runCurrent()
        assertEquals(1, viewModel.bandwidthHistory.value.samples.size)
        stateFlow.value = MqvpnState.Connecting
        runCurrent()
        fakeNanos += 1_000_000_000L; advanceTimeBy(1_000); runCurrent()
        assertEquals(1, viewModel.bandwidthHistory.value.samples.size) // paused, history kept
        stateFlow.value = MqvpnState.Connected(connectedInfo())
        runCurrent()
        fakeNanos += 1_000_000_000L; advanceTimeBy(1_000); runCurrent()
        assertEquals(2, viewModel.bandwidthHistory.value.samples.size) // resumed
    }

    private fun reorder(delivered: Long, filled: Long) =
        ReorderStats(delivered = delivered, gapCount = filled, gapFilled = filled)

    @Test
    fun `reorder history lossPct and elapsed follow eager flows and clear on disconnect`() = tickerTest {
        var now = 1_000L
        val vm = MqvpnViewModel(mockManager, mockAvailability, { now }, fakeNanoClock)
        runCurrent()
        stateFlow.value = MqvpnState.Connected(connectedInfo())
        runCurrent() // connectedAt = 1000
        reorderStatsFlow.value = reorder(10, 1)
        statsFlow.value = VpnStats(dgramSent = 100, dgramLost = 1)
        now += 1_000; fakeNanos += 1_000_000_000L; advanceTimeBy(1_000); runCurrent() // baseline
        reorderStatsFlow.value = reorder(20, 3)
        statsFlow.value = VpnStats(dgramSent = 200, dgramLost = 3)
        now += 1_000; fakeNanos += 1_000_000_000L; advanceTimeBy(1_000); runCurrent()
        // no subscriber on any stateIn view was attached
        assertEquals(1, vm.reorderHistory.value.samples.size)
        assertEquals(2L, vm.elapsedSec.value)
        assertEquals(0.02, vm.lossPct.value!!, 1e-9) // (3-1)/(200-100)
        stateFlow.value = MqvpnState.Disconnected
        runCurrent()
        assertTrue(vm.reorderHistory.value.samples.isEmpty())
        assertNull(vm.lossPct.value)
        assertNull(vm.elapsedSec.value)
    }

    @Test
    fun `elapsed is anchored at the transition into Connected not at each emission`() = tickerTest {
        var now = 1_000L
        val vm = MqvpnViewModel(mockManager, mockAvailability, { now }, fakeNanoClock)
        runCurrent()
        stateFlow.value = MqvpnState.Connected(connectedInfo())
        runCurrent()
        now += 5_000
        stateFlow.value = MqvpnState.Connected(connectedInfo().copy(mtu = 1300)) // re-emission
        runCurrent()
        fakeNanos += 1_000_000_000L; advanceTimeBy(1_000); runCurrent()
        assertEquals(5L, vm.elapsedSec.value)
    }

    @Test
    fun `elapsed counts from the service connect timestamp on re-attach`() = tickerTest {
        // A re-attached UI (new ViewModel) replays a Connected state that the
        // service emitted earlier; elapsed must span the whole session, not
        // the time since the replay.
        stateFlow.value = MqvpnState.Connected(connectedInfo().copy(connectedAtMs = 4_000L))
        var now = 10_000L
        val vm = MqvpnViewModel(mockManager, mockAvailability, { now }, fakeNanoClock)
        runCurrent()
        now += 1_000; fakeNanos += 1_000_000_000L; advanceTimeBy(1_000); runCurrent()
        assertEquals(7L, vm.elapsedSec.value) // (11_000 - 4_000) / 1000
    }
}
