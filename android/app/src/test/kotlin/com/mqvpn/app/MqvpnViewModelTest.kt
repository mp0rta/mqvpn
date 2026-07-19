// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import com.mqvpn.app.data.DemoSettings
import com.mqvpn.app.data.SettingsRepository
import com.mqvpn.app.service.MyVpnService
import com.mqvpn.app.ui.LogEvent
import com.mqvpn.app.ui.MqvpnViewModel
import com.mqvpn.sdk.core.MqvpnManager
import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
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
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
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
    private val mockRepository = mockk<SettingsRepository>(relaxed = true).also {
        every { it.settings } returns MutableStateFlow(testSettings)
    }

    private val fixedClock: () -> Long = { 42L }

    private lateinit var viewModel: MqvpnViewModel

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        viewModel = MqvpnViewModel(mockManager, mockRepository, fixedClock)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

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
    fun `connect delegates to manager`() {
        val config = MqvpnConfig(
            serverAddress = "vpn.example.com",
            authKey = "testkey",
        )
        viewModel.connect(config)
        verify { mockManager.connect(config, MyVpnService::class.java) }
    }

    @Test
    fun `disconnect delegates to manager`() {
        viewModel.disconnect()
        verify { mockManager.disconnect() }
    }

    @Test
    fun `state updates propagate`() = runTest(testDispatcher) {
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
        advanceUntilIdle()

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
    fun `connectWithSavedSettings connects using config built from repository settings`() = runTest(testDispatcher) {
        viewModel.connectWithSavedSettings()
        advanceUntilIdle()

        verify(exactly = 1) { mockManager.connect(testSettings.toMqvpnConfig(), MyVpnService::class.java) }
        assertEquals(false, viewModel.connectPending.value)
        assertNull(viewModel.connectError.value)
    }

    @Test
    fun `repeated connectWithSavedSettings calls while read is suspended only connect once`() = runTest(testDispatcher) {
        val signal = MutableSharedFlow<DemoSettings>()
        val slowRepository = mockk<SettingsRepository>(relaxed = true).also {
            every { it.settings } returns signal
        }
        val slowViewModel = MqvpnViewModel(mockManager, slowRepository, fixedClock)

        slowViewModel.connectWithSavedSettings()
        slowViewModel.connectWithSavedSettings()
        slowViewModel.connectWithSavedSettings()
        advanceUntilIdle()

        assertEquals(true, slowViewModel.connectPending.value)
        verify(exactly = 0) { mockManager.connect(any(), any()) }

        signal.emit(testSettings)
        advanceUntilIdle()

        verify(exactly = 1) { mockManager.connect(any(), any()) }
        assertEquals(false, slowViewModel.connectPending.value)
    }

    @Test
    fun `connectWithSavedSettings surfaces repository failure without connecting`() = runTest(testDispatcher) {
        val failingRepository = mockk<SettingsRepository>(relaxed = true).also {
            every { it.settings } returns flow { throw IllegalStateException("boom") }
        }
        val failingViewModel = MqvpnViewModel(mockManager, failingRepository, fixedClock)

        failingViewModel.connectWithSavedSettings()
        advanceUntilIdle()

        assertEquals("Connect failed: boom", failingViewModel.connectError.value)
        assertEquals(false, failingViewModel.connectPending.value)
        verify(exactly = 0) { mockManager.connect(any(), any()) }

        // A subsequent successful attempt clears the error.
        every { failingRepository.settings } returns MutableStateFlow(testSettings)
        failingViewModel.connectWithSavedSettings()
        advanceUntilIdle()

        assertNull(failingViewModel.connectError.value)
        verify(exactly = 1) { mockManager.connect(testSettings.toMqvpnConfig(), MyVpnService::class.java) }
    }

    @Test
    fun `state and path emissions feed events`() = runTest(testDispatcher) {
        val stateJob = launch { viewModel.vpnState.collect {} }
        val pathJob = launch { viewModel.paths.collect {} }
        advanceUntilIdle()

        val info = TunnelInfo(
            assignedIp = "10.0.0.2",
            prefix = 24,
            serverIp = "1.2.3.4",
            serverPrefix = 24,
            mtu = 1400,
        )
        stateFlow.value = MqvpnState.Connected(info)
        advanceUntilIdle()

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
        advanceUntilIdle()

        assertTrue(
            viewModel.events.value.any { it.kind == LogEvent.Kind.PathAdded("wlan0", 1) },
        )

        stateJob.cancel()
        pathJob.cancel()
    }
}
