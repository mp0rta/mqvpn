// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import com.mqvpn.app.data.DemoSettings
import com.mqvpn.app.data.SettingsRepository
import com.mqvpn.app.ui.SettingsViewModel
import com.mqvpn.sdk.core.MqvpnManager
import com.mqvpn.sdk.core.model.MqvpnError
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.TunnelInfo
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class SettingsViewModelTest {

    private val testDispatcher = StandardTestDispatcher()

    private val stateFlow = MutableStateFlow<MqvpnState>(MqvpnState.Disconnected)
    private val mockManager = mockk<MqvpnManager>(relaxed = true).also {
        every { it.vpnState } returns stateFlow
    }

    private val testSettings = DemoSettings(serverAddress = "repo.example.com", serverPort = 1234)
    private val settingsFlow = MutableStateFlow(testSettings)
    private val mockRepository = mockk<SettingsRepository>(relaxed = true).also {
        every { it.settings } returns settingsFlow
        coEvery { it.save(any()) } returns Unit
    }

    private lateinit var viewModel: SettingsViewModel

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        viewModel = SettingsViewModel(mockRepository, mockManager)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `repository emission populates loaded`() = runTest(testDispatcher) {
        advanceUntilIdle()

        assertEquals(testSettings, viewModel.loaded.value)
        assertNull(viewModel.loadError.value)
    }

    @Test
    fun `repository read failure surfaces loadError and leaves loaded null`() = runTest(testDispatcher) {
        val failingRepository = mockk<SettingsRepository>(relaxed = true).also {
            every { it.settings } returns flow { throw IllegalStateException("boom") }
        }
        val failingViewModel = SettingsViewModel(failingRepository, mockManager)
        advanceUntilIdle()

        assertNull(failingViewModel.loaded.value)
        assertEquals("Load failed: boom", failingViewModel.loadError.value)
    }

    @Test
    fun `save with valid draft persists and sets saveDone until consumed`() = runTest(testDispatcher) {
        advanceUntilIdle()
        val draft = testSettings.copy(serverAddress = "new.example.com")

        viewModel.save(draft)
        advanceUntilIdle()

        coVerify(exactly = 1) { mockRepository.save(draft) }
        assertFalse(viewModel.isSaving.value)
        assertTrue(viewModel.saveDone.value)
        assertNull(viewModel.saveError.value)

        viewModel.consumeSaveDone()
        assertFalse(viewModel.saveDone.value)
    }

    @Test
    fun `save failure surfaces saveError and leaves saveDone false`() = runTest(testDispatcher) {
        advanceUntilIdle()
        val failingRepository = mockk<SettingsRepository>(relaxed = true).also {
            every { it.settings } returns settingsFlow
            coEvery { it.save(any()) } throws IllegalStateException("boom")
        }
        val failingViewModel = SettingsViewModel(failingRepository, mockManager)
        advanceUntilIdle()

        failingViewModel.save(testSettings)
        advanceUntilIdle()

        assertEquals("Save failed: boom", failingViewModel.saveError.value)
        assertFalse(failingViewModel.saveDone.value)
        assertFalse(failingViewModel.isSaving.value)
    }

    @Test
    fun `second save while first is in flight is ignored`() = runTest(testDispatcher) {
        advanceUntilIdle()
        val gate = CompletableDeferred<Unit>()
        val slowRepository = mockk<SettingsRepository>(relaxed = true).also {
            every { it.settings } returns settingsFlow
            coEvery { it.save(any()) } coAnswers { gate.await() }
        }
        val slowViewModel = SettingsViewModel(slowRepository, mockManager)
        advanceUntilIdle()

        slowViewModel.save(testSettings)
        slowViewModel.save(testSettings)
        advanceUntilIdle()

        assertTrue(slowViewModel.isSaving.value)
        coVerify(exactly = 1) { slowRepository.save(any()) }

        gate.complete(Unit)
        advanceUntilIdle()
    }

    @Test
    fun `save while not editable is ignored`() = runTest(testDispatcher) {
        val info = TunnelInfo(
            assignedIp = "10.0.0.2",
            prefix = 24,
            serverIp = "1.2.3.4",
            serverPrefix = 24,
            mtu = 1400,
        )
        stateFlow.value = MqvpnState.Connected(info)
        advanceUntilIdle()

        assertFalse(viewModel.isEditable.value)

        viewModel.save(testSettings)
        advanceUntilIdle()

        coVerify(exactly = 0) { mockRepository.save(any()) }
    }

    @Test
    fun `save with invalid draft is ignored`() = runTest(testDispatcher) {
        advanceUntilIdle()
        val invalidDraft = testSettings.copy(serverAddress = "   ")

        viewModel.save(invalidDraft)
        advanceUntilIdle()

        coVerify(exactly = 0) { mockRepository.save(any()) }
    }

    @Test
    fun `isEditable reflects vpnState kind`() = runTest(testDispatcher) {
        advanceUntilIdle()
        assertTrue(viewModel.isEditable.value)

        val info = TunnelInfo(
            assignedIp = "10.0.0.2",
            prefix = 24,
            serverIp = "1.2.3.4",
            serverPrefix = 24,
            mtu = 1400,
        )
        stateFlow.value = MqvpnState.Connected(info)
        advanceUntilIdle()
        assertFalse(viewModel.isEditable.value)

        stateFlow.value = MqvpnState.Error(MqvpnError.Timeout("Connection timeout"))
        advanceUntilIdle()
        assertTrue(viewModel.isEditable.value)
    }
}
