// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import androidx.datastore.core.DataStore
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import com.mqvpn.app.data.DemoSettings
import com.mqvpn.app.data.SettingsRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class SettingsRepositoryTest {

    @get:Rule
    val tmpFolder = TemporaryFolder()

    private val testDispatcher = StandardTestDispatcher()
    private val storeScope = CoroutineScope(testDispatcher + Job())

    @After
    fun tearDown() {
        storeScope.cancel()
    }

    private fun newFile(): File = File(tmpFolder.root, "test-${System.nanoTime()}.preferences_pb")

    private fun newDataStore(
        file: File,
        corruptionHandler: ReplaceFileCorruptionHandler<Preferences>? = null,
        scope: CoroutineScope = storeScope,
    ): DataStore<Preferences> =
        PreferenceDataStoreFactory.create(
            corruptionHandler = corruptionHandler,
            migrations = SettingsRepository.MIGRATIONS,
            scope = scope,
            produceFile = { file },
        )

    /**
     * Seed [file] the way pre-migration builds wrote it (no schema-version
     * key), then release the store so the file can be reopened.
     */
    private suspend fun TestScope.seedLegacyStore(
        file: File,
        block: suspend (MutablePreferences) -> Unit,
    ) {
        val seedScope = CoroutineScope(testDispatcher + Job())
        val seed = PreferenceDataStoreFactory.create(scope = seedScope, produceFile = { file })
        seed.edit { block(it) }
        seedScope.cancel()
        testScheduler.advanceUntilIdle()
    }

    @Test
    fun `fresh store yields defaults`() = runTest(testDispatcher) {
        val repo = SettingsRepository(newDataStore(newFile()))
        assertEquals(DemoSettings(), repo.settings.first())
    }

    @Test
    fun `save round-trips every field`() = runTest(testDispatcher) {
        val repo = SettingsRepository(newDataStore(newFile()))
        val nonDefault = DemoSettings(
            serverAddress = "203.0.113.5",
            serverPort = 8443,
            tlsServerName = "vpn.example.com",
            authKey = "another-key",
            insecure = false,
            killSwitch = true,
            reorderEnabled = true,
            reorderProfile = "FIBER_LTE",
            reorderPorts = "443,8443",
            hybridEnabled = true,
            hybridTcpMode = "RAW",
        )

        repo.save(nonDefault)

        assertEquals(nonDefault, repo.settings.first())
    }

    @Test
    fun `partial store defaults missing fields`() = runTest(testDispatcher) {
        val file = newFile()
        val store = newDataStore(file)
        store.edit { prefs ->
            prefs[stringPreferencesKey("server_address")] = "198.51.100.9"
            prefs[intPreferencesKey("server_port")] = 51820
        }

        val repo = SettingsRepository(store)
        val result = repo.settings.first()

        val expected = DemoSettings(serverAddress = "198.51.100.9", serverPort = 51820)
        assertEquals(expected, result)
    }

    @Test
    fun `pre-migration store with baked-in insecure=true is reset to false`() = runTest(testDispatcher) {
        val file = newFile()
        seedLegacyStore(file) { prefs ->
            prefs[stringPreferencesKey("server_address")] = "203.0.113.5"
            prefs[booleanPreferencesKey("insecure")] = true
        }

        val repo = SettingsRepository(newDataStore(file))
        val result = repo.settings.first()

        assertEquals(false, result.insecure)
        assertEquals("203.0.113.5", result.serverAddress)
    }

    @Test
    fun `pre-migration store with insecure=false stays false`() = runTest(testDispatcher) {
        val file = newFile()
        seedLegacyStore(file) { prefs ->
            prefs[booleanPreferencesKey("insecure")] = false
        }

        val repo = SettingsRepository(newDataStore(file))

        assertEquals(false, repo.settings.first().insecure)
    }

    @Test
    fun `explicit insecure=true saved after migration survives a reopen`() = runTest(testDispatcher) {
        val file = newFile()
        val firstScope = CoroutineScope(testDispatcher + Job())
        val firstRepo = SettingsRepository(newDataStore(file, scope = firstScope))
        firstRepo.save(DemoSettings(serverAddress = "203.0.113.5", insecure = true))
        firstScope.cancel()
        testScheduler.advanceUntilIdle()

        val repo = SettingsRepository(newDataStore(file))

        assertEquals(true, repo.settings.first().insecure)
    }

    @Test
    fun `corrupt store emits defaults`() = runTest(testDispatcher) {
        val file = newFile()
        file.writeBytes(byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x42, 0x13, 0x37))

        val repo = SettingsRepository(newDataStore(file))

        assertEquals(DemoSettings(), repo.settings.first())
    }

    @Test
    fun `explicit insecure=true saved after corruption recovery survives a reopen`() = runTest(testDispatcher) {
        val file = newFile()
        file.writeBytes(byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x42, 0x13, 0x37))

        val firstScope = CoroutineScope(testDispatcher + Job())
        val firstRepo = SettingsRepository(
            newDataStore(file, ReplaceFileCorruptionHandler { emptyPreferences() }, scope = firstScope),
        )
        firstRepo.save(DemoSettings(serverAddress = "203.0.113.5", insecure = true))
        firstScope.cancel()
        testScheduler.advanceUntilIdle()

        val repo = SettingsRepository(
            newDataStore(file, ReplaceFileCorruptionHandler { emptyPreferences() }),
        )

        assertEquals(true, repo.settings.first().insecure)
    }

    @Test
    fun `save self-heals a corrupt store when a corruption handler is installed`() = runTest(testDispatcher) {
        val file = newFile()
        file.writeBytes(byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x42, 0x13, 0x37))

        val store = newDataStore(file, ReplaceFileCorruptionHandler { emptyPreferences() })
        val repo = SettingsRepository(store)

        val nonDefault = DemoSettings(
            serverAddress = "203.0.113.5",
            serverPort = 8443,
            tlsServerName = "vpn.example.com",
            authKey = "another-key",
            insecure = false,
            killSwitch = true,
            reorderEnabled = true,
            reorderProfile = "FIBER_LTE",
            reorderPorts = "443,8443",
            hybridEnabled = true,
            hybridTcpMode = "RAW",
        )

        repo.save(nonDefault)

        assertEquals(nonDefault, repo.settings.first())
    }
}
