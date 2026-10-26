// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app

import android.app.Application
import com.mqvpn.sdk.network.TransportAvailability
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject

@HiltAndroidApp
class MqvpnApplication : Application() {
    @Inject lateinit var transportAvailability: TransportAvailability

    override fun onCreate() {
        super.onCreate()
        // Never stopped: one passive callback is cheap and the UI needs it for the app's lifetime.
        transportAvailability.start()
    }
}
