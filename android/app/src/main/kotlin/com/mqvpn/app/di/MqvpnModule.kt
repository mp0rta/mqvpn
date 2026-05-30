// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.app.di

import android.content.Context
import com.mqvpn.sdk.core.MqvpnManager
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object MqvpnModule {
    @Provides
    @Singleton
    fun provideMqvpnManager(@ApplicationContext context: Context): MqvpnManager {
        return MqvpnManager(context)
    }
}
