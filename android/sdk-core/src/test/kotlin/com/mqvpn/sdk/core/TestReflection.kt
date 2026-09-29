// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import com.mqvpn.sdk.runtime.MqvpnExecutor

internal object TestReflection {

    fun createDummyTunnel(reorderEnabled: Boolean = false): MqvpnTunnel {
        // handle 0 = a destroyed tunnel: every method returns an error without
        // a JNI call, so the native library is never loaded in JVM tests.
        val ctor = MqvpnTunnel::class.java.getDeclaredConstructor(
            Long::class.javaPrimitiveType,
            Long::class.javaPrimitiveType,
            Long::class.javaPrimitiveType,
            Boolean::class.javaPrimitiveType,
        )
        ctor.isAccessible = true
        return ctor.newInstance(0L, 0L, 1L, reorderEnabled) as MqvpnTunnel
    }

    fun createBridge(executor: MqvpnExecutor, tunnel: MqvpnTunnel): TunnelBridge {
        val ctor = TunnelBridge::class.java.getDeclaredConstructor(
            MqvpnExecutor::class.java,
            MqvpnTunnel::class.java,
        )
        ctor.isAccessible = true
        return ctor.newInstance(executor, tunnel) as TunnelBridge
    }
}
