// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.core

import com.mqvpn.sdk.runtime.MqvpnExecutor

internal object TestReflection {

    fun createDummyTunnel(): MqvpnTunnel {
        val ctor = MqvpnTunnel::class.java.getDeclaredConstructor(
            Long::class.javaPrimitiveType,
            Long::class.javaPrimitiveType,
            Boolean::class.javaPrimitiveType,
        )
        ctor.isAccessible = true
        return ctor.newInstance(0L, 0L, false) as MqvpnTunnel
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
