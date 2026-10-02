// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

package com.mqvpn.sdk.network

import android.net.ConnectivityManager
import android.net.NetworkRequest
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowConnectivityManager

/**
 * A ConnectivityManager that refuses chosen registrations, the way a missing
 * permission or the per-app request limit does, and that rejects
 * unregistering a callback it never registered, as the framework does.
 */
@Implements(ConnectivityManager::class)
class RefusingConnectivityManagerShadow : ShadowConnectivityManager() {

    companion object {
        /** Refuse the listening registration. */
        var refuseListen = false

        /** Number of requestNetwork() calls that succeed before one is refused; -1 never refuses. */
        var requestsBeforeRefusal = -1

        private var requests = 0

        fun reset() {
            refuseListen = false
            requestsBeforeRefusal = -1
            requests = 0
        }
    }

    // ShadowConnectivityManager.requestNetwork registers through
    // registerNetworkCallback; that inner call is not the listen.
    private var inRequest = false

    @Implementation
    override fun registerNetworkCallback(
        request: NetworkRequest,
        networkCallback: ConnectivityManager.NetworkCallback,
    ) {
        if (refuseListen && !inRequest) throw SecurityException("listen refused")
        super.registerNetworkCallback(request, networkCallback)
    }

    @Implementation
    override fun requestNetwork(
        request: NetworkRequest,
        networkCallback: ConnectivityManager.NetworkCallback,
    ) {
        if (requestsBeforeRefusal >= 0 && requests++ >= requestsBeforeRefusal) {
            throw SecurityException("request refused")
        }
        inRequest = true
        try {
            super.requestNetwork(request, networkCallback)
        } finally {
            inRequest = false
        }
    }

    @Implementation
    override fun unregisterNetworkCallback(networkCallback: ConnectivityManager.NetworkCallback) {
        require(networkCallback in networkCallbacks) { "NetworkCallback was not registered" }
        super.unregisterNetworkCallback(networkCallback)
    }
}
