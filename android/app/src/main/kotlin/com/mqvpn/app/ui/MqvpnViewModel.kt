package com.mqvpn.app.ui

import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.mqvpn.app.service.MyVpnService
import com.mqvpn.sdk.core.MqvpnManager
import com.mqvpn.sdk.core.model.MqvpnConfig
import com.mqvpn.sdk.core.model.MqvpnState
import com.mqvpn.sdk.core.model.PathInfo
import com.mqvpn.sdk.core.model.VpnStats
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

@HiltViewModel
class MqvpnViewModel @Inject constructor(
    private val manager: MqvpnManager,
) : ViewModel() {

    val vpnState: StateFlow<MqvpnState> = manager.vpnState
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), MqvpnState.Disconnected)

    val stats: StateFlow<VpnStats> = manager.stats
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), VpnStats())

    val paths: StateFlow<List<PathInfo>> = manager.paths
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    fun connect(config: MqvpnConfig) {
        manager.connect(config, MyVpnService::class.java)
    }

    fun disconnect() {
        manager.disconnect()
    }

    fun prepareVpn(): Intent? = manager.prepareVpn()

    override fun onCleared() {
        manager.destroy()
    }
}
