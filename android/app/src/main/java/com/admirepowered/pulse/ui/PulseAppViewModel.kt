package com.admirepowered.pulse.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.admirepowered.pulse.core.PulseCoreBridge
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class PulseAppViewModel(application: Application) : AndroidViewModel(application) {
    private val _state = MutableStateFlow(
        PulseAppState(
            profiles = sampleProfiles,
            proxies = sampleProxies,
            connections = sampleConnections,
            coreStatus = PulseCoreBridge.statusText(),
        ),
    )
    val state: StateFlow<PulseAppState> = _state

    fun setScreen(screen: PulseScreen) {
        _state.update { it.copy(screen = screen) }
    }

    fun setVpnRunning(running: Boolean) {
        _state.update { it.copy(vpnRunning = running) }
    }

    fun setProxyMode(mode: ProxyMode) {
        _state.update { it.copy(proxyMode = mode) }
    }

    fun setThemeMode(mode: ThemeMode) {
        _state.update { it.copy(themeMode = mode) }
    }

    fun selectProfile(profileId: String) {
        _state.update { it.copy(selectedProfileId = profileId) }
    }

    fun selectProxy(proxyId: String) {
        _state.update {
            it.copy(
                selectedProxyId = proxyId,
                proxies = it.proxies.map { proxy -> proxy.copy(selected = proxy.id == proxyId) },
            )
        }
    }

    fun refreshProfile(profileId: String) {
        viewModelScope.launch {
            _state.update { it.copy(refreshingProfileId = profileId) }
            delay(900)
            _state.update { it.copy(refreshingProfileId = null) }
        }
    }

    companion object {
        private val sampleProfiles = listOf(
            ProfileItem("default", "主订阅", 3, 168, "今天 16:08"),
            ProfileItem("work", "工作线路", 2, 92, "昨天 21:30"),
            ProfileItem("local", "本地配置", 1, 44, "6 月 8 日"),
        )

        private val sampleProxies = listOf(
            ProxyItem("auto", "自动选择", "Proxy", 128, true),
            ProxyItem("hk-01", "香港 01", "Proxy", 86, false),
            ProxyItem("jp-02", "日本 02", "Proxy", 142, false),
            ProxyItem("sg-01", "新加坡 01", "Proxy", null, false),
        )

        private val sampleConnections = listOf(
            ConnectionItem("1", "github.com", "DOMAIN-SUFFIX", "28.4 MB", "2.1 MB", "1.4 MB/s"),
            ConnectionItem("2", "api.openai.com", "DOMAIN", "12.8 MB", "814 KB", "320 KB/s"),
            ConnectionItem("3", "cloudflare.com", "MATCH", "5.7 MB", "440 KB", "0 KB/s"),
        )
    }
}
