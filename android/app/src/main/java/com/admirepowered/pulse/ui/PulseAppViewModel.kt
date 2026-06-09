package com.admirepowered.pulse.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.admirepowered.pulse.core.PulseCoreBridge
import com.admirepowered.pulse.core.PulseMihomoApi
import com.admirepowered.pulse.core.PulseProfileRecord
import com.admirepowered.pulse.core.PulseProfileStore
import com.admirepowered.pulse.core.PulseSettingsStore
import com.admirepowered.pulse.vpn.PulseVpnService
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class PulseAppViewModel(application: Application) : AndroidViewModel(application) {
    private val _state = MutableStateFlow(
        PulseAppState(
            proxies = sampleProxies,
            connections = sampleConnections,
            coreStatus = PulseCoreBridge.statusText(),
        ),
    )
    val state: StateFlow<PulseAppState> = _state

    init {
        loadSettings()
        loadProfiles()
        refreshRuntimeStatus()
    }

    fun setScreen(screen: PulseScreen) {
        _state.update { it.copy(screen = screen) }
        if (screen == PulseScreen.Proxies) {
            refreshProxies()
        }
        if (screen == PulseScreen.Connections) {
            refreshConnections()
        }
        if (screen == PulseScreen.Dashboard) {
            refreshDashboard()
        }
    }

    fun setVpnRunning(running: Boolean) {
        _state.update { it.copy(vpnRunning = running, coreStatus = PulseCoreBridge.statusText()) }
        if (running) {
            refreshProxies()
            refreshDashboard()
        }
    }

    fun confirmVpnStart() {
        _state.update { it.copy(vpnRunning = true, proxyMessage = "", coreStatus = PulseCoreBridge.statusText()) }
        viewModelScope.launch {
            delay(1_000)
            val running = PulseCoreBridge.isRunning()
            val message = if (running) {
                ""
            } else {
                PulseCoreBridge.lastError().ifBlank { "VPN 未启动，请检查授权或配置" }
            }
            _state.update {
                it.copy(
                    vpnRunning = running,
                    coreStatus = PulseCoreBridge.statusText(),
                    proxyMessage = message,
                )
            }
            if (running) {
                refreshProxies()
                refreshDashboard()
            }
        }
    }

    fun rejectVpnPermission() {
        _state.update {
            it.copy(
                vpnRunning = false,
                proxyMessage = "VPN 授权已取消",
                coreStatus = PulseCoreBridge.statusText(),
            )
        }
    }

    fun refreshRuntimeStatus() {
        val running = PulseCoreBridge.isRunning()
        _state.update { it.copy(vpnRunning = running, coreStatus = PulseCoreBridge.statusText()) }
        if (running) {
            refreshDashboard()
        }
    }

    fun setProxyMode(mode: ProxyMode) {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(proxyMode = mode) }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.setMode(mode) }
            }
            result.onSuccess {
                _state.update { it.copy(proxyMode = mode) }
            }.onFailure { error ->
                _state.update { it.copy(proxyMessage = error.message ?: "切换模式失败") }
            }
        }
    }

    fun setThemeMode(mode: ThemeMode) {
        _state.update { it.copy(themeMode = mode) }
    }

    fun setProxyUpdateProfiles(enabled: Boolean) {
        PulseSettingsStore.setProxyUpdateProfiles(getApplication(), enabled)
        _state.update { it.copy(proxyUpdateProfiles = enabled) }
    }

    fun updateImportUrl(value: String) {
        _state.update { it.copy(importUrl = value, profileMessage = "") }
    }

    fun importProfileFromUrl() {
        importProfileFromUrl(_state.value.importUrl, clearInput = true)
    }

    fun importProfileFromUrl(url: String) {
        _state.update { it.copy(screen = PulseScreen.Profiles) }
        importProfileFromUrl(url, clearInput = false)
    }

    private fun importProfileFromUrl(url: String, clearInput: Boolean) {
        if (url.isBlank()) {
            _state.update { it.copy(profileMessage = "请输入订阅 URL") }
            return
        }
        viewModelScope.launch {
            _state.update { it.copy(importBusy = true, profileMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    PulseProfileStore.importFromUrl(
                        context = getApplication(),
                        profileUrl = url,
                        useProxy = shouldProxyProfileUpdate(),
                    )
                }
            }
            result.onSuccess { record ->
                reloadProfiles(record.id, "订阅已导入")
                if (clearInput) {
                    _state.update { it.copy(importUrl = "") }
                }
                reloadCoreIfRunning("订阅已导入")
            }.onFailure { error ->
                _state.update { it.copy(profileMessage = error.message ?: "导入失败") }
            }
            _state.update { it.copy(importBusy = false) }
        }
    }

    fun selectProfile(profileId: String) {
        if (profileId == _state.value.selectedProfileId) return
        PulseProfileStore.select(getApplication(), profileId)
        _state.update { it.copy(selectedProfileId = profileId, profileMessage = "") }
        reloadCoreIfRunning("订阅已切换")
    }

    fun selectProxy(proxyId: String) {
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.selectProxy(proxyId) }
            }
            result.onSuccess {
                _state.update {
                    it.copy(
                        selectedProxyId = proxyId,
                        proxyMessage = "",
                        proxies = it.proxies.map { proxy -> proxy.copy(selected = proxy.id == proxyId) },
                    )
                }
            }.onFailure { error ->
                _state.update { it.copy(proxyMessage = error.message ?: "切换节点失败") }
            }
        }
    }

    fun refreshProxies() {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(proxyMessage = "请先启动 Pulse VPN") }
            return
        }
        viewModelScope.launch {
            _state.update { it.copy(loadingProxies = true, proxyMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.proxies() }
            }
            result.onSuccess { proxies ->
                _state.update {
                    it.copy(
                        proxies = proxies.ifEmpty { sampleProxies },
                        loadingProxies = false,
                        proxyMessage = if (proxies.isEmpty()) "没有可切换的策略组" else "",
                    )
                }
            }.onFailure { error ->
                _state.update {
                    it.copy(
                        loadingProxies = false,
                        proxyMessage = error.message ?: "读取节点失败",
                    )
                }
            }
        }
    }

    fun refreshConnections() {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(connectionMessage = "请先启动 Pulse VPN") }
            return
        }
        viewModelScope.launch {
            _state.update { it.copy(loadingConnections = true, connectionMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.connections() }
            }
            result.onSuccess { connections ->
                _state.update {
                    it.copy(
                        connections = connections,
                        loadingConnections = false,
                        connectionMessage = if (connections.isEmpty()) "当前没有活动连接" else "",
                    )
                }
            }.onFailure { error ->
                _state.update {
                    it.copy(
                        loadingConnections = false,
                        connectionMessage = error.message ?: "读取连接失败",
                    )
                }
            }
        }
    }

    fun refreshDashboard() {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(traffic = TrafficSnapshot(), connections = emptyList()) }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val traffic = PulseMihomoApi.traffic()
                    val connections = PulseMihomoApi.connections()
                    traffic to connections
                }
            }
            result.onSuccess { (traffic, connections) ->
                _state.update {
                    it.copy(
                        traffic = traffic,
                        connections = connections,
                        connectionMessage = "",
                    )
                }
            }.onFailure { error ->
                _state.update { it.copy(connectionMessage = error.message ?: "读取流量失败") }
            }
        }
    }

    fun refreshProfile(profileId: String) {
        val profile = _state.value.profiles.firstOrNull { it.id == profileId } ?: return
        val selectedProfileId = _state.value.selectedProfileId
        val refreshesSelectedProfile = profileId == selectedProfileId
        if (profile.url.isBlank()) {
            _state.update { it.copy(profileMessage = "本地配置没有订阅 URL") }
            return
        }
        viewModelScope.launch {
            _state.update { it.copy(refreshingProfileId = profileId, profileMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    PulseProfileStore.importFromUrl(
                        context = getApplication(),
                        profileUrl = profile.url,
                        activate = refreshesSelectedProfile,
                        useProxy = shouldProxyProfileUpdate(),
                    )
                }
            }
            result.onSuccess {
                reloadProfiles(selectedProfileId, "订阅已更新")
                if (refreshesSelectedProfile) {
                    reloadCoreIfRunning("订阅已更新")
                }
            }.onFailure { error ->
                _state.update { it.copy(profileMessage = error.message ?: "更新失败") }
            }
            _state.update { it.copy(refreshingProfileId = null) }
        }
    }

    private fun loadProfiles() {
        val active = PulseProfileStore.active(getApplication())
        reloadProfiles(active.id, "")
    }

    private fun loadSettings() {
        val settings = PulseSettingsStore.load(getApplication())
        _state.update { it.copy(proxyUpdateProfiles = settings.proxyUpdateProfiles) }
    }

    private fun shouldProxyProfileUpdate(): Boolean {
        return _state.value.proxyUpdateProfiles && PulseCoreBridge.isRunning()
    }

    private fun reloadProfiles(selectedId: String, message: String) {
        val profiles = PulseProfileStore.list(getApplication()).map(::toProfileItem)
        _state.update {
            it.copy(
                profiles = profiles,
                selectedProfileId = selectedId,
                profileMessage = message,
            )
        }
    }

    private fun reloadCoreIfRunning(message: String) {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(profileMessage = message) }
            return
        }
        PulseVpnService.restart(getApplication())
        _state.update {
            it.copy(
                profileMessage = "$message，正在重载代理",
                vpnRunning = true,
                loadingProxies = true,
            )
        }
        viewModelScope.launch {
            delay(1_200)
            refreshRuntimeStatus()
            refreshProxies()
        }
    }

    private fun toProfileItem(record: PulseProfileRecord): ProfileItem {
        return ProfileItem(
            id = record.id,
            name = record.name,
            url = record.url,
            path = record.path,
            providerCount = 0,
            ruleCount = 0,
            updatedAt = dateFormat.format(Date(record.updatedAt)),
        )
    }

    companion object {
        private val dateFormat = SimpleDateFormat("MM-dd HH:mm", Locale.getDefault())

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
