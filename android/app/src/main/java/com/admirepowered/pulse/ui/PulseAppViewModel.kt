package com.admirepowered.pulse.ui

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.admirepowered.pulse.BuildConfig
import com.admirepowered.pulse.core.PulseBackgroundRecord
import com.admirepowered.pulse.core.PulseBackgroundStore
import com.admirepowered.pulse.core.PulseCoreBridge
import com.admirepowered.pulse.core.PulseCustomRuleStore
import com.admirepowered.pulse.core.PulseExternalResourceStatus
import com.admirepowered.pulse.core.PulseExternalResourceStore
import com.admirepowered.pulse.core.PulseLogEntry
import com.admirepowered.pulse.core.PulseLogStore
import com.admirepowered.pulse.core.PulseMihomoApi
import com.admirepowered.pulse.core.PulseProfileLinkParser
import com.admirepowered.pulse.core.PulseProfileRecord
import com.admirepowered.pulse.core.PulseProfileStore
import com.admirepowered.pulse.core.PulseSubscriptionInfo
import com.admirepowered.pulse.core.PulseSettingsStore
import com.admirepowered.pulse.core.PulseUpdateChecker
import com.admirepowered.pulse.core.PulseUpdateInstaller
import com.admirepowered.pulse.core.PulseWebDavStore
import com.admirepowered.pulse.vpn.PulseVpnService
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class PulseAppViewModel(application: Application) : AndroidViewModel(application) {
    private var lastConnectionSamples: Map<String, ConnectionSample> = emptyMap()
    private var accessControlReloadJob: Job? = null

    private val _state = MutableStateFlow(
        PulseAppState(
            appVersion = BuildConfig.VERSION_NAME,
            coreStatus = PulseCoreBridge.statusText(),
        ),
    )
    val state: StateFlow<PulseAppState> = _state

    init {
        loadSettings()
        loadProfiles()
        refreshRuntimeStatus()
        checkForUpdatesOnStartup()
        autoRefreshProfilesOnStartup()
    }

    fun setScreen(screen: PulseScreen) {
        _state.update { it.copy(screen = screen) }
        if (screen == PulseScreen.Proxies) {
            refreshProxies()
        }
        if (screen == PulseScreen.Connections) {
            refreshConnections()
        }
        if (screen == PulseScreen.Rules) {
            refreshRules()
        }
        if (screen == PulseScreen.Providers) {
            refreshProviders()
        }
        if (screen == PulseScreen.Dashboard) {
            refreshDashboard()
            refreshCoreVersion()
        }
        if (screen == PulseScreen.Logs) {
            refreshLogs()
        }
        if (screen == PulseScreen.Settings) {
            refreshCoreVersion()
        }
    }

    fun setVpnRunning(running: Boolean) {
        _state.update { it.copy(vpnRunning = running, coreStatus = PulseCoreBridge.statusText()) }
        if (running) {
            refreshProxies()
            refreshDashboard()
            refreshCoreVersion()
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
            if (message.isNotBlank()) {
                PulseLogStore.warn(getApplication(), message)
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
                refreshCoreVersion()
            }
        }
    }

    fun rejectVpnPermission() {
        PulseLogStore.warn(getApplication(), "VPN 授权已取消")
        _state.update {
            it.copy(
                vpnRunning = false,
                proxyMessage = "VPN 授权已取消",
                coreStatus = PulseCoreBridge.statusText(),
            )
        }
    }

    fun notifyAutoStartVpnNeedsPermission() {
        val message = "启动时自动连接需要先手动授权 VPN"
        PulseLogStore.warn(getApplication(), message)
        _state.update {
            it.copy(
                vpnRunning = false,
                proxyMessage = message,
                coreStatus = PulseCoreBridge.statusText(),
            )
        }
    }

    fun refreshRuntimeStatus() {
        loadSettings()
        val running = PulseCoreBridge.isRunning()
        _state.update {
            it.copy(
                vpnRunning = running,
                coreStatus = PulseCoreBridge.statusText(),
                coreVersion = if (running) it.coreVersion else "",
            )
        }
        if (running) {
            refreshCoreVersion()
            refreshDashboard()
        }
    }

    fun refreshCoreVersion() {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(coreVersion = "") }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.version() }
            }
            result.onSuccess { version ->
                _state.update { it.copy(coreVersion = version) }
            }.onFailure {
                _state.update { it.copy(coreVersion = "读取失败") }
            }
        }
    }

    fun refreshLogs() {
        viewModelScope.launch {
            val localLogs = withContext(Dispatchers.IO) {
                PulseLogStore.read(getApplication()).map(::toLogItem)
            }
            _state.update {
                it.copy(
                    logs = localLogs,
                    logMessage = if (localLogs.isEmpty()) "暂无日志" else "",
                )
            }
            if (!PulseCoreBridge.isRunning()) return@launch
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.logs() }
            }
            result.onSuccess { coreLogs ->
                val logs = (coreLogs + localLogs).take(500)
                _state.update {
                    it.copy(
                        logs = logs,
                        logMessage = if (logs.isEmpty()) "暂无日志" else "",
                    )
                }
            }.onFailure { error ->
                val message = error.message ?: "读取核心日志失败"
                PulseLogStore.warn(getApplication(), message)
                _state.update {
                    it.copy(
                        logs = PulseLogStore.read(getApplication()).map(::toLogItem),
                        logMessage = message,
                    )
                }
            }
        }
    }

    fun clearLogs() {
        PulseLogStore.clear(getApplication())
        _state.update { it.copy(logs = emptyList(), logMessage = "日志已清空") }
    }

    fun shareLogs(text: String) {
        if (text.isBlank()) {
            _state.update { it.copy(logMessage = "没有可分享的日志") }
            return
        }
        shareText(
            text = text,
            subject = "Pulse Android 日志",
            title = "分享日志",
            onFailure = { message -> _state.update { it.copy(logMessage = message) } },
        )
    }

    fun shareProfileEditorContent(text: String) {
        if (text.isBlank()) {
            _state.update { it.copy(profileEditorMessage = "没有可分享的配置") }
            return
        }
        shareText(
            text = text,
            subject = "Pulse Android 配置 ${_state.value.editingProfileName}".trim(),
            title = "分享配置",
            onFailure = { message -> _state.update { it.copy(profileEditorMessage = message) } },
        )
    }

    fun exportProfileEditorContentToUri(text: String, uri: Uri) {
        if (text.isBlank()) {
            _state.update { it.copy(profileEditorMessage = "没有可导出的配置") }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { writeTextToUri(uri, text) }
            }
            result.onSuccess { bytes ->
                _state.update { it.copy(profileEditorMessage = "配置已导出: ${formatBytes(bytes.toLong())}") }
            }.onFailure { error ->
                _state.update { it.copy(profileEditorMessage = error.message ?: "导出配置失败") }
            }
        }
    }

    fun shareRules(text: String) {
        if (text.isBlank()) {
            _state.update { it.copy(ruleMessage = "没有可分享的规则") }
            return
        }
        shareText(
            text = text,
            subject = "Pulse Android 规则",
            title = "分享规则",
            onFailure = { message -> _state.update { it.copy(ruleMessage = message) } },
        )
    }

    fun shareCustomRules(text: String) {
        if (text.isBlank()) {
            _state.update { it.copy(customRuleMessage = "没有可分享的自定义规则") }
            return
        }
        shareText(
            text = text,
            subject = "Pulse Android 自定义规则",
            title = "分享自定义规则",
            onFailure = { message -> _state.update { it.copy(customRuleMessage = message) } },
        )
    }

    fun shareProxies(text: String) {
        if (text.isBlank()) {
            _state.update { it.copy(proxyMessage = "没有可分享的节点") }
            return
        }
        shareText(
            text = text,
            subject = "Pulse Android 节点",
            title = "分享节点",
            onFailure = { message -> _state.update { it.copy(proxyMessage = message) } },
        )
    }

    fun shareProviders(text: String) {
        if (text.isBlank()) {
            _state.update { it.copy(providerMessage = "没有可分享的提供者") }
            return
        }
        shareText(
            text = text,
            subject = "Pulse Android 提供者",
            title = "分享提供者",
            onFailure = { message -> _state.update { it.copy(providerMessage = message) } },
        )
    }

    fun shareConnections(text: String) {
        if (text.isBlank()) {
            _state.update { it.copy(connectionMessage = "没有可分享的连接") }
            return
        }
        shareText(
            text = text,
            subject = "Pulse Android 连接",
            title = "分享连接",
            onFailure = { message -> _state.update { it.copy(connectionMessage = message) } },
        )
    }

    fun shareAccessControl(text: String) {
        if (text.isBlank()) {
            _state.update { it.copy(coreMessage = "没有可分享的访问控制列表") }
            return
        }
        shareText(
            text = text,
            subject = "Pulse Android 访问控制",
            title = "分享访问控制",
            onFailure = { message -> _state.update { it.copy(coreMessage = message) } },
        )
    }

    fun shareProfileContent(profileId: String) {
        val profile = _state.value.profiles.firstOrNull { it.id == profileId }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseProfileStore.readContent(getApplication(), profileId) }
            }
            result.onSuccess { content ->
                if (content.isBlank()) {
                    _state.update { it.copy(profileMessage = "配置内容为空") }
                } else {
                    shareText(
                        text = content,
                        subject = "Pulse Android 配置 ${profile?.name.orEmpty()}".trim(),
                        title = "分享配置",
                        onFailure = { message -> _state.update { it.copy(profileMessage = message) } },
                    )
                }
            }.onFailure { error ->
                _state.update { it.copy(profileMessage = error.message ?: "分享配置失败") }
            }
        }
    }

    fun exportProfileContentToUri(profileId: String, uri: Uri) {
        val profile = _state.value.profiles.firstOrNull { it.id == profileId }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val content = PulseProfileStore.readContent(getApplication(), profileId)
                    require(content.isNotBlank()) { "配置内容为空" }
                    val stream = getApplication<Application>().contentResolver.openOutputStream(uri)
                        ?: throw IllegalArgumentException("无法写入配置文件")
                    stream.bufferedWriter(Charsets.UTF_8).use { it.write(content) }
                    content.toByteArray(Charsets.UTF_8).size
                }
            }
            result.onSuccess { bytes ->
                val message = "配置已导出: ${profile?.name.orEmpty().ifBlank { profileId }} (${formatBytes(bytes.toLong())})"
                PulseLogStore.info(getApplication(), message)
                _state.update { it.copy(profileMessage = message) }
            }.onFailure { error ->
                _state.update { it.copy(profileMessage = error.message ?: "导出配置失败") }
            }
        }
    }

    private fun shareText(
        text: String,
        subject: String,
        title: String,
        onFailure: (String) -> Unit,
    ) {
        val intent = Intent(Intent.ACTION_SEND)
            .setType("text/plain")
            .putExtra(Intent.EXTRA_SUBJECT, subject)
            .putExtra(Intent.EXTRA_TEXT, text)
        val chooser = Intent.createChooser(intent, title)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { getApplication<Application>().startActivity(chooser) }
            .onFailure { error ->
                onFailure(error.message ?: "$title 失败")
            }
    }

    fun setProxyMode(mode: ProxyMode) {
        if (!PulseCoreBridge.isRunning()) {
            PulseSettingsStore.setProxyMode(getApplication(), mode.toMihomoMode())
            _state.update { it.copy(proxyMode = mode) }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.setMode(mode) }
            }
            result.onSuccess {
                PulseSettingsStore.setProxyMode(getApplication(), mode.toMihomoMode())
                _state.update { it.copy(proxyMode = mode) }
                PulseVpnService.refreshStatusUi(getApplication())
            }.onFailure { error ->
                _state.update { it.copy(proxyMessage = error.message ?: "切换模式失败") }
            }
        }
    }

    fun setThemeMode(mode: ThemeMode) {
        PulseSettingsStore.setThemeMode(getApplication(), mode.name)
        _state.update { it.copy(themeMode = mode) }
    }

    fun setAllowLan(enabled: Boolean) {
        PulseSettingsStore.setAllowLan(getApplication(), enabled)
        _state.update { it.copy(allowLan = enabled) }
        if (PulseCoreBridge.isRunning()) {
            reloadCoreIfRunning("局域网访问设置已更新")
        }
    }

    fun setCoreLogLevel(level: CoreLogLevel) {
        PulseSettingsStore.setCoreLogLevel(getApplication(), level.value)
        _state.update { it.copy(coreLogLevel = level) }
        if (PulseCoreBridge.isRunning()) {
            reloadCoreIfRunning("日志级别已更新")
        }
    }

    fun restartCore() {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(coreMessage = "请先启动 Pulse VPN") }
            return
        }
        PulseLogStore.info(getApplication(), "正在重启核心")
        lastConnectionSamples = emptyMap()
        PulseVpnService.restart(getApplication())
        _state.update {
            it.copy(
                coreRestarting = true,
                coreMessage = "正在重启核心",
                vpnRunning = true,
                loadingProxies = true,
            )
        }
        viewModelScope.launch {
            delay(1_200)
            refreshRuntimeStatus()
            refreshProxies()
            _state.update {
                it.copy(
                    coreRestarting = false,
                    coreMessage = if (PulseCoreBridge.isRunning()) "核心已重启" else PulseCoreBridge.lastError().ifBlank { "核心重启失败" },
                )
            }
        }
    }

    fun setAccessControlMode(mode: AccessControlMode) {
        PulseSettingsStore.setAccessControlMode(getApplication(), mode.name)
        _state.update { it.copy(accessControlMode = mode) }
        if (PulseCoreBridge.isRunning()) {
            accessControlReloadJob?.cancel()
            accessControlReloadJob = null
            reloadCoreIfRunning("访问控制设置已更新")
        }
    }

    fun toggleAccessControlApp(packageName: String) {
        val apps = _state.value.accessControlApps.map { app ->
            if (app.packageName == packageName) {
                app.copy(selected = !app.selected)
            } else {
                app
            }
        }
        saveAccessControlApps(apps)
    }

    fun setAllAccessControlApps(selected: Boolean) {
        val apps = _state.value.accessControlApps.map { it.copy(selected = selected) }
        saveAccessControlApps(apps)
    }

    fun invertAccessControlApps() {
        val apps = _state.value.accessControlApps.map { it.copy(selected = !it.selected) }
        saveAccessControlApps(apps)
    }

    fun setAccessControlApps(packageNames: Set<String>, selected: Boolean) {
        if (packageNames.isEmpty()) return
        val apps = _state.value.accessControlApps.map { app ->
            if (app.packageName in packageNames) {
                app.copy(selected = selected)
            } else {
                app
            }
        }
        saveAccessControlApps(apps)
    }

    fun invertAccessControlApps(packageNames: Set<String>) {
        if (packageNames.isEmpty()) return
        val apps = _state.value.accessControlApps.map { app ->
            if (app.packageName in packageNames) {
                app.copy(selected = !app.selected)
            } else {
                app
            }
        }
        saveAccessControlApps(apps)
    }

    fun setProxyUpdateProfiles(enabled: Boolean) {
        PulseSettingsStore.setProxyUpdateProfiles(getApplication(), enabled)
        _state.update { it.copy(proxyUpdateProfiles = enabled) }
    }

    fun setAutoUpdateProfiles(enabled: Boolean) {
        PulseSettingsStore.setAutoUpdateProfiles(getApplication(), enabled)
        _state.update { it.copy(autoUpdateProfiles = enabled) }
        if (enabled) {
            autoRefreshProfilesOnStartup(delayMillis = 300)
        }
    }

    fun setAutoStartVpn(enabled: Boolean) {
        PulseSettingsStore.setAutoStartVpn(getApplication(), enabled)
        _state.update { it.copy(autoStartVpn = enabled) }
    }

    fun setDelayTestUrl(url: String) {
        PulseSettingsStore.setDelayTestUrl(getApplication(), url)
        _state.update { it.copy(delayTestUrl = url.ifBlank { com.admirepowered.pulse.core.DEFAULT_DELAY_TEST_URL }) }
    }

    fun setBackgroundImageUri(uri: String) {
        PulseSettingsStore.setBackgroundImageUri(getApplication(), uri)
        _state.update { it.copy(backgroundImageUri = uri) }
    }

    fun importBackgroundImage(uri: Uri) {
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseBackgroundStore.add(getApplication(), uri) }
            }
            result.onSuccess { background ->
                PulseSettingsStore.setBackgroundImageUri(getApplication(), background.path)
                _state.update {
                    it.copy(
                        backgroundImageUri = background.path,
                        backgrounds = PulseBackgroundStore.list(getApplication()).map(::toBackgroundImageItem),
                    )
                }
                PulseLogStore.info(getApplication(), "背景已添加: ${background.name}")
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "添加背景失败")
            }
        }
    }

    fun selectBackgroundImage(id: String) {
        val background = PulseBackgroundStore.find(getApplication(), id) ?: return
        PulseSettingsStore.setBackgroundImageUri(getApplication(), background.path)
        _state.update { it.copy(backgroundImageUri = background.path) }
    }

    fun deleteBackgroundImage(id: String) {
        val deletingCurrent = _state.value.backgrounds.firstOrNull { it.id == id }?.path == _state.value.backgroundImageUri
        val next = PulseBackgroundStore.delete(getApplication(), id)
        val backgrounds = PulseBackgroundStore.list(getApplication()).map(::toBackgroundImageItem)
        val nextPath = if (deletingCurrent) next?.path.orEmpty() else _state.value.backgroundImageUri
        PulseSettingsStore.setBackgroundImageUri(getApplication(), nextPath)
        _state.update {
            it.copy(
                backgroundImageUri = nextPath,
                backgrounds = backgrounds,
            )
        }
    }

    fun setBackgroundOpacityPercent(value: Int) {
        PulseSettingsStore.setBackgroundOpacityPercent(getApplication(), value)
        _state.update { it.copy(backgroundOpacityPercent = value.coerceIn(0, 60)) }
    }

    fun setBackgroundBlurDp(value: Int) {
        PulseSettingsStore.setBackgroundBlurDp(getApplication(), value)
        _state.update { it.copy(backgroundBlurDp = value.coerceIn(0, 40)) }
    }

    fun setDisableUpdateCheck(disabled: Boolean) {
        PulseSettingsStore.setDisableUpdateCheck(getApplication(), disabled)
        _state.update {
            it.copy(
                disableUpdateCheck = disabled,
                updateMessage = if (disabled) "已关闭启动时自动检查更新" else it.updateMessage,
            )
        }
        if (!disabled) {
            checkForUpdates(auto = true)
        }
    }

    fun setWebDavEnabled(enabled: Boolean) {
        PulseSettingsStore.setWebDavEnabled(getApplication(), enabled)
        _state.update { it.copy(webDavEnabled = enabled) }
    }

    fun setWebDavUrl(url: String) {
        PulseSettingsStore.setWebDavUrl(getApplication(), url)
        _state.update { it.copy(webDavUrl = url) }
    }

    fun setWebDavUsername(username: String) {
        PulseSettingsStore.setWebDavUsername(getApplication(), username)
        _state.update { it.copy(webDavUsername = username) }
    }

    fun setWebDavPassword(password: String) {
        PulseSettingsStore.setWebDavPassword(getApplication(), password)
        _state.update { it.copy(webDavPassword = password) }
    }

    fun uploadWebDavProfiles() {
        if (_state.value.syncingWebDav) return
        val url = _state.value.webDavUrl
        val username = _state.value.webDavUsername
        val password = _state.value.webDavPassword
        viewModelScope.launch {
            _state.update { it.copy(syncingWebDav = true, webDavMessage = "正在上传数据备份") }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseWebDavStore.uploadProfiles(getApplication(), url, username, password) }
            }
            result.onSuccess { bytes ->
                val message = "数据备份已上传: ${formatBytes(bytes.toLong())}"
                PulseLogStore.info(getApplication(), message)
                _state.update { it.copy(webDavMessage = message) }
            }.onFailure { error ->
                val message = error.message ?: "WebDAV 上传失败"
                PulseLogStore.error(getApplication(), message)
                _state.update { it.copy(webDavMessage = message) }
            }
            _state.update { it.copy(syncingWebDav = false) }
        }
    }

    fun downloadWebDavProfiles() {
        if (_state.value.syncingWebDav) return
        val url = _state.value.webDavUrl
        val username = _state.value.webDavUsername
        val password = _state.value.webDavPassword
        viewModelScope.launch {
            _state.update { it.copy(syncingWebDav = true, webDavMessage = "正在下载数据备份") }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseWebDavStore.downloadProfiles(getApplication(), url, username, password) }
            }
            result.onSuccess { count ->
                val active = PulseProfileStore.active(getApplication())
                val message = "数据备份已恢复: $count 个订阅"
                PulseLogStore.info(getApplication(), message)
                loadSettings()
                reloadProfiles(active.id, message)
                _state.update { it.copy(webDavMessage = message) }
                if (PulseCoreBridge.isRunning()) {
                    reloadCoreIfRunning("数据备份已恢复")
                }
            }.onFailure { error ->
                val message = error.message ?: "WebDAV 下载失败"
                PulseLogStore.error(getApplication(), message)
                _state.update { it.copy(webDavMessage = message) }
            }
            _state.update { it.copy(syncingWebDav = false) }
        }
    }

    fun exportBackupToUri(uri: Uri) {
        if (_state.value.syncingWebDav) return
        viewModelScope.launch {
            _state.update { it.copy(syncingWebDav = true, webDavMessage = "正在导出本地备份") }
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val backup = PulseProfileStore.exportBackup(getApplication())
                    val bytes = backup.toByteArray(Charsets.UTF_8)
                    val stream = getApplication<Application>().contentResolver.openOutputStream(uri)
                        ?: throw IllegalArgumentException("无法写入备份文件")
                    stream.use { it.write(bytes) }
                    bytes.size
                }
            }
            result.onSuccess { bytes ->
                val message = "本地备份已导出: ${formatBytes(bytes.toLong())}"
                PulseLogStore.info(getApplication(), message)
                _state.update { it.copy(webDavMessage = message) }
            }.onFailure { error ->
                val message = error.message ?: "导出本地备份失败"
                PulseLogStore.error(getApplication(), message)
                _state.update { it.copy(webDavMessage = message) }
            }
            _state.update { it.copy(syncingWebDav = false) }
        }
    }

    fun importBackupFromUri(uri: Uri) {
        if (_state.value.syncingWebDav) return
        viewModelScope.launch {
            _state.update { it.copy(syncingWebDav = true, webDavMessage = "正在恢复本地备份") }
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val stream = getApplication<Application>().contentResolver.openInputStream(uri)
                        ?: throw IllegalArgumentException("无法读取备份文件")
                    val body = stream.bufferedReader(Charsets.UTF_8).use { it.readText() }
                    PulseProfileStore.importBackup(getApplication(), body)
                    PulseProfileStore.list(getApplication()).size
                }
            }
            result.onSuccess { count ->
                val active = PulseProfileStore.active(getApplication())
                val message = "本地备份已恢复: $count 个订阅"
                PulseLogStore.info(getApplication(), message)
                loadSettings()
                reloadProfiles(active.id, message)
                _state.update { it.copy(webDavMessage = message) }
                if (PulseCoreBridge.isRunning()) {
                    reloadCoreIfRunning("本地备份已恢复")
                }
            }.onFailure { error ->
                val message = error.message ?: "恢复本地备份失败"
                PulseLogStore.error(getApplication(), message)
                _state.update { it.copy(webDavMessage = message) }
            }
            _state.update { it.copy(syncingWebDav = false) }
        }
    }

    fun updateExternalResources() {
        if (_state.value.updatingExternalResources) return
        viewModelScope.launch {
            _state.update {
                it.copy(
                    updatingExternalResources = true,
                    externalResourceMessage = "正在更新 GeoSite / GeoIP",
                )
            }
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    PulseExternalResourceStore.update(
                        context = getApplication(),
                        useProxy = shouldProxyProfileUpdate(),
                    )
                }
            }
            result.onSuccess { update ->
                val message = if (update.failures.isEmpty()) {
                    "外部资源已更新 ${update.updated} 项"
                } else {
                    val failureText = update.failures.joinToString("；")
                    "外部资源已更新 ${update.updated}/${update.total} 项，失败: $failureText"
                }
                val shouldReloadCore = update.updated > 0 && PulseCoreBridge.isRunning()
                PulseLogStore.info(getApplication(), message)
                _state.update {
                    it.copy(
                        externalResourceMessage = if (shouldReloadCore) "$message，正在重载核心" else message,
                        externalResources = loadExternalResourceItems(),
                    )
                }
                if (shouldReloadCore) {
                    reloadCoreAfterExternalResourceUpdate(message)
                }
            }.onFailure { error ->
                val message = error.message ?: "外部资源更新失败"
                PulseLogStore.error(getApplication(), message)
                _state.update {
                    it.copy(
                        externalResourceMessage = message,
                        externalResources = loadExternalResourceItems(),
                    )
                }
            }
            _state.update { it.copy(updatingExternalResources = false) }
        }
    }

    fun checkForUpdates() {
        checkForUpdates(auto = false)
    }

    private fun checkForUpdates(auto: Boolean) {
        if (_state.value.checkingUpdate) return
        viewModelScope.launch {
            _state.update { state ->
                state.copy(
                    checkingUpdate = !auto,
                    updateMessage = if (auto) state.updateMessage else "正在检查更新",
                    updateReleaseUrl = if (auto) state.updateReleaseUrl else "",
                    updateAvailable = if (auto) state.updateAvailable else false,
                    updateApkAssetName = if (auto) state.updateApkAssetName else "",
                    updateApkAssetUrl = if (auto) state.updateApkAssetUrl else "",
                )
            }
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    PulseUpdateChecker.check(
                        context = getApplication(),
                        currentVersion = BuildConfig.VERSION_NAME,
                        useProxy = shouldProxyProfileUpdate(),
                    )
                }
            }
            result.onSuccess { info ->
                val message = if (info.hasUpdate) {
                    if (info.apkAssetUrl.isBlank()) {
                        "发现新版本 ${info.latestVersion}，未找到 APK，点击打开 Release"
                    } else {
                        "发现新版本 ${info.latestVersion}，点击下载并安装"
                    }
                } else {
                    "当前已是最新版本 ${info.currentVersion}"
                }
                PulseLogStore.info(getApplication(), message)
                _state.update {
                    it.copy(
                        checkingUpdate = false,
                        updateMessage = if (auto && !info.hasUpdate) it.updateMessage else message,
                        updateReleaseUrl = info.releaseUrl,
                        updateAvailable = info.hasUpdate,
                        updateApkAssetName = info.apkAssetName,
                        updateApkAssetUrl = info.apkAssetUrl,
                    )
                }
            }.onFailure { error ->
                val message = error.message ?: "检查更新失败"
                PulseLogStore.error(getApplication(), message)
                _state.update {
                    it.copy(
                        checkingUpdate = false,
                        updateMessage = if (auto) it.updateMessage else message,
                        updateReleaseUrl = if (auto) it.updateReleaseUrl else "",
                        updateAvailable = if (auto) it.updateAvailable else false,
                        updateApkAssetName = if (auto) it.updateApkAssetName else "",
                        updateApkAssetUrl = if (auto) it.updateApkAssetUrl else "",
                    )
                }
            }
        }
    }

    fun downloadAndInstallUpdate() {
        val apkUrl = _state.value.updateApkAssetUrl
        val apkName = _state.value.updateApkAssetName
        if (apkUrl.isBlank()) {
            openUpdateRelease()
            return
        }
        if (_state.value.downloadingUpdate) return
        viewModelScope.launch {
            _state.update {
                it.copy(
                    downloadingUpdate = true,
                    updateMessage = "正在下载 ${apkName.ifBlank { "Android APK" }}",
                )
            }
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    PulseUpdateInstaller.downloadApk(
                        context = getApplication(),
                        apkUrl = apkUrl,
                        fileName = apkName,
                        useProxy = shouldProxyProfileUpdate(),
                    ) { downloaded, total ->
                        val message = if (total > 0) {
                            val percent = (downloaded * 100 / total).coerceIn(0, 100)
                            "正在下载 ${apkName.ifBlank { "Android APK" }} $percent% (${formatBytes(downloaded)} / ${formatBytes(total)})"
                        } else {
                            "正在下载 ${apkName.ifBlank { "Android APK" }} (${formatBytes(downloaded)})"
                        }
                        _state.update { it.copy(updateMessage = message) }
                    }
                }
            }
            result.onSuccess { apk ->
                val installResult = runCatching { PulseUpdateInstaller.openInstall(getApplication(), apk) }
                installResult.onSuccess {
                    val message = "APK 已下载，正在打开系统安装器"
                    PulseLogStore.info(getApplication(), message)
                    _state.update {
                        it.copy(
                            downloadingUpdate = false,
                            updateMessage = message,
                        )
                    }
                }.onFailure { error ->
                    val message = error.message ?: "无法打开系统安装器"
                    PulseLogStore.warn(getApplication(), message)
                    _state.update {
                        it.copy(
                            downloadingUpdate = false,
                            updateMessage = message,
                        )
                    }
                }
            }.onFailure { error ->
                val message = error.message ?: "下载更新失败"
                PulseLogStore.error(getApplication(), message)
                _state.update {
                    it.copy(
                        downloadingUpdate = false,
                        updateMessage = message,
                    )
                }
            }
        }
    }

    fun openUpdateRelease() {
        val url = _state.value.updateReleaseUrl
        if (url.isBlank()) {
            checkForUpdates()
            return
        }
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { getApplication<Application>().startActivity(intent) }
            .onFailure { error ->
                _state.update { it.copy(updateMessage = error.message ?: "无法打开 Release 页面") }
            }
    }

    fun updateImportUrl(value: String) {
        _state.update { it.copy(importUrl = value, profileMessage = "") }
    }

    fun importProfileFromUrl() {
        val urls = PulseProfileLinkParser.extractProfileUrls(_state.value.importUrl)
        if (urls.isNotEmpty()) {
            importProfilesFromUrls(urls, clearInput = true)
        } else {
            importProfileFromUrl(_state.value.importUrl, clearInput = true)
        }
    }

    fun importProfileFromClipboard(text: String) {
        val trimmed = text.trim()
        if (trimmed.isBlank()) {
            _state.update { it.copy(profileMessage = "剪贴板为空") }
            return
        }
        val urls = PulseProfileLinkParser.extractProfileUrls(trimmed)
        if (urls.isNotEmpty()) {
            importProfilesFromUrls(urls)
        } else if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            importProfilesFromUrls(listOf(trimmed))
        } else {
            importProfileFromText(trimmed)
        }
    }

    fun importProfileFromUrl(url: String) {
        _state.update { it.copy(screen = PulseScreen.Profiles) }
        importProfileFromUrl(url, clearInput = false)
    }

    fun importProfilesFromUrls(urls: List<String>, clearInput: Boolean = false) {
        val targets = urls.map { it.trim() }
            .filter { it.startsWith("http://") || it.startsWith("https://") }
            .distinct()
        if (targets.isEmpty()) {
            _state.update { it.copy(profileMessage = "没有可导入的订阅 URL") }
            return
        }
        if (targets.size == 1) {
            importProfileFromUrl(targets.first(), clearInput = clearInput)
            return
        }
        _state.update { it.copy(screen = PulseScreen.Profiles) }
        viewModelScope.launch {
            _state.update { it.copy(importBusy = true, profileMessage = "正在导入 ${targets.size} 个订阅") }
            var successCount = 0
            var lastRecordId = _state.value.selectedProfileId
            val failures = mutableListOf<String>()
            targets.forEachIndexed { index, url ->
                _state.update { it.copy(profileMessage = "正在导入 ${index + 1}/${targets.size}") }
                val result = withContext(Dispatchers.IO) {
                    runCatching {
                        PulseProfileStore.importFromUrl(
                            context = getApplication(),
                            profileUrl = url,
                            activate = false,
                            useProxy = shouldProxyProfileUpdate(),
                        )
                    }
                }
                result.onSuccess { record ->
                    successCount += 1
                    lastRecordId = record.id
                    PulseLogStore.info(getApplication(), "订阅已导入: ${record.name}")
                }.onFailure { error ->
                    val message = error.message ?: "导入失败"
                    failures += message
                    PulseLogStore.error(getApplication(), "导入订阅失败: $message")
                }
            }
            if (successCount > 0) {
                PulseProfileStore.select(getApplication(), lastRecordId)
                reloadProfiles(
                    lastRecordId,
                    if (failures.isEmpty()) {
                        "已导入 $successCount 个订阅"
                    } else {
                        "已导入 $successCount/${targets.size} 个订阅，失败 ${failures.size} 个"
                    },
                )
                if (clearInput) {
                    _state.update { it.copy(importUrl = "") }
                }
                reloadCoreIfRunning("订阅已导入")
            } else {
                _state.update { it.copy(profileMessage = failures.firstOrNull() ?: "导入失败") }
            }
            _state.update { it.copy(importBusy = false) }
        }
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
                PulseLogStore.info(getApplication(), "订阅已导入: ${record.name}")
                reloadProfiles(record.id, "订阅已导入")
                if (clearInput) {
                    _state.update { it.copy(importUrl = "") }
                }
                reloadCoreIfRunning("订阅已导入")
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "导入订阅失败")
                _state.update { it.copy(profileMessage = error.message ?: "导入失败") }
            }
            _state.update { it.copy(importBusy = false) }
        }
    }

    fun importProfileFromUri(uri: Uri) {
        _state.update { it.copy(screen = PulseScreen.Profiles) }
        viewModelScope.launch {
            _state.update { it.copy(importBusy = true, profileMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseProfileStore.importFromUri(getApplication(), uri) }
            }
            result.onSuccess { record ->
                PulseLogStore.info(getApplication(), "本地配置已导入: ${record.name}")
                reloadProfiles(record.id, "本地配置已导入")
                reloadCoreIfRunning("本地配置已导入")
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "导入本地配置失败")
                _state.update { it.copy(profileMessage = error.message ?: "导入失败") }
            }
            _state.update { it.copy(importBusy = false) }
        }
    }

    fun importProfilesFromUris(uris: List<Uri>) {
        val targets = uris.distinct()
        if (targets.isEmpty()) return
        if (targets.size == 1) {
            importProfileFromUri(targets.first())
            return
        }
        _state.update { it.copy(screen = PulseScreen.Profiles) }
        viewModelScope.launch {
            _state.update { it.copy(importBusy = true, profileMessage = "正在导入 ${targets.size} 个配置") }
            var successCount = 0
            var lastRecordId = _state.value.selectedProfileId
            val failures = mutableListOf<String>()
            targets.forEachIndexed { index, uri ->
                _state.update { it.copy(profileMessage = "正在导入 ${index + 1}/${targets.size}") }
                val result = withContext(Dispatchers.IO) {
                    runCatching { PulseProfileStore.importFromUri(getApplication(), uri, activate = false) }
                }
                result.onSuccess { record ->
                    successCount += 1
                    lastRecordId = record.id
                    PulseLogStore.info(getApplication(), "本地配置已导入: ${record.name}")
                }.onFailure { error ->
                    val message = error.message ?: "导入失败"
                    failures += message
                    PulseLogStore.error(getApplication(), "导入本地配置失败: $message")
                }
            }
            if (successCount > 0) {
                PulseProfileStore.select(getApplication(), lastRecordId)
                reloadProfiles(
                    lastRecordId,
                    if (failures.isEmpty()) {
                        "已导入 $successCount 个配置"
                    } else {
                        "已导入 $successCount/${targets.size} 个配置，失败 ${failures.size} 个"
                    },
                )
                reloadCoreIfRunning("本地配置已导入")
            } else {
                _state.update {
                    it.copy(profileMessage = failures.firstOrNull() ?: "导入失败")
                }
            }
            _state.update { it.copy(importBusy = false) }
        }
    }

    fun importProfileFromText(text: String) {
        _state.update { it.copy(screen = PulseScreen.Profiles) }
        viewModelScope.launch {
            _state.update { it.copy(importBusy = true, profileMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseProfileStore.importFromText(getApplication(), text) }
            }
            result.onSuccess { record ->
                PulseLogStore.info(getApplication(), "分享配置已导入: ${record.name}")
                reloadProfiles(record.id, "分享配置已导入")
                reloadCoreIfRunning("分享配置已导入")
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "导入分享配置失败")
                _state.update { it.copy(profileMessage = error.message ?: "导入失败") }
            }
            _state.update { it.copy(importBusy = false) }
        }
    }

    fun selectProfile(profileId: String) {
        if (profileId == _state.value.selectedProfileId) return
        PulseProfileStore.select(getApplication(), profileId)
        PulseLogStore.info(getApplication(), "切换订阅: $profileId")
        _state.update { it.copy(selectedProfileId = profileId, profileMessage = "") }
        reloadCoreIfRunning("订阅已切换")
    }

    fun selectProxy(proxyId: String) {
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.selectProxy(proxyId) }
            }
            result.onSuccess {
                PulseLogStore.info(getApplication(), "切换节点: $proxyId")
                _state.update { it.copy(selectedProxyId = proxyId, proxyMessage = "") }
                refreshProxies()
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "切换节点失败")
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
                        proxyGroups = proxies,
                        loadingProxies = false,
                        proxyMessage = if (proxies.isEmpty()) "没有可切换的策略组" else "",
                    )
                }
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "读取节点失败")
                _state.update {
                    it.copy(
                        loadingProxies = false,
                        proxyMessage = error.message ?: "读取节点失败",
                    )
                }
            }
        }
    }

    fun testProxyDelays() {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(proxyMessage = "请先启动 Pulse VPN") }
            return
        }
        if (_state.value.measuringProxyGroupName != null || _state.value.measuringProxyId != null) {
            _state.update { it.copy(proxyMessage = "正在测速，请稍候") }
            return
        }
        val targets = _state.value.proxyGroups
            .flatMap { it.proxies }
            .distinctBy { it.name }
        if (targets.isEmpty()) {
            _state.update { it.copy(proxyMessage = "没有可测速的节点") }
            return
        }
        viewModelScope.launch {
            _state.update { it.copy(measuringProxies = true, proxyMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.testProxyDelays(targets, _state.value.delayTestUrl) }
            }
            result.onSuccess { count ->
                _state.update {
                    it.copy(
                        proxyMessage = if (count == 0) "没有完成测速的节点" else "已测速 $count 个节点",
                    )
                }
                refreshProxies()
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "测速失败")
                _state.update { it.copy(proxyMessage = error.message ?: "测速失败") }
            }
            _state.update { it.copy(measuringProxies = false) }
        }
    }

    fun testProxyGroupDelays(groupName: String) {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(proxyMessage = "请先启动 Pulse VPN") }
            return
        }
        if (_state.value.measuringProxies || _state.value.measuringProxyId != null || _state.value.measuringProxyGroupName != null) {
            _state.update { it.copy(proxyMessage = "正在测速，请稍候") }
            return
        }
        val group = _state.value.proxyGroups.firstOrNull { it.name == groupName } ?: return
        val targets = group.proxies.distinctBy { it.name }
        if (targets.isEmpty()) {
            _state.update { it.copy(proxyMessage = "${group.name} 没有可测速的节点") }
            return
        }
        viewModelScope.launch {
            _state.update { it.copy(measuringProxyGroupName = group.name, proxyMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.testProxyDelays(targets, _state.value.delayTestUrl) }
            }
            result.onSuccess { count ->
                _state.update {
                    it.copy(
                        proxyMessage = if (count == 0) "${group.name} 没有完成测速的节点" else "${group.name} 已测速 $count 个节点",
                    )
                }
                refreshProxies()
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "${group.name} 测速失败")
                _state.update { it.copy(proxyMessage = error.message ?: "${group.name} 测速失败") }
            }
            _state.update { it.copy(measuringProxyGroupName = null) }
        }
    }

    fun testProxyDelay(proxyId: String) {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(proxyMessage = "请先启动 Pulse VPN") }
            return
        }
        if (_state.value.measuringProxies || _state.value.measuringProxyGroupName != null) {
            _state.update { it.copy(proxyMessage = "正在测速，请稍候") }
            return
        }
        val proxy = _state.value.proxyGroups
            .flatMap { it.proxies }
            .firstOrNull { it.id == proxyId } ?: return
        viewModelScope.launch {
            _state.update { it.copy(measuringProxyId = proxyId, proxyMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.testProxyDelay(proxy, _state.value.delayTestUrl) }
            }
            result.onSuccess {
                _state.update { it.copy(proxyMessage = "${proxy.name} 测速完成") }
                refreshProxies()
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "${proxy.name} 测速失败")
                _state.update { it.copy(proxyMessage = error.message ?: "${proxy.name} 测速失败") }
            }
            _state.update { it.copy(measuringProxyId = null) }
        }
    }

    fun refreshConnections() {
        refreshConnections(showLoading = true)
    }

    fun refreshConnectionsQuietly() {
        refreshConnections(showLoading = false)
    }

    private fun refreshConnections(showLoading: Boolean) {
        if (!PulseCoreBridge.isRunning()) {
            lastConnectionSamples = emptyMap()
            _state.update {
                it.copy(
                    connections = emptyList(),
                    closedConnections = prependClosedConnections(it.connections, it.closedConnections),
                    connectionMessage = "请先启动 Pulse VPN",
                )
            }
            return
        }
        viewModelScope.launch {
            if (showLoading) {
                _state.update { it.copy(loadingConnections = true, connectionMessage = "") }
            }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.connections() }
            }
            result.onSuccess { connections ->
                val measuredConnections = withConnectionSpeeds(connections)
                val closedConnections = mergeClosedConnections(_state.value.connections, measuredConnections)
                _state.update {
                    it.copy(
                        connections = measuredConnections,
                        closedConnections = closedConnections,
                        loadingConnections = false,
                        connectionMessage = if (measuredConnections.isEmpty()) "当前没有活动连接" else "",
                    )
                }
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "读取连接失败")
                _state.update {
                    it.copy(
                        loadingConnections = false,
                        connectionMessage = error.message ?: "读取连接失败",
                    )
                }
            }
        }
    }

    fun closeConnection(id: String) {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(connectionMessage = "请先启动 Pulse VPN") }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.closeConnection(id) }
            }
            result.onSuccess {
                PulseLogStore.info(getApplication(), "连接已断开")
                val target = _state.value.connections.firstOrNull { it.id == id }
                _state.update {
                    it.copy(
                        connectionMessage = "连接已断开",
                        closedConnections = prependClosedConnections(listOfNotNull(target), it.closedConnections),
                        connections = it.connections.filterNot { connection -> connection.id == id },
                    )
                }
                refreshConnections()
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "断开连接失败")
                _state.update { it.copy(connectionMessage = error.message ?: "断开连接失败") }
            }
        }
    }

    fun closeAllConnections() {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(connectionMessage = "请先启动 Pulse VPN") }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.closeAllConnections() }
            }
            result.onSuccess {
                PulseLogStore.info(getApplication(), "连接已清空")
                lastConnectionSamples = emptyMap()
                _state.update {
                    it.copy(
                        connectionMessage = "连接已清空",
                        closedConnections = prependClosedConnections(it.connections, it.closedConnections),
                        connections = emptyList(),
                    )
                }
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "清空连接失败")
                _state.update { it.copy(connectionMessage = error.message ?: "清空连接失败") }
            }
        }
    }

    fun clearClosedConnections() {
        _state.update {
            it.copy(
                closedConnections = emptyList(),
                connectionMessage = "已断开连接历史已清空",
            )
        }
    }

    fun refreshRules() {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(ruleMessage = "请先启动 Pulse VPN") }
            return
        }
        viewModelScope.launch {
            _state.update { it.copy(loadingRules = true, ruleMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.rules() }
            }
            result.onSuccess { rules ->
                _state.update {
                    it.copy(
                        rules = rules,
                        loadingRules = false,
                        ruleMessage = if (rules.isEmpty()) "暂无规则" else "",
                    )
                }
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "读取规则失败")
                _state.update {
                    it.copy(
                        loadingRules = false,
                        ruleMessage = error.message ?: "读取规则失败",
                    )
                }
            }
        }
    }

    fun refreshProviders() {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(providerMessage = "请先启动 Pulse VPN") }
            return
        }
        viewModelScope.launch {
            _state.update { it.copy(loadingProviders = true, providerMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.providers() }
            }
            result.onSuccess { providers ->
                _state.update {
                    it.copy(
                        providers = providers.sortedWith(
                            compareBy<ProviderItem> { it.kind.ordinal }
                                .thenBy(String.CASE_INSENSITIVE_ORDER) { it.name },
                        ),
                        loadingProviders = false,
                        providerMessage = if (providers.isEmpty()) "暂无提供者" else "",
                    )
                }
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "读取提供者失败")
                _state.update {
                    it.copy(
                        loadingProviders = false,
                        providerMessage = error.message ?: "读取提供者失败",
                    )
                }
            }
        }
    }

    fun updateProvider(name: String, kind: ProviderKind) {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(providerMessage = "请先启动 Pulse VPN") }
            return
        }
        viewModelScope.launch {
            _state.update { it.copy(updatingProviderName = providerUpdateKey(name, kind), providerMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseMihomoApi.updateProvider(name, kind) }
            }
            result.onSuccess {
                PulseLogStore.info(getApplication(), "${kind.label}提供者已更新: $name")
                _state.update { it.copy(providerMessage = "${kind.label}提供者已更新") }
                refreshProviders()
                if (PulseCoreBridge.isRunning()) {
                    refreshProxies()
                }
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "更新${kind.label}提供者失败")
                _state.update { it.copy(providerMessage = error.message ?: "更新${kind.label}提供者失败") }
            }
            _state.update { it.copy(updatingProviderName = null) }
        }
    }

    fun updateAllProviders() {
        updateProviders(_state.value.providers, allProviders = true)
    }

    fun updateProviders(providers: List<ProviderItem>) {
        updateProviders(providers, allProviders = providers.size == _state.value.providers.size)
    }

    private fun updateProviders(providers: List<ProviderItem>, allProviders: Boolean) {
        if (!PulseCoreBridge.isRunning()) {
            _state.update { it.copy(providerMessage = "请先启动 Pulse VPN") }
            return
        }
        if (providers.isEmpty()) {
            _state.update { it.copy(providerMessage = "暂无可更新的提供者") }
            return
        }
        val totalLabel = if (allProviders) "全部提供者" else "当前筛选提供者"
        viewModelScope.launch {
            _state.update {
                it.copy(
                    updatingProviderName = ALL_PROVIDERS_UPDATE,
                    providerMessage = "正在更新$totalLabel: ${providers.size} 个",
                )
            }
            var successCount = 0
            var failureCount = 0
            withContext(Dispatchers.IO) {
                providers.forEachIndexed { index, provider ->
                    _state.update {
                        it.copy(
                            providerMessage = "正在更新 ${index + 1}/${providers.size}: ${provider.name}",
                        )
                    }
                    runCatching { PulseMihomoApi.updateProvider(provider.name, provider.kind) }
                        .onSuccess {
                            successCount += 1
                            PulseLogStore.info(getApplication(), "${provider.kind.label}提供者已更新: ${provider.name}")
                        }
                        .onFailure { error ->
                            failureCount += 1
                            PulseLogStore.warn(
                                getApplication(),
                                "${provider.kind.label}提供者更新失败 ${provider.name}: ${error.message}",
                            )
                        }
                }
            }
            val message = if (failureCount == 0) {
                "${totalLabel}已更新: $successCount 个"
            } else {
                "${totalLabel}更新完成: 成功 $successCount 个，失败 $failureCount 个"
            }
            _state.update {
                it.copy(
                    updatingProviderName = null,
                    providerMessage = message,
                )
            }
            refreshProviders()
            if (PulseCoreBridge.isRunning()) {
                refreshProxies()
            }
        }
    }

    fun refreshDashboard() {
        if (!PulseCoreBridge.isRunning()) {
            lastConnectionSamples = emptyMap()
            _state.update {
                it.copy(
                    traffic = TrafficSnapshot(),
                    closedConnections = prependClosedConnections(it.connections, it.closedConnections),
                    connections = emptyList(),
                )
            }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val traffic = PulseMihomoApi.traffic()
                    val snapshot = PulseMihomoApi.connectionSnapshot()
                    val memory = if (snapshot.memory == "0 B") {
                        runCatching { PulseMihomoApi.memory() }.getOrDefault(snapshot.memory)
                    } else {
                        snapshot.memory
                    }
                    traffic.copy(memory = memory) to snapshot.connections
                }
            }
            result.onSuccess { (traffic, connections) ->
                val measuredConnections = withConnectionSpeeds(connections)
                val closedConnections = mergeClosedConnections(_state.value.connections, measuredConnections)
                _state.update {
                    it.copy(
                        traffic = traffic,
                        connections = measuredConnections,
                        closedConnections = closedConnections,
                        connectionMessage = "",
                    )
                }
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "读取流量失败")
                _state.update { it.copy(connectionMessage = error.message ?: "读取流量失败") }
            }
        }
    }

    fun refreshProfile(profileId: String) {
        refreshProfile(profileId, useProxy = shouldProxyProfileUpdate())
    }

    fun refreshAllProfiles() {
        refreshAllProfiles(useProxy = shouldProxyProfileUpdate())
    }

    fun refreshAllProfilesWithProxy(useProxy: Boolean) {
        refreshAllProfiles(useProxy = useProxy)
    }

    private fun refreshAllProfiles(useProxy: Boolean) {
        if (_state.value.refreshingProfileId != null) {
            _state.update { it.copy(profileMessage = "正在更新订阅，请稍候") }
            return
        }
        val profiles = _state.value.profiles.filter { it.url.isNotBlank() }
        if (profiles.isEmpty()) {
            _state.update { it.copy(profileMessage = "没有可更新的远程订阅") }
            return
        }
        val selectedProfileId = _state.value.selectedProfileId
        val updateRouteLabel = if (useProxy) "通过代理" else "直连"
        viewModelScope.launch {
            var successCount = 0
            var failureCount = 0
            var selectedUpdated = false
            _state.update {
                it.copy(
                    refreshingProfileId = profiles.first().id,
                    profileMessage = "正在${updateRouteLabel}更新 ${profiles.size} 个订阅",
                )
            }
            profiles.forEach { profile ->
                _state.update { it.copy(refreshingProfileId = profile.id) }
                val result = withContext(Dispatchers.IO) {
                    runCatching {
                        PulseProfileStore.refreshFromUrl(
                            context = getApplication(),
                            profileId = profile.id,
                            useProxy = useProxy,
                        )
                    }
                }
                result.onSuccess { record ->
                    successCount += 1
                    if (record.id == selectedProfileId) selectedUpdated = true
                    PulseLogStore.info(getApplication(), "订阅已更新: ${record.name}")
                }.onFailure { error ->
                    failureCount += 1
                    PulseLogStore.error(getApplication(), "更新订阅失败 ${profile.name}: ${error.message}")
                }
            }
            val message = if (failureCount == 0) {
                "全部订阅已${updateRouteLabel}更新: $successCount 个"
            } else {
                "订阅${updateRouteLabel}更新完成: 成功 $successCount 个，失败 $failureCount 个"
            }
            reloadProfiles(selectedProfileId, message)
            _state.update { it.copy(refreshingProfileId = null, profileMessage = message) }
            if (selectedUpdated) {
                reloadCoreIfRunning("订阅已更新")
            }
        }
    }

    fun refreshProfileWithProxy(profileId: String, useProxy: Boolean) {
        refreshProfile(profileId, useProxy = useProxy)
    }

    private fun refreshProfile(profileId: String, useProxy: Boolean) {
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
                    PulseProfileStore.refreshFromUrl(
                        context = getApplication(),
                        profileId = profileId,
                        useProxy = useProxy,
                    )
                }
            }
            result.onSuccess {
                PulseLogStore.info(getApplication(), "订阅已更新: ${profile.name}")
                reloadProfiles(selectedProfileId, "订阅已更新")
                if (refreshesSelectedProfile) {
                    reloadCoreIfRunning("订阅已更新")
                }
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "更新订阅失败")
                _state.update { it.copy(profileMessage = error.message ?: "更新失败") }
            }
            _state.update { it.copy(refreshingProfileId = null) }
        }
    }

    fun updateProfileSource(profileId: String, source: String) {
        val selectedProfileId = _state.value.selectedProfileId
        val updatesSelectedProfile = profileId == selectedProfileId
        viewModelScope.launch {
            _state.update { it.copy(refreshingProfileId = profileId, profileMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    PulseProfileStore.updateSource(
                        context = getApplication(),
                        profileId = profileId,
                        profileUrl = source,
                        useProxy = shouldProxyProfileUpdate(),
                    )
                }
            }
            result.onSuccess { record ->
                PulseLogStore.info(getApplication(), "订阅 URL 已更新: ${record.name}")
                reloadProfiles(selectedProfileId, "订阅 URL 已更新")
                if (updatesSelectedProfile) {
                    reloadCoreIfRunning("订阅 URL 已更新")
                }
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "更新订阅 URL 失败")
                _state.update { it.copy(profileMessage = error.message ?: "更新失败") }
            }
            _state.update { it.copy(refreshingProfileId = null) }
        }
    }

    fun renameProfile(profileId: String, name: String) {
        val selectedProfileId = _state.value.selectedProfileId
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseProfileStore.rename(getApplication(), profileId, name) }
            }
            result.onSuccess { record ->
                PulseLogStore.info(getApplication(), "订阅已重命名: ${record.name}")
                reloadProfiles(selectedProfileId, "订阅已重命名")
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "重命名订阅失败")
                _state.update { it.copy(profileMessage = error.message ?: "重命名失败") }
            }
        }
    }

    fun copyProfileSource(profileId: String) {
        val profile = _state.value.profiles.firstOrNull { it.id == profileId } ?: return
        if (profile.url.isBlank()) {
            _state.update { it.copy(profileMessage = "本地配置没有订阅 URL") }
            return
        }
        val manager = getApplication<Application>().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        manager.setPrimaryClip(ClipData.newPlainText("Pulse 订阅 URL", profile.url))
        _state.update { it.copy(profileMessage = "订阅 URL 已复制") }
    }

    fun openProfileEditor(profileId: String) {
        val profile = _state.value.profiles.firstOrNull { it.id == profileId } ?: return
        _state.update {
            it.copy(
                editingProfileId = profileId,
                editingProfileName = profile.name,
                editingProfileContent = "",
                loadingProfileContent = true,
                profileMessage = "正在打开配置编辑器",
                profileEditorMessage = "",
            )
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseProfileStore.readContent(getApplication(), profileId) }
            }
            result.onSuccess { content ->
                _state.update {
                    it.copy(
                        screen = PulseScreen.ProfileEditor,
                        editingProfileContent = content,
                        loadingProfileContent = false,
                        profileMessage = "",
                        profileEditorMessage = "",
                    )
                }
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "读取配置失败")
                _state.update {
                    it.copy(
                        screen = PulseScreen.Profiles,
                        loadingProfileContent = false,
                        profileMessage = error.message ?: "读取配置失败",
                        profileEditorMessage = error.message ?: "读取配置失败",
                    )
                }
            }
        }
    }

    fun updateProfileEditorContent(content: String) {
        _state.update { it.copy(editingProfileContent = content, profileEditorMessage = "") }
    }

    fun closeProfileEditor() {
        _state.update { it.copy(screen = PulseScreen.Profiles) }
    }

    fun openCustomRules() {
        val selectedProfileId = _state.value.selectedProfileId
        _state.update {
            it.copy(
                screen = PulseScreen.CustomRules,
                loadingCustomRules = true,
                customRuleMessage = "",
                customRulePolicies = customRulePolicies(),
            )
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseCustomRuleStore.read(getApplication(), selectedProfileId) }
            }
            result.onSuccess { rules ->
                _state.update {
                    it.copy(
                        customRules = rules,
                        loadingCustomRules = false,
                        customRuleMessage = if (rules.isEmpty()) "暂无自定义规则" else "",
                    )
                }
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "读取自定义规则失败")
                _state.update {
                    it.copy(
                        loadingCustomRules = false,
                        customRuleMessage = error.message ?: "读取自定义规则失败",
                    )
                }
            }
        }
    }

    fun closeCustomRules() {
        _state.update { it.copy(screen = PulseScreen.Rules) }
    }

    fun addCustomRule() {
        val policy = _state.value.customRulePolicies.firstOrNull().orEmpty().ifBlank { "DIRECT" }
        _state.update {
            it.copy(
                customRules = it.customRules + CustomRuleItem(
                    id = PulseCustomRuleStore.newRuleId(),
                    type = "DOMAIN-SUFFIX",
                    payload = "",
                    proxy = policy,
                ),
                customRuleMessage = "",
            )
        }
    }

    fun duplicateCustomRule(index: Int) {
        _state.update {
            val source = it.customRules.getOrNull(index) ?: return@update it
            val next = it.customRules.toMutableList()
            next.add(index + 1, source.copy(id = PulseCustomRuleStore.newRuleId()))
            it.copy(
                customRules = next,
                customRuleMessage = "已复制第 ${index + 1} 条规则，保存后生效",
            )
        }
    }

    fun importCustomRulesFromText(text: String) {
        val rules = PulseCustomRuleStore.parseRuleText(text)
        if (rules.isEmpty()) {
            _state.update { it.copy(customRuleMessage = "没有可导入的规则") }
            return
        }
        _state.update {
            it.copy(
                customRules = it.customRules + rules,
                customRuleMessage = "已导入 ${rules.size} 条规则，保存后生效",
            )
        }
    }

    fun importCustomRulesFromUri(uri: Uri) {
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val stream = getApplication<Application>().contentResolver.openInputStream(uri)
                        ?: throw IllegalArgumentException("无法读取规则文件")
                    stream.bufferedReader(Charsets.UTF_8).use { it.readText() }
                }
            }
            result.onSuccess(::importCustomRulesFromText)
                .onFailure { error ->
                    _state.update { it.copy(customRuleMessage = error.message ?: "导入规则文件失败") }
                }
        }
    }

    fun exportProxiesToUri(text: String, uri: Uri) {
        if (text.isBlank()) {
            _state.update { it.copy(proxyMessage = "没有可导出的节点") }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { writeTextToUri(uri, text) }
            }
            result.onSuccess { bytes ->
                _state.update { it.copy(proxyMessage = "节点已导出: ${formatBytes(bytes.toLong())}") }
            }.onFailure { error ->
                _state.update { it.copy(proxyMessage = error.message ?: "导出节点失败") }
            }
        }
    }

    fun exportConnectionsToUri(text: String, uri: Uri) {
        if (text.isBlank()) {
            _state.update { it.copy(connectionMessage = "没有可导出的连接") }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { writeTextToUri(uri, text) }
            }
            result.onSuccess { bytes ->
                _state.update { it.copy(connectionMessage = "连接已导出: ${formatBytes(bytes.toLong())}") }
            }.onFailure { error ->
                _state.update { it.copy(connectionMessage = error.message ?: "导出连接失败") }
            }
        }
    }

    fun exportAccessControlToUri(text: String, uri: Uri) {
        if (text.isBlank()) {
            _state.update { it.copy(coreMessage = "没有可导出的访问控制列表") }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { writeTextToUri(uri, text) }
            }
            result.onSuccess { bytes ->
                _state.update { it.copy(coreMessage = "访问控制已导出: ${formatBytes(bytes.toLong())}") }
            }.onFailure { error ->
                _state.update { it.copy(coreMessage = error.message ?: "导出访问控制失败") }
            }
        }
    }

    fun exportLogsToUri(text: String, uri: Uri) {
        if (text.isBlank()) {
            _state.update { it.copy(logMessage = "没有可导出的日志") }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { writeTextToUri(uri, text) }
            }
            result.onSuccess { bytes ->
                _state.update { it.copy(logMessage = "日志已导出: ${formatBytes(bytes.toLong())}") }
            }.onFailure { error ->
                _state.update { it.copy(logMessage = error.message ?: "导出日志失败") }
            }
        }
    }

    fun exportRulesToUri(text: String, uri: Uri) {
        if (text.isBlank()) {
            _state.update { it.copy(ruleMessage = "没有可导出的规则") }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { writeTextToUri(uri, text) }
            }
            result.onSuccess { bytes ->
                _state.update { it.copy(ruleMessage = "规则已导出: ${formatBytes(bytes.toLong())}") }
            }.onFailure { error ->
                _state.update { it.copy(ruleMessage = error.message ?: "导出规则失败") }
            }
        }
    }

    fun exportProvidersToUri(text: String, uri: Uri) {
        if (text.isBlank()) {
            _state.update { it.copy(providerMessage = "没有可导出的提供者") }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { writeTextToUri(uri, text) }
            }
            result.onSuccess { bytes ->
                _state.update { it.copy(providerMessage = "提供者已导出: ${formatBytes(bytes.toLong())}") }
            }.onFailure { error ->
                _state.update { it.copy(providerMessage = error.message ?: "导出提供者失败") }
            }
        }
    }

    fun exportCustomRulesToUri(text: String, uri: Uri) {
        if (text.isBlank()) {
            _state.update { it.copy(customRuleMessage = "没有可导出的规则") }
            return
        }
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { writeTextToUri(uri, text) }
            }
            result.onSuccess { bytes ->
                _state.update { it.copy(customRuleMessage = "自定义规则已导出: ${formatBytes(bytes.toLong())}") }
            }.onFailure { error ->
                _state.update { it.copy(customRuleMessage = error.message ?: "导出规则文件失败") }
            }
        }
    }

    private fun writeTextToUri(uri: Uri, text: String): Int {
        val normalized = text.trimEnd() + "\n"
        val stream = getApplication<Application>().contentResolver.openOutputStream(uri)
            ?: throw IllegalArgumentException("无法写入文件")
        stream.bufferedWriter(Charsets.UTF_8).use { it.write(normalized) }
        return normalized.toByteArray(Charsets.UTF_8).size
    }

    fun updateCustomRule(index: Int, rule: CustomRuleItem) {
        _state.update {
            if (index !in it.customRules.indices) {
                it
            } else {
                it.copy(
                    customRules = it.customRules.mapIndexed { current, item ->
                        if (current == index) rule else item
                    },
                    customRuleMessage = "",
                )
            }
        }
    }

    fun moveCustomRule(from: Int, to: Int) {
        _state.update {
            if (from !in it.customRules.indices || to !in it.customRules.indices) {
                it
            } else {
                val next = it.customRules.toMutableList()
                val item = next.removeAt(from)
                next.add(to, item)
                it.copy(customRules = next, customRuleMessage = "")
            }
        }
    }

    fun deleteCustomRule(index: Int) {
        _state.update {
            if (index !in it.customRules.indices) {
                it
            } else {
                it.copy(
                    customRules = it.customRules.filterIndexed { current, _ -> current != index },
                    customRuleMessage = "",
                )
            }
        }
    }

    fun saveCustomRules() {
        val selectedProfileId = _state.value.selectedProfileId
        val rules = _state.value.customRules
        viewModelScope.launch {
            _state.update { it.copy(savingCustomRules = true, customRuleMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseCustomRuleStore.write(getApplication(), selectedProfileId, rules) }
            }
            result.onSuccess {
                PulseLogStore.info(getApplication(), "自定义规则已保存")
                _state.update {
                    it.copy(
                        savingCustomRules = false,
                        customRuleMessage = "自定义规则已保存",
                    )
                }
                reloadCoreIfRunning("自定义规则已保存")
                if (PulseCoreBridge.isRunning()) {
                    refreshRules()
                }
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "保存自定义规则失败")
                _state.update {
                    it.copy(
                        savingCustomRules = false,
                        customRuleMessage = error.message ?: "保存自定义规则失败",
                    )
                }
            }
        }
    }

    fun saveProfileEditor() {
        val profileId = _state.value.editingProfileId ?: return
        val content = _state.value.editingProfileContent
        val selectedProfileId = _state.value.selectedProfileId
        val savesSelectedProfile = profileId == selectedProfileId
        viewModelScope.launch {
            _state.update { it.copy(savingProfileContent = true, profileEditorMessage = "") }
            val result = withContext(Dispatchers.IO) {
                runCatching { PulseProfileStore.saveContent(getApplication(), profileId, content) }
            }
            result.onSuccess { record ->
                PulseLogStore.info(getApplication(), "配置已保存: ${record.name}")
                reloadProfiles(selectedProfileId, "配置已保存")
                _state.update {
                    it.copy(
                        screen = PulseScreen.ProfileEditor,
                        editingProfileId = profileId,
                        editingProfileName = record.name,
                        editingProfileContent = content,
                        savingProfileContent = false,
                        profileEditorMessage = "配置已保存",
                    )
                }
                if (savesSelectedProfile) {
                    reloadCoreIfRunning("配置已保存")
                }
            }.onFailure { error ->
                PulseLogStore.error(getApplication(), error.message ?: "保存配置失败")
                _state.update {
                    it.copy(
                        savingProfileContent = false,
                        profileEditorMessage = error.message ?: "保存配置失败",
                    )
                }
            }
        }
    }

    fun deleteProfile(profileId: String) {
        val deletingSelectedProfile = profileId == _state.value.selectedProfileId
        val result = runCatching { PulseProfileStore.delete(getApplication(), profileId) }
        result.onSuccess { active ->
            PulseLogStore.info(getApplication(), "订阅已删除: $profileId")
            reloadProfiles(active.id, "订阅已删除")
            if (deletingSelectedProfile) {
                reloadCoreIfRunning("订阅已切换")
            }
        }.onFailure { error ->
            PulseLogStore.error(getApplication(), error.message ?: "删除订阅失败")
            _state.update { it.copy(profileMessage = error.message ?: "删除失败") }
        }
    }

    private fun loadProfiles() {
        val active = PulseProfileStore.active(getApplication())
        reloadProfiles(active.id, "")
    }

    private fun loadSettings() {
        val settings = PulseSettingsStore.load(getApplication())
        val accessMode = runCatching { AccessControlMode.valueOf(settings.accessControlMode) }
            .getOrDefault(AccessControlMode.Off)
        val logLevel = CoreLogLevel.entries.firstOrNull { it.value == settings.coreLogLevel }
            ?: CoreLogLevel.Info
        val proxyMode = ProxyMode.entries.firstOrNull { it.toMihomoMode() == settings.proxyMode }
            ?: ProxyMode.Rule
        _state.update {
            it.copy(
                allowLan = settings.allowLan,
                coreLogLevel = logLevel,
                proxyMode = proxyMode,
                proxyUpdateProfiles = settings.proxyUpdateProfiles,
                autoUpdateProfiles = settings.autoUpdateProfiles,
                autoStartVpn = settings.autoStartVpn,
                themeMode = runCatching { ThemeMode.valueOf(settings.themeMode) }
                    .getOrDefault(ThemeMode.System),
                delayTestUrl = settings.delayTestUrl,
                backgroundImageUri = settings.backgroundImageUri,
                backgrounds = PulseBackgroundStore.list(getApplication()).map(::toBackgroundImageItem),
                backgroundOpacityPercent = settings.backgroundOpacityPercent,
                backgroundBlurDp = settings.backgroundBlurDp,
                disableUpdateCheck = settings.disableUpdateCheck,
                webDavEnabled = settings.webDavEnabled,
                webDavUrl = settings.webDavUrl,
                webDavUsername = settings.webDavUsername,
                webDavPassword = settings.webDavPassword,
                externalResources = loadExternalResourceItems(),
                accessControlMode = accessMode,
                accessControlApps = installedAccessApps(settings.accessControlPackages),
            )
        }
    }

    private fun checkForUpdatesOnStartup() {
        viewModelScope.launch {
            delay(1_800)
            if (!_state.value.disableUpdateCheck) {
                checkForUpdates(auto = true)
            }
        }
    }

    private fun autoRefreshProfilesOnStartup(delayMillis: Long = 2_400) {
        viewModelScope.launch {
            delay(delayMillis)
            if (!_state.value.autoUpdateProfiles) return@launch
            val dueProfiles = withContext(Dispatchers.IO) {
                PulseProfileStore.autoRefreshDueProfiles(getApplication())
            }
            if (dueProfiles.isEmpty()) return@launch

            val selectedProfileId = _state.value.selectedProfileId
            var successCount = 0
            var selectedUpdated = false
            _state.update {
                it.copy(
                    refreshingProfileId = dueProfiles.first().id,
                    profileMessage = "正在自动更新 ${dueProfiles.size} 个订阅",
                )
            }
            dueProfiles.forEach { profile ->
                _state.update { it.copy(refreshingProfileId = profile.id) }
                val result = withContext(Dispatchers.IO) {
                    runCatching {
                        PulseProfileStore.refreshFromUrl(
                            context = getApplication(),
                            profileId = profile.id,
                            useProxy = shouldProxyProfileUpdate(),
                        )
                    }
                }
                result.onSuccess { record ->
                    successCount += 1
                    if (record.id == selectedProfileId) selectedUpdated = true
                    PulseLogStore.info(getApplication(), "自动更新订阅: ${record.name}")
                }.onFailure { error ->
                    PulseLogStore.warn(getApplication(), "自动更新订阅失败 ${profile.name}: ${error.message}")
                }
            }
            val message = if (successCount == dueProfiles.size) {
                "自动更新订阅完成: $successCount 个"
            } else {
                "自动更新订阅完成: $successCount/${dueProfiles.size} 个"
            }
            reloadProfiles(selectedProfileId, message)
            _state.update { it.copy(refreshingProfileId = null, profileMessage = message) }
            if (selectedUpdated) {
                reloadCoreIfRunning("订阅已自动更新")
            }
        }
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
        lastConnectionSamples = emptyMap()
        PulseVpnService.reloadCore(getApplication())
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
            val resultMessage = if (PulseCoreBridge.isRunning()) {
                "$message，代理已重载"
            } else {
                PulseCoreBridge.lastError().ifBlank { "$message，代理重载失败" }
            }
            _state.update { it.copy(profileMessage = resultMessage, loadingProxies = false) }
        }
    }

    private fun reloadCoreAfterExternalResourceUpdate(message: String) {
        lastConnectionSamples = emptyMap()
        PulseVpnService.reloadCore(getApplication())
        _state.update {
            it.copy(
                vpnRunning = true,
                loadingProxies = true,
            )
        }
        viewModelScope.launch {
            delay(1_200)
            refreshRuntimeStatus()
            refreshProxies()
            val resultMessage = if (PulseCoreBridge.isRunning()) {
                "$message，核心已重载"
            } else {
                PulseCoreBridge.lastError().ifBlank { "$message，核心重载失败" }
            }
            _state.update { it.copy(externalResourceMessage = resultMessage) }
        }
    }

    private fun saveAccessControlApps(apps: List<AppAccessItem>) {
        val selectedPackages = apps
            .filter { it.selected }
            .map { it.packageName }
            .toSet()
        PulseSettingsStore.setAccessControlPackages(getApplication(), selectedPackages)
        _state.update { it.copy(accessControlApps = apps) }
        scheduleAccessControlReload()
    }

    private fun scheduleAccessControlReload() {
        if (!PulseCoreBridge.isRunning()) return
        accessControlReloadJob?.cancel()
        accessControlReloadJob = viewModelScope.launch {
            delay(800)
            reloadCoreIfRunning("访问控制应用列表已更新")
            accessControlReloadJob = null
        }
    }

    private fun mergeClosedConnections(previous: List<ConnectionItem>, active: List<ConnectionItem>): List<ConnectionItem> {
        val activeIds = active.map { it.id }.toSet()
        val disappeared = previous.filter { it.id !in activeIds && it.closedAt <= 0 }
        return prependClosedConnections(disappeared, _state.value.closedConnections)
    }

    private fun prependClosedConnections(items: List<ConnectionItem>, existing: List<ConnectionItem>): List<ConnectionItem> {
        if (items.isEmpty()) return existing
        val closedAt = System.currentTimeMillis() / 1000
        val closed = items.map { item -> item.copy(closedAt = closedAt) }
        val seen = mutableSetOf<String>()
        return (closed + existing)
            .filter { item ->
                val key = "${item.id}:${item.closedAt}"
                if (key in seen) {
                    false
                } else {
                    seen += key
                    true
                }
            }
            .take(MAX_CLOSED_CONNECTIONS)
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
            subscription = toSubscriptionInfoItem(record.subscription),
        )
    }

    private fun toSubscriptionInfoItem(info: PulseSubscriptionInfo): SubscriptionInfoItem {
        if (info.total <= 0) {
            return SubscriptionInfoItem(
                expire = formatExpire(info.expire),
                updateInterval = formatUpdateInterval(info.updateInterval),
                hasData = info.expire > 0 || info.rawUserInfo.isNotBlank() || info.updateInterval > 0,
            )
        }
        val used = (info.upload + info.download).coerceAtLeast(0)
        val available = (info.total - used).coerceAtLeast(0)
        return SubscriptionInfoItem(
            used = formatBytes(used),
            available = formatBytes(available),
            total = formatBytes(info.total),
            expire = formatExpire(info.expire),
            updateInterval = formatUpdateInterval(info.updateInterval),
            percent = ((used.toDouble() / info.total.toDouble()) * 100.0).toFloat().coerceIn(0f, 100f),
            hasData = true,
        )
    }

    private fun formatExpire(expire: Long): String {
        if (expire <= 0) return "长期有效"
        return expireDateFormat.format(Date(expire * 1000))
    }

    private fun formatUpdateInterval(hours: Int): String {
        if (hours <= 0) return ""
        return if (hours < 24) {
            "${hours} 小时"
        } else {
            val days = hours / 24
            val restHours = hours % 24
            if (restHours == 0) "${days} 天" else "${days} 天 ${restHours} 小时"
        }
    }

    private fun formatBytes(value: Long): String {
        val units = arrayOf("B", "KB", "MB", "GB", "TB")
        var size = value.toDouble()
        var index = 0
        while (size >= 1024 && index < units.lastIndex) {
            size /= 1024
            index++
        }
        return if (index == 0) {
            "${size.toLong()} ${units[index]}"
        } else {
            "%.1f %s".format(size, units[index])
        }
    }

    private fun toLogItem(entry: PulseLogEntry): LogItem {
        return LogItem(
            time = entry.time,
            level = entry.level,
            message = entry.message,
            source = "Pulse",
        )
    }

    private fun toBackgroundImageItem(record: PulseBackgroundRecord): BackgroundImageItem {
        return BackgroundImageItem(
            id = record.id,
            name = record.name,
            path = record.path,
        )
    }

    private fun loadExternalResourceItems(): List<ExternalResourceItem> {
        return PulseExternalResourceStore.status(getApplication()).map(::toExternalResourceItem)
    }

    private fun toExternalResourceItem(status: PulseExternalResourceStatus): ExternalResourceItem {
        val text = if (status.exists) {
            "${formatBytes(status.sizeBytes)}，${dateFormat.format(Date(status.updatedAt))}"
        } else {
            "未下载"
        }
        return ExternalResourceItem(
            name = status.name,
            status = text,
            ready = status.exists,
        )
    }

    private fun installedAccessApps(selectedPackages: Set<String>): List<AppAccessItem> {
        val context = getApplication<Application>()
        val packageManager = context.packageManager
        return packageManager.getInstalledApplications(0)
            .mapNotNull { applicationInfo ->
                val packageName = applicationInfo.packageName
                if (packageName == context.packageName) return@mapNotNull null
                val systemApp = applicationInfo.isSystemPackage()
                AppAccessItem(
                    label = applicationInfo.loadLabel(packageManager).toString().ifBlank { packageName },
                    packageName = packageName,
                    selected = packageName in selectedPackages,
                    systemApp = systemApp,
                )
            }
            .distinctBy { it.packageName }
            .sortedWith(
                compareBy<AppAccessItem> { it.systemApp }
                    .thenBy(String.CASE_INSENSITIVE_ORDER) { it.label }
                    .thenBy { it.packageName },
            )
    }

    private fun customRulePolicies(): List<String> {
        val policies = _state.value.proxyGroups
            .map { it.name }
            .filter { it.isNotBlank() }
        return (policies + listOf("DIRECT", "REJECT", "REJECT-DROP"))
            .distinct()
    }

    private fun withConnectionSpeeds(connections: List<ConnectionItem>): List<ConnectionItem> {
        val now = System.currentTimeMillis()
        val previous = lastConnectionSamples
        val updatedSamples = connections.associate { connection ->
            connection.id to ConnectionSample(
                download = connection.downloadBytes,
                upload = connection.uploadBytes,
                timeMillis = now,
            )
        }
        lastConnectionSamples = updatedSamples
        return connections.map { connection ->
            val sample = previous[connection.id]
            if (sample == null || now <= sample.timeMillis) {
                connection
            } else {
                val seconds = ((now - sample.timeMillis).toDouble() / 1000.0).coerceAtLeast(0.1)
                val downloadSpeed = ((connection.downloadBytes - sample.download).coerceAtLeast(0) / seconds).toLong()
                val uploadSpeed = ((connection.uploadBytes - sample.upload).coerceAtLeast(0) / seconds).toLong()
                connection.copy(
                    downloadSpeed = "${formatBytes(downloadSpeed)}/s",
                    uploadSpeed = "${formatBytes(uploadSpeed)}/s",
                    downloadSpeedBytes = downloadSpeed,
                    uploadSpeedBytes = uploadSpeed,
                )
            }
        }
    }

    companion object {
        private const val MAX_CLOSED_CONNECTIONS = 500
        private const val ALL_PROVIDERS_UPDATE = "__all_providers__"
        private val dateFormat = SimpleDateFormat("MM-dd HH:mm", Locale.getDefault())
        private val expireDateFormat = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault())
    }
}

private fun providerUpdateKey(name: String, kind: ProviderKind): String {
    return "${kind.name}:$name"
}

private fun ProxyMode.toMihomoMode(): String {
    return when (this) {
        ProxyMode.Rule -> "rule"
        ProxyMode.Global -> "global"
        ProxyMode.Direct -> "direct"
    }
}

private data class ConnectionSample(
    val download: Long,
    val upload: Long,
    val timeMillis: Long,
)

private fun ApplicationInfo.isSystemPackage(): Boolean {
    val systemFlags = ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
    return flags and systemFlags != 0
}
