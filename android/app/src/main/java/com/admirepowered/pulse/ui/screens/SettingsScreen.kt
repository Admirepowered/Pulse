package com.admirepowered.pulse.ui.screens

import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import com.admirepowered.pulse.core.DEFAULT_DELAY_TEST_URL
import com.admirepowered.pulse.ui.AccessControlMode
import com.admirepowered.pulse.ui.BackgroundImageItem
import com.admirepowered.pulse.ui.CoreLogLevel
import com.admirepowered.pulse.ui.PulseAppState
import com.admirepowered.pulse.ui.ThemeMode
import com.admirepowered.pulse.ui.components.PulseRow
import com.admirepowered.pulse.ui.components.ThemeModeChips

@Composable
fun SettingsScreen(
    state: PulseAppState,
    onThemeChange: (ThemeMode) -> Unit,
    onAllowLanChange: (Boolean) -> Unit,
    onCoreLogLevelChange: (CoreLogLevel) -> Unit,
    onAutoStartVpnChange: (Boolean) -> Unit,
    onAutoUpdateProfilesChange: (Boolean) -> Unit,
    onProxyUpdateProfilesChange: (Boolean) -> Unit,
    onDelayTestUrlChange: (String) -> Unit,
    onUpdateExternalResources: () -> Unit,
    onCheckForUpdates: () -> Unit,
    onDownloadAndInstallUpdate: () -> Unit,
    onOpenUpdateRelease: () -> Unit,
    onDisableUpdateCheckChange: (Boolean) -> Unit,
    onWebDavEnabledChange: (Boolean) -> Unit,
    onWebDavUrlChange: (String) -> Unit,
    onWebDavUsernameChange: (String) -> Unit,
    onWebDavPasswordChange: (String) -> Unit,
    onUploadWebDavProfiles: () -> Unit,
    onDownloadWebDavProfiles: () -> Unit,
    onExportLocalBackup: () -> Unit,
    onImportLocalBackup: () -> Unit,
    onChooseBackground: () -> Unit,
    onClearBackground: () -> Unit,
    onSelectBackground: (String) -> Unit,
    onDeleteBackground: (String) -> Unit,
    onBackgroundOpacityChange: (Int) -> Unit,
    onBackgroundBlurChange: (Int) -> Unit,
    onRestartCore: () -> Unit,
    onOpenConnections: () -> Unit,
    onOpenRules: () -> Unit,
    onOpenProviders: () -> Unit,
    onOpenLogs: () -> Unit,
    onOpenAccessControl: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val selectedAppCount = state.accessControlApps.count { it.selected }
    val selectedBackgroundName = state.backgrounds.firstOrNull { it.path == state.backgroundImageUri }?.name
    val coreVersionLabel = when {
        state.coreVersion.isNotBlank() -> state.coreVersion
        state.vpnRunning -> "正在读取核心版本"
        else -> "核心未运行"
    }
    var deletingBackground by remember { mutableStateOf<BackgroundImageItem?>(null) }
    var confirmImportBackup by remember { mutableStateOf(false) }
    var confirmRestoreWebDav by remember { mutableStateOf(false) }
    var confirmInstallUpdate by remember { mutableStateOf(false) }
    var showWebDavPassword by remember { mutableStateOf(false) }
    var settingsQuery by remember { mutableStateOf("") }
    val settingsKeyword = settingsQuery.trim().lowercase()
    fun settingsMatches(vararg texts: String): Boolean {
        return settingsKeyword.isBlank() || texts.any { it.lowercase().contains(settingsKeyword) }
    }
    fun copySetting(label: String, value: String) {
        clipboard.setText(AnnotatedString("$label: $value"))
        Toast.makeText(context, "$label 已复制", Toast.LENGTH_SHORT).show()
    }
    val showAppearance = settingsMatches("外观", "主题", "深色", "浅色", "跟随系统", "背景", "图片", "透明度", "模糊")
    val showNetwork = settingsMatches("网络", "允许局域网", "启动时自动连接", "访问控制", "代理更新订阅", "自动更新订阅", "黑名单", "白名单")
    val showCore = settingsMatches("核心", "日志级别", "测速", "重启", "mihomo", "URL")
    val showPages = settingsMatches("页面", "连接", "规则", "提供者", "日志", "快捷开关")
    val showSync = settingsMatches("同步", "备份", "WebDAV", "导出", "导入", "上传", "恢复", "密码")
    val showResources = settingsMatches("资源", "外部资源", "GeoSite", "GeoIP", "geoip.metadb", "GeoSite.dat")
    val showVersion = settingsMatches("版本", "更新", "Release", "APK", "Pulse Android", "mihomo core", "不自动检查更新")
    val hasSettingsMatch = listOf(
        showAppearance,
        showNetwork,
        showCore,
        showPages,
        showSync,
        showResources,
        showVersion,
    ).any { it }

    deletingBackground?.let { background ->
        AlertDialog(
            onDismissRequest = { deletingBackground = null },
            title = { Text("删除背景") },
            text = { Text("确定删除「${background.name}」吗？图片文件会从 Pulse 数据目录移除。") },
            confirmButton = {
                TextButton(
                    onClick = {
                        onDeleteBackground(background.id)
                        deletingBackground = null
                    },
                ) {
                    Text("删除")
                }
            },
            dismissButton = {
                TextButton(onClick = { deletingBackground = null }) {
                    Text("取消")
                }
            },
        )
    }

    if (confirmImportBackup) {
        AlertDialog(
            onDismissRequest = { confirmImportBackup = false },
            title = { Text("导入备份") },
            text = { Text("导入本地备份会覆盖当前订阅、设置和自定义规则。确定继续吗？") },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmImportBackup = false
                        onImportLocalBackup()
                    },
                ) {
                    Text("继续")
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmImportBackup = false }) {
                    Text("取消")
                }
            },
        )
    }

    if (confirmRestoreWebDav) {
        AlertDialog(
            onDismissRequest = { confirmRestoreWebDav = false },
            title = { Text("恢复备份") },
            text = { Text("从 WebDAV 恢复会覆盖当前订阅、设置和自定义规则。确定继续吗？") },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmRestoreWebDav = false
                        onDownloadWebDavProfiles()
                    },
                ) {
                    Text("恢复")
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmRestoreWebDav = false }) {
                    Text("取消")
                }
            },
        )
    }

    if (confirmInstallUpdate) {
        AlertDialog(
            onDismissRequest = { confirmInstallUpdate = false },
            title = { Text("安装更新") },
            text = {
                Text(
                    "将下载并打开系统安装器安装 ${state.updateApkAssetName.ifBlank { "Pulse Android APK" }}。继续吗？",
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmInstallUpdate = false
                        onDownloadAndInstallUpdate()
                    },
                ) {
                    Text("下载")
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmInstallUpdate = false }) {
                    Text("取消")
                }
            },
        )
    }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(20.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp),
    ) {
        item {
            Text("设置", style = MaterialTheme.typography.headlineSmall)
        }
        item {
            OutlinedTextField(
                value = settingsQuery,
                onValueChange = { settingsQuery = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                trailingIcon = {
                    if (settingsQuery.isNotBlank()) {
                        IconButton(onClick = { settingsQuery = "" }) {
                            Icon(Icons.Filled.Close, contentDescription = "清空设置搜索")
                        }
                    }
                },
                placeholder = { Text("搜索设置项") },
            )
        }
        if (!hasSettingsMatch) {
            item {
                Text(
                    "没有匹配的设置项",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
        if (showAppearance) {
            item {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("外观", style = MaterialTheme.typography.titleMedium)
                    ThemeModeChips(selected = state.themeMode, onThemeChange = onThemeChange)
                }
            }
            item {
                PulseRow(
                    title = "背景图片",
                    subtitle = if (state.backgroundImageUri.isBlank()) {
                        "未选择背景图片"
                    } else {
                        "当前 ${selectedBackgroundName ?: "自定义背景"}，图片已保存到 App 数据目录"
                    },
                    modifier = Modifier.clickable(onClick = onChooseBackground),
                    trailing = {
                        Button(
                            onClick = onClearBackground,
                            enabled = state.backgroundImageUri.isNotBlank(),
                        ) {
                            Text("清除")
                        }
                    },
                )
            }
            if (state.backgrounds.isNotEmpty()) {
                state.backgrounds.forEach { background ->
                    item {
                        PulseRow(
                            title = background.name,
                            subtitle = if (background.path == state.backgroundImageUri) "当前背景" else "点击切换到这张背景",
                            modifier = Modifier.clickable { onSelectBackground(background.id) },
                            trailing = {
                                Button(onClick = { deletingBackground = background }) {
                                    Text("删除")
                                }
                            },
                        )
                    }
                }
            }
            if (state.backgroundImageUri.isNotBlank()) {
                item {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            "背景强度 ${state.backgroundOpacityPercent}%",
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Slider(
                            value = state.backgroundOpacityPercent.toFloat(),
                            onValueChange = { onBackgroundOpacityChange(it.toInt()) },
                            valueRange = 0f..60f,
                            steps = 11,
                            modifier = Modifier.padding(horizontal = 16.dp),
                        )
                        Text(
                            "背景模糊 ${state.backgroundBlurDp}dp",
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Slider(
                            value = state.backgroundBlurDp.toFloat(),
                            onValueChange = { onBackgroundBlurChange(it.toInt()) },
                            valueRange = 0f..40f,
                            steps = 39,
                            modifier = Modifier.padding(horizontal = 16.dp),
                        )
                    }
                }
            }
        }
        if (showNetwork) {
            item {
                Text("网络", style = MaterialTheme.typography.titleMedium)
            }
            item {
                PulseRow(
                    title = "允许局域网",
                    subtitle = "允许同网段设备访问本机代理入口",
                    modifier = Modifier.clickable { onAllowLanChange(!state.allowLan) },
                    trailing = {
                        Switch(
                            checked = state.allowLan,
                            onCheckedChange = onAllowLanChange,
                        )
                    },
                )
            }
            item {
                PulseRow(
                    title = "启动时自动连接",
                    subtitle = "打开 Pulse 时自动启动 VPN；首次使用仍需要系统授权",
                    modifier = Modifier.clickable { onAutoStartVpnChange(!state.autoStartVpn) },
                    trailing = {
                        Switch(
                            checked = state.autoStartVpn,
                            onCheckedChange = onAutoStartVpnChange,
                        )
                    },
                )
            }
            item {
                PulseRow(
                    title = "访问控制",
                    subtitle = accessControlSubtitle(state.accessControlMode, selectedAppCount),
                    modifier = Modifier.clickable(onClick = onOpenAccessControl),
                )
            }
            item {
                PulseRow(
                    title = "代理更新订阅",
                    subtitle = "VPN 运行时优先通过本地 mihomo 代理更新订阅，失败后自动直连",
                    modifier = Modifier.clickable { onProxyUpdateProfilesChange(!state.proxyUpdateProfiles) },
                    trailing = {
                        Switch(
                            checked = state.proxyUpdateProfiles,
                            onCheckedChange = onProxyUpdateProfilesChange,
                        )
                    },
                )
            }
            item {
                PulseRow(
                    title = "按间隔自动更新订阅",
                    subtitle = "启动时根据订阅返回的 profile-update-interval 刷新到期订阅",
                    modifier = Modifier.clickable { onAutoUpdateProfilesChange(!state.autoUpdateProfiles) },
                    trailing = {
                        Switch(
                            checked = state.autoUpdateProfiles,
                            onCheckedChange = onAutoUpdateProfilesChange,
                        )
                    },
                )
            }
        }
        if (showCore) {
            item {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("核心日志级别", style = MaterialTheme.typography.titleMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        CoreLogLevel.entries.forEach { level ->
                            FilterChip(
                                selected = state.coreLogLevel == level,
                                onClick = { onCoreLogLevelChange(level) },
                                label = { Text(level.label) },
                            )
                        }
                    }
                }
            }
            item {
                Text("节点测速", style = MaterialTheme.typography.titleMedium)
            }
            item {
                OutlinedTextField(
                    value = state.delayTestUrl,
                    onValueChange = onDelayTestUrlChange,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    singleLine = true,
                    label = { Text("测速 URL") },
                    placeholder = { Text(DEFAULT_DELAY_TEST_URL) },
                    trailingIcon = {
                        Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                            if (state.delayTestUrl.isNotBlank()) {
                                IconButton(onClick = { onDelayTestUrlChange("") }) {
                                    Icon(Icons.Filled.Close, contentDescription = "清空测速 URL")
                                }
                            }
                            TextButton(
                                onClick = { onDelayTestUrlChange(DEFAULT_DELAY_TEST_URL) },
                                enabled = state.delayTestUrl != DEFAULT_DELAY_TEST_URL,
                            ) {
                                Text("默认")
                            }
                        }
                    },
                )
            }
            item {
                PulseRow(
                    title = "重启核心",
                    subtitle = state.coreMessage.ifBlank {
                        if (state.vpnRunning) "重新启动 mihomo 并加载当前配置" else "请先启动 Pulse VPN"
                    },
                    modifier = Modifier.clickable(
                        enabled = state.vpnRunning && !state.coreRestarting,
                        onClick = onRestartCore,
                    ),
                    trailing = {
                        if (state.coreRestarting) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(22.dp),
                                strokeWidth = 2.dp,
                            )
                        }
                    },
                )
            }
        }
        if (showPages) {
            item {
                Text("页面", style = MaterialTheme.typography.titleMedium)
            }
            item {
                PulseRow(
                    title = "连接",
                    subtitle = "查看当前活动连接和流量",
                    modifier = Modifier.clickable(onClick = onOpenConnections),
                )
            }
            item {
                PulseRow(
                    title = "规则",
                    subtitle = "查看当前配置的规则列表",
                    modifier = Modifier.clickable(onClick = onOpenRules),
                )
            }
            item {
                PulseRow(
                    title = "提供者",
                    subtitle = "查看并更新 Proxy Providers / Rule Providers",
                    modifier = Modifier.clickable(onClick = onOpenProviders),
                )
            }
            item {
                PulseRow(
                    title = "日志",
                    subtitle = "查看启动、订阅和核心日志",
                    modifier = Modifier.clickable(onClick = onOpenLogs),
                )
            }
            item {
                PulseRow(
                    title = "快捷开关",
                    subtitle = "可在系统快捷设置面板中启用 Pulse 磁贴，用于快速启动或停止代理",
                )
            }
        }
        if (showSync) {
            item {
                Text("同步", style = MaterialTheme.typography.titleMedium)
            }
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Button(
                    onClick = onExportLocalBackup,
                    enabled = !state.syncingWebDav,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("导出备份")
                }
                Button(
                    onClick = { confirmImportBackup = true },
                    enabled = !state.syncingWebDav,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("导入备份")
                }
            }
        }
        item {
            PulseRow(
                title = "WebDAV",
                subtitle = state.webDavMessage.ifBlank { "同步订阅、设置和自定义规则" },
                modifier = Modifier.clickable { onWebDavEnabledChange(!state.webDavEnabled) },
                trailing = {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        IconButton(
                            onClick = {
                                copySetting(
                                    "WebDAV",
                                    state.webDavMessage.ifBlank { "同步订阅、设置和自定义规则" },
                                )
                            },
                        ) {
                            Icon(Icons.Filled.ContentCopy, contentDescription = "复制 WebDAV 状态")
                        }
                        Switch(
                            checked = state.webDavEnabled,
                            onCheckedChange = onWebDavEnabledChange,
                        )
                    }
                },
            )
        }
        if (state.webDavEnabled) {
            item {
                OutlinedTextField(
                    value = state.webDavUrl,
                    onValueChange = onWebDavUrlChange,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    singleLine = true,
                    label = { Text("WebDAV URL") },
                    placeholder = { Text("https://example.com/dav/ 或完整 json 文件地址") },
                    trailingIcon = {
                        if (state.webDavUrl.isNotBlank()) {
                            IconButton(onClick = { onWebDavUrlChange("") }) {
                                Icon(Icons.Filled.Close, contentDescription = "清空 WebDAV URL")
                            }
                        }
                    },
                )
            }
            item {
                OutlinedTextField(
                    value = state.webDavUsername,
                    onValueChange = onWebDavUsernameChange,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    singleLine = true,
                    label = { Text("用户名") },
                    trailingIcon = {
                        if (state.webDavUsername.isNotBlank()) {
                            IconButton(onClick = { onWebDavUsernameChange("") }) {
                                Icon(Icons.Filled.Close, contentDescription = "清空 WebDAV 用户名")
                            }
                        }
                    },
                )
            }
            item {
                OutlinedTextField(
                    value = state.webDavPassword,
                    onValueChange = onWebDavPasswordChange,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    singleLine = true,
                    label = { Text("密码") },
                    visualTransformation = if (showWebDavPassword) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    trailingIcon = {
                        IconButton(onClick = { showWebDavPassword = !showWebDavPassword }) {
                            Icon(
                                if (showWebDavPassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = if (showWebDavPassword) "隐藏密码" else "显示密码",
                            )
                        }
                    },
                )
            }
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Button(
                        onClick = onUploadWebDavProfiles,
                        enabled = state.webDavUrl.isNotBlank() && !state.syncingWebDav,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("上传备份")
                    }
                    Button(
                        onClick = { confirmRestoreWebDav = true },
                        enabled = state.webDavUrl.isNotBlank() && !state.syncingWebDav,
                        modifier = Modifier.weight(1f),
                    ) {
                        Text("恢复备份")
                    }
                }
            }
            if (state.syncingWebDav) {
                item {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp),
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(22.dp),
                            strokeWidth = 2.dp,
                        )
                        Text(
                            state.webDavMessage.ifBlank { "正在处理备份" },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.secondary,
                        )
                    }
                }
            }
        }
        }
        if (showResources) {
            item {
                Text("资源", style = MaterialTheme.typography.titleMedium)
            }
            item {
                PulseRow(
                    title = "外部资源更新",
                    subtitle = state.externalResourceMessage.ifBlank { "更新 GeoSite.dat 和 geoip.metadb" },
                    modifier = Modifier.clickable(
                        enabled = !state.updatingExternalResources,
                        onClick = onUpdateExternalResources,
                    ),
                    trailing = {
                        if (state.updatingExternalResources) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(22.dp),
                                strokeWidth = 2.dp,
                            )
                        }
                    },
                )
            }
            state.externalResources.forEach { resource ->
                item {
                    val resourceStatus = if (resource.ready) "已就绪，${resource.status}" else resource.status
                    PulseRow(
                        title = resource.name,
                        subtitle = resourceStatus,
                        modifier = Modifier.clickable {
                            copySetting(resource.name, resourceStatus)
                        },
                    )
                }
            }
        }
        if (showVersion) {
            item {
                Text("版本", style = MaterialTheme.typography.titleMedium)
            }
            item {
                PulseRow(
                    title = "Pulse Android",
                    subtitle = state.appVersion.ifBlank { "未知版本" },
                    modifier = Modifier.clickable {
                        copySetting("Pulse Android", state.appVersion.ifBlank { "未知版本" })
                    },
                )
            }
            item {
                PulseRow(
                    title = "mihomo core",
                    subtitle = coreVersionLabel,
                    modifier = Modifier.clickable {
                        copySetting("mihomo core", coreVersionLabel)
                    },
                )
            }
            item {
                PulseRow(
                    title = "检查更新",
                    subtitle = state.updateMessage.ifBlank { "检查 GitHub Release 中的 Pulse 最新版本" },
                    modifier = Modifier.clickable(
                        enabled = !state.checkingUpdate && !state.downloadingUpdate,
                        onClick = {
                            if (state.updateAvailable && state.updateApkAssetUrl.isNotBlank()) {
                                confirmInstallUpdate = true
                            } else if (state.updateAvailable && state.updateReleaseUrl.isNotBlank()) {
                                onOpenUpdateRelease()
                            } else {
                                onCheckForUpdates()
                            }
                        },
                    ),
                    trailing = {
                        if (state.checkingUpdate || state.downloadingUpdate) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(22.dp),
                                strokeWidth = 2.dp,
                            )
                        } else {
                            IconButton(
                                onClick = {
                                    copySetting(
                                        "检查更新",
                                        state.updateMessage.ifBlank { "检查 GitHub Release 中的 Pulse 最新版本" },
                                    )
                                },
                            ) {
                                Icon(Icons.Filled.ContentCopy, contentDescription = "复制更新状态")
                            }
                        }
                    },
                )
            }
            item {
                PulseRow(
                    title = "不自动检查更新",
                    subtitle = "开启后启动 Pulse 时不再自动查询 GitHub Release，手动检查仍可使用",
                    modifier = Modifier.clickable { onDisableUpdateCheckChange(!state.disableUpdateCheck) },
                    trailing = {
                        Switch(
                            checked = state.disableUpdateCheck,
                            onCheckedChange = onDisableUpdateCheckChange,
                        )
                    },
                )
            }
        }
        item {
            Text(
                "Android 版通过 VpnService 接管流量，Windows 的 TUN 管理项不会迁移到这里。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.secondary,
            )
        }
    }
}

private fun accessControlSubtitle(mode: AccessControlMode, selectedAppCount: Int): String {
    return when (mode) {
        AccessControlMode.Off -> "不限制应用"
        AccessControlMode.Include -> "白名单，已选择 $selectedAppCount 个应用"
        AccessControlMode.Exclude -> "黑名单，已选择 $selectedAppCount 个应用"
    }
}
