package com.admirepowered.pulse.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.admirepowered.pulse.ui.PulseAppState
import com.admirepowered.pulse.ui.ThemeMode
import com.admirepowered.pulse.ui.components.PulseRow
import com.admirepowered.pulse.ui.components.ThemeModeChips

@Composable
fun SettingsScreen(
    state: PulseAppState,
    onThemeChange: (ThemeMode) -> Unit,
    canRequestQuickTile: Boolean,
    onAddQuickTile: () -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(20.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp),
    ) {
        item {
            Text("设置", style = MaterialTheme.typography.headlineSmall)
        }
        item {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("主题", style = MaterialTheme.typography.titleMedium)
                ThemeModeChips(selected = state.themeMode, onThemeChange = onThemeChange)
            }
        }
        item {
            PulseRow(
                title = "允许局域网",
                subtitle = "允许同网段设备访问本机代理入口",
                trailing = { Switch(checked = true, onCheckedChange = { }) },
            )
        }
        item {
            PulseRow(
                title = "代理更新订阅",
                subtitle = "更新订阅时优先走当前代理",
                trailing = { Switch(checked = true, onCheckedChange = { }) },
            )
        }
        item {
            PulseRow(
                title = "快捷开关",
                subtitle = if (canRequestQuickTile) {
                    "添加 Pulse 到系统快捷设置，点击即可启动或停止代理"
                } else {
                    "当前系统需要手动编辑快捷设置来添加 Pulse"
                },
                trailing = {
                    Button(
                        onClick = onAddQuickTile,
                        enabled = canRequestQuickTile,
                    ) {
                        Text("添加")
                    }
                },
            )
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
