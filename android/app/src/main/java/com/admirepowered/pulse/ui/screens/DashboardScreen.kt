package com.admirepowered.pulse.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.RestartAlt
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.admirepowered.pulse.ui.ProxyMode
import com.admirepowered.pulse.ui.PulseAppState
import com.admirepowered.pulse.ui.components.ProxyModeChips
import com.admirepowered.pulse.ui.components.PulseMetricCard
import kotlinx.coroutines.delay

@Composable
fun DashboardScreen(
    state: PulseAppState,
    onToggleVpn: (Boolean) -> Unit,
    onModeChange: (ProxyMode) -> Unit,
    onRestartCore: () -> Unit,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var downloadSpeedPoints by remember { mutableStateOf<List<Long>>(emptyList()) }
    var uploadSpeedPoints by remember { mutableStateOf<List<Long>>(emptyList()) }

    LaunchedEffect(state.vpnRunning) {
        while (state.vpnRunning) {
            onRefresh()
            delay(2_000)
        }
    }
    LaunchedEffect(state.vpnRunning, state.traffic.downloadSpeedBytes, state.traffic.uploadSpeedBytes) {
        if (state.vpnRunning) {
            downloadSpeedPoints = (downloadSpeedPoints + state.traffic.downloadSpeedBytes).takeLast(32)
            uploadSpeedPoints = (uploadSpeedPoints + state.traffic.uploadSpeedBytes).takeLast(32)
        } else {
            downloadSpeedPoints = emptyList()
            uploadSpeedPoints = emptyList()
        }
    }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            ) {
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Text("Pulse Android", style = MaterialTheme.typography.headlineMedium)
                    Text(
                        if (state.vpnRunning) "VPNService 已接管网络" else "准备接管 Android 网络流量",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.secondary,
                    )
                }
                IconButton(
                    onClick = onRefresh,
                    enabled = state.vpnRunning,
                ) {
                    Icon(Icons.Filled.Refresh, contentDescription = "刷新运行状态")
                }
            }
        }

        item {
            NetworkSpeedPanel(
                uploadSpeed = state.traffic.uploadSpeed,
                downloadSpeed = state.traffic.downloadSpeed,
                downloadPoints = downloadSpeedPoints,
                uploadPoints = uploadSpeedPoints,
            )
        }

        item {
            RuntimeSummaryPanel(
                state = state,
            )
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                PulseMetricCard(
                    "下载",
                    state.traffic.downloadTotal,
                    "总计流量",
                    Modifier.weight(1f),
                )
                PulseMetricCard(
                    "速度",
                    state.traffic.downloadSpeed,
                    "实时下载",
                    Modifier.weight(1f),
                )
            }
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                PulseMetricCard(
                    "上传",
                    state.traffic.uploadTotal,
                    "总计流量",
                    Modifier.weight(1f),
                )
                PulseMetricCard(
                    "连接",
                    state.connections.size.toString(),
                    "当前活跃",
                    Modifier.weight(1f),
                )
            }
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                PulseMetricCard(
                    "上传速度",
                    state.traffic.uploadSpeed,
                    "实时上传",
                    Modifier.weight(1f),
                )
                PulseMetricCard(
                    "内存",
                    state.traffic.memory,
                    "核心占用",
                    Modifier.weight(1f),
                )
            }
        }

        item {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                Text("代理模式", style = MaterialTheme.typography.titleMedium)
                ProxyModeChips(selected = state.proxyMode, onModeChange = onModeChange)
            }
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                if (state.vpnRunning) {
                    OutlinedButton(
                        onClick = { onToggleVpn(false) },
                        modifier = Modifier.weight(1f),
                    ) {
                        Icon(Icons.Filled.PowerSettingsNew, contentDescription = null)
                        Text("停止 VPN", modifier = Modifier.padding(start = 8.dp))
                    }
                } else {
                    Button(
                        onClick = { onToggleVpn(true) },
                        modifier = Modifier.weight(1f),
                    ) {
                        Icon(Icons.Filled.PowerSettingsNew, contentDescription = null)
                        Text("启动 VPN", modifier = Modifier.padding(start = 8.dp))
                    }
                }
                OutlinedButton(
                    onClick = onRestartCore,
                    enabled = state.vpnRunning && !state.coreRestarting,
                    modifier = Modifier.weight(1f),
                ) {
                    if (state.coreRestarting) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                        )
                    } else {
                        Icon(Icons.Filled.RestartAlt, contentDescription = null)
                    }
                    Text("重启核心", modifier = Modifier.padding(start = 8.dp))
                }
            }
        }

        if (state.coreMessage.isNotBlank()) {
            item {
                Text(
                    state.coreMessage,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }

        item {
            Text(
                dashboardCoreStatus(state),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.secondary,
            )
        }
    }
}

@Composable
private fun RuntimeSummaryPanel(
    state: PulseAppState,
    modifier: Modifier = Modifier,
) {
    val profile = state.profiles.firstOrNull { it.id == state.selectedProfileId }
    val selectedGroups = state.proxyGroups
        .filter { it.selectedName.isNotBlank() }
        .take(3)
        .joinToString(" / ") { "${it.name}: ${it.selectedName}" }
        .ifBlank { state.selectedProxyId.ifBlank { "未选择节点" } }
    val subscription = profile?.subscription
    val subscriptionText = when {
        subscription == null -> "暂无订阅"
        subscription.hasData -> buildString {
            append(subscription.used.ifBlank { "0 B" })
            append(" / ")
            append(subscription.total.ifBlank { subscription.available.ifBlank { "未知" } })
            if (subscription.expire.isNotBlank()) append("，到期 ${subscription.expire}")
        }
        else -> "暂无订阅流量信息"
    }

    Surface(
        color = MaterialTheme.colorScheme.surfaceContainer,
        shape = MaterialTheme.shapes.medium,
        modifier = modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("当前配置", style = MaterialTheme.typography.titleMedium)
            SummaryLine("订阅", profile?.name ?: "未选择订阅")
            SummaryLine("流量", subscriptionText)
            SummaryLine("节点", selectedGroups)
            SummaryLine("模式", state.proxyMode.label)
        }
    }
}

@Composable
private fun SummaryLine(label: String, value: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.secondary,
            modifier = Modifier.weight(0.22f),
        )
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(0.78f),
        )
    }
}

@Composable
private fun NetworkSpeedPanel(
    uploadSpeed: String,
    downloadSpeed: String,
    downloadPoints: List<Long>,
    uploadPoints: List<Long>,
) {
    val downloadLineColor = MaterialTheme.colorScheme.primary
    val uploadLineColor = MaterialTheme.colorScheme.tertiary
    val gridColor = MaterialTheme.colorScheme.outlineVariant
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainer,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                Text("实时速度", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                SpeedLabel(Icons.Filled.ArrowUpward, uploadSpeed, uploadLineColor)
                SpeedLabel(Icons.Filled.ArrowDownward, downloadSpeed, downloadLineColor)
            }
            Canvas(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(96.dp),
            ) {
                val horizontalStep = size.height / 3f
                for (index in 1..2) {
                    val y = horizontalStep * index
                    drawLine(
                        color = gridColor,
                        start = Offset(0f, y),
                        end = Offset(size.width, y),
                        strokeWidth = 1.dp.toPx(),
                    )
                }
                val maxValue = (downloadPoints + uploadPoints)
                    .maxOrNull()
                    ?.coerceAtLeast(1L)
                    ?.toFloat()
                    ?: 1f
                drawSpeedPath(downloadPoints, maxValue, downloadLineColor)
                drawSpeedPath(uploadPoints, maxValue, uploadLineColor)
            }
        }
    }
}

private fun androidx.compose.ui.graphics.drawscope.DrawScope.drawSpeedPath(
    points: List<Long>,
    maxValue: Float,
    color: androidx.compose.ui.graphics.Color,
) {
    if (points.size < 2) return
    val stepX = size.width / (points.size - 1).coerceAtLeast(1)
    val path = Path()
    points.forEachIndexed { index, value ->
        val x = stepX * index
        val y = size.height - (value.toFloat() / maxValue * size.height)
        if (index == 0) {
            path.moveTo(x, y)
        } else {
            path.lineTo(x, y)
        }
    }
    drawPath(
        path = path,
        color = color,
        style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round),
    )
}

@Composable
private fun SpeedLabel(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    text: String,
    color: androidx.compose.ui.graphics.Color,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(16.dp), tint = color)
        Text(text, style = MaterialTheme.typography.labelMedium, color = color)
    }
}

private fun dashboardCoreStatus(state: PulseAppState): String {
    val version = when {
        state.coreVersion.isNotBlank() -> " / mihomo ${state.coreVersion}"
        state.vpnRunning -> " / 正在读取核心版本"
        else -> ""
    }
    return "${state.coreStatus}$version"
}
