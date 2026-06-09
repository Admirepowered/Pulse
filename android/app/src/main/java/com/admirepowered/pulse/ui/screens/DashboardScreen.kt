package com.admirepowered.pulse.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.admirepowered.pulse.ui.ProxyMode
import com.admirepowered.pulse.ui.PulseAppState
import com.admirepowered.pulse.ui.components.ProxyModeChips
import com.admirepowered.pulse.ui.components.PulseMetricCard

@Composable
fun DashboardScreen(
    state: PulseAppState,
    onToggleVpn: (Boolean) -> Unit,
    onModeChange: (ProxyMode) -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Pulse Android", style = MaterialTheme.typography.headlineMedium)
                Text(
                    if (state.vpnRunning) "VPNService 已接管网络" else "准备接管 Android 网络流量",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                PulseMetricCard("下载", state.traffic.downloadTotal, "总计流量", Modifier.weight(1f))
                PulseMetricCard("速度", state.traffic.downloadSpeed, "实时下载", Modifier.weight(1f))
            }
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                PulseMetricCard("上传", state.traffic.uploadTotal, "总计流量", Modifier.weight(1f))
                PulseMetricCard("连接", state.connections.size.toString(), "当前活跃", Modifier.weight(1f))
            }
        }

        item {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                Text("代理模式", style = MaterialTheme.typography.titleMedium)
                ProxyModeChips(selected = state.proxyMode, onModeChange = onModeChange)
            }
        }

        item {
            if (state.vpnRunning) {
                OutlinedButton(onClick = { onToggleVpn(false) }, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Filled.PowerSettingsNew, contentDescription = null)
                    Text("停止 Pulse VPN", modifier = Modifier.padding(start = 8.dp))
                }
            } else {
                Button(onClick = { onToggleVpn(true) }, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Filled.PowerSettingsNew, contentDescription = null)
                    Text("启动 Pulse VPN", modifier = Modifier.padding(start = 8.dp))
                }
            }
        }

        item {
            Text(
                state.coreStatus,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.secondary,
            )
        }
    }
}
