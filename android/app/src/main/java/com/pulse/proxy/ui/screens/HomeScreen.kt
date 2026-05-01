package com.pulse.proxy.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pulse.proxy.data.VpnStatus
import com.pulse.proxy.ui.MainViewModel
import com.pulse.proxy.ui.theme.RunningGreen
import com.pulse.proxy.ui.theme.StoppedRed
import com.pulse.proxy.ui.theme.TrafficDown
import com.pulse.proxy.ui.theme.TrafficUp

@Composable
fun HomeScreen(
    viewModel: MainViewModel,
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit
) {
    val status by viewModel.vpnStatus.collectAsState()
    val configState by viewModel.configUiState.collectAsState()
    val selectedSubscription = configState.selectedSubscription
    val selectedEndpoint = configState.endpoints.firstOrNull { it.reference == configState.selectedEndpointKey }
        ?: configState.endpoints.firstOrNull { it.key == configState.selectedEndpointKey }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(24.dp))

            // Status indicator
            Text(
                text = if (status.running) "VPN Running" else "VPN Stopped",
                style = MaterialTheme.typography.headlineMedium,
                color = if (status.running) RunningGreen else StoppedRed,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = if (status.running) "Traffic is being proxied" else "Tap start to connect",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(32.dp))

            // Start/Stop button
            Button(
                onClick = {
                    if (status.running) {
                        onStopVpn()
                    } else {
                        onStartVpn()
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (status.running) StoppedRed else RunningGreen
                )
            ) {
                Icon(
                    imageVector = if (status.running) Icons.Default.Stop else Icons.Default.PlayArrow,
                    contentDescription = null,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (status.running) "Stop VPN" else "Start VPN",
                    style = MaterialTheme.typography.titleMedium
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Traffic stats
            if (status.running) {
                TrafficStatsCard(status)
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Connection info
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Connection Info",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    InfoRow("Config", selectedSubscription?.name ?: "No subscription")
                    InfoRow("Server", selectedEndpoint?.title ?: "No server selected")
                    InfoRow("Connections", status.activeConnections.toString())
                    InfoRow("Memory", "${formatBytes(status.memoryUsedBytes)} / ${formatBytes(status.memoryMaxBytes)}")
                    InfoRow("Core", if (status.proxyRunning) "Running" else "Stopped")
                    InfoRow("Proxy", "SOCKS5://127.0.0.1:1080")
                    InfoRow("VPN Address", "10.0.0.2/24")
                    InfoRow("DNS", "8.8.8.8, 1.1.1.1")
                }
            }
        }
    }
}

@Composable
private fun TrafficStatsCard(status: VpnStatus) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceEvenly
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    Icons.Default.ArrowUpward,
                    contentDescription = null,
                    tint = TrafficUp,
                    modifier = Modifier.size(24.dp)
                )
                Text(
                    text = formatBytes(status.txBytes),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text("Upload", style = MaterialTheme.typography.bodySmall)
            }
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    Icons.Default.ArrowDownward,
                    contentDescription = null,
                    tint = TrafficDown,
                    modifier = Modifier.size(24.dp)
                )
                Text(
                    text = formatBytes(status.rxBytes),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text("Download", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = label, style = MaterialTheme.typography.bodyMedium,
             color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(text = value, style = MaterialTheme.typography.bodyMedium)
    }
}

private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return "%.1f KB".format(kb)
    val mb = kb / 1024.0
    return "%.1f MB".format(mb)
}
