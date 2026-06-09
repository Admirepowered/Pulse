package com.admirepowered.pulse.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.AssistChip
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.admirepowered.pulse.ui.ProxyItem
import com.admirepowered.pulse.ui.components.PulseRow

@Composable
fun ProxiesScreen(
    proxies: List<ProxyItem>,
    loading: Boolean,
    measuring: Boolean,
    measuringProxyId: String?,
    message: String,
    onProxySelect: (String) -> Unit,
    onTestProxyDelays: () -> Unit,
    onTestProxyDelay: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier,
        contentPadding = PaddingValues(vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text("节点", style = MaterialTheme.typography.headlineSmall)
                IconButton(
                    onClick = onTestProxyDelays,
                    enabled = !loading && !measuring,
                ) {
                    if (measuring) {
                        CircularProgressIndicator(strokeWidth = 2.dp)
                    } else {
                        Icon(Icons.Filled.Speed, contentDescription = "测速")
                    }
                }
            }
        }
        if (loading) {
            item {
                CircularProgressIndicator(modifier = Modifier.padding(horizontal = 20.dp))
            }
        }
        if (message.isNotBlank()) {
            item {
                Text(
                    message,
                    modifier = Modifier.padding(horizontal = 20.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
        items(proxies, key = { it.id }) { proxy ->
            Surface(
                color = if (proxy.selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier
                    .padding(horizontal = 12.dp)
                    .clickable { onProxySelect(proxy.id) },
            ) {
                PulseRow(
                    title = proxy.name,
                    subtitle = proxy.group,
                    trailing = {
                        val measuringThisProxy = measuringProxyId == proxy.id
                        AssistChip(
                            onClick = { onTestProxyDelay(proxy.id) },
                            enabled = !measuring && !measuringThisProxy,
                            label = {
                                if (measuringThisProxy) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(18.dp),
                                        strokeWidth = 2.dp,
                                    )
                                } else {
                                    Text(proxy.delayMs?.let { "${it}ms" } ?: "未测速")
                                }
                            },
                        )
                        if (proxy.selected) {
                            Icon(Icons.Filled.CheckCircle, contentDescription = "已选中")
                        }
                    },
                )
            }
        }
    }
}
