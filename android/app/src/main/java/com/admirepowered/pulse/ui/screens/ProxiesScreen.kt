package com.admirepowered.pulse.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Icon
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
    onProxySelect: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Text(
                "节点",
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp),
                style = MaterialTheme.typography.headlineSmall,
            )
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
                        AssistChip(
                            onClick = { },
                            label = { Text(proxy.delayMs?.let { "${it}ms" } ?: "未测速") },
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
