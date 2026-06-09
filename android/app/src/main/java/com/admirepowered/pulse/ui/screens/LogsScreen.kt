package com.admirepowered.pulse.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.admirepowered.pulse.ui.LogItem
import com.admirepowered.pulse.ui.components.PulseRow

@Composable
fun LogsScreen(
    logs: List<LogItem>,
    message: String,
    onRefresh: () -> Unit,
    onClear: () -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Row(
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    "日志",
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.headlineSmall,
                )
                IconButton(onClick = onRefresh) {
                    Icon(Icons.Filled.Refresh, contentDescription = "刷新日志")
                }
                IconButton(onClick = onClear, enabled = logs.isNotEmpty()) {
                    Icon(Icons.Filled.DeleteSweep, contentDescription = "清空日志")
                }
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
        itemsIndexed(logs, key = { index, item -> "${item.time}-${item.level}-$index" }) { _, item ->
            PulseRow(
                title = item.message,
                subtitle = item.time,
                trailing = {
                    AssistChip(onClick = { }, label = { Text(item.level) })
                },
            )
        }
    }
}
