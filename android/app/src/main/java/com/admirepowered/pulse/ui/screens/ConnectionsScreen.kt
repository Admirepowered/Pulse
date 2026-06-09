package com.admirepowered.pulse.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AssistChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.admirepowered.pulse.ui.ConnectionItem
import com.admirepowered.pulse.ui.components.PulseRow

@Composable
fun ConnectionsScreen(
    connections: List<ConnectionItem>,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Text(
                "连接",
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp),
                style = MaterialTheme.typography.headlineSmall,
            )
        }
        items(connections, key = { it.id }) { connection ->
            PulseRow(
                title = connection.host,
                subtitle = "${connection.rule}  DL ${connection.download}  UL ${connection.upload}",
                trailing = {
                    AssistChip(onClick = { }, label = { Text(connection.speed) })
                },
            )
        }
    }
}
