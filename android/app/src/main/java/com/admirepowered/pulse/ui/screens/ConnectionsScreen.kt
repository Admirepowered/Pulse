package com.admirepowered.pulse.ui.screens

import android.widget.Toast
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.admirepowered.pulse.ui.ConnectionItem
import com.admirepowered.pulse.ui.TrafficSnapshot
import com.admirepowered.pulse.ui.components.PulseMetricCard
import com.admirepowered.pulse.ui.components.PulseRow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.delay

@Composable
fun ConnectionsScreen(
    connections: List<ConnectionItem>,
    closedConnections: List<ConnectionItem>,
    traffic: TrafficSnapshot,
    loading: Boolean,
    message: String,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onClose: (String) -> Unit,
    onCloseAll: () -> Unit,
    onClearClosed: () -> Unit,
    onShare: (String) -> Unit,
    onExportFile: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var query by remember { mutableStateOf("") }
    var sort by remember { mutableStateOf(ConnectionSort.Default) }
    var sortExpanded by remember { mutableStateOf(false) }
    var expandedConnectionId by remember { mutableStateOf<String?>(null) }
    var tab by remember { mutableStateOf(ConnectionTab.Active) }
    var networkFilter by remember { mutableStateOf("全部网络") }
    var typeFilter by remember { mutableStateOf("全部类型") }
    var ruleFilter by remember { mutableStateOf("全部规则") }
    var processFilter by remember { mutableStateOf("全部进程") }
    var autoRefresh by remember { mutableStateOf(true) }
    var confirmCloseAll by remember { mutableStateOf(false) }
    var confirmClearClosed by remember { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val rows = if (tab == ConnectionTab.Active) connections else closedConnections
    val networkFilters = remember(rows) {
        listOf("全部网络") + rows.map { it.network.ifBlank { "未知网络" } }.distinct().sorted()
    }
    val typeFilters = remember(rows) {
        listOf("全部类型") + rows.map { it.connectionType.ifBlank { "未知类型" } }.distinct().sorted()
    }
    val ruleFilters = remember(rows) {
        listOf("全部规则") + rows.map { it.rule.ifBlank { "未知规则" } }.distinct().sorted()
    }
    val processFilters = remember(rows) {
        listOf("全部进程") + rows.map { it.process.ifBlank { "未知进程" } }.distinct().sorted()
    }
    val queryMatchedConnections = remember(rows, query) {
        val value = query.trim().lowercase()
        rows.filter { connection ->
            if (value.isBlank()) {
                true
            } else {
                listOf(
                    connection.host,
                    connection.destinationIp,
                    connection.source,
                    connection.network,
                    connection.connectionType,
                    connection.process,
                    connection.rule,
                    connection.rulePayload,
                    connection.chains,
                    connection.download,
                    connection.upload,
                    connection.downloadSpeed,
                    connection.uploadSpeed,
                )
                    .any { it.lowercase().contains(value) }
            }
        }
    }
    val networkFilterCounts = remember(queryMatchedConnections) {
        networkFilters.associateWith { network ->
            if (network == "全部网络") queryMatchedConnections.size else queryMatchedConnections.count {
                it.network.ifBlank { "未知网络" } == network
            }
        }
    }
    val networkMatchedConnections = remember(queryMatchedConnections, networkFilter) {
        queryMatchedConnections.filter { connection ->
            networkFilter == "全部网络" || connection.network.ifBlank { "未知网络" } == networkFilter
        }
    }
    val typeFilterCounts = remember(networkMatchedConnections) {
        typeFilters.associateWith { type ->
            if (type == "全部类型") networkMatchedConnections.size else networkMatchedConnections.count {
                it.connectionType.ifBlank { "未知类型" } == type
            }
        }
    }
    val typeMatchedConnections = remember(networkMatchedConnections, typeFilter) {
        networkMatchedConnections.filter { connection ->
            typeFilter == "全部类型" || connection.connectionType.ifBlank { "未知类型" } == typeFilter
        }
    }
    val ruleFilterCounts = remember(typeMatchedConnections) {
        ruleFilters.associateWith { rule ->
            if (rule == "全部规则") typeMatchedConnections.size else typeMatchedConnections.count {
                it.rule.ifBlank { "未知规则" } == rule
            }
        }
    }
    val ruleMatchedConnections = remember(typeMatchedConnections, ruleFilter) {
        typeMatchedConnections.filter { connection ->
            ruleFilter == "全部规则" || connection.rule.ifBlank { "未知规则" } == ruleFilter
        }
    }
    val processFilterCounts = remember(ruleMatchedConnections) {
        processFilters.associateWith { process ->
            if (process == "全部进程") ruleMatchedConnections.size else ruleMatchedConnections.count {
                it.process.ifBlank { "未知进程" } == process
            }
        }
    }
    val filteredConnections = remember(ruleMatchedConnections, processFilter) {
        ruleMatchedConnections.filter { connection ->
            processFilter == "全部进程" || connection.process.ifBlank { "未知进程" } == processFilter
        }
    }
    val hasActiveFilters = query.isNotBlank() ||
        networkFilter != "全部网络" ||
        typeFilter != "全部类型" ||
        ruleFilter != "全部规则" ||
        processFilter != "全部进程" ||
        sort != ConnectionSort.Default
    val sortedConnections = remember(filteredConnections, sort) {
        when (sort) {
            ConnectionSort.Default -> filteredConnections
            ConnectionSort.DownloadAsc -> filteredConnections.sortedBy { it.downloadBytes }
            ConnectionSort.DownloadDesc -> filteredConnections.sortedByDescending { it.downloadBytes }
            ConnectionSort.UploadAsc -> filteredConnections.sortedBy { it.uploadBytes }
            ConnectionSort.UploadDesc -> filteredConnections.sortedByDescending { it.uploadBytes }
            ConnectionSort.DownloadSpeedAsc -> filteredConnections.sortedBy { it.downloadSpeedBytes }
            ConnectionSort.DownloadSpeedDesc -> filteredConnections.sortedByDescending { it.downloadSpeedBytes }
            ConnectionSort.UploadSpeedAsc -> filteredConnections.sortedBy { it.uploadSpeedBytes }
            ConnectionSort.UploadSpeedDesc -> filteredConnections.sortedByDescending { it.uploadSpeedBytes }
        }
    }
    val visibleNetworkCount = remember(sortedConnections) {
        sortedConnections.map { it.network.ifBlank { "未知网络" } }.distinct().size
    }
    val visibleTypeCount = remember(sortedConnections) {
        sortedConnections.map { it.connectionType.ifBlank { "未知类型" } }.distinct().size
    }
    val visibleRuleCount = remember(sortedConnections) {
        sortedConnections.map { it.rule.ifBlank { "未知规则" } }.distinct().size
    }
    val visibleProcessCount = remember(sortedConnections) {
        sortedConnections.map { it.process.ifBlank { "未知进程" } }.distinct().size
    }
    LaunchedEffect(autoRefresh) {
        while (autoRefresh) {
            delay(2_000)
            onRefresh()
        }
    }
    LaunchedEffect(networkFilters, typeFilters, ruleFilters, processFilters) {
        if (networkFilter !in networkFilters) networkFilter = "全部网络"
        if (typeFilter !in typeFilters) typeFilter = "全部类型"
        if (ruleFilter !in ruleFilters) ruleFilter = "全部规则"
        if (processFilter !in processFilters) processFilter = "全部进程"
    }

    if (confirmCloseAll) {
        AlertDialog(
            onDismissRequest = { confirmCloseAll = false },
            title = { Text("全部断开") },
            text = { Text("确定断开当前 ${connections.size} 个活动连接吗？") },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmCloseAll = false
                        onCloseAll()
                    },
                ) {
                    Text("断开")
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmCloseAll = false }) {
                    Text("取消")
                }
            },
        )
    }
    if (confirmClearClosed) {
        AlertDialog(
            onDismissRequest = { confirmClearClosed = false },
            title = { Text("清空已断开") },
            text = { Text("确定清空 ${closedConnections.size} 条已断开连接历史吗？") },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmClearClosed = false
                        onClearClosed()
                        expandedConnectionId = null
                    },
                ) {
                    Text("清空")
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmClearClosed = false }) {
                    Text("取消")
                }
            },
        )
    }

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
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回设置")
                }
                Text(
                    "连接",
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.headlineSmall,
                )
                IconButton(onClick = onRefresh, enabled = !loading) {
                    Icon(Icons.Filled.Refresh, contentDescription = "刷新连接")
                }
                IconButton(
                    onClick = {
                        clipboard.setText(AnnotatedString(sortedConnections.toClipboardText(tab)))
                        Toast.makeText(context, "当前连接已复制", Toast.LENGTH_SHORT).show()
                    },
                    enabled = sortedConnections.isNotEmpty(),
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "复制当前连接")
                }
                IconButton(
                    onClick = { onShare(sortedConnections.toClipboardText(tab)) },
                    enabled = sortedConnections.isNotEmpty(),
                ) {
                    Icon(Icons.Filled.Share, contentDescription = "分享当前连接")
                }
                IconButton(
                    onClick = { onExportFile(sortedConnections.toClipboardText(tab)) },
                    enabled = sortedConnections.isNotEmpty(),
                ) {
                    Icon(Icons.Filled.Download, contentDescription = "导出当前连接")
                }
                IconButton(
                    onClick = {
                        if (tab == ConnectionTab.Active) {
                            confirmCloseAll = true
                        } else {
                            confirmClearClosed = true
                        }
                    },
                    enabled = if (tab == ConnectionTab.Active) connections.isNotEmpty() else closedConnections.isNotEmpty(),
                ) {
                    Icon(
                        Icons.Filled.DeleteSweep,
                        contentDescription = if (tab == ConnectionTab.Active) "全部断开" else "清空已断开历史",
                    )
                }
            }
        }
        item {
            Column(
                modifier = Modifier.padding(horizontal = 20.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    PulseMetricCard(
                        title = "活动连接",
                        value = connections.size.toString(),
                        helper = "已断开 ${closedConnections.size}",
                        modifier = Modifier.weight(1f),
                    )
                    PulseMetricCard(
                        title = "内存",
                        value = traffic.memory,
                        helper = "核心占用",
                        modifier = Modifier.weight(1f),
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    PulseMetricCard(
                        title = "下载",
                        value = traffic.downloadSpeed,
                        helper = "累计 ${traffic.downloadTotal}",
                        modifier = Modifier.weight(1f),
                    )
                    PulseMetricCard(
                        title = "上传",
                        value = traffic.uploadSpeed,
                        helper = "累计 ${traffic.uploadTotal}",
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
        item {
            Row(
                modifier = Modifier
                    .padding(horizontal = 20.dp)
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                FilterChip(
                    selected = autoRefresh,
                    onClick = { autoRefresh = !autoRefresh },
                    label = { Text("自动刷新 2s") },
                )
                AssistChip(onClick = { }, label = { Text("${sortedConnections.size}/${rows.size}") })
                AssistChip(onClick = { }, label = { Text("网络 $visibleNetworkCount") })
                AssistChip(onClick = { }, label = { Text("类型 $visibleTypeCount") })
                AssistChip(onClick = { }, label = { Text("规则 $visibleRuleCount") })
                AssistChip(onClick = { }, label = { Text("进程 $visibleProcessCount") })
                FilterChip(
                    selected = false,
                    onClick = {
                        query = ""
                        networkFilter = "全部网络"
                        typeFilter = "全部类型"
                        ruleFilter = "全部规则"
                        processFilter = "全部进程"
                        sort = ConnectionSort.Default
                        expandedConnectionId = null
                    },
                    enabled = hasActiveFilters,
                    label = { Text("重置筛选") },
                )
                ConnectionTab.entries.forEach { item ->
                    val count = if (item == ConnectionTab.Active) connections.size else closedConnections.size
                    FilterChip(
                        selected = tab == item,
                        onClick = {
                            tab = item
                            expandedConnectionId = null
                            networkFilter = "全部网络"
                            typeFilter = "全部类型"
                            ruleFilter = "全部规则"
                            processFilter = "全部进程"
                        },
                        label = { Text("${item.label} $count") },
                    )
                }
            }
        }
        item {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp),
                singleLine = true,
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                trailingIcon = {
                    if (query.isNotBlank()) {
                        IconButton(onClick = { query = "" }) {
                            Icon(Icons.Filled.Close, contentDescription = "清空搜索")
                        }
                    }
                },
                placeholder = { Text("搜索域名、IP、规则") },
            )
        }
        item {
            Row(
                modifier = Modifier
                    .padding(horizontal = 20.dp)
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                networkFilters.forEach { item ->
                    FilterChip(
                        selected = networkFilter == item,
                        onClick = { networkFilter = item },
                        label = { Text("$item ${networkFilterCounts[item] ?: 0}") },
                    )
                }
            }
        }
        item {
            Row(
                modifier = Modifier
                    .padding(horizontal = 20.dp)
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                typeFilters.forEach { item ->
                    FilterChip(
                        selected = typeFilter == item,
                        onClick = { typeFilter = item },
                        label = { Text("$item ${typeFilterCounts[item] ?: 0}") },
                    )
                }
            }
        }
        item {
            Row(
                modifier = Modifier
                    .padding(horizontal = 20.dp)
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                ruleFilters.forEach { item ->
                    FilterChip(
                        selected = ruleFilter == item,
                        onClick = { ruleFilter = item },
                        label = { Text("$item ${ruleFilterCounts[item] ?: 0}") },
                    )
                }
            }
        }
        item {
            Row(
                modifier = Modifier
                    .padding(horizontal = 20.dp)
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                processFilters.forEach { item ->
                    FilterChip(
                        selected = processFilter == item,
                        onClick = { processFilter = item },
                        label = { Text("$item ${processFilterCounts[item] ?: 0}") },
                    )
                }
            }
        }
        item {
            Row(
                modifier = Modifier.padding(horizontal = 20.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text("排序", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.secondary)
                Box {
                    TextButton(onClick = { sortExpanded = true }) {
                        Text(sort.label)
                        Icon(Icons.Filled.ArrowDropDown, contentDescription = null)
                    }
                    DropdownMenu(
                        expanded = sortExpanded,
                        onDismissRequest = { sortExpanded = false },
                    ) {
                        ConnectionSort.entries.forEach { item ->
                            DropdownMenuItem(
                                text = { Text(item.label) },
                                onClick = {
                                    sort = item
                                    sortExpanded = false
                                },
                            )
                        }
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
        if (!loading && sortedConnections.isEmpty()) {
            item {
                Text(
                    if (
                        query.isBlank() &&
                        networkFilter == "全部网络" &&
                        typeFilter == "全部类型" &&
                        ruleFilter == "全部规则" &&
                        processFilter == "全部进程"
                    ) {
                        if (tab == ConnectionTab.Active) "暂无活动连接" else "暂无已断开连接"
                    } else {
                        "没有匹配的连接"
                    },
                    modifier = Modifier.padding(horizontal = 20.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
        items(sortedConnections, key = { "${it.id}-${it.closedAt}" }) { connection ->
            val expanded = expandedConnectionId == connection.id
            var rowMenuExpanded by remember(connection.id, connection.closedAt) { mutableStateOf(false) }
            Column {
                PulseRow(
                    title = connection.host,
                    subtitle = connection.summaryLine(tab),
                    modifier = Modifier.connectionRowActions(
                        onClick = {
                            expandedConnectionId = if (expanded) null else connection.id
                        },
                        onLongClick = { rowMenuExpanded = true },
                    ),
                    trailing = {
                        Box {
                            Column(
                                horizontalAlignment = Alignment.End,
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                AssistChip(onClick = { }, label = { Text("DL ${connection.downloadSpeed}") })
                                AssistChip(onClick = { }, label = { Text("UL ${connection.uploadSpeed}") })
                                IconButton(
                                    onClick = {
                                        expandedConnectionId = if (expanded) null else connection.id
                                    },
                                ) {
                                    Icon(
                                        if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                                        contentDescription = if (expanded) "收起详情" else "展开详情",
                                    )
                                }
                            }
                            DropdownMenu(
                                expanded = rowMenuExpanded,
                                onDismissRequest = { rowMenuExpanded = false },
                            ) {
                                DropdownMenuItem(
                                    text = { Text("复制连接") },
                                    leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                                    onClick = {
                                        rowMenuExpanded = false
                                        clipboard.setText(AnnotatedString(connection.toClipboardText()))
                                        Toast.makeText(context, "连接信息已复制", Toast.LENGTH_SHORT).show()
                                    },
                                )
                                DropdownMenuItem(
                                    text = { Text(if (expanded) "收起详情" else "展开详情") },
                                    leadingIcon = {
                                        Icon(
                                            if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                                            contentDescription = null,
                                        )
                                    },
                                    onClick = {
                                        rowMenuExpanded = false
                                        expandedConnectionId = if (expanded) null else connection.id
                                    },
                                )
                                if (tab == ConnectionTab.Active) {
                                    DropdownMenuItem(
                                        text = { Text("断开连接") },
                                        leadingIcon = { Icon(Icons.Filled.Close, contentDescription = null) },
                                        onClick = {
                                            rowMenuExpanded = false
                                            onClose(connection.id)
                                        },
                                    )
                                }
                                DropdownMenuItem(
                                    text = { Text("筛选同网络") },
                                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                                    onClick = {
                                        rowMenuExpanded = false
                                        networkFilter = connection.network.ifBlank { "未知网络" }
                                    },
                                )
                                DropdownMenuItem(
                                    text = { Text("筛选同类型") },
                                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                                    onClick = {
                                        rowMenuExpanded = false
                                        typeFilter = connection.connectionType.ifBlank { "未知类型" }
                                    },
                                )
                                DropdownMenuItem(
                                    text = { Text("筛选同规则") },
                                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                                    onClick = {
                                        rowMenuExpanded = false
                                        ruleFilter = connection.rule.ifBlank { "未知规则" }
                                    },
                                )
                                DropdownMenuItem(
                                    text = { Text("筛选同进程") },
                                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                                    onClick = {
                                        rowMenuExpanded = false
                                        processFilter = connection.process.ifBlank { "未知进程" }
                                    },
                                )
                            }
                        }
                    },
                )
                if (expanded) {
                    Column(
                        modifier = Modifier.padding(horizontal = 36.dp, vertical = 4.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        connection.detailLines().forEach { line ->
                            Text(
                                line,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.secondary,
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun ConnectionItem.summaryLine(tab: ConnectionTab): String {
    val route = listOf(
        network.ifBlank { "-" },
        rule.ifBlank { "-" },
        chains.ifBlank { "-" },
    ).joinToString(" · ")
    val status = if (tab == ConnectionTab.Closed) "已断开  " else ""
    return "$status$route  DL $download  UL $upload"
}

private fun ConnectionItem.detailLines(): List<String> {
    return listOfNotNull(
        "ID: $id".takeIf { id.isNotBlank() },
        "目标: ${destinationIp.ifBlank { host }}".takeIf { host.isNotBlank() || destinationIp.isNotBlank() },
        "来源: $source".takeIf { source.isNotBlank() },
        "进程: $process".takeIf { process.isNotBlank() },
        "网络: $network".takeIf { network.isNotBlank() },
        "类型: $connectionType".takeIf { connectionType.isNotBlank() },
        "规则: ${rule.ifBlank { "-" }}".takeIf { rule.isNotBlank() },
        "规则内容: $rulePayload".takeIf { rulePayload.isNotBlank() },
        "链路: $chains".takeIf { chains.isNotBlank() },
        "开始时间: $start".takeIf { start.isNotBlank() },
        "断开时间: ${closedAt.toClosedTimeLabel()}".takeIf { closedAt > 0 },
        "下载: $download / ${downloadSpeed}",
        "上传: $upload / ${uploadSpeed}",
    )
}

@OptIn(ExperimentalFoundationApi::class)
private fun Modifier.connectionRowActions(
    onClick: () -> Unit,
    onLongClick: () -> Unit,
): Modifier {
    return combinedClickable(
        onClick = onClick,
        onLongClick = onLongClick,
    )
}

private fun ConnectionItem.toClipboardText(): String {
    return detailLines().joinToString("\n")
}

private fun List<ConnectionItem>.toClipboardText(tab: ConnectionTab): String {
    val title = if (tab == ConnectionTab.Active) "活动连接" else "已断开连接"
    return joinToString("\n\n") { connection ->
        "$title\n${connection.toClipboardText()}"
    }
}

private fun Long.toClosedTimeLabel(): String {
    if (this <= 0) return ""
    return closedTimeFormat.format(Date(this * 1000))
}

private val closedTimeFormat = SimpleDateFormat("MM-dd HH:mm:ss", Locale.getDefault())

private enum class ConnectionTab(val label: String) {
    Active("活动"),
    Closed("已断开"),
}

private enum class ConnectionSort(val label: String) {
    Default("默认"),
    DownloadAsc("下载总量升序"),
    DownloadDesc("下载总量降序"),
    UploadAsc("上传总量升序"),
    UploadDesc("上传总量降序"),
    DownloadSpeedAsc("下载速度升序"),
    DownloadSpeedDesc("下载速度降序"),
    UploadSpeedAsc("上传速度升序"),
    UploadSpeedDesc("上传速度降序"),
}
