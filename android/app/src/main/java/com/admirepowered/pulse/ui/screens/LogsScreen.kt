package com.admirepowered.pulse.ui.screens

import android.widget.Toast
import androidx.compose.foundation.ExperimentalFoundationApi
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
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.admirepowered.pulse.ui.LogItem
import com.admirepowered.pulse.ui.components.PulseRow
import java.text.Collator
import java.util.Locale
import kotlinx.coroutines.delay

@Composable
fun LogsScreen(
    logs: List<LogItem>,
    message: String,
    onRefresh: () -> Unit,
    onClear: () -> Unit,
    onShare: (String) -> Unit,
    onExportFile: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var query by remember { mutableStateOf("") }
    var selectedLevel by remember { mutableStateOf("全部") }
    var selectedSource by remember { mutableStateOf("全部来源") }
    var sortMode by remember { mutableStateOf(LogSortMode.Default) }
    var autoRefresh by remember { mutableStateOf(false) }
    var confirmClear by remember { mutableStateOf(false) }
    val levels = remember(logs) {
        listOf("全部") + logs.map { it.level }.filter { it.isNotBlank() }.distinct().sorted()
    }
    val sources = remember(logs) {
        listOf("全部来源") + logs.map { it.source.ifBlank { "未知来源" } }.distinct().sorted()
    }
    val queryMatchedLogs = remember(logs, query) {
        val keyword = query.trim().lowercase()
        logs.filter { item ->
            keyword.isBlank() ||
                listOf(item.time, item.level, item.source, item.message).any { it.lowercase().contains(keyword) }
        }
    }
    val levelFilterCounts = remember(queryMatchedLogs) {
        levels.associateWith { level ->
            if (level == "全部") queryMatchedLogs.size else queryMatchedLogs.count { it.level == level }
        }
    }
    val levelMatchedLogs = remember(queryMatchedLogs, selectedLevel) {
        queryMatchedLogs.filter { item ->
            selectedLevel == "全部" || item.level == selectedLevel
        }
    }
    val sourceFilterCounts = remember(levelMatchedLogs) {
        sources.associateWith { source ->
            if (source == "全部来源") levelMatchedLogs.size else levelMatchedLogs.count { it.source.ifBlank { "未知来源" } == source }
        }
    }
    val filteredLogs = remember(levelMatchedLogs, selectedSource, sortMode) {
        levelMatchedLogs.filter { item ->
            selectedSource == "全部来源" || item.source.ifBlank { "未知来源" } == selectedSource
        }.sortedWith(sortMode.comparator())
    }
    val errorCount = remember(filteredLogs) {
        filteredLogs.count { it.level.isLogError() }
    }
    val warningCount = remember(filteredLogs) {
        filteredLogs.count { it.level.isLogWarning() }
    }
    val sourceCount = remember(filteredLogs) {
        filteredLogs.map { it.source.ifBlank { "未知来源" } }.distinct().size
    }
    val hasActiveFilters = query.isNotBlank() ||
        selectedLevel != "全部" ||
        selectedSource != "全部来源" ||
        sortMode != LogSortMode.Default
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    LaunchedEffect(autoRefresh) {
        while (autoRefresh) {
            delay(2_000)
            onRefresh()
        }
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text("清空日志") },
            text = { Text("确定清空当前日志吗？这会移除 Pulse 本地日志记录。") },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmClear = false
                        onClear()
                    },
                ) {
                    Text("清空")
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmClear = false }) {
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
                    "日志",
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.headlineSmall,
                )
                IconButton(onClick = onRefresh) {
                    Icon(Icons.Filled.Refresh, contentDescription = "刷新日志")
                }
                IconButton(
                    onClick = {
                        clipboard.setText(AnnotatedString(filteredLogs.toClipboardText()))
                        Toast.makeText(context, "当前日志已复制", Toast.LENGTH_SHORT).show()
                    },
                    enabled = filteredLogs.isNotEmpty(),
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "复制当前日志")
                }
                IconButton(
                    onClick = { onShare(filteredLogs.toClipboardText()) },
                    enabled = filteredLogs.isNotEmpty(),
                ) {
                    Icon(Icons.Filled.Share, contentDescription = "分享当前日志")
                }
                IconButton(
                    onClick = { onExportFile(filteredLogs.toClipboardText()) },
                    enabled = filteredLogs.isNotEmpty(),
                ) {
                    Icon(Icons.Filled.Download, contentDescription = "导出当前日志")
                }
                IconButton(onClick = { confirmClear = true }, enabled = logs.isNotEmpty()) {
                    Icon(Icons.Filled.DeleteSweep, contentDescription = "清空日志")
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
                placeholder = { Text("搜索时间、级别、内容") },
            )
        }
        item {
            Row(
                modifier = Modifier.padding(horizontal = 20.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                FilterChip(
                    selected = autoRefresh,
                    onClick = { autoRefresh = !autoRefresh },
                    label = { Text("自动刷新 2s") },
                )
                AssistChip(
                    onClick = { },
                    label = { Text("${filteredLogs.size}/${logs.size}") },
                )
                AssistChip(
                    onClick = { },
                    label = { Text("错误 $errorCount") },
                )
                AssistChip(
                    onClick = { },
                    label = { Text("警告 $warningCount") },
                )
                AssistChip(
                    onClick = { },
                    label = { Text("来源 $sourceCount") },
                )
                FilterChip(
                    selected = false,
                    onClick = {
                        query = ""
                        selectedLevel = "全部"
                        selectedSource = "全部来源"
                        sortMode = LogSortMode.Default
                    },
                    enabled = hasActiveFilters,
                    label = { Text("重置筛选") },
                )
            }
        }
        item {
            Row(
                modifier = Modifier
                    .padding(horizontal = 20.dp)
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                levels.forEach { level ->
                    FilterChip(
                        selected = selectedLevel == level,
                        onClick = { selectedLevel = level },
                        label = { Text("$level ${levelFilterCounts[level] ?: 0}") },
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
                sources.forEach { source ->
                    FilterChip(
                        selected = selectedSource == source,
                        onClick = { selectedSource = source },
                        label = { Text("$source ${sourceFilterCounts[source] ?: 0}") },
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
                LogSortMode.entries.forEach { item ->
                    FilterChip(
                        selected = sortMode == item,
                        onClick = { sortMode = item },
                        label = { Text(item.label) },
                    )
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
        if (filteredLogs.isEmpty()) {
            item {
                Text(
                    if (logs.isEmpty()) "暂无日志" else "没有匹配的日志",
                    modifier = Modifier.padding(horizontal = 20.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
        itemsIndexed(filteredLogs, key = { index, item -> "${item.time}-${item.level}-$index" }) { _, item ->
            var itemMenuExpanded by remember(item.time, item.level, item.message) { mutableStateOf(false) }
            PulseRow(
                title = item.message,
                subtitle = item.time,
                modifier = Modifier.logRowActions(onLongClick = { itemMenuExpanded = true }),
                trailing = {
                    Box {
                        Column(
                            horizontalAlignment = Alignment.End,
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            AssistChip(onClick = { }, label = { Text(item.source.ifBlank { "未知来源" }) })
                            AssistChip(onClick = { }, label = { Text(item.level) })
                        }
                        DropdownMenu(
                            expanded = itemMenuExpanded,
                            onDismissRequest = { itemMenuExpanded = false },
                        ) {
                            DropdownMenuItem(
                                text = { Text("复制日志") },
                                leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                                onClick = {
                                    itemMenuExpanded = false
                                    clipboard.setText(AnnotatedString(item.toLogLine()))
                                    Toast.makeText(context, "日志已复制", Toast.LENGTH_SHORT).show()
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("复制消息") },
                                leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                                onClick = {
                                    itemMenuExpanded = false
                                    clipboard.setText(AnnotatedString(item.message))
                                    Toast.makeText(context, "日志消息已复制", Toast.LENGTH_SHORT).show()
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("复制来源和级别") },
                                leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                                onClick = {
                                    itemMenuExpanded = false
                                    val source = item.source.ifBlank { "未知来源" }
                                    clipboard.setText(AnnotatedString("$source\t${item.level}"))
                                    Toast.makeText(context, "日志来源已复制", Toast.LENGTH_SHORT).show()
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("筛选同级别") },
                                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                                onClick = {
                                    itemMenuExpanded = false
                                    selectedLevel = item.level
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("筛选同来源") },
                                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                                onClick = {
                                    itemMenuExpanded = false
                                    selectedSource = item.source.ifBlank { "未知来源" }
                                },
                            )
                        }
                    }
                },
            )
        }
    }
}

private fun List<LogItem>.toClipboardText(): String {
    return joinToString("\n") { item -> item.toLogLine() }
}

private fun LogItem.toLogLine(): String {
    return "$time\t${source.ifBlank { "未知来源" }}\t$level\t$message"
}

private fun String.isLogError(): Boolean {
    val value = lowercase()
    return value == "error" || value == "fatal" || value == "错误"
}

private fun String.isLogWarning(): Boolean {
    val value = lowercase()
    return value == "warning" || value == "warn" || value == "警告"
}

@OptIn(ExperimentalFoundationApi::class)
private fun Modifier.logRowActions(onLongClick: () -> Unit): Modifier {
    return combinedClickable(
        onClick = {},
        onLongClick = onLongClick,
    )
}

private enum class LogSortMode(val label: String) {
    Default("默认排序"),
    TimeDesc("时间降序"),
    TimeAsc("时间升序"),
    LevelAsc("级别升序"),
    LevelDesc("级别降序"),
    SourceAsc("来源升序"),
    SourceDesc("来源降序"),
    MessageAsc("消息升序"),
    MessageDesc("消息降序"),
}

private fun LogSortMode.comparator(): Comparator<LogItem> {
    val collator = Collator.getInstance(Locale.getDefault())
    fun compareText(left: String, right: String): Int = collator.compare(left, right)
    return when (this) {
        LogSortMode.Default -> Comparator { _, _ -> 0 }
        LogSortMode.TimeDesc -> compareByDescending { it.time }
        LogSortMode.TimeAsc -> compareBy { it.time }
        LogSortMode.LevelAsc -> Comparator { left, right ->
            compareText(left.level, right.level)
        }
        LogSortMode.LevelDesc -> Comparator { left, right ->
            compareText(right.level, left.level)
        }
        LogSortMode.SourceAsc -> Comparator { left, right ->
            compareText(left.source.ifBlank { "未知来源" }, right.source.ifBlank { "未知来源" })
        }
        LogSortMode.SourceDesc -> Comparator { left, right ->
            compareText(right.source.ifBlank { "未知来源" }, left.source.ifBlank { "未知来源" })
        }
        LogSortMode.MessageAsc -> Comparator { left, right ->
            compareText(left.message, right.message)
        }
        LogSortMode.MessageDesc -> Comparator { left, right ->
            compareText(right.message, left.message)
        }
    }
}
