package com.admirepowered.pulse.ui.screens

import android.widget.Toast
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.AssistChip
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.Alignment
import com.admirepowered.pulse.ui.ProxyGroupItem
import com.admirepowered.pulse.ui.ProxyItem
import java.text.Collator
import java.util.Locale

@Composable
fun ProxiesScreen(
    groups: List<ProxyGroupItem>,
    loading: Boolean,
    measuring: Boolean,
    measuringProxyId: String?,
    measuringGroupName: String?,
    message: String,
    onProxySelect: (String) -> Unit,
    onTestProxyDelays: () -> Unit,
    onTestProxyGroupDelays: (String) -> Unit,
    onTestProxyDelay: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var query by rememberSaveable { mutableStateOf("") }
    var groupTypeFilter by rememberSaveable { mutableStateOf(PROXY_GROUP_TYPE_ALL) }
    var filter by rememberSaveable { mutableStateOf(ProxyFilter.All) }
    var sortMode by rememberSaveable { mutableStateOf(ProxySortMode.Default) }
    var expandedGroups by remember { mutableStateOf<Set<String>>(emptySet()) }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val queryMatchedGroups = remember(groups, query) {
        val keyword = query.trim().lowercase()
        groups.mapNotNull { group ->
            val groupMatches = keyword.isBlank() ||
                listOf(group.name, group.type, group.selectedName)
                    .any { it.lowercase().contains(keyword) }
            val queryMatchedProxies = if (groupMatches) {
                group.proxies
            } else {
                group.proxies.filter { proxy ->
                    listOf(proxy.name, proxy.group)
                        .any { it.lowercase().contains(keyword) }
                }
            }
            if (queryMatchedProxies.isEmpty()) null else group.copy(proxies = queryMatchedProxies)
        }
    }
    val groupTypes = remember(queryMatchedGroups) {
        listOf(PROXY_GROUP_TYPE_ALL) + queryMatchedGroups
            .map { it.normalizedType() }
            .distinct()
            .sorted()
    }
    val groupTypeCounts = remember(queryMatchedGroups, groupTypes) {
        groupTypes.associateWith { type ->
            if (type == PROXY_GROUP_TYPE_ALL) {
                queryMatchedGroups.size
            } else {
                queryMatchedGroups.count { it.normalizedType() == type }
            }
        }
    }
    val typeMatchedGroups = remember(queryMatchedGroups, groupTypeFilter) {
        queryMatchedGroups.filter { group ->
            groupTypeFilter == PROXY_GROUP_TYPE_ALL || group.normalizedType() == groupTypeFilter
        }
    }
    val proxyFilterCounts = remember(typeMatchedGroups) {
        ProxyFilter.entries.associateWith { proxyFilter ->
            typeMatchedGroups.sumOf { group -> group.proxies.count(proxyFilter::matches) }
        }
    }
    val filteredGroups = remember(typeMatchedGroups, filter, sortMode) {
        typeMatchedGroups.mapNotNull { group ->
            val proxies = group.proxies
                .filter(filter::matches)
                .sortedWith(sortMode.comparator())
            if (proxies.isEmpty()) null else group.copy(proxies = proxies)
        }
    }
    val visibleProxies = remember(filteredGroups) {
        filteredGroups.flatMap { it.proxies }
    }
    val selectedProxyCount = remember(visibleProxies) {
        visibleProxies.count { it.selected }
    }
    val measuredProxyCount = remember(visibleProxies) {
        visibleProxies.count { it.delayMs != null && !it.isTimeout() }
    }
    val untestedProxyCount = remember(visibleProxies) {
        visibleProxies.count { it.delayMs == null }
    }
    val timeoutProxyCount = remember(visibleProxies) {
        visibleProxies.count { it.isTimeout() }
    }
    val hasActiveFilters = query.isNotBlank() ||
        groupTypeFilter != PROXY_GROUP_TYPE_ALL ||
        filter != ProxyFilter.All ||
        sortMode != ProxySortMode.Default ||
        expandedGroups.isNotEmpty()

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "节点",
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.headlineSmall,
                )
                IconButton(
                    onClick = onTestProxyDelays,
                    enabled = !loading && !measuring && measuringProxyId == null && measuringGroupName == null,
                ) {
                    if (measuring) {
                        CircularProgressIndicator(strokeWidth = 2.dp)
                    } else {
                        Icon(Icons.Filled.Speed, contentDescription = "测速")
                    }
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
                placeholder = { Text("搜索节点、分组、当前选择") },
            )
        }
        item {
            Row(
                modifier = Modifier
                    .padding(horizontal = 20.dp)
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                AssistChip(
                    onClick = { expandedGroups = filteredGroups.map { it.name }.toSet() },
                    enabled = filteredGroups.isNotEmpty(),
                    label = { Text("全部展开") },
                    leadingIcon = {
                        Icon(
                            Icons.Filled.ExpandMore,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                        )
                    },
                )
                AssistChip(
                    onClick = { expandedGroups = emptySet() },
                    enabled = expandedGroups.isNotEmpty() || query.isNotBlank(),
                    label = { Text("全部收起") },
                    leadingIcon = {
                        Icon(
                            Icons.Filled.ExpandLess,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                        )
                    },
                )
                AssistChip(onClick = { }, label = { Text("${filteredGroups.size}/${groups.size} 组") })
                AssistChip(onClick = { }, label = { Text("节点 ${visibleProxies.size}") })
                AssistChip(onClick = { }, label = { Text("当前 $selectedProxyCount") })
                AssistChip(onClick = { }, label = { Text("已测 $measuredProxyCount") })
                AssistChip(onClick = { }, label = { Text("未测 $untestedProxyCount") })
                AssistChip(onClick = { }, label = { Text("超时 $timeoutProxyCount") })
                FilterChip(
                    selected = false,
                    onClick = {
                        query = ""
                        groupTypeFilter = PROXY_GROUP_TYPE_ALL
                        filter = ProxyFilter.All
                        sortMode = ProxySortMode.Default
                        expandedGroups = emptySet()
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
                groupTypes.forEach { type ->
                    FilterChip(
                        selected = groupTypeFilter == type,
                        onClick = { groupTypeFilter = type },
                        label = { Text("$type ${groupTypeCounts[type] ?: 0}") },
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
                ProxyFilter.entries.forEach { item ->
                    FilterChip(
                        selected = filter == item,
                        onClick = { filter = item },
                        label = { Text("${item.label} ${proxyFilterCounts[item] ?: 0}") },
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
                ProxySortMode.entries.forEach { item ->
                    FilterChip(
                        selected = sortMode == item,
                        onClick = { sortMode = item },
                        label = { Text(item.label) },
                    )
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
        if (!loading && filteredGroups.isEmpty()) {
            item {
                Text(
                    if (query.isBlank() && filter == ProxyFilter.All) "暂无节点分组" else "没有匹配的节点",
                    modifier = Modifier.padding(horizontal = 20.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
        items(filteredGroups, key = { it.name }) { group ->
            ProxyGroupDrawer(
                group = group,
                expanded = query.isNotBlank() || group.name in expandedGroups,
                measuring = measuring,
                measuringProxyId = measuringProxyId,
                measuringGroupName = measuringGroupName,
                onToggleExpanded = {
                    expandedGroups = if (group.name in expandedGroups) {
                        expandedGroups - group.name
                    } else {
                        expandedGroups + group.name
                    }
                },
                onProxySelect = onProxySelect,
                onTestGroup = { onTestProxyGroupDelays(group.name) },
                onTestProxyDelay = onTestProxyDelay,
                onFilterSelected = { filter = ProxyFilter.Selected },
                onFilterGroup = { groupName ->
                    query = groupName
                    expandedGroups = expandedGroups + groupName
                },
            )
        }
    }
}

private fun List<ProxyGroupItem>.toClipboardText(): String {
    return joinToString("\n\n") { group -> group.toClipboardText() }
}

private fun ProxyGroupItem.toClipboardText(): String {
    val header = listOf(
        name,
        type.ifBlank { "Selector" },
        "当前 ${selectedName.ifBlank { "未选择" }}",
        "${proxies.size} 节点",
    ).joinToString(" / ")
    val nodes = proxies.joinToString("\n") { proxy ->
        "  - ${proxy.toClipboardText()}"
    }
    return if (nodes.isBlank()) header else "$header\n$nodes"
}

private fun ProxyItem.toClipboardText(): String {
    val selected = if (selected) "已选中" else "未选中"
    val delay = delayMs?.let { "${it}ms" } ?: "未测速"
    return "$name / $selected / $delay"
}

private const val PROXY_GROUP_TYPE_ALL = "全部类型"

private fun ProxyGroupItem.normalizedType(): String {
    return type.ifBlank { "Selector" }
}

private enum class ProxyFilter(val label: String) {
    All("全部"),
    Selected("当前"),
    Measured("已测速"),
    Untested("未测速"),
    Timeout("超时"),
}

private enum class ProxySortMode(val label: String) {
    Default("默认排序"),
    DelayAsc("延迟低"),
    DelayDesc("延迟高"),
    NameAsc("名称升序"),
    NameDesc("名称降序"),
}

private fun ProxySortMode.comparator(): Comparator<ProxyItem> {
    val collator = Collator.getInstance(Locale.getDefault())
    val nameComparator = Comparator<ProxyItem> { left, right ->
        collator.compare(left.name, right.name)
    }
    return when (this) {
        ProxySortMode.Default -> compareByDescending<ProxyItem> { it.selected }
        ProxySortMode.DelayAsc -> Comparator { left, right ->
            left.delaySortValue().compareTo(right.delaySortValue())
        }
        ProxySortMode.DelayDesc -> Comparator { left, right ->
            right.delaySortValue().compareTo(left.delaySortValue())
        }
        ProxySortMode.NameAsc -> nameComparator
        ProxySortMode.NameDesc -> nameComparator.reversed()
    }
}

private fun ProxyItem.delaySortValue(): Int {
    val delay = delayMs ?: return Int.MAX_VALUE
    return if (delay < 0) Int.MAX_VALUE - 1 else delay
}

private fun ProxyFilter.matches(proxy: ProxyItem): Boolean {
    return when (this) {
        ProxyFilter.All -> true
        ProxyFilter.Selected -> proxy.selected
        ProxyFilter.Measured -> proxy.delayMs != null && !proxy.isTimeout()
        ProxyFilter.Untested -> proxy.delayMs == null
        ProxyFilter.Timeout -> proxy.isTimeout()
    }
}

private fun ProxyItem.isTimeout(): Boolean {
    val delay = delayMs ?: return false
    return delay < 0 || delay >= 5_000
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ProxyGroupDrawer(
    group: ProxyGroupItem,
    expanded: Boolean,
    measuring: Boolean,
    measuringProxyId: String?,
    measuringGroupName: String?,
    onToggleExpanded: () -> Unit,
    onProxySelect: (String) -> Unit,
    onTestGroup: () -> Unit,
    onTestProxyDelay: (String) -> Unit,
    onFilterSelected: () -> Unit,
    onFilterGroup: (String) -> Unit,
) {
    val groupMeasuring = measuringGroupName == group.name
    val testingBusy = measuring || measuringProxyId != null || measuringGroupName != null
    var menuExpanded by remember { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainer,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.padding(horizontal = 12.dp),
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .combinedClickable(
                        onClick = onToggleExpanded,
                        onLongClick = { menuExpanded = true },
                    )
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                    contentDescription = if (expanded) "收起" else "展开",
                )
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        group.name,
                        style = MaterialTheme.typography.titleMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        "${group.type.ifBlank { "Selector" }} / ${group.selectedName.ifBlank { "未选择" }}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.secondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                AssistChip(onClick = { }, label = { Text("${group.proxies.size} 节点") })
                Box {
                    IconButton(
                        onClick = onTestGroup,
                        enabled = !testingBusy,
                        modifier = Modifier.size(36.dp),
                    ) {
                        if (groupMeasuring) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp,
                            )
                        } else {
                            Icon(
                                Icons.Filled.Speed,
                                contentDescription = "测速当前分组",
                                modifier = Modifier.size(18.dp),
                            )
                        }
                    }
                    DropdownMenu(
                        expanded = menuExpanded,
                        onDismissRequest = { menuExpanded = false },
                    ) {
                        DropdownMenuItem(
                            text = { Text(if (expanded) "收起分组" else "展开分组") },
                            leadingIcon = {
                                Icon(
                                    if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                                    contentDescription = null,
                                )
                            },
                            onClick = {
                                menuExpanded = false
                                onToggleExpanded()
                            },
                        )
                        DropdownMenuItem(
                            text = { Text("测速分组") },
                            leadingIcon = { Icon(Icons.Filled.Speed, contentDescription = null) },
                            enabled = !testingBusy,
                            onClick = {
                                menuExpanded = false
                                onTestGroup()
                            },
                        )
                        DropdownMenuItem(
                            text = { Text("复制分组信息") },
                            leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                            onClick = {
                                menuExpanded = false
                                clipboard.setText(AnnotatedString(group.toClipboardText()))
                                Toast.makeText(context, "分组信息已复制", Toast.LENGTH_SHORT).show()
                            },
                        )
                        DropdownMenuItem(
                            text = { Text("复制当前节点") },
                            leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                            enabled = group.selectedName.isNotBlank(),
                            onClick = {
                                menuExpanded = false
                                clipboard.setText(AnnotatedString(group.selectedName))
                                Toast.makeText(context, "当前节点已复制", Toast.LENGTH_SHORT).show()
                            },
                        )
                    }
                }
            }
            if (expanded) {
                BoxWithConstraints(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 12.dp, end = 12.dp, bottom = 12.dp),
                ) {
                    val columns = if (maxWidth >= 520.dp) 3 else 2
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        group.proxies.chunked(columns).forEach { row ->
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                row.forEach { proxy ->
                                    ProxyNodeCell(
                                        name = proxy.name,
                                        selected = proxy.selected,
                                        delayText = proxy.delayMs?.let { "${it}ms" } ?: "未测速",
                                        measuring = measuringProxyId == proxy.id,
                                        testingDisabled = testingBusy,
                                        onSelect = { onProxySelect(proxy.id) },
                                        onTest = { onTestProxyDelay(proxy.id) },
                                        onFilterSelected = onFilterSelected,
                                        onFilterGroup = { onFilterGroup(group.name) },
                                        modifier = Modifier.weight(1f),
                                    )
                                }
                                repeat(columns - row.size) {
                                    Column(modifier = Modifier.weight(1f)) {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ProxyNodeCell(
    name: String,
    selected: Boolean,
    delayText: String,
    measuring: Boolean,
    testingDisabled: Boolean,
    onSelect: () -> Unit,
    onTest: () -> Unit,
    onFilterSelected: () -> Unit,
    onFilterGroup: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var menuExpanded by remember { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    Surface(
        color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface,
        shape = MaterialTheme.shapes.small,
        modifier = modifier
            .heightIn(min = 58.dp)
            .combinedClickable(
                onClick = onSelect,
                onLongClick = { menuExpanded = true },
            ),
    ) {
        Box {
            Column(
                modifier = Modifier.padding(10.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        name,
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodyMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (selected) {
                        Icon(
                            Icons.Filled.CheckCircle,
                            contentDescription = "已选中",
                            modifier = Modifier.size(16.dp),
                            tint = MaterialTheme.colorScheme.primary,
                        )
                    }
                }
                Row(
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        delayText,
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.secondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    IconButton(
                        onClick = onTest,
                        enabled = !testingDisabled && !measuring,
                        modifier = Modifier.size(28.dp),
                    ) {
                        if (measuring) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp,
                            )
                        } else {
                            Icon(
                                Icons.Filled.Speed,
                                contentDescription = "测速",
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    }
                }
            }
            DropdownMenu(
                expanded = menuExpanded,
                onDismissRequest = { menuExpanded = false },
            ) {
                DropdownMenuItem(
                    text = { Text("切换节点") },
                    leadingIcon = { Icon(Icons.Filled.CheckCircle, contentDescription = null) },
                    onClick = {
                        menuExpanded = false
                        onSelect()
                    },
                )
                DropdownMenuItem(
                    text = { Text("测速节点") },
                    leadingIcon = { Icon(Icons.Filled.Speed, contentDescription = null) },
                    enabled = !testingDisabled && !measuring,
                    onClick = {
                        menuExpanded = false
                        onTest()
                    },
                )
                DropdownMenuItem(
                    text = { Text("复制名称") },
                    leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                    onClick = {
                        menuExpanded = false
                        clipboard.setText(AnnotatedString(name))
                        Toast.makeText(context, "节点名称已复制", Toast.LENGTH_SHORT).show()
                    },
                )
                DropdownMenuItem(
                    text = { Text("筛选当前节点") },
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    onClick = {
                        menuExpanded = false
                        onFilterSelected()
                    },
                )
                DropdownMenuItem(
                    text = { Text("筛选同分组") },
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    onClick = {
                        menuExpanded = false
                        onFilterGroup()
                    },
                )
            }
        }
    }
}
