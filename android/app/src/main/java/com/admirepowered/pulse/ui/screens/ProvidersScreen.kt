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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AssistChip
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.admirepowered.pulse.ui.ProviderItem
import com.admirepowered.pulse.ui.ProviderKind
import com.admirepowered.pulse.ui.components.PulseRow
import java.text.Collator
import java.util.Locale

@Composable
fun ProvidersScreen(
    providers: List<ProviderItem>,
    loading: Boolean,
    updatingProviderName: String?,
    message: String,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onUpdateProvider: (String, ProviderKind) -> Unit,
    onUpdateAllProviders: () -> Unit,
    onUpdateProviders: (List<ProviderItem>) -> Unit,
    modifier: Modifier = Modifier,
) {
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf(ProviderFilter.All) }
    var vehicleFilter by remember { mutableStateOf("全部来源") }
    var sortMode by remember { mutableStateOf(ProviderSortMode.Default) }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val vehicleFilters = remember(providers) {
        listOf("全部来源") + providers.map { it.vehicle.ifBlank { "未知来源" } }.distinct().sorted()
    }
    val queryMatchedProviders = remember(providers, query) {
        val value = query.trim().lowercase()
        providers.filter { provider ->
            value.isBlank() ||
                listOf(provider.name, provider.kind.label, provider.vehicle, provider.updatedAt)
                    .any { it.lowercase().contains(value) }
        }
    }
    val providerFilterCounts = remember(queryMatchedProviders) {
        ProviderFilter.entries.associateWith { providerFilter ->
            when (providerFilter) {
                ProviderFilter.All -> queryMatchedProviders.size
                ProviderFilter.Proxy -> queryMatchedProviders.count { it.kind == ProviderKind.Proxy }
                ProviderFilter.Rule -> queryMatchedProviders.count { it.kind == ProviderKind.Rule }
            }
        }
    }
    val kindMatchedProviders = remember(queryMatchedProviders, filter) {
        queryMatchedProviders.filter { provider ->
            when (filter) {
                ProviderFilter.All -> true
                ProviderFilter.Proxy -> provider.kind == ProviderKind.Proxy
                ProviderFilter.Rule -> provider.kind == ProviderKind.Rule
            }
        }
    }
    val vehicleFilterCounts = remember(kindMatchedProviders) {
        vehicleFilters.associateWith { vehicle ->
            if (vehicle == "全部来源") {
                kindMatchedProviders.size
            } else {
                kindMatchedProviders.count { it.vehicle.ifBlank { "未知来源" } == vehicle }
            }
        }
    }
    val filteredProviders = remember(kindMatchedProviders, vehicleFilter, sortMode) {
        kindMatchedProviders.filter { provider ->
            vehicleFilter == "全部来源" || provider.vehicle.ifBlank { "未知来源" } == vehicleFilter
        }.sortedWith(sortMode.comparator())
    }
    val visibleProxyProviderCount = remember(filteredProviders) {
        filteredProviders.count { it.kind == ProviderKind.Proxy }
    }
    val visibleRuleProviderCount = remember(filteredProviders) {
        filteredProviders.count { it.kind == ProviderKind.Rule }
    }
    val visibleProviderItemCount = remember(filteredProviders) {
        filteredProviders.sumOf { it.count }
    }
    val visibleProviderSourceCount = remember(filteredProviders) {
        filteredProviders.map { it.vehicle.ifBlank { "未知来源" } }.distinct().size
    }
    val hasActiveFilters = query.isNotBlank() ||
        filter != ProviderFilter.All ||
        vehicleFilter != "全部来源" ||
        sortMode != ProviderSortMode.Default

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
                    "提供者",
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.headlineSmall,
                )
                IconButton(
                    onClick = {
                        clipboard.setText(AnnotatedString(filteredProviders.toClipboardText()))
                        Toast.makeText(context, "当前提供者已复制", Toast.LENGTH_SHORT).show()
                    },
                    enabled = filteredProviders.isNotEmpty(),
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "复制当前提供者")
                }
                IconButton(onClick = onRefresh, enabled = !loading) {
                    Icon(Icons.Filled.Refresh, contentDescription = "刷新提供者")
                }
                IconButton(
                    onClick = onUpdateAllProviders,
                    enabled = providers.isNotEmpty() && !loading && updatingProviderName == null,
                ) {
                    if (updatingProviderName == ALL_PROVIDERS_UPDATE_KEY) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(22.dp),
                            strokeWidth = 2.dp,
                        )
                    } else {
                        Icon(Icons.Filled.Refresh, contentDescription = "全部更新提供者")
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
                placeholder = { Text("搜索名称、代理/规则、类型、时间") },
            )
        }
        item {
            Row(
                modifier = Modifier
                    .padding(horizontal = 20.dp)
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                AssistChip(onClick = { }, label = { Text("${filteredProviders.size}/${providers.size}") })
                AssistChip(onClick = { }, label = { Text("代理 $visibleProxyProviderCount") })
                AssistChip(onClick = { }, label = { Text("规则 $visibleRuleProviderCount") })
                AssistChip(onClick = { }, label = { Text("条目 $visibleProviderItemCount") })
                AssistChip(onClick = { }, label = { Text("来源 $visibleProviderSourceCount") })
                AssistChip(
                    onClick = { onUpdateProviders(filteredProviders) },
                    enabled = filteredProviders.isNotEmpty() && !loading && updatingProviderName == null,
                    label = { Text("更新当前") },
                    leadingIcon = {
                        Icon(
                            Icons.Filled.Refresh,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                        )
                    },
                )
                FilterChip(
                    selected = false,
                    onClick = {
                        query = ""
                        filter = ProviderFilter.All
                        vehicleFilter = "全部来源"
                        sortMode = ProviderSortMode.Default
                    },
                    enabled = hasActiveFilters,
                    label = { Text("重置筛选") },
                )
                ProviderFilter.entries.forEach { item ->
                    FilterChip(
                        selected = filter == item,
                        onClick = { filter = item },
                        label = { Text("${item.label} ${providerFilterCounts[item] ?: 0}") },
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
                vehicleFilters.forEach { item ->
                    FilterChip(
                        selected = vehicleFilter == item,
                        onClick = { vehicleFilter = item },
                        label = { Text("$item ${vehicleFilterCounts[item] ?: 0}") },
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
                ProviderSortMode.entries.forEach { item ->
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
        if (!loading && filteredProviders.isEmpty()) {
            item {
                Text(
                    if (query.isBlank() && filter == ProviderFilter.All && vehicleFilter == "全部来源") "暂无提供者" else "没有匹配的提供者",
                    modifier = Modifier.padding(horizontal = 20.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
        items(filteredProviders, key = { "${it.kind.name}:${it.name}" }) { provider ->
            var providerMenuExpanded by remember(provider.kind, provider.name) { mutableStateOf(false) }
            PulseRow(
                title = provider.name,
                subtitle = "${provider.kind.label} / ${provider.updatedAt.ifBlank { "未提供更新时间" }}",
                modifier = Modifier.providerRowActions(onLongClick = { providerMenuExpanded = true }),
                trailing = {
                    Box {
                        Column(
                            horizontalAlignment = Alignment.End,
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            AssistChip(
                                onClick = { },
                                label = {
                                    Text(
                                        provider.countLabel(),
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                },
                            )
                            if (updatingProviderName == provider.updateKey()) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(24.dp),
                                    strokeWidth = 2.dp,
                                )
                            } else {
                                IconButton(onClick = { onUpdateProvider(provider.name, provider.kind) }) {
                                    Icon(Icons.Filled.Refresh, contentDescription = "更新提供者")
                                }
                            }
                        }
                        DropdownMenu(
                            expanded = providerMenuExpanded,
                            onDismissRequest = { providerMenuExpanded = false },
                        ) {
                            DropdownMenuItem(
                                text = { Text("更新提供者") },
                                leadingIcon = { Icon(Icons.Filled.Refresh, contentDescription = null) },
                                enabled = updatingProviderName == null,
                                onClick = {
                                    providerMenuExpanded = false
                                    onUpdateProvider(provider.name, provider.kind)
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("复制信息") },
                                leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                                onClick = {
                                    providerMenuExpanded = false
                                    clipboard.setText(AnnotatedString(provider.toClipboardLine()))
                                    Toast.makeText(context, "提供者信息已复制", Toast.LENGTH_SHORT).show()
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("复制名称") },
                                leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                                onClick = {
                                    providerMenuExpanded = false
                                    clipboard.setText(AnnotatedString(provider.name))
                                    Toast.makeText(context, "提供者名称已复制", Toast.LENGTH_SHORT).show()
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("筛选同类型") },
                                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                                onClick = {
                                    providerMenuExpanded = false
                                    filter = when (provider.kind) {
                                        ProviderKind.Proxy -> ProviderFilter.Proxy
                                        ProviderKind.Rule -> ProviderFilter.Rule
                                    }
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("筛选同来源") },
                                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                                onClick = {
                                    providerMenuExpanded = false
                                    vehicleFilter = provider.vehicle.ifBlank { "未知来源" }
                                },
                            )
                        }
                    }
                },
            )
        }
    }
}

private fun ProviderItem.countLabel(): String {
    return when (kind) {
        ProviderKind.Proxy -> "$count 节点"
        ProviderKind.Rule -> "$count 规则"
    }
}

private fun ProviderItem.updateKey(): String {
    return "${kind.name}:$name"
}

private fun List<ProviderItem>.toClipboardText(): String {
    return joinToString("\n") { provider -> provider.toClipboardLine() }
}

private fun ProviderItem.toClipboardLine(): String {
    return listOf(
        name,
        kind.label,
        countLabel(),
        updatedAt.ifBlank { "未提供更新时间" },
        vehicle.ifBlank { "未知来源" },
    ).joinToString(" / ")
}

@OptIn(ExperimentalFoundationApi::class)
private fun Modifier.providerRowActions(onLongClick: () -> Unit): Modifier {
    return combinedClickable(
        onClick = {},
        onLongClick = onLongClick,
    )
}

private enum class ProviderFilter(val label: String) {
    All("全部"),
    Proxy("代理"),
    Rule("规则"),
}

private enum class ProviderSortMode(val label: String) {
    Default("默认排序"),
    NameAsc("名称升序"),
    NameDesc("名称降序"),
    UpdatedDesc("最近更新"),
    UpdatedAsc("最早更新"),
    CountDesc("数量高"),
    CountAsc("数量低"),
}

private fun ProviderSortMode.comparator(): Comparator<ProviderItem> {
    val collator = Collator.getInstance(Locale.getDefault())
    val nameComparator = Comparator<ProviderItem> { left, right ->
        collator.compare(left.name, right.name)
    }
    return when (this) {
        ProviderSortMode.Default -> Comparator { _, _ -> 0 }
        ProviderSortMode.NameAsc -> nameComparator
        ProviderSortMode.NameDesc -> nameComparator.reversed()
        ProviderSortMode.UpdatedDesc -> compareByDescending { it.updatedAt }
        ProviderSortMode.UpdatedAsc -> compareBy { it.updatedAt }
        ProviderSortMode.CountDesc -> compareByDescending { it.count }
        ProviderSortMode.CountAsc -> compareBy { it.count }
    }
}

private const val ALL_PROVIDERS_UPDATE_KEY = "__all_providers__"
