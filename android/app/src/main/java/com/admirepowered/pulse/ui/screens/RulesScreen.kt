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
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.EditNote
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
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
import com.admirepowered.pulse.ui.RuleItem
import com.admirepowered.pulse.ui.components.PulseRow
import java.text.Collator
import java.util.Locale

@Composable
fun RulesScreen(
    rules: List<RuleItem>,
    loading: Boolean,
    message: String,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onOpenCustomRules: () -> Unit,
    onShare: (String) -> Unit,
    onExportFile: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var query by remember { mutableStateOf("") }
    var selectedType by remember { mutableStateOf("全部") }
    var selectedPolicy by remember { mutableStateOf("全部策略") }
    var sortMode by remember { mutableStateOf(RuleSortMode.Default) }
    val ruleTypes = remember(rules) {
        listOf("全部") + rules.map { it.type.ifBlank { "MATCH" } }.distinct().sorted()
    }
    val rulePolicies = remember(rules) {
        listOf("全部策略") + rules.map { it.proxy.ifBlank { "DIRECT" } }.distinct().sorted()
    }
    val queryMatchedRules = remember(rules, query) {
        val value = query.trim().lowercase()
        rules.filter { rule ->
            if (value.isBlank()) {
                true
            } else {
                listOf(rule.type, rule.payload, rule.proxy)
                    .any { it.lowercase().contains(value) }
            }
        }
    }
    val typeFilterCounts = remember(queryMatchedRules) {
        ruleTypes.associateWith { type ->
            if (type == "全部") queryMatchedRules.size else queryMatchedRules.count { it.type.ifBlank { "MATCH" } == type }
        }
    }
    val typeMatchedRules = remember(queryMatchedRules, selectedType) {
        queryMatchedRules.filter { rule ->
            selectedType == "全部" || rule.type.ifBlank { "MATCH" } == selectedType
        }
    }
    val policyFilterCounts = remember(typeMatchedRules) {
        rulePolicies.associateWith { policy ->
            if (policy == "全部策略") typeMatchedRules.size else typeMatchedRules.count { it.proxy.ifBlank { "DIRECT" } == policy }
        }
    }
    val filteredRules = remember(typeMatchedRules, selectedPolicy, sortMode) {
        typeMatchedRules.filter { rule ->
            selectedPolicy == "全部策略" || rule.proxy.ifBlank { "DIRECT" } == selectedPolicy
        }.sortedWith(sortMode.comparator())
    }
    val hasActiveFilters = query.isNotBlank() ||
        selectedType != "全部" ||
        selectedPolicy != "全部策略" ||
        sortMode != RuleSortMode.Default
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current

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
                    "规则",
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.headlineSmall,
                )
                IconButton(onClick = onOpenCustomRules) {
                    Icon(Icons.Filled.EditNote, contentDescription = "编辑自定义规则")
                }
                IconButton(
                    onClick = {
                        clipboard.setText(AnnotatedString(filteredRules.toClipboardText()))
                        Toast.makeText(context, "当前规则已复制", Toast.LENGTH_SHORT).show()
                    },
                    enabled = filteredRules.isNotEmpty(),
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "复制当前规则")
                }
                IconButton(
                    onClick = { onShare(filteredRules.toClipboardText()) },
                    enabled = filteredRules.isNotEmpty(),
                ) {
                    Icon(Icons.Filled.Share, contentDescription = "分享当前规则")
                }
                IconButton(
                    onClick = { onExportFile(filteredRules.toClipboardText()) },
                    enabled = filteredRules.isNotEmpty(),
                ) {
                    Icon(Icons.Filled.Download, contentDescription = "导出当前规则")
                }
                IconButton(onClick = onRefresh, enabled = !loading) {
                    Icon(Icons.Filled.Refresh, contentDescription = "刷新规则")
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
                placeholder = { Text("搜索规则类型、内容、策略") },
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
                AssistChip(onClick = { }, label = { Text("${filteredRules.size}/${rules.size}") })
                FilterChip(
                    selected = false,
                    onClick = {
                        query = ""
                        selectedType = "全部"
                        selectedPolicy = "全部策略"
                        sortMode = RuleSortMode.Default
                    },
                    enabled = hasActiveFilters,
                    label = { Text("重置筛选") },
                )
                ruleTypes.forEach { type ->
                    FilterChip(
                        selected = selectedType == type,
                        onClick = { selectedType = type },
                        label = { Text("$type ${typeFilterCounts[type] ?: 0}") },
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
                verticalAlignment = Alignment.CenterVertically,
            ) {
                rulePolicies.forEach { policy ->
                    FilterChip(
                        selected = selectedPolicy == policy,
                        onClick = { selectedPolicy = policy },
                        label = { Text("$policy ${policyFilterCounts[policy] ?: 0}") },
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
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RuleSortMode.entries.forEach { item ->
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
        if (!loading && filteredRules.isEmpty()) {
            item {
                Text(
                    if (query.isBlank() && selectedType == "全部" && selectedPolicy == "全部策略") "暂无规则" else "没有匹配的规则",
                    modifier = Modifier.padding(horizontal = 20.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
        itemsIndexed(filteredRules, key = { index, item -> "${item.type}-${item.payload}-$index" }) { _, rule ->
            var ruleMenuExpanded by remember(rule.type, rule.payload, rule.proxy) { mutableStateOf(false) }
            PulseRow(
                title = rule.payload.ifBlank { "MATCH" },
                subtitle = rule.proxy,
                modifier = Modifier.ruleRowActions(onLongClick = { ruleMenuExpanded = true }),
                trailing = {
                    Box {
                        Column(
                            horizontalAlignment = Alignment.End,
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            AssistChip(onClick = { }, label = { Text(rule.type.ifBlank { "-" }) })
                            Text(
                                rule.proxy,
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.secondary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                        DropdownMenu(
                            expanded = ruleMenuExpanded,
                            onDismissRequest = { ruleMenuExpanded = false },
                        ) {
                            DropdownMenuItem(
                                text = { Text("复制规则") },
                                leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                                onClick = {
                                    ruleMenuExpanded = false
                                    clipboard.setText(AnnotatedString(rule.toRuleLine()))
                                    Toast.makeText(context, "规则已复制", Toast.LENGTH_SHORT).show()
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("复制内容") },
                                leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                                onClick = {
                                    ruleMenuExpanded = false
                                    clipboard.setText(AnnotatedString(rule.payload.ifBlank { "MATCH" }))
                                    Toast.makeText(context, "规则内容已复制", Toast.LENGTH_SHORT).show()
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("复制策略") },
                                leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                                onClick = {
                                    ruleMenuExpanded = false
                                    clipboard.setText(AnnotatedString(rule.proxy.ifBlank { "DIRECT" }))
                                    Toast.makeText(context, "规则策略已复制", Toast.LENGTH_SHORT).show()
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("筛选同类型") },
                                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                                onClick = {
                                    ruleMenuExpanded = false
                                    selectedType = rule.type.ifBlank { "MATCH" }
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("筛选同策略") },
                                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                                onClick = {
                                    ruleMenuExpanded = false
                                    selectedPolicy = rule.proxy.ifBlank { "DIRECT" }
                                },
                            )
                        }
                    }
                },
            )
        }
    }
}

private fun List<RuleItem>.toClipboardText(): String {
    return joinToString("\n") { rule -> rule.toRuleLine() }
}

private fun RuleItem.toRuleLine(): String {
    return listOf(type, payload, proxy)
        .filter { it.isNotBlank() }
        .joinToString(",")
}

@OptIn(ExperimentalFoundationApi::class)
private fun Modifier.ruleRowActions(onLongClick: () -> Unit): Modifier {
    return combinedClickable(
        onClick = {},
        onLongClick = onLongClick,
    )
}

private enum class RuleSortMode(val label: String) {
    Default("默认排序"),
    PayloadAsc("内容升序"),
    PayloadDesc("内容降序"),
    TypeAsc("类型升序"),
    TypeDesc("类型降序"),
    PolicyAsc("策略升序"),
    PolicyDesc("策略降序"),
}

private fun RuleSortMode.comparator(): Comparator<RuleItem> {
    val collator = Collator.getInstance(Locale.getDefault())
    fun compareText(left: String, right: String): Int = collator.compare(left, right)
    return when (this) {
        RuleSortMode.Default -> Comparator { _, _ -> 0 }
        RuleSortMode.PayloadAsc -> Comparator { left, right ->
            compareText(left.payload.ifBlank { "MATCH" }, right.payload.ifBlank { "MATCH" })
        }
        RuleSortMode.PayloadDesc -> Comparator { left, right ->
            compareText(right.payload.ifBlank { "MATCH" }, left.payload.ifBlank { "MATCH" })
        }
        RuleSortMode.TypeAsc -> Comparator { left, right ->
            compareText(left.type.ifBlank { "MATCH" }, right.type.ifBlank { "MATCH" })
        }
        RuleSortMode.TypeDesc -> Comparator { left, right ->
            compareText(right.type.ifBlank { "MATCH" }, left.type.ifBlank { "MATCH" })
        }
        RuleSortMode.PolicyAsc -> Comparator { left, right ->
            compareText(left.proxy.ifBlank { "DIRECT" }, right.proxy.ifBlank { "DIRECT" })
        }
        RuleSortMode.PolicyDesc -> Comparator { left, right ->
            compareText(right.proxy.ifBlank { "DIRECT" }, left.proxy.ifBlank { "DIRECT" })
        }
    }
}
