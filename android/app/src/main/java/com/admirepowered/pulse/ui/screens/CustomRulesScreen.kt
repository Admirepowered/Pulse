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
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.LibraryAdd
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material.icons.Icons
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
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
import com.admirepowered.pulse.ui.CustomRuleItem

private val ruleTypes = listOf(
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "GEOSITE",
    "MATCH",
)

@Composable
fun CustomRulesScreen(
    rules: List<CustomRuleItem>,
    policies: List<String>,
    loading: Boolean,
    saving: Boolean,
    message: String,
    onBack: () -> Unit,
    onAdd: () -> Unit,
    onImportText: (String) -> Unit,
    onImportFile: () -> Unit,
    onExportFile: (String) -> Unit,
    onUpdate: (Int, CustomRuleItem) -> Unit,
    onDuplicate: (Int) -> Unit,
    onMove: (Int, Int) -> Unit,
    onDelete: (Int) -> Unit,
    onSave: () -> Unit,
    onShare: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var query by remember { mutableStateOf("") }
    var selectedType by remember { mutableStateOf("全部") }
    var selectedPolicy by remember { mutableStateOf("全部策略") }
    var deletingRule by remember { mutableStateOf<Pair<Int, CustomRuleItem>?>(null) }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val types = remember(rules) {
        listOf("全部") + rules.map { it.type.ifBlank { "MATCH" } }.distinct().sorted()
    }
    val policyFilters = remember(rules, policies) {
        val fromRules = rules.map { it.proxy.ifBlank { "DIRECT" } }
        listOf("全部策略") + (fromRules + policies).filter { it.isNotBlank() }.distinct().sorted()
    }
    val queryMatchedRules = remember(rules, query) {
        val keyword = query.trim().lowercase()
        rules.mapIndexed { index, rule -> index to rule }
            .filter { (_, rule) ->
                keyword.isBlank() ||
                    listOf(rule.type, rule.payload, rule.proxy, if (rule.noResolve) "no-resolve" else "")
                        .any { it.lowercase().contains(keyword) }
            }
    }
    val typeFilterCounts = remember(queryMatchedRules) {
        types.associateWith { type ->
            if (type == "全部") queryMatchedRules.size else queryMatchedRules.count { (_, rule) ->
                rule.type.ifBlank { "MATCH" } == type
            }
        }
    }
    val typeMatchedRules = remember(queryMatchedRules, selectedType) {
        queryMatchedRules.filter { (_, rule) ->
            selectedType == "全部" || rule.type.ifBlank { "MATCH" } == selectedType
        }
    }
    val policyFilterCounts = remember(typeMatchedRules) {
        policyFilters.associateWith { policy ->
            if (policy == "全部策略") typeMatchedRules.size else typeMatchedRules.count { (_, rule) ->
                rule.proxy.ifBlank { "DIRECT" } == policy
            }
        }
    }
    val filteredRules = remember(typeMatchedRules, selectedPolicy) {
        typeMatchedRules.filter { (_, rule) ->
            selectedPolicy == "全部策略" || rule.proxy.ifBlank { "DIRECT" } == selectedPolicy
        }
    }
    val hasActiveFilters = query.isNotBlank() ||
        selectedType != "全部" ||
        selectedPolicy != "全部策略"
    LaunchedEffect(types, policyFilters) {
        if (selectedType !in types) selectedType = "全部"
        if (selectedPolicy !in policyFilters) selectedPolicy = "全部策略"
    }
    fun applyQuickSort(sortMode: CustomRuleSortMode) {
        val targetOrder = sortMode.sort(rules)
        val currentOrder = rules.indices.toMutableList()
        targetOrder.forEachIndexed { targetIndex, originalIndex ->
            val currentIndex = currentOrder.indexOf(originalIndex)
            if (currentIndex >= 0 && currentIndex != targetIndex) {
                onMove(currentIndex, targetIndex)
                val moved = currentOrder.removeAt(currentIndex)
                currentOrder.add(targetIndex, moved)
            }
        }
    }
    deletingRule?.let { (index, rule) ->
        AlertDialog(
            onDismissRequest = { deletingRule = null },
            title = { Text("删除自定义规则") },
            text = {
                Text("确定删除第 ${index + 1} 条规则「${rule.toRuleText()}」吗？")
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        onDelete(index)
                        deletingRule = null
                    },
                ) {
                    Text("删除")
                }
            },
            dismissButton = {
                TextButton(onClick = { deletingRule = null }) {
                    Text("取消")
                }
            },
        )
    }
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            Row(
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回规则")
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text("自定义规则", style = MaterialTheme.typography.headlineSmall)
                    Text(
                        "保存后会注入到订阅规则之前",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.secondary,
                    )
                }
                if (saving) {
                    CircularProgressIndicator(strokeWidth = 2.dp)
                } else {
                    IconButton(
                        onClick = {
                            clipboard.setText(AnnotatedString(filteredRules.map { it.second }.toClipboardText()))
                            Toast.makeText(context, "自定义规则已复制", Toast.LENGTH_SHORT).show()
                        },
                        enabled = !loading && filteredRules.isNotEmpty(),
                    ) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = "复制自定义规则")
                    }
                    IconButton(
                        onClick = { onShare(filteredRules.map { it.second }.toClipboardText()) },
                        enabled = !loading && filteredRules.isNotEmpty(),
                    ) {
                        Icon(Icons.Filled.Share, contentDescription = "分享自定义规则")
                    }
                    IconButton(
                        onClick = { onExportFile(filteredRules.map { it.second }.toClipboardText()) },
                        enabled = !loading && filteredRules.isNotEmpty(),
                    ) {
                        Icon(Icons.Filled.Download, contentDescription = "导出自定义规则")
                    }
                    IconButton(
                        onClick = {
                            onImportText(clipboard.getText()?.text.orEmpty())
                        },
                        enabled = !loading,
                    ) {
                        Icon(Icons.Filled.ContentPaste, contentDescription = "从剪贴板导入规则")
                    }
                    IconButton(
                        onClick = onImportFile,
                        enabled = !loading,
                    ) {
                        Icon(Icons.Filled.UploadFile, contentDescription = "从文件导入规则")
                    }
                    IconButton(onClick = onSave, enabled = !loading) {
                        Icon(Icons.Filled.Save, contentDescription = "保存自定义规则")
                    }
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
                placeholder = { Text("搜索类型、内容、策略") },
                supportingText = { Text("${filteredRules.size}/${rules.size}") },
            )
        }
        item {
            Row(
                modifier = Modifier
                    .padding(horizontal = 20.dp)
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                FilterChip(
                    selected = false,
                    onClick = {
                        query = ""
                        selectedType = "全部"
                        selectedPolicy = "全部策略"
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
                types.forEach { type ->
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
            ) {
                policyFilters.forEach { policy ->
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
            ) {
                CustomRuleSortMode.entries.forEach { item ->
                    FilterChip(
                        selected = false,
                        onClick = { applyQuickSort(item) },
                        enabled = rules.size > 1 && !loading && !saving,
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
        if (!loading && filteredRules.isEmpty()) {
            item {
                Text(
                    if (rules.isEmpty()) "暂无自定义规则" else "没有匹配的自定义规则",
                    modifier = Modifier.padding(horizontal = 20.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
        itemsIndexed(filteredRules, key = { _, item -> item.second.id }) { _, item ->
            val index = item.first
            val rule = item.second
            RuleEditorRow(
                index = index,
                rule = rule,
                policies = policies,
                canMoveUp = index > 0,
                canMoveDown = index < rules.lastIndex,
                onUpdate = { onUpdate(index, it) },
                onDuplicate = { onDuplicate(index) },
                onMoveUp = { onMove(index, index - 1) },
                onMoveDown = { onMove(index, index + 1) },
                onFilterType = { selectedType = rule.type.ifBlank { "MATCH" } },
                onFilterPolicy = { selectedPolicy = rule.proxy.ifBlank { "DIRECT" } },
                onDelete = { deletingRule = index to rule },
            )
        }
        item {
            FilledIconButton(
                onClick = onAdd,
                modifier = Modifier.padding(horizontal = 20.dp),
            ) {
                Icon(Icons.Filled.Add, contentDescription = "添加规则")
            }
        }
    }
}

private fun List<CustomRuleItem>.toClipboardText(): String {
    return joinToString("\n") { rule -> rule.toRuleText() }
}

private fun CustomRuleItem.toRuleText(): String {
    return buildList {
        add(type.ifBlank { "MATCH" })
        if (type != "MATCH" && payload.isNotBlank()) {
            add(payload)
        }
        add(proxy.ifBlank { "DIRECT" })
        if (noResolve) {
            add("no-resolve")
        }
    }.joinToString(",")
}

private enum class CustomRuleSortMode(val label: String) {
    Type("按类型排序"),
    Policy("按策略排序"),
    Payload("按内容排序"),
}

private fun CustomRuleSortMode.sort(rules: List<CustomRuleItem>): List<Int> {
    return rules.mapIndexed { index, rule -> index to rule }
        .sortedWith(
            when (this) {
                CustomRuleSortMode.Type -> compareBy<Pair<Int, CustomRuleItem>> { it.second.type.ifBlank { "MATCH" } }
                    .thenBy { it.second.payload }
                    .thenBy { it.first }
                CustomRuleSortMode.Policy -> compareBy<Pair<Int, CustomRuleItem>> { it.second.proxy.ifBlank { "DIRECT" } }
                    .thenBy { it.second.type.ifBlank { "MATCH" } }
                    .thenBy { it.first }
                CustomRuleSortMode.Payload -> compareBy<Pair<Int, CustomRuleItem>> { it.second.payload.ifBlank { "MATCH" } }
                    .thenBy { it.second.type.ifBlank { "MATCH" } }
                    .thenBy { it.first }
            },
        )
        .map { it.first }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun RuleEditorRow(
    index: Int,
    rule: CustomRuleItem,
    policies: List<String>,
    canMoveUp: Boolean,
    canMoveDown: Boolean,
    onUpdate: (CustomRuleItem) -> Unit,
    onDuplicate: () -> Unit,
    onMoveUp: () -> Unit,
    onMoveDown: () -> Unit,
    onFilterType: () -> Unit,
    onFilterPolicy: () -> Unit,
    onDelete: () -> Unit,
) {
    var menuExpanded by remember(rule.id) { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp),
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.combinedClickable(
                    onClick = {},
                    onLongClick = { menuExpanded = true },
                ),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("#${index + 1}", style = MaterialTheme.typography.labelLarge)
                ChoiceButton(
                    value = rule.type,
                    options = ruleTypes,
                    modifier = Modifier.weight(1f),
                    onChoose = { type ->
                        onUpdate(rule.copy(type = type, payload = if (type == "MATCH") "" else rule.payload))
                    },
                )
                IconButton(onClick = onMoveUp, enabled = canMoveUp) {
                    Icon(Icons.Filled.ArrowUpward, contentDescription = "上移")
                }
                IconButton(onClick = onMoveDown, enabled = canMoveDown) {
                    Icon(Icons.Filled.ArrowDownward, contentDescription = "下移")
                }
                IconButton(onClick = onDelete) {
                    Icon(Icons.Filled.Delete, contentDescription = "删除")
                }
                DropdownMenu(
                    expanded = menuExpanded,
                    onDismissRequest = { menuExpanded = false },
                ) {
                    DropdownMenuItem(
                        text = { Text("复制规则") },
                        leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                        onClick = {
                            menuExpanded = false
                            clipboard.setText(AnnotatedString(rule.toRuleText()))
                            Toast.makeText(context, "自定义规则已复制", Toast.LENGTH_SHORT).show()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("复制为新规则") },
                        leadingIcon = { Icon(Icons.Filled.LibraryAdd, contentDescription = null) },
                        onClick = {
                            menuExpanded = false
                            onDuplicate()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("上移") },
                        leadingIcon = { Icon(Icons.Filled.ArrowUpward, contentDescription = null) },
                        enabled = canMoveUp,
                        onClick = {
                            menuExpanded = false
                            onMoveUp()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("下移") },
                        leadingIcon = { Icon(Icons.Filled.ArrowDownward, contentDescription = null) },
                        enabled = canMoveDown,
                        onClick = {
                            menuExpanded = false
                            onMoveDown()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("筛选同类型") },
                        leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                        onClick = {
                            menuExpanded = false
                            onFilterType()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("筛选同策略") },
                        leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                        onClick = {
                            menuExpanded = false
                            onFilterPolicy()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("删除") },
                        leadingIcon = { Icon(Icons.Filled.Delete, contentDescription = null) },
                        onClick = {
                            menuExpanded = false
                            onDelete()
                        },
                    )
                }
            }
            OutlinedTextField(
                value = rule.payload,
                onValueChange = { onUpdate(rule.copy(payload = it)) },
                enabled = rule.type != "MATCH",
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text(if (rule.type == "MATCH") "MATCH 无需内容" else "规则内容") },
                placeholder = { Text("example.com / 1.1.1.0/24 / cn") },
            )
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                ChoiceButton(
                    value = rule.proxy,
                    options = policies.ifEmpty { listOf("DIRECT", "REJECT") },
                    modifier = Modifier.weight(1f),
                    onChoose = { onUpdate(rule.copy(proxy = it)) },
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = rule.noResolve,
                        onCheckedChange = { onUpdate(rule.copy(noResolve = it)) },
                    )
                    Text("no-resolve", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
private fun ChoiceButton(
    value: String,
    options: List<String>,
    modifier: Modifier = Modifier,
    onChoose: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    Box(modifier = modifier) {
        TextButton(onClick = { expanded = true }) {
            Text(value.ifBlank { options.firstOrNull().orEmpty() })
            Icon(Icons.Filled.ArrowDropDown, contentDescription = null)
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            options.forEach { option ->
                DropdownMenuItem(
                    text = { Text(option) },
                    onClick = {
                        expanded = false
                        onChoose(option)
                    },
                )
            }
        }
    }
}
