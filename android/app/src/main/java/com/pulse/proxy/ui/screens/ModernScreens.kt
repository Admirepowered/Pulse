package com.pulse.proxy.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.pulse.proxy.data.EndpointItem
import com.pulse.proxy.data.RuleActionOption
import com.pulse.proxy.data.RuleConditionOption
import com.pulse.proxy.data.UiSettings
import com.pulse.proxy.data.VisualRule
import com.pulse.proxy.data.VpnStatus
import com.pulse.proxy.ui.MainViewModel
import com.pulse.proxy.ui.theme.RunningGreen
import com.pulse.proxy.ui.theme.StoppedRed
import java.util.UUID

@Composable
fun DashboardScreen(
    viewModel: MainViewModel,
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit
) {
    val status by viewModel.vpnStatus.collectAsState()
    val config by viewModel.configUiState.collectAsState()
    val settings by viewModel.uiSettings.collectAsState()
    val endpoint = config.endpoints.firstOrNull { it.reference == config.selectedEndpointKey }
        ?: config.endpoints.firstOrNull()

    Background(settings) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Text("仪表盘", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                Text("Pulse Proxy", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(12.dp)
                                    .clip(CircleShape)
                                    .background(if (status.running) RunningGreen else StoppedRed)
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(if (status.running) "VPN 运行中" else "VPN 已停止", fontWeight = FontWeight.SemiBold)
                            Spacer(Modifier.weight(1f))
                            Button(onClick = { if (status.running) onStopVpn() else onStartVpn() }) {
                                Icon(if (status.running) Icons.Default.Stop else Icons.Default.PlayArrow, null)
                                Spacer(Modifier.width(6.dp))
                                Text(if (status.running) "停止" else "启动")
                            }
                        }
                        Text(endpoint?.title ?: "未选择节点", maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(config.selectedSubscription?.name ?: "未选择配置", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            item { StatGrid(status) }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("运行信息", fontWeight = FontWeight.SemiBold)
                        InfoLine("连接数", "${status.activeConnections} / ${settings.maxConnections}")
                        InfoLine("内存", "${formatBytes(status.memoryUsedBytes)} / ${formatBytes(status.memoryMaxBytes)}")
                        InfoLine("Core", if (status.proxyRunning) "Running" else "Stopped")
                        InfoLine("UDP", if (settings.udpDirect) "非 DNS 直连放行" else "仅 DNS relay")
                    }
                }
            }
        }
    }
}

@Composable
fun ProxyScreen(viewModel: MainViewModel) {
    val config by viewModel.configUiState.collectAsState()
    val status by viewModel.vpnStatus.collectAsState()
    val settings by viewModel.uiSettings.collectAsState()
    var query by remember { mutableStateOf("") }
    val endpoints = config.endpoints.filter {
        query.isBlank() ||
            it.title.contains(query, ignoreCase = true) ||
            it.server.contains(query, ignoreCase = true) ||
            it.type.contains(query, ignoreCase = true)
    }

    Background(settings) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            item {
                Text("代理", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                Text("选择当前 Profile 的节点，流量统计来自 TUN 转发层。", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            item {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    label = { Text("搜索节点 / 类型 / 地址") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
            }
            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    AssistChip(onClick = {}, label = { Text("上传 ${formatBytes(status.txBytes)}") })
                    AssistChip(onClick = {}, label = { Text("下载 ${formatBytes(status.rxBytes)}") })
                    AssistChip(onClick = {}, label = { Text("${status.activeConnections} 连接") })
                }
            }
            if (endpoints.isEmpty()) {
                item { EmptyState("当前配置没有可用节点。") }
            } else {
                items(endpoints, key = { it.reference }) { endpoint ->
                    EndpointCard(
                        endpoint = endpoint,
                        selected = endpoint.reference == config.selectedEndpointKey,
                        onClick = { viewModel.selectEndpoint(endpoint.reference) }
                    )
                }
            }
        }
    }
}

@Composable
fun ConfigurationScreen(
    viewModel: MainViewModel,
    onImportFile: () -> Unit
) {
    val config by viewModel.configUiState.collectAsState()
    val settings by viewModel.uiSettings.collectAsState()
    var rules by remember(config.visualRules) { mutableStateOf(config.visualRules) }
    var editingRule by remember { mutableStateOf<VisualRule?>(null) }

    Background(settings) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Text("配置", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                Text("订阅、Profile、规则和基础选项集中管理。", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("订阅导入", fontWeight = FontWeight.SemiBold)
                        OutlinedTextField(
                            value = config.subscriptionUrl,
                            onValueChange = { viewModel.setSubscriptionUrl(it) },
                            label = { Text("订阅 URL") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = { viewModel.updateSubscription() }, modifier = Modifier.weight(1f)) {
                                Icon(Icons.Default.Refresh, null)
                                Spacer(Modifier.width(6.dp))
                                Text("更新")
                            }
                            OutlinedButton(onClick = onImportFile, modifier = Modifier.weight(1f)) {
                                Icon(Icons.Default.FolderOpen, null)
                                Spacer(Modifier.width(6.dp))
                                Text("文件")
                            }
                        }
                        if (config.statusMessage.isNotBlank()) {
                            Text(config.statusMessage, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
            item { SectionTitle("Profiles") }
            if (config.subscriptions.isEmpty()) {
                item { EmptyState("从 URL 或文件导入后，这里会显示 Profile。") }
            } else {
                items(config.subscriptions, key = { it.id }) { profile ->
                    SelectCard(
                        title = profile.name,
                        subtitle = "${profile.type.uppercase()}  ${profile.url}",
                        selected = profile.id == config.selectedSubscriptionId,
                        onClick = { viewModel.selectSubscription(profile.id) }
                    )
                }
            }
            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SectionTitle("规则")
                    Spacer(Modifier.weight(1f))
                    TextButton(onClick = {
                        editingRule = VisualRule(
                            id = UUID.randomUUID().toString(),
                            name = "New rule",
                            action = RuleActionOption.Proxy,
                            condition = RuleConditionOption.DomainSuffix,
                            value = ""
                        )
                    }) {
                        Icon(Icons.Default.Add, null)
                        Text("添加")
                    }
                    Button(onClick = { viewModel.saveVisualRules(rules) }) {
                        Icon(Icons.Default.Save, null)
                        Spacer(Modifier.width(4.dp))
                        Text("保存")
                    }
                }
            }
            if (rules.isEmpty()) {
                item { EmptyState("暂无规则。") }
            } else {
                itemsIndexed(rules, key = { _, rule -> rule.id }) { index, rule ->
                    RuleManageCard(
                        rule = rule,
                        canMoveUp = index > 0,
                        canMoveDown = index < rules.lastIndex,
                        onEdit = { editingRule = rule },
                        onDelete = { rules = rules.filterNot { it.id == rule.id } },
                        onMoveUp = {
                            rules = rules.toMutableList().also {
                                val item = it.removeAt(index)
                                it.add(index - 1, item)
                            }
                        },
                        onMoveDown = {
                            rules = rules.toMutableList().also {
                                val item = it.removeAt(index)
                                it.add(index + 1, item)
                            }
                        }
                    )
                }
            }
        }
    }

    editingRule?.let { rule ->
        RuleEditorDialog(
            rule = rule,
            endpoints = config.endpoints,
            onDismiss = { editingRule = null },
            onSave = { updated ->
                rules = if (rules.any { it.id == updated.id }) {
                    rules.map { if (it.id == updated.id) updated else it }
                } else {
                    rules + updated
                }
                editingRule = null
            }
        )
    }
}

@Composable
fun ToolsScreen(viewModel: MainViewModel) {
    val settings by viewModel.uiSettings.collectAsState()
    val status by viewModel.vpnStatus.collectAsState()
    val logs by viewModel.logEntries.collectAsState()

    Background(settings) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Text("工具", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                Text("外观、限制、诊断和快捷操作。", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("外观", fontWeight = FontWeight.SemiBold)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            listOf("默认", "晨光", "海蓝", "夜色").forEachIndexed { index, label ->
                                FilterChip(
                                    selected = settings.backgroundStyle == index,
                                    onClick = { viewModel.setBackgroundStyle(index) },
                                    label = { Text(label) }
                                )
                            }
                        }
                    }
                }
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("运行限制", fontWeight = FontWeight.SemiBold)
                        Text("最大连接数：${settings.maxConnections}")
                        Slider(
                            value = settings.maxConnections.toFloat(),
                            onValueChange = { viewModel.setMaxConnections(it.toInt()) },
                            valueRange = 64f..2048f,
                            steps = 30
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("非 DNS UDP 直连放行")
                                Text("QUIC、游戏和部分 App UDP 不进入代理核心", color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            Switch(checked = settings.udpDirect, onCheckedChange = { viewModel.setUdpDirect(it) })
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("VPN 自动启动")
                                Text("保存设置，后续可接系统启动逻辑", color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            Switch(checked = settings.vpnAutoStart, onCheckedChange = { viewModel.setVpnAutoStart(it) })
                        }
                    }
                }
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("诊断", fontWeight = FontWeight.SemiBold)
                        InfoLine("内存", "${formatBytes(status.memoryUsedBytes)} / ${formatBytes(status.memoryMaxBytes)}")
                        InfoLine("连接数", status.activeConnections.toString())
                        InfoLine("上传", formatBytes(status.txBytes))
                        InfoLine("下载", formatBytes(status.rxBytes))
                    }
                }
            }
            item { SectionTitle("最近日志") }
            items(logs.takeLast(30).reversed()) { entry ->
                Text(entry.message, style = MaterialTheme.typography.bodySmall)
                Divider()
            }
        }
    }
}

@Composable
private fun Background(settings: UiSettings, content: @Composable () -> Unit) {
    val brush = when (settings.backgroundStyle) {
        1 -> Brush.verticalGradient(listOf(Color(0xFFFFFBF0), Color(0xFFEAF4FF)))
        2 -> Brush.verticalGradient(listOf(Color(0xFFE8F5FF), Color(0xFFF7FBFF)))
        3 -> Brush.verticalGradient(listOf(Color(0xFF111827), Color(0xFF273142)))
        else -> Brush.verticalGradient(listOf(MaterialTheme.colorScheme.background, MaterialTheme.colorScheme.background))
    }
    Box(modifier = Modifier.fillMaxSize().background(brush)) {
        content()
    }
}

@Composable
private fun StatGrid(status: VpnStatus) {
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
        StatCard("上传", formatBytes(status.txBytes), Modifier.weight(1f))
        StatCard("下载", formatBytes(status.rxBytes), Modifier.weight(1f))
    }
}

@Composable
private fun StatCard(label: String, value: String, modifier: Modifier = Modifier) {
    Card(modifier = modifier) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun EndpointCard(endpoint: EndpointItem, selected: Boolean, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface
        )
    ) {
        Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = selected, onClick = onClick)
            Spacer(Modifier.width(8.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(endpoint.title, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text("${endpoint.type}  ${endpoint.server}", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (selected) Icon(Icons.Default.CheckCircle, null, tint = MaterialTheme.colorScheme.primary)
        }
    }
}

@Composable
private fun SelectCard(title: String, subtitle: String, selected: Boolean, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surface
        )
    ) {
        Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = selected, onClick = onClick)
            Spacer(Modifier.width(8.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(title, fontWeight = FontWeight.SemiBold)
                Text(subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun RuleManageCard(
    rule: VisualRule,
    canMoveUp: Boolean,
    canMoveDown: Boolean,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onMoveUp: () -> Unit,
    onMoveDown: () -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth().clickable(onClick = onEdit)) {
        Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(rule.name, fontWeight = FontWeight.SemiBold)
                Text("${rule.action.label} / ${rule.condition.label} / ${rule.value}", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            IconButton(onClick = onMoveUp, enabled = canMoveUp) { Icon(Icons.Default.ArrowUpward, null) }
            IconButton(onClick = onMoveDown, enabled = canMoveDown) { Icon(Icons.Default.ArrowDownward, null) }
            IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, null) }
        }
    }
}

@Composable
private fun RuleEditorDialog(
    rule: VisualRule,
    endpoints: List<EndpointItem>,
    onDismiss: () -> Unit,
    onSave: (VisualRule) -> Unit
) {
    var name by remember(rule.id) { mutableStateOf(rule.name) }
    var action by remember(rule.id) { mutableStateOf(rule.action) }
    var condition by remember(rule.id) { mutableStateOf(rule.condition) }
    var value by remember(rule.id) { mutableStateOf(rule.value) }
    var endpoint by remember(rule.id) { mutableStateOf(rule.endpoint) }
    var resolve by remember(rule.id) { mutableStateOf(rule.resolve) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("编辑规则") },
        text = {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                item { OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("名称") }) }
                item {
                    OptionRow("动作", RuleActionOption.entries, action, { it.label }) { action = it }
                }
                item {
                    OptionRow("条件", RuleConditionOption.entries, condition, { it.label }) { condition = it }
                }
                item {
                    OutlinedTextField(
                        value = value,
                        onValueChange = { value = it },
                        label = { Text("值，可用逗号分隔") }
                    )
                }
                if (action == RuleActionOption.Proxy && endpoints.isNotEmpty()) {
                    item {
                        Text("目标节点", fontWeight = FontWeight.SemiBold)
                        endpoints.take(8).forEach { ep ->
                            SelectCard(
                                title = ep.title,
                                subtitle = ep.server,
                                selected = endpoint == ep.reference,
                                onClick = { endpoint = ep.reference }
                            )
                            Spacer(Modifier.height(6.dp))
                        }
                    }
                }
                if (condition == RuleConditionOption.Region) {
                    item {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("解析域名后匹配区域", modifier = Modifier.weight(1f))
                            Switch(checked = resolve, onCheckedChange = { resolve = it })
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = {
                onSave(rule.copy(name = name, action = action, condition = condition, value = value, endpoint = endpoint, resolve = resolve))
            }) { Text("保存") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } }
    )
}

@Composable
private fun <T> OptionRow(label: String, values: List<T>, selected: T, text: (T) -> String, onSelect: (T) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(label, fontWeight = FontWeight.SemiBold)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            values.forEach { item ->
                FilterChip(selected = item == selected, onClick = { onSelect(item) }, label = { Text(text(item)) })
            }
        }
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
}

@Composable
private fun InfoLine(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun EmptyState(text: String) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Text(text, modifier = Modifier.padding(16.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return "%.1f KB".format(kb)
    val mb = kb / 1024.0
    if (mb < 1024) return "%.1f MB".format(mb)
    return "%.1f GB".format(mb / 1024.0)
}
