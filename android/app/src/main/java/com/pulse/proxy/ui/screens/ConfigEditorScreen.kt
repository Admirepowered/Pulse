package com.pulse.proxy.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Save
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.pulse.proxy.data.EndpointItem
import com.pulse.proxy.data.RuleActionOption
import com.pulse.proxy.data.RuleConditionOption
import com.pulse.proxy.data.SubscriptionProfile
import com.pulse.proxy.data.VisualRule
import com.pulse.proxy.ui.MainViewModel
import java.util.UUID

@Composable
fun ConfigEditorScreen(
    viewModel: MainViewModel,
    onImportFile: () -> Unit,
    onBack: () -> Unit
) {
    val state by viewModel.configUiState.collectAsState()

    Scaffold(
        topBar = {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton(onClick = onBack) { Text("Back") }
                Spacer(modifier = Modifier.weight(1f))
                TextButton(onClick = { viewModel.refreshConfigurationState() }) {
                    Icon(Icons.Default.Refresh, contentDescription = null)
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Refresh")
                }
            }
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
        ) {
            item {
                Text(
                    text = "Profiles",
                    style = MaterialTheme.typography.headlineMedium,
                    modifier = Modifier.padding(vertical = 8.dp)
                )
                OutlinedTextField(
                    value = state.subscriptionUrl,
                    onValueChange = { viewModel.setSubscriptionUrl(it) },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Profile URL") },
                    singleLine = true
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { viewModel.updateSubscription() },
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Add, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("URL")
                    }
                    Button(
                        onClick = onImportFile,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.FolderOpen, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("File")
                    }
                }
                if (state.statusMessage.isNotBlank()) {
                    Text(
                        text = state.statusMessage,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                }
                Spacer(modifier = Modifier.height(16.dp))
            }

            if (state.subscriptions.isEmpty()) {
                item { EmptyCard("Import a profile from URL or file to get started.") }
            } else {
                items(state.subscriptions, key = { it.id }) { profile ->
                    SubscriptionRow(
                        profile = profile,
                        selected = profile.id == state.selectedSubscriptionId,
                        onClick = { viewModel.selectSubscription(profile.id) }
                    )
                }
            }

            item {
                Spacer(modifier = Modifier.height(16.dp))
                Text("Servers", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Spacer(modifier = Modifier.height(8.dp))
            }

            if (state.endpoints.isEmpty()) {
                item { EmptyCard("No servers found in the selected profile.") }
            } else {
                itemsIndexed(state.endpoints, key = { _, endpoint -> endpoint.reference }) { _, endpoint ->
                    EndpointRow(
                        endpoint = endpoint,
                        selected = endpoint.reference == state.selectedEndpointKey,
                        onClick = { viewModel.selectEndpoint(endpoint.reference) }
                    )
                }
            }
        }
    }
}

@Composable
fun RulesScreen(
    viewModel: MainViewModel,
    onBack: () -> Unit
) {
    val state by viewModel.configUiState.collectAsState()
    var rules by remember(state.visualRules) { mutableStateOf(state.visualRules) }
    var editingRule by remember { mutableStateOf<VisualRule?>(null) }

    Scaffold(
        topBar = {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton(onClick = onBack) { Text("Back") }
                Spacer(modifier = Modifier.weight(1f))
                TextButton(onClick = {
                    editingRule = VisualRule(
                        id = UUID.randomUUID().toString(),
                        name = "New rule",
                        action = RuleActionOption.Proxy,
                        condition = RuleConditionOption.DomainSuffix,
                        value = ""
                    )
                }) {
                    Icon(Icons.Default.Add, contentDescription = null)
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Add")
                }
                Spacer(modifier = Modifier.width(8.dp))
                Button(onClick = {
                    viewModel.saveVisualRules(rules)
                    onBack()
                }) {
                    Icon(Icons.Default.Save, contentDescription = null)
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Save")
                }
            }
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
        ) {
            item {
                Text(
                    text = "Rules",
                    style = MaterialTheme.typography.headlineMedium,
                    modifier = Modifier.padding(vertical = 8.dp)
                )
            }
            if (rules.isEmpty()) {
                item { EmptyCard("No rules. Add a rule and save.") }
            } else {
                itemsIndexed(rules, key = { _, rule -> rule.id }) { index, rule ->
                    RuleRow(
                        rule = rule,
                        canMoveUp = index > 0,
                        canMoveDown = index < rules.lastIndex,
                        onClick = { editingRule = rule },
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
        RuleDialog(
            rule = rule,
            endpoints = state.endpoints,
            onDismiss = { editingRule = null },
            onDelete = {
                rules = rules.filterNot { it.id == rule.id }
                editingRule = null
            },
            onSave = { updated ->
                val exists = rules.any { it.id == updated.id }
                rules = if (exists) {
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
private fun SubscriptionRow(profile: SubscriptionProfile, selected: Boolean, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp)
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface
        )
    ) {
        Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = selected, onClick = onClick)
            Spacer(modifier = Modifier.width(8.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(profile.name, style = MaterialTheme.typography.titleSmall)
                Text(
                    listOf(profile.type.uppercase(), profile.url).joinToString("  "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun EndpointRow(endpoint: EndpointItem, selected: Boolean, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp)
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surface
        )
    ) {
        Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = selected, onClick = onClick)
            Spacer(modifier = Modifier.width(8.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(endpoint.title, style = MaterialTheme.typography.titleSmall)
                Text(
                    listOf(endpoint.type, endpoint.server).filter { it.isNotBlank() }.joinToString(" / "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun RuleRow(
    rule: VisualRule,
    canMoveUp: Boolean,
    canMoveDown: Boolean,
    onClick: () -> Unit,
    onMoveUp: () -> Unit,
    onMoveDown: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp)
            .clickable(onClick = onClick)
    ) {
        Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(rule.name, style = MaterialTheme.typography.titleSmall)
                Text(
                    "${rule.action.label} / ${rule.condition.label} / ${rule.value}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            IconButton(onClick = onMoveUp, enabled = canMoveUp) {
                Icon(Icons.Default.ArrowUpward, contentDescription = null)
            }
            IconButton(onClick = onMoveDown, enabled = canMoveDown) {
                Icon(Icons.Default.ArrowDownward, contentDescription = null)
            }
        }
    }
}

@Composable
private fun RuleDialog(
    rule: VisualRule,
    endpoints: List<EndpointItem>,
    onDismiss: () -> Unit,
    onDelete: () -> Unit,
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
        title = { Text("Rule") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Name") })
                OptionButtons(
                    label = "Action",
                    values = RuleActionOption.entries,
                    selected = action,
                    text = { it.label },
                    onSelect = { action = it }
                )
                OptionButtons(
                    label = "Condition",
                    values = RuleConditionOption.entries,
                    selected = condition,
                    text = { it.label },
                    onSelect = { condition = it }
                )
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it },
                    label = { Text(if (condition == RuleConditionOption.Region) "Region" else "Value, comma separated") }
                )
                if (action == RuleActionOption.Proxy && endpoints.isNotEmpty()) {
                    OptionButtons(
                        label = "Server",
                        values = endpoints,
                        selected = endpoints.firstOrNull { it.reference == endpoint }
                            ?: endpoints.firstOrNull { it.key == endpoint }
                            ?: endpoints.first(),
                        text = { it.title },
                        onSelect = { endpoint = it.reference }
                    )
                }
                if (condition == RuleConditionOption.Region) {
                    TextButton(onClick = { resolve = !resolve }) {
                        Text("Resolve domain: ${if (resolve) "On" else "Off"}")
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = {
                onSave(
                    rule.copy(
                        name = name,
                        action = action,
                        condition = condition,
                        value = value,
                        endpoint = endpoint,
                        resolve = resolve
                    )
                )
            }) { Text("Save") }
        },
        dismissButton = {
            Row {
                TextButton(onClick = onDelete) { Text("Delete") }
                TextButton(onClick = onDismiss) { Text("Cancel") }
            }
        }
    )
}

@Composable
private fun <T> OptionButtons(
    label: String,
    values: List<T>,
    selected: T,
    text: (T) -> String,
    onSelect: (T) -> Unit
) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            values.take(4).forEach { value ->
                TextButton(onClick = { onSelect(value) }) {
                    Text(
                        text = text(value),
                        color = if (value == selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    }
}

@Composable
private fun EmptyCard(message: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Text(
            text = message,
            modifier = Modifier.padding(16.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
