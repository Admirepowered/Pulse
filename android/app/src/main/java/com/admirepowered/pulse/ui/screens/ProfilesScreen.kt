package com.admirepowered.pulse.ui.screens

import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Route
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.WifiOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
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
import com.admirepowered.pulse.ui.ProfileItem
import com.admirepowered.pulse.ui.SubscriptionInfoItem

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ProfilesScreen(
    profiles: List<ProfileItem>,
    selectedProfileId: String,
    refreshingProfileId: String?,
    importUrl: String,
    importBusy: Boolean,
    message: String,
    onProfileSelect: (String) -> Unit,
    onRefreshProfile: (String) -> Unit,
    onRefreshAllProfiles: () -> Unit,
    onRefreshAllProfilesWithProxy: (Boolean) -> Unit,
    onRefreshProfileWithProxy: (String, Boolean) -> Unit,
    onUpdateProfileSource: (String, String) -> Unit,
    onRenameProfile: (String, String) -> Unit,
    onCopyProfileSource: (String) -> Unit,
    onShareProfileContent: (String) -> Unit,
    onExportProfileContent: (ProfileItem) -> Unit,
    onDeleteProfile: (String) -> Unit,
    onImportUrlChange: (String) -> Unit,
    onImportProfile: () -> Unit,
    onImportClipboardProfile: (String) -> Unit,
    onImportProfileFile: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    var editingProfile by remember { mutableStateOf<ProfileItem?>(null) }
    var editingUrl by remember { mutableStateOf("") }
    var renamingProfile by remember { mutableStateOf<ProfileItem?>(null) }
    var editingName by remember { mutableStateOf("") }
    var deletingProfile by remember { mutableStateOf<ProfileItem?>(null) }
    var updateAllMenuExpanded by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    val queryMatchedProfiles = remember(profiles, query) {
        val keyword = query.trim().lowercase()
        profiles
            .filter { profile ->
                keyword.isBlank() || profile.searchText().lowercase().contains(keyword)
            }
    }
    val filteredProfiles = queryMatchedProfiles

    deletingProfile?.let { profile ->
        AlertDialog(
            onDismissRequest = { deletingProfile = null },
            title = { Text("删除订阅") },
            text = {
                Text("确定删除「${profile.name}」吗？配置文件会从 Pulse 数据目录移除。")
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        onDeleteProfile(profile.id)
                        deletingProfile = null
                    },
                ) {
                    Text("删除")
                }
            },
            dismissButton = {
                TextButton(onClick = { deletingProfile = null }) {
                    Text("取消")
                }
            },
        )
    }

    fun commitRename(profile: ProfileItem) {
        val nextName = editingName.trim()
        if (nextName.isBlank()) return
        if (nextName != profile.name) {
            onRenameProfile(profile.id, nextName)
        }
        renamingProfile = null
        editingName = ""
    }

    fun commitProfileUrl(profile: ProfileItem) {
        val nextUrl = editingUrl.trim()
        if (nextUrl.isBlank()) return
        if (nextUrl != profile.url) {
            onUpdateProfileSource(profile.id, nextUrl)
        }
        editingProfile = null
        editingUrl = ""
    }


    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Row(
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "订阅",
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.headlineSmall,
                )
                IconButton(
                    onClick = onRefreshAllProfiles,
                    enabled = profiles.any { it.url.isNotBlank() } && refreshingProfileId == null && !importBusy,
                ) {
                    Icon(Icons.Filled.Refresh, contentDescription = "更新全部订阅")
                }
                IconButton(
                    onClick = { updateAllMenuExpanded = true },
                    enabled = profiles.any { it.url.isNotBlank() } && refreshingProfileId == null && !importBusy,
                ) {
                    Icon(Icons.Filled.MoreVert, contentDescription = "全部更新选项")
                }
                DropdownMenu(
                    expanded = updateAllMenuExpanded,
                    onDismissRequest = { updateAllMenuExpanded = false },
                ) {
                    DropdownMenuItem(
                        text = { Text("按设置更新全部") },
                        leadingIcon = { Icon(Icons.Filled.Refresh, contentDescription = null) },
                        onClick = {
                            updateAllMenuExpanded = false
                            onRefreshAllProfiles()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("全部通过代理更新") },
                        leadingIcon = { Icon(Icons.Filled.Route, contentDescription = null) },
                        onClick = {
                            updateAllMenuExpanded = false
                            onRefreshAllProfilesWithProxy(true)
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("全部直连更新") },
                        leadingIcon = { Icon(Icons.Filled.WifiOff, contentDescription = null) },
                        onClick = {
                            updateAllMenuExpanded = false
                            onRefreshAllProfilesWithProxy(false)
                        },
                    )
                }
            }
        }
        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = importUrl,
                    onValueChange = onImportUrlChange,
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    label = { Text("订阅 URL") },
                    placeholder = { Text("https://example.com/config.yaml") },
                    trailingIcon = {
                        if (importUrl.isNotBlank()) {
                            IconButton(onClick = { onImportUrlChange("") }) {
                                Icon(Icons.Filled.Close, contentDescription = "清空订阅 URL")
                            }
                        }
                    },
                )
                FilledIconButton(
                    onClick = onImportProfile,
                    enabled = !importBusy,
                ) {
                    if (importBusy) {
                        CircularProgressIndicator(strokeWidth = 2.dp)
                    } else {
                        Icon(Icons.Filled.Add, contentDescription = "导入订阅")
                    }
                }
                IconButton(
                    onClick = {
                        clipboard.getText()?.text?.let(onImportClipboardProfile)
                    },
                    enabled = !importBusy,
                ) {
                    Icon(Icons.Filled.ContentPaste, contentDescription = "从剪贴板导入")
                }
                IconButton(
                    onClick = onImportProfileFile,
                    enabled = !importBusy,
                ) {
                    Icon(Icons.Filled.FolderOpen, contentDescription = "导入本地配置")
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
                    .padding(horizontal = 12.dp),
                singleLine = true,
                leadingIcon = {
                    Icon(Icons.Filled.Search, contentDescription = null)
                },
                trailingIcon = {
                    if (query.isNotBlank()) {
                        IconButton(onClick = { query = "" }) {
                            Icon(Icons.Filled.Close, contentDescription = "清空搜索")
                        }
                    }
                },
                placeholder = { Text("搜索订阅名称、URL、流量或到期时间") },
            )
        }
        if (filteredProfiles.isEmpty()) {
            item {
                Text(
                    if (profiles.isEmpty()) "暂无订阅" else "没有匹配的订阅",
                    modifier = Modifier.padding(horizontal = 20.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
        items(filteredProfiles, key = { it.id }) { profile ->
            val selected = profile.id == selectedProfileId
            var actionMenuExpanded by remember(profile.id) { mutableStateOf(false) }
            Surface(
                color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier
                    .padding(horizontal = 12.dp)
                    .combinedClickable(
                        enabled = renamingProfile?.id != profile.id && editingProfile?.id != profile.id,
                        onClick = { onProfileSelect(profile.id) },
                        onLongClick = { actionMenuExpanded = true },
                    ),
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(
                            modifier = Modifier.weight(1f),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            if (renamingProfile?.id == profile.id) {
                                Row(
                                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    OutlinedTextField(
                                        value = editingName,
                                        onValueChange = { editingName = it },
                                        modifier = Modifier.weight(1f),
                                        singleLine = true,
                                        label = { Text("订阅名称") },
                                    )
                                    IconButton(
                                        onClick = { commitRename(profile) },
                                        enabled = editingName.isNotBlank(),
                                    ) {
                                        Icon(Icons.Filled.Check, contentDescription = "保存订阅名称")
                                    }
                                    IconButton(
                                        onClick = {
                                            renamingProfile = null
                                            editingName = ""
                                        },
                                    ) {
                                        Icon(Icons.Filled.Close, contentDescription = "取消重命名")
                                    }
                                }
                            } else {
                                Text(profile.name, style = MaterialTheme.typography.titleMedium)
                            }
                            Text(
                                profileMeta(profile),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.secondary,
                            )
                            if (editingProfile?.id == profile.id) {
                                Row(
                                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    OutlinedTextField(
                                        value = editingUrl,
                                        onValueChange = { editingUrl = it },
                                        modifier = Modifier.weight(1f),
                                        singleLine = true,
                                        label = { Text("订阅 URL") },
                                        placeholder = { Text("https://example.com/config.yaml") },
                                    )
                                    IconButton(
                                        onClick = { commitProfileUrl(profile) },
                                        enabled = editingUrl.isNotBlank(),
                                    ) {
                                        Icon(Icons.Filled.Check, contentDescription = "保存订阅 URL")
                                    }
                                    IconButton(
                                        onClick = {
                                            editingProfile = null
                                            editingUrl = ""
                                        },
                                    ) {
                                        Icon(Icons.Filled.Close, contentDescription = "取消编辑 URL")
                                    }
                                }
                            }
                        }
                        if (refreshingProfileId == profile.id) {
                            CircularProgressIndicator(strokeWidth = 2.dp)
                        } else {
                            IconButton(onClick = { onRefreshProfile(profile.id) }) {
                                Icon(Icons.Filled.Refresh, contentDescription = "更新订阅")
                            }
                        }
                        ProfileActionsMenu(
                            profile = profile,
                            canEdit = profile.id != "default" && profile.url.isNotBlank(),
                            canDelete = profile.id != "default",
                            onEdit = {
                                editingProfile = profile
                                editingUrl = profile.url
                            },
                            onRename = {
                                renamingProfile = profile
                                editingName = profile.name
                            },
                            onCopySource = { onCopyProfileSource(profile.id) },
                            onShareProfileContent = { onShareProfileContent(profile.id) },
                            onExportProfileContent = { onExportProfileContent(profile) },
                            onRefreshWithProxy = { onRefreshProfileWithProxy(profile.id, true) },
                            onRefreshDirect = { onRefreshProfileWithProxy(profile.id, false) },
                            onDelete = { deletingProfile = profile },
                            expandedOverride = actionMenuExpanded,
                            onExpandedChange = { actionMenuExpanded = it },
                        )
                        AnimatedVisibility(selected) {
                            Icon(Icons.Filled.Check, contentDescription = "当前订阅")
                        }
                    }
                    SubscriptionUsageBar(profile.subscription)
                }
            }
        }
    }
}

@Composable
private fun ProfileActionsMenu(
    profile: ProfileItem,
    canEdit: Boolean,
    canDelete: Boolean,
    onEdit: () -> Unit,
    onRename: () -> Unit,
    onCopySource: () -> Unit,
    onShareProfileContent: () -> Unit,
    onExportProfileContent: () -> Unit,
    onRefreshWithProxy: () -> Unit,
    onRefreshDirect: () -> Unit,
    onDelete: () -> Unit,
    expandedOverride: Boolean? = null,
    onExpandedChange: ((Boolean) -> Unit)? = null,
) {
    var internalExpanded by remember { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val expanded = expandedOverride ?: internalExpanded
    fun setExpanded(value: Boolean) {
        if (onExpandedChange != null) {
            onExpandedChange(value)
        } else {
            internalExpanded = value
        }
    }
    IconButton(onClick = { setExpanded(true) }) {
        Icon(Icons.Filled.MoreVert, contentDescription = "订阅操作")
    }
    DropdownMenu(
        expanded = expanded,
        onDismissRequest = { setExpanded(false) },
    ) {
        DropdownMenuItem(
            text = { Text("重命名") },
            leadingIcon = { Icon(Icons.Filled.Edit, contentDescription = null) },
            onClick = {
                setExpanded(false)
                onRename()
            },
        )
        DropdownMenuItem(
            text = { Text("复制 URL") },
            leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
            enabled = profile.url.isNotBlank(),
            onClick = {
                setExpanded(false)
                onCopySource()
            },
        )
        DropdownMenuItem(
            text = { Text("复制订阅信息") },
            leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
            onClick = {
                setExpanded(false)
                clipboard.setText(AnnotatedString(profile.toSubscriptionInfoText()))
                Toast.makeText(context, "订阅信息已复制", Toast.LENGTH_SHORT).show()
            },
        )
        DropdownMenuItem(
            text = { Text("编辑 URL") },
            leadingIcon = { Icon(Icons.Filled.Edit, contentDescription = null) },
            enabled = canEdit,
            onClick = {
                setExpanded(false)
                onEdit()
            },
        )
        DropdownMenuItem(
            text = { Text("分享配置") },
            leadingIcon = { Icon(Icons.Filled.Share, contentDescription = null) },
            onClick = {
                setExpanded(false)
                onShareProfileContent()
            },
        )
        DropdownMenuItem(
            text = { Text("导出配置") },
            leadingIcon = { Icon(Icons.Filled.Download, contentDescription = null) },
            onClick = {
                setExpanded(false)
                onExportProfileContent()
            },
        )
        DropdownMenuItem(
            text = { Text("通过代理更新") },
            leadingIcon = { Icon(Icons.Filled.Route, contentDescription = null) },
            enabled = profile.url.isNotBlank(),
            onClick = {
                setExpanded(false)
                onRefreshWithProxy()
            },
        )
        DropdownMenuItem(
            text = { Text("直连更新") },
            leadingIcon = { Icon(Icons.Filled.WifiOff, contentDescription = null) },
            enabled = profile.url.isNotBlank(),
            onClick = {
                setExpanded(false)
                onRefreshDirect()
            },
        )
        DropdownMenuItem(
            text = { Text("删除") },
            leadingIcon = { Icon(Icons.Filled.Delete, contentDescription = null) },
            enabled = canDelete,
            onClick = {
                setExpanded(false)
                onDelete()
            },
        )
    }
}

@Composable
private fun SubscriptionUsageBar(subscription: SubscriptionInfoItem) {
    if (!subscription.hasData) return
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        if (subscription.total.isNotBlank()) {
            LinearProgressIndicator(
                progress = { subscription.percent / 100f },
                modifier = Modifier.fillMaxWidth(),
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    "已用 ${subscription.used}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
                Text(
                    "可用 ${subscription.available} / 总量 ${subscription.total}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        } else {
            Text(
                "流量信息未提供",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.secondary,
            )
        }
        Text(
            "到期 ${subscription.expire}",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.secondary,
        )
        if (subscription.updateInterval.isNotBlank()) {
            Text(
                "更新间隔 ${subscription.updateInterval}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.secondary,
            )
        }
    }
}

private fun profileMeta(profile: ProfileItem): String {
    val type = if (profile.url.isBlank()) "本地配置" else "远程订阅"
    return "$type / ${profile.updatedAt}"
}

private fun ProfileItem.toSubscriptionInfoText(): String {
    val info = subscription
    return buildString {
        appendLine(name)
        appendLine(profileMeta(this@toSubscriptionInfoText))
        if (url.isNotBlank()) appendLine("URL: $url")
        if (!info.hasData) {
            appendLine("订阅信息: 未提供")
        } else {
            appendLine("已用: ${info.used.ifBlank { "-" }}")
            appendLine("可用: ${info.available.ifBlank { "-" }}")
            appendLine("总量: ${info.total.ifBlank { "-" }}")
            appendLine("使用率: ${"%.1f".format(info.percent)}%")
            appendLine("到期: ${info.expire.ifBlank { "-" }}")
            if (info.updateInterval.isNotBlank()) {
                appendLine("更新间隔: ${info.updateInterval}")
            }
        }
    }.trimEnd()
}

private fun ProfileItem.searchText(): String {
    val subscription = subscription
    return listOf(
        name,
        profileMeta(this),
        subscription.used,
        subscription.available,
        subscription.total,
        subscription.expire,
        subscription.updateInterval,
    ).joinToString(" ")
}
