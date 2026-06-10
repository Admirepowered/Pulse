package com.admirepowered.pulse.ui.screens

import android.graphics.Bitmap
import android.graphics.Canvas as AndroidCanvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.widget.Toast
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DoneAll
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ElevatedFilterChip
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.TextButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.admirepowered.pulse.ui.AccessControlMode
import com.admirepowered.pulse.ui.AppAccessItem
import com.admirepowered.pulse.ui.components.PulseRow

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun AccessControlScreen(
    mode: AccessControlMode,
    apps: List<AppAccessItem>,
    onModeChange: (AccessControlMode) -> Unit,
    onToggleApp: (String) -> Unit,
    onSelectApps: (Set<String>, Boolean) -> Unit,
    onInvertSelection: (Set<String>) -> Unit,
    onShare: (String) -> Unit,
    onExportFile: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val clipboardManager = LocalClipboardManager.current
    val context = LocalContext.current
    var query by remember { mutableStateOf("") }
    var appKindFilter by remember { mutableStateOf(AppKindFilter.User) }
    val selectedCount = apps.count { it.selected }
    val selectedApps = remember(apps) {
        apps.filter { it.selected }
    }
    val modeDescription = when (mode) {
        AccessControlMode.Off -> "当前不限制应用，勾选列表会保留，开启后立即生效。"
        AccessControlMode.Include -> "白名单模式：只代理勾选的应用。"
        AccessControlMode.Exclude -> "黑名单模式：勾选的应用会绕过代理。"
    }
    val queryMatchedApps = remember(apps, query) {
        val keyword = query.trim().lowercase()
        apps.filter { app ->
            keyword.isBlank() ||
                app.label.lowercase().contains(keyword) ||
                app.packageName.lowercase().contains(keyword)
        }
    }
    val appKindFilterCounts = remember(queryMatchedApps) {
        AppKindFilter.entries.associateWith { item -> item.count(queryMatchedApps) }
    }
    val kindMatchedApps = remember(queryMatchedApps, appKindFilter) {
        queryMatchedApps.filter { app -> appKindFilter.matches(app) }
    }
    val filteredApps = kindMatchedApps
    val filteredPackageNames = remember(filteredApps) {
        filteredApps.map { it.packageName }.toSet()
    }
    val currentListText = remember(mode, filteredApps) {
        filteredApps.toAccessControlText("Pulse 访问控制 - 当前列表", mode)
    }
    val selectedListText = remember(mode, selectedApps) {
        selectedApps.toAccessControlText("Pulse 访问控制 - 已选应用", mode)
    }
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回设置")
                }
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text("访问控制", style = MaterialTheme.typography.headlineSmall)
                    Text(
                        "已选择 $selectedCount/${apps.size} 个应用",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.secondary,
                    )
                }
            }
        }
        item {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("控制模式", style = MaterialTheme.typography.titleMedium)
                Row(
                    modifier = Modifier.horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    AccessModeChip(
                        selected = mode == AccessControlMode.Exclude,
                        text = AccessControlMode.Exclude.label,
                        onClick = { onModeChange(AccessControlMode.Exclude) },
                    )
                    AccessModeChip(
                        selected = mode == AccessControlMode.Include,
                        text = AccessControlMode.Include.label,
                        onClick = { onModeChange(AccessControlMode.Include) },
                    )
                    AccessModeChip(
                        selected = mode == AccessControlMode.Off,
                        text = "关闭",
                        onClick = { onModeChange(AccessControlMode.Off) },
                    )
                }
                Text(
                    modeDescription,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
        item {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("搜索应用") },
                placeholder = { Text("应用名或包名") },
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
            )
        }
        item {
            Row(
                modifier = Modifier.horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                AppKindFilter.entries.forEach { item ->
                    FilterChip(
                        selected = appKindFilter == item,
                        onClick = { appKindFilter = item },
                        label = { Text(item.label(appKindFilterCounts[item] ?: 0)) },
                    )
                }
            }
        }
        item {
            Row(
                modifier = Modifier.horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                TextButton(onClick = { onSelectApps(filteredPackageNames, true) }, enabled = filteredApps.isNotEmpty()) {
                    Icon(
                        Icons.Filled.DoneAll,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(Modifier.width(6.dp))
                    Text("全选")
                }
                TextButton(
                    onClick = { onSelectApps(filteredPackageNames, false) },
                    enabled = filteredApps.any { it.selected },
                ) {
                    Text("清空")
                }
                TextButton(
                    onClick = { onInvertSelection(filteredPackageNames) },
                    enabled = filteredApps.isNotEmpty(),
                ) {
                    Icon(
                        Icons.Filled.SwapHoriz,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(Modifier.width(6.dp))
                    Text("反选")
                }
            }
        }
        item {
            Row(
                modifier = Modifier.horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                TextButton(
                    onClick = {
                        clipboardManager.setText(AnnotatedString(currentListText))
                        Toast.makeText(context, "当前列表已复制", Toast.LENGTH_SHORT).show()
                    },
                    enabled = filteredApps.isNotEmpty(),
                ) {
                    Icon(
                        Icons.Filled.ContentCopy,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(Modifier.width(6.dp))
                    Text("复制当前")
                }
                TextButton(
                    onClick = { onShare(currentListText) },
                    enabled = filteredApps.isNotEmpty(),
                ) {
                    Icon(
                        Icons.Filled.Share,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(Modifier.width(6.dp))
                    Text("分享当前")
                }
                TextButton(
                    onClick = { onExportFile(currentListText) },
                    enabled = filteredApps.isNotEmpty(),
                ) {
                    Icon(
                        Icons.Filled.Download,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(Modifier.width(6.dp))
                    Text("导出当前")
                }
                TextButton(
                    onClick = {
                        clipboardManager.setText(AnnotatedString(selectedListText))
                        Toast.makeText(context, "已选应用已复制", Toast.LENGTH_SHORT).show()
                    },
                    enabled = selectedApps.isNotEmpty(),
                ) {
                    Icon(
                        Icons.Filled.ContentCopy,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(Modifier.width(6.dp))
                    Text("复制已选")
                }
                TextButton(
                    onClick = { onShare(selectedListText) },
                    enabled = selectedApps.isNotEmpty(),
                ) {
                    Icon(
                        Icons.Filled.Share,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                    )
                    Spacer(Modifier.width(6.dp))
                    Text("分享已选")
                }
            }
        }
        item {
            Text("应用列表", style = MaterialTheme.typography.titleMedium)
        }
        if (filteredApps.isEmpty()) {
            item {
                Text(
                    if (query.isBlank()) "没有可选择的应用" else "没有匹配的应用",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
        items(filteredApps, key = { it.packageName }) { app ->
            var appMenuExpanded by remember(app.packageName) { mutableStateOf(false) }
            PulseRow(
                title = app.label,
                subtitle = "${if (app.systemApp) "系统应用" else "用户应用"} · ${app.packageName}",
                modifier = Modifier.combinedClickable(
                    onClick = { onToggleApp(app.packageName) },
                    onLongClick = { appMenuExpanded = true },
                ),
                leading = {
                    AppIcon(packageName = app.packageName, label = app.label)
                },
                trailing = {
                    Box {
                        Checkbox(
                            checked = app.selected,
                            onCheckedChange = { onToggleApp(app.packageName) },
                        )
                        DropdownMenu(
                            expanded = appMenuExpanded,
                            onDismissRequest = { appMenuExpanded = false },
                        ) {
                            DropdownMenuItem(
                                text = { Text(if (app.selected) "取消选中" else "选中应用") },
                                leadingIcon = {
                                    Icon(
                                        if (app.selected) Icons.Filled.Close else Icons.Filled.DoneAll,
                                        contentDescription = null,
                                    )
                                },
                                onClick = {
                                    appMenuExpanded = false
                                    onSelectApps(setOf(app.packageName), !app.selected)
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("复制应用信息") },
                                leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                                onClick = {
                                    appMenuExpanded = false
                                    clipboardManager.setText(AnnotatedString(app.toAccessControlLine()))
                                    Toast.makeText(context, "应用信息已复制", Toast.LENGTH_SHORT).show()
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("复制包名") },
                                leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null) },
                                onClick = {
                                    appMenuExpanded = false
                                    clipboardManager.setText(AnnotatedString(app.packageName))
                                    Toast.makeText(context, "应用包名已复制", Toast.LENGTH_SHORT).show()
                                },
                            )
                        }
                    }
                },
            )
        }
    }
}

@Composable
private fun AccessModeChip(
    selected: Boolean,
    text: String,
    onClick: () -> Unit,
) {
    if (selected) {
        ElevatedFilterChip(
            selected = true,
            onClick = onClick,
            label = { Text(text) },
        )
    } else {
        FilterChip(
            selected = false,
            onClick = onClick,
            label = { Text(text) },
        )
    }
}

private enum class AppKindFilter {
    User,
    System,
}

private fun AppKindFilter.matches(app: AppAccessItem): Boolean {
    return when (this) {
        AppKindFilter.User -> !app.systemApp
        AppKindFilter.System -> app.systemApp
    }
}

private fun AppKindFilter.count(apps: List<AppAccessItem>): Int {
    return when (this) {
        AppKindFilter.User -> apps.count { !it.systemApp }
        AppKindFilter.System -> apps.count { it.systemApp }
    }
}

private fun AppKindFilter.label(count: Int): String {
    return when (this) {
        AppKindFilter.User -> "用户应用 $count"
        AppKindFilter.System -> "系统应用 $count"
    }
}

@Composable
private fun AppIcon(packageName: String, label: String) {
    val context = LocalContext.current
    val image = remember(packageName) {
        runCatching {
            context.packageManager.getApplicationIcon(packageName).toImageBitmap()
        }.getOrNull()
    }
    if (image != null) {
        Image(
            bitmap = image,
            contentDescription = "$label 图标",
            modifier = Modifier.size(40.dp),
        )
    }
}

private fun Drawable.toImageBitmap(): ImageBitmap {
    if (this is BitmapDrawable && bitmap != null) {
        return bitmap.asImageBitmap()
    }
    val width = intrinsicWidth.takeIf { it > 0 } ?: 48
    val height = intrinsicHeight.takeIf { it > 0 } ?: 48
    val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
    val canvas = AndroidCanvas(bitmap)
    setBounds(0, 0, canvas.width, canvas.height)
    draw(canvas)
    return bitmap.asImageBitmap()
}

private fun List<AppAccessItem>.toAccessControlText(title: String, mode: AccessControlMode): String {
    val appList = this
    return buildString {
        appendLine(title)
        appendLine("模式: ${mode.label}")
        appendLine("数量: ${appList.size}")
        appList.forEach { app ->
            appendLine(app.toAccessControlLine())
        }
    }.trimEnd()
}

private fun AppAccessItem.toAccessControlLine(): String {
    val kind = if (systemApp) "系统应用" else "用户应用"
    return "${if (selected) "[x]" else "[ ]"} $label\t$kind\t$packageName"
}
