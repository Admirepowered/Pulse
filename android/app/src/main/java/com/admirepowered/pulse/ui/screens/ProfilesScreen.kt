package com.admirepowered.pulse.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.admirepowered.pulse.ui.ProfileItem
import com.admirepowered.pulse.ui.components.PulseRow

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
    onDeleteProfile: (String) -> Unit,
    onImportUrlChange: (String) -> Unit,
    onImportProfile: () -> Unit,
    onImportProfileFile: () -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Text(
                "订阅",
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp),
                style = MaterialTheme.typography.headlineSmall,
            )
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
        items(profiles, key = { it.id }) { profile ->
            val selected = profile.id == selectedProfileId
            Surface(
                color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier
                    .padding(horizontal = 12.dp)
                    .clickable { onProfileSelect(profile.id) },
            ) {
                PulseRow(
                    title = profile.name,
                    subtitle = if (profile.url.isBlank()) {
                        "本地配置 / ${profile.updatedAt}"
                    } else {
                        "远程订阅 / ${profile.updatedAt}"
                    },
                    trailing = {
                        if (refreshingProfileId == profile.id) {
                            CircularProgressIndicator(strokeWidth = 2.dp)
                        } else {
                            IconButton(onClick = { onRefreshProfile(profile.id) }) {
                                Icon(Icons.Filled.Refresh, contentDescription = "更新订阅")
                            }
                        }
                        if (profile.id != "default") {
                            IconButton(onClick = { onDeleteProfile(profile.id) }) {
                                Icon(Icons.Filled.Delete, contentDescription = "删除订阅")
                            }
                        }
                        AnimatedVisibility(selected) {
                            Icon(Icons.Filled.Check, contentDescription = "当前订阅")
                        }
                    },
                )
            }
        }
    }
}
