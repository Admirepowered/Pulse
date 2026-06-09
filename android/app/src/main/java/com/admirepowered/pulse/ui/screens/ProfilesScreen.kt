package com.admirepowered.pulse.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.admirepowered.pulse.ui.ProfileItem
import com.admirepowered.pulse.ui.components.PulseRow

@Composable
fun ProfilesScreen(
    profiles: List<ProfileItem>,
    selectedProfileId: String,
    refreshingProfileId: String?,
    onProfileSelect: (String) -> Unit,
    onRefreshProfile: (String) -> Unit,
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
                    subtitle = "${profile.providerCount} 个策略组 / ${profile.ruleCount} 条规则 / ${profile.updatedAt}",
                    trailing = {
                        if (refreshingProfileId == profile.id) {
                            CircularProgressIndicator(strokeWidth = 2.dp)
                        } else {
                            IconButton(onClick = { onRefreshProfile(profile.id) }) {
                                Icon(Icons.Filled.Refresh, contentDescription = "更新订阅")
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
