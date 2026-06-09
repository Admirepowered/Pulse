package com.admirepowered.pulse.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.admirepowered.pulse.ui.ProxyMode
import com.admirepowered.pulse.ui.ThemeMode

@Composable
fun ProxyModeChips(
    selected: ProxyMode,
    onModeChange: (ProxyMode) -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(modifier = modifier, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        ProxyMode.entries.forEach { mode ->
            FilterChip(
                selected = selected == mode,
                onClick = { onModeChange(mode) },
                label = { Text(mode.label) },
            )
        }
    }
}

@Composable
fun ThemeModeChips(
    selected: ThemeMode,
    onThemeChange: (ThemeMode) -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(modifier = modifier, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        ThemeMode.entries.forEach { mode ->
            FilterChip(
                selected = selected == mode,
                onClick = { onThemeChange(mode) },
                label = { Text(mode.label) },
            )
        }
    }
}
