package com.admirepowered.pulse.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cable
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.admirepowered.pulse.ui.screens.ConnectionsScreen
import com.admirepowered.pulse.ui.screens.DashboardScreen
import com.admirepowered.pulse.ui.screens.ProfilesScreen
import com.admirepowered.pulse.ui.screens.ProxiesScreen
import com.admirepowered.pulse.ui.screens.SettingsScreen

@Composable
fun PulseApp(
    state: PulseAppState,
    onToggleVpn: (Boolean) -> Unit,
    onModeChange: (ProxyMode) -> Unit,
    onThemeChange: (ThemeMode) -> Unit,
    onProfileSelect: (String) -> Unit,
    onProxySelect: (String) -> Unit,
    onRefreshProfile: (String) -> Unit,
) {
    val viewModel = androidx.lifecycle.viewmodel.compose.viewModel<PulseAppViewModel>()
    Scaffold(
        bottomBar = {
            NavigationBar {
                PulseScreen.entries.forEach { screen ->
                    NavigationBarItem(
                        selected = state.screen == screen,
                        onClick = { viewModel.setScreen(screen) },
                        icon = { Icon(screen.icon(), contentDescription = screen.label) },
                        label = { Text(screen.label) },
                    )
                }
            }
        },
    ) { padding ->
        val modifier = Modifier.padding(padding)
        when (state.screen) {
            PulseScreen.Dashboard -> DashboardScreen(
                state = state,
                onToggleVpn = onToggleVpn,
                onModeChange = onModeChange,
                modifier = modifier,
            )

            PulseScreen.Profiles -> ProfilesScreen(
                profiles = state.profiles,
                selectedProfileId = state.selectedProfileId,
                refreshingProfileId = state.refreshingProfileId,
                onProfileSelect = onProfileSelect,
                onRefreshProfile = onRefreshProfile,
                modifier = modifier,
            )

            PulseScreen.Proxies -> ProxiesScreen(
                proxies = state.proxies,
                onProxySelect = onProxySelect,
                modifier = modifier,
            )

            PulseScreen.Connections -> ConnectionsScreen(
                connections = state.connections,
                modifier = modifier,
            )

            PulseScreen.Settings -> SettingsScreen(
                state = state,
                onThemeChange = onThemeChange,
                modifier = modifier,
            )
        }
    }
}

private fun PulseScreen.icon() = when (this) {
    PulseScreen.Dashboard -> Icons.Filled.Dashboard
    PulseScreen.Profiles -> Icons.Filled.Storage
    PulseScreen.Proxies -> Icons.Filled.Dns
    PulseScreen.Connections -> Icons.Filled.Cable
    PulseScreen.Settings -> Icons.Filled.Settings
}
