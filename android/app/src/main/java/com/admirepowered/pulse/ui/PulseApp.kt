package com.admirepowered.pulse.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.automirrored.filled.ReceiptLong
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
import com.admirepowered.pulse.ui.screens.LogsScreen
import com.admirepowered.pulse.ui.screens.ProfilesScreen
import com.admirepowered.pulse.ui.screens.ProxiesScreen
import com.admirepowered.pulse.ui.screens.SettingsScreen

@Composable
fun PulseApp(
    state: PulseAppState,
    onScreenChange: (PulseScreen) -> Unit,
    onToggleVpn: (Boolean) -> Unit,
    onModeChange: (ProxyMode) -> Unit,
    onThemeChange: (ThemeMode) -> Unit,
    onProfileSelect: (String) -> Unit,
    onProxySelect: (String) -> Unit,
    onTestProxyDelays: () -> Unit,
    onTestProxyDelay: (String) -> Unit,
    onRefreshProfile: (String) -> Unit,
    onDeleteProfile: (String) -> Unit,
    onImportUrlChange: (String) -> Unit,
    onImportProfile: () -> Unit,
    onImportProfileFile: () -> Unit,
    onRefreshLogs: () -> Unit,
    onClearLogs: () -> Unit,
    canRequestQuickTile: Boolean,
    onAddQuickTile: () -> Unit,
    onAllowLanChange: (Boolean) -> Unit,
    onProxyUpdateProfilesChange: (Boolean) -> Unit,
) {
    Scaffold(
        bottomBar = {
            NavigationBar {
                PulseScreen.entries.forEach { screen ->
                    NavigationBarItem(
                        selected = state.screen == screen,
                        onClick = { onScreenChange(screen) },
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
                importUrl = state.importUrl,
                importBusy = state.importBusy,
                message = state.profileMessage,
                onProfileSelect = onProfileSelect,
                onRefreshProfile = onRefreshProfile,
                onDeleteProfile = onDeleteProfile,
                onImportUrlChange = onImportUrlChange,
                onImportProfile = onImportProfile,
                onImportProfileFile = onImportProfileFile,
                modifier = modifier,
            )

            PulseScreen.Proxies -> ProxiesScreen(
                proxies = state.proxies,
                loading = state.loadingProxies,
                measuring = state.measuringProxies,
                measuringProxyId = state.measuringProxyId,
                message = state.proxyMessage,
                onProxySelect = onProxySelect,
                onTestProxyDelays = onTestProxyDelays,
                onTestProxyDelay = onTestProxyDelay,
                modifier = modifier,
            )

            PulseScreen.Connections -> ConnectionsScreen(
                connections = state.connections,
                loading = state.loadingConnections,
                message = state.connectionMessage,
                modifier = modifier,
            )

            PulseScreen.Logs -> LogsScreen(
                logs = state.logs,
                message = state.logMessage,
                onRefresh = onRefreshLogs,
                onClear = onClearLogs,
                modifier = modifier,
            )

            PulseScreen.Settings -> SettingsScreen(
                state = state,
                onThemeChange = onThemeChange,
                canRequestQuickTile = canRequestQuickTile,
                onAddQuickTile = onAddQuickTile,
                onAllowLanChange = onAllowLanChange,
                onProxyUpdateProfilesChange = onProxyUpdateProfilesChange,
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
    PulseScreen.Logs -> Icons.AutoMirrored.Filled.ReceiptLong
    PulseScreen.Settings -> Icons.Filled.Settings
}
