package com.admirepowered.pulse.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.automirrored.filled.ListAlt
import androidx.compose.material.icons.automirrored.filled.ReceiptLong
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cable
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Inventory2
import androidx.compose.material.icons.filled.EditNote
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import com.admirepowered.pulse.ui.screens.ConnectionsScreen
import com.admirepowered.pulse.ui.screens.AccessControlScreen
import com.admirepowered.pulse.ui.screens.CustomRulesScreen
import com.admirepowered.pulse.ui.screens.DashboardScreen
import com.admirepowered.pulse.ui.screens.LogsScreen
import com.admirepowered.pulse.ui.screens.ProfileEditorScreen
import com.admirepowered.pulse.ui.screens.ProfilesScreen
import com.admirepowered.pulse.ui.screens.ProxiesScreen
import com.admirepowered.pulse.ui.screens.ProvidersScreen
import com.admirepowered.pulse.ui.screens.RulesScreen
import com.admirepowered.pulse.ui.screens.SettingsScreen

@Composable
fun PulseApp(
    state: PulseAppState,
    onScreenChange: (PulseScreen) -> Unit,
    onToggleVpn: (Boolean) -> Unit,
    onModeChange: (ProxyMode) -> Unit,
    onRefreshDashboard: () -> Unit,
    onThemeChange: (ThemeMode) -> Unit,
    onProfileSelect: (String) -> Unit,
    onProxySelect: (String) -> Unit,
    onTestProxyDelays: () -> Unit,
    onTestProxyGroupDelays: (String) -> Unit,
    onTestProxyDelay: (String) -> Unit,
    onRefreshProfile: (String) -> Unit,
    onRefreshAllProfiles: () -> Unit,
    onRefreshAllProfilesWithProxy: (Boolean) -> Unit,
    onRefreshProfileWithProxy: (String, Boolean) -> Unit,
    onUpdateProfileSource: (String, String) -> Unit,
    onRenameProfile: (String, String) -> Unit,
    onCopyProfileSource: (String) -> Unit,
    onOpenProfileEditor: (String) -> Unit,
    onShareProfileContent: (String) -> Unit,
    onExportProfileContent: (ProfileItem) -> Unit,
    onProfileEditorContentChange: (String) -> Unit,
    onSaveProfileEditor: () -> Unit,
    onShareProfileEditor: (String) -> Unit,
    onExportProfileEditorToFile: (String) -> Unit,
    onCloseProfileEditor: () -> Unit,
    onDeleteProfile: (String) -> Unit,
    onImportUrlChange: (String) -> Unit,
    onImportProfile: () -> Unit,
    onImportClipboardProfile: (String) -> Unit,
    onImportProfileFile: () -> Unit,
    onRefreshLogs: () -> Unit,
    onClearLogs: () -> Unit,
    onShareLogs: (String) -> Unit,
    onExportLogsToFile: (String) -> Unit,
    onRefreshRules: () -> Unit,
    onShareRules: (String) -> Unit,
    onExportRulesToFile: (String) -> Unit,
    onOpenCustomRules: () -> Unit,
    onCloseCustomRules: () -> Unit,
    onAddCustomRule: () -> Unit,
    onImportCustomRulesFromText: (String) -> Unit,
    onImportCustomRulesFromFile: () -> Unit,
    onExportCustomRulesToFile: (String) -> Unit,
    onUpdateCustomRule: (Int, CustomRuleItem) -> Unit,
    onDuplicateCustomRule: (Int) -> Unit,
    onMoveCustomRule: (Int, Int) -> Unit,
    onDeleteCustomRule: (Int) -> Unit,
    onSaveCustomRules: () -> Unit,
    onShareCustomRules: (String) -> Unit,
    onRefreshProviders: () -> Unit,
    onUpdateProvider: (String, ProviderKind) -> Unit,
    onUpdateAllProviders: () -> Unit,
    onUpdateProviders: (List<ProviderItem>) -> Unit,
    onRefreshConnections: () -> Unit,
    onCloseConnection: (String) -> Unit,
    onCloseAllConnections: () -> Unit,
    onClearClosedConnections: () -> Unit,
    onShareConnections: (String) -> Unit,
    onExportConnectionsToFile: (String) -> Unit,
    onRestartCore: () -> Unit,
    onAllowLanChange: (Boolean) -> Unit,
    onCoreLogLevelChange: (CoreLogLevel) -> Unit,
    onAccessControlModeChange: (AccessControlMode) -> Unit,
    onToggleAccessControlApp: (String) -> Unit,
    onSetAccessControlApps: (Set<String>, Boolean) -> Unit,
    onInvertAccessControlApps: (Set<String>) -> Unit,
    onShareAccessControl: (String) -> Unit,
    onExportAccessControlToFile: (String) -> Unit,
    onAutoStartVpnChange: (Boolean) -> Unit,
    onAutoUpdateProfilesChange: (Boolean) -> Unit,
    onProxyUpdateProfilesChange: (Boolean) -> Unit,
    onDelayTestUrlChange: (String) -> Unit,
    onUpdateExternalResources: () -> Unit,
    onCheckForUpdates: () -> Unit,
    onDownloadAndInstallUpdate: () -> Unit,
    onOpenUpdateRelease: () -> Unit,
    onDisableUpdateCheckChange: (Boolean) -> Unit,
    onWebDavEnabledChange: (Boolean) -> Unit,
    onWebDavUrlChange: (String) -> Unit,
    onWebDavUsernameChange: (String) -> Unit,
    onWebDavPasswordChange: (String) -> Unit,
    onUploadWebDavProfiles: () -> Unit,
    onDownloadWebDavProfiles: () -> Unit,
    onExportLocalBackup: () -> Unit,
    onImportLocalBackup: () -> Unit,
    onChooseBackground: () -> Unit,
    onClearBackground: () -> Unit,
    onSelectBackground: (String) -> Unit,
    onDeleteBackground: (String) -> Unit,
    onBackgroundOpacityChange: (Int) -> Unit,
    onBackgroundBlurChange: (Int) -> Unit,
) {
    if (
        state.screen == PulseScreen.Connections ||
        state.screen == PulseScreen.Rules ||
        state.screen == PulseScreen.Providers ||
        state.screen == PulseScreen.ProfileEditor ||
        state.screen == PulseScreen.CustomRules ||
        state.screen == PulseScreen.Logs ||
        state.screen == PulseScreen.AccessControl
    ) {
        BackHandler {
            if (state.screen == PulseScreen.ProfileEditor) {
                onCloseProfileEditor()
            } else if (state.screen == PulseScreen.CustomRules) {
                onCloseCustomRules()
            } else {
                onScreenChange(PulseScreen.Settings)
            }
        }
    }
    val bottomScreens = listOf(
        PulseScreen.Dashboard,
        PulseScreen.Profiles,
        PulseScreen.Proxies,
        PulseScreen.Settings,
    )
    Scaffold(
        containerColor = Color.Transparent,
        bottomBar = {
            if (state.screen in bottomScreens) {
                NavigationBar {
                    bottomScreens.forEach { screen ->
                        NavigationBarItem(
                            selected = screen.isSelectedFor(state.screen),
                            onClick = { onScreenChange(screen) },
                            icon = { Icon(screen.icon(), contentDescription = screen.label) },
                            label = { Text(screen.label) },
                        )
                    }
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
                onRestartCore = onRestartCore,
                onRefresh = onRefreshDashboard,
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
                onRefreshAllProfiles = onRefreshAllProfiles,
                onRefreshAllProfilesWithProxy = onRefreshAllProfilesWithProxy,
                onRefreshProfileWithProxy = onRefreshProfileWithProxy,
                onUpdateProfileSource = onUpdateProfileSource,
                onRenameProfile = onRenameProfile,
                onCopyProfileSource = onCopyProfileSource,
                onOpenProfileEditor = onOpenProfileEditor,
                onShareProfileContent = onShareProfileContent,
                onExportProfileContent = onExportProfileContent,
                onDeleteProfile = onDeleteProfile,
                onImportUrlChange = onImportUrlChange,
                onImportProfile = onImportProfile,
                onImportClipboardProfile = onImportClipboardProfile,
                onImportProfileFile = onImportProfileFile,
                modifier = modifier,
            )

            PulseScreen.Proxies -> ProxiesScreen(
                groups = state.proxyGroups,
                loading = state.loadingProxies,
                measuring = state.measuringProxies,
                measuringProxyId = state.measuringProxyId,
                measuringGroupName = state.measuringProxyGroupName,
                message = state.proxyMessage,
                onProxySelect = onProxySelect,
                onTestProxyDelays = onTestProxyDelays,
                onTestProxyGroupDelays = onTestProxyGroupDelays,
                onTestProxyDelay = onTestProxyDelay,
                modifier = modifier,
            )

            PulseScreen.Connections -> ConnectionsScreen(
                connections = state.connections,
                closedConnections = state.closedConnections,
                traffic = state.traffic,
                loading = state.loadingConnections,
                message = state.connectionMessage,
                onBack = { onScreenChange(PulseScreen.Settings) },
                onRefresh = onRefreshConnections,
                onClose = onCloseConnection,
                onCloseAll = onCloseAllConnections,
                onClearClosed = onClearClosedConnections,
                onShare = onShareConnections,
                onExportFile = onExportConnectionsToFile,
                modifier = modifier,
            )

            PulseScreen.Rules -> RulesScreen(
                rules = state.rules,
                loading = state.loadingRules,
                message = state.ruleMessage,
                onBack = { onScreenChange(PulseScreen.Settings) },
                onRefresh = onRefreshRules,
                onOpenCustomRules = onOpenCustomRules,
                onShare = onShareRules,
                onExportFile = onExportRulesToFile,
                modifier = modifier,
            )

            PulseScreen.CustomRules -> CustomRulesScreen(
                rules = state.customRules,
                policies = state.customRulePolicies,
                loading = state.loadingCustomRules,
                saving = state.savingCustomRules,
                message = state.customRuleMessage,
                onBack = onCloseCustomRules,
                onAdd = onAddCustomRule,
                onImportText = onImportCustomRulesFromText,
                onImportFile = onImportCustomRulesFromFile,
                onExportFile = onExportCustomRulesToFile,
                onUpdate = onUpdateCustomRule,
                onDuplicate = onDuplicateCustomRule,
                onMove = onMoveCustomRule,
                onDelete = onDeleteCustomRule,
                onSave = onSaveCustomRules,
                onShare = onShareCustomRules,
                modifier = modifier,
            )

            PulseScreen.Providers -> ProvidersScreen(
                providers = state.providers,
                loading = state.loadingProviders,
                updatingProviderName = state.updatingProviderName,
                message = state.providerMessage,
                onBack = { onScreenChange(PulseScreen.Settings) },
                onRefresh = onRefreshProviders,
                onUpdateProvider = onUpdateProvider,
                onUpdateAllProviders = onUpdateAllProviders,
                onUpdateProviders = onUpdateProviders,
                modifier = modifier,
            )

            PulseScreen.ProfileEditor -> ProfileEditorScreen(
                title = state.editingProfileName,
                content = state.editingProfileContent,
                loading = state.loadingProfileContent,
                saving = state.savingProfileContent,
                message = state.profileEditorMessage,
                onContentChange = onProfileEditorContentChange,
                onSave = onSaveProfileEditor,
                onShare = onShareProfileEditor,
                onExportFile = onExportProfileEditorToFile,
                onBack = onCloseProfileEditor,
                modifier = modifier,
            )

            PulseScreen.Logs -> LogsScreen(
                logs = state.logs,
                message = state.logMessage,
                onRefresh = onRefreshLogs,
                onClear = onClearLogs,
                onShare = onShareLogs,
                onExportFile = onExportLogsToFile,
                onBack = { onScreenChange(PulseScreen.Settings) },
                modifier = modifier,
            )

            PulseScreen.AccessControl -> AccessControlScreen(
                mode = state.accessControlMode,
                apps = state.accessControlApps,
                onModeChange = onAccessControlModeChange,
                onToggleApp = onToggleAccessControlApp,
                onSelectApps = onSetAccessControlApps,
                onInvertSelection = onInvertAccessControlApps,
                onShare = onShareAccessControl,
                onExportFile = onExportAccessControlToFile,
                onBack = { onScreenChange(PulseScreen.Settings) },
                modifier = modifier,
            )

            PulseScreen.Settings -> SettingsScreen(
                state = state,
                onThemeChange = onThemeChange,
                onAllowLanChange = onAllowLanChange,
                onCoreLogLevelChange = onCoreLogLevelChange,
                onAutoStartVpnChange = onAutoStartVpnChange,
                onAutoUpdateProfilesChange = onAutoUpdateProfilesChange,
                onProxyUpdateProfilesChange = onProxyUpdateProfilesChange,
                onDelayTestUrlChange = onDelayTestUrlChange,
                onUpdateExternalResources = onUpdateExternalResources,
                onCheckForUpdates = onCheckForUpdates,
                onDownloadAndInstallUpdate = onDownloadAndInstallUpdate,
                onOpenUpdateRelease = onOpenUpdateRelease,
                onDisableUpdateCheckChange = onDisableUpdateCheckChange,
                onWebDavEnabledChange = onWebDavEnabledChange,
                onWebDavUrlChange = onWebDavUrlChange,
                onWebDavUsernameChange = onWebDavUsernameChange,
                onWebDavPasswordChange = onWebDavPasswordChange,
                onUploadWebDavProfiles = onUploadWebDavProfiles,
                onDownloadWebDavProfiles = onDownloadWebDavProfiles,
                onExportLocalBackup = onExportLocalBackup,
                onImportLocalBackup = onImportLocalBackup,
                onChooseBackground = onChooseBackground,
                onClearBackground = onClearBackground,
                onSelectBackground = onSelectBackground,
                onDeleteBackground = onDeleteBackground,
                onBackgroundOpacityChange = onBackgroundOpacityChange,
                onBackgroundBlurChange = onBackgroundBlurChange,
                onRestartCore = onRestartCore,
                onOpenConnections = { onScreenChange(PulseScreen.Connections) },
                onOpenRules = { onScreenChange(PulseScreen.Rules) },
                onOpenProviders = { onScreenChange(PulseScreen.Providers) },
                onOpenLogs = { onScreenChange(PulseScreen.Logs) },
                onOpenAccessControl = { onScreenChange(PulseScreen.AccessControl) },
                modifier = modifier,
            )
        }
    }
}

private fun PulseScreen.isSelectedFor(current: PulseScreen): Boolean {
    if (this == current) return true
    if (this == PulseScreen.Profiles && current == PulseScreen.ProfileEditor) return true
    return this == PulseScreen.Settings && (
        current == PulseScreen.Connections ||
            current == PulseScreen.Rules ||
            current == PulseScreen.CustomRules ||
            current == PulseScreen.Providers ||
            current == PulseScreen.Logs ||
            current == PulseScreen.AccessControl
    )
}

private fun PulseScreen.icon() = when (this) {
    PulseScreen.Dashboard -> Icons.Filled.Dashboard
    PulseScreen.Profiles -> Icons.Filled.Storage
    PulseScreen.Proxies -> Icons.Filled.Dns
    PulseScreen.Connections -> Icons.Filled.Cable
    PulseScreen.Rules -> Icons.AutoMirrored.Filled.ListAlt
    PulseScreen.Providers -> Icons.Filled.Inventory2
    PulseScreen.ProfileEditor -> Icons.Filled.EditNote
    PulseScreen.CustomRules -> Icons.AutoMirrored.Filled.ListAlt
    PulseScreen.Logs -> Icons.AutoMirrored.Filled.ReceiptLong
    PulseScreen.AccessControl -> Icons.Filled.Settings
    PulseScreen.Settings -> Icons.Filled.Settings
}
