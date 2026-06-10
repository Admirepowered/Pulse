package com.admirepowered.pulse

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.viewmodel.compose.viewModel
import com.admirepowered.pulse.core.PulseProfileLinkParser
import com.admirepowered.pulse.ui.PulseApp
import com.admirepowered.pulse.ui.PulseAppViewModel
import com.admirepowered.pulse.ui.components.PulseAppBackground
import com.admirepowered.pulse.ui.theme.PulseTheme
import com.admirepowered.pulse.vpn.PulseVpnService

class MainActivity : ComponentActivity() {
    private val incomingProfileUrls = mutableStateOf<List<String>>(emptyList())
    private val incomingProfileUris = mutableStateOf<List<Uri>>(emptyList())
    private val incomingProfileText = mutableStateOf<String?>(null)
    private val requestVpnStart = mutableStateOf(false)

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermissionIfNeeded()
        consumeIncomingProfileIntent(intent)
        setContent {
            PulseAndroidApp(
                incomingProfileUrls = incomingProfileUrls.value,
                incomingProfileUris = incomingProfileUris.value,
                incomingProfileText = incomingProfileText.value,
                requestVpnStart = requestVpnStart.value,
                onProfileUrlsConsumed = { incomingProfileUrls.value = emptyList() },
                onProfileUrisConsumed = { incomingProfileUris.value = emptyList() },
                onProfileTextConsumed = { incomingProfileText.value = null },
                onRequestVpnStartConsumed = { requestVpnStart.value = false },
                onRequestVpn = {
                    val prepareIntent = VpnService.prepare(this)
                    if (prepareIntent == null) {
                        PulseVpnService.start(this)
                        true
                    } else {
                        false
                    }
                },
                onStopVpn = {
                    PulseVpnService.stop(this)
                },
                onLaunchVpnPermission = { launcher ->
                    VpnService.prepare(this)?.let(launcher::launch)
                },
            )
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        consumeIncomingProfileIntent(intent)
    }

    private fun consumeIncomingProfileIntent(intent: Intent?) {
        requestVpnStart.value = intent?.getBooleanExtra(EXTRA_REQUEST_VPN_START, false) == true
        val urls = PulseProfileLinkParser.extractProfileUrls(intent)
        incomingProfileUrls.value = urls
        incomingProfileUris.value = if (urls.isEmpty()) {
            PulseProfileLinkParser.extractProfileUris(intent)
        } else {
            emptyList()
        }
        incomingProfileText.value = if (urls.isEmpty() && incomingProfileUris.value.isEmpty()) {
            PulseProfileLinkParser.extractProfileText(intent)
        } else {
            null
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return
        notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

}

const val EXTRA_REQUEST_VPN_START = "com.admirepowered.pulse.REQUEST_VPN_START"

@Composable
private fun PulseAndroidApp(
    incomingProfileUrls: List<String>,
    incomingProfileUris: List<Uri>,
    incomingProfileText: String?,
    requestVpnStart: Boolean,
    onProfileUrlsConsumed: () -> Unit,
    onProfileUrisConsumed: () -> Unit,
    onProfileTextConsumed: () -> Unit,
    onRequestVpnStartConsumed: () -> Unit,
    onRequestVpn: () -> Boolean,
    onStopVpn: () -> Unit,
    onLaunchVpnPermission: (androidx.activity.result.ActivityResultLauncher<Intent>) -> Unit,
) {
    val viewModel: PulseAppViewModel = viewModel()
    val context = LocalContext.current
    val state by viewModel.state.collectAsState()
    var autoStartAttempted by rememberSaveable { mutableStateOf(false) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        viewModel.refreshRuntimeStatus()
    }
    LaunchedEffect(incomingProfileUrls) {
        if (incomingProfileUrls.isEmpty()) return@LaunchedEffect
        viewModel.importProfilesFromUrls(incomingProfileUrls)
        onProfileUrlsConsumed()
    }
    LaunchedEffect(incomingProfileUris) {
        if (incomingProfileUris.isEmpty()) return@LaunchedEffect
        viewModel.importProfilesFromUris(incomingProfileUris)
        onProfileUrisConsumed()
    }
    LaunchedEffect(incomingProfileText) {
        val text = incomingProfileText ?: return@LaunchedEffect
        viewModel.importProfileFromText(text)
        onProfileTextConsumed()
    }
    val profileFileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments(),
    ) { uris ->
        viewModel.importProfilesFromUris(uris)
    }
    val backgroundImageLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        viewModel.importBackgroundImage(uri)
    }
    val exportBackupLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        uri?.let(viewModel::exportBackupToUri)
    }
    var pendingExportProfileId by rememberSaveable { mutableStateOf<String?>(null) }
    val exportProfileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/yaml"),
    ) { uri ->
        val profileId = pendingExportProfileId
        pendingExportProfileId = null
        if (uri != null && profileId != null) {
            viewModel.exportProfileContentToUri(profileId, uri)
        }
    }
    var pendingProfileEditorExportText by rememberSaveable { mutableStateOf<String?>(null) }
    val exportProfileEditorLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/yaml"),
    ) { uri ->
        val text = pendingProfileEditorExportText
        pendingProfileEditorExportText = null
        if (uri != null && text != null) {
            viewModel.exportProfileEditorContentToUri(text, uri)
        }
    }
    val importBackupLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        uri?.let(viewModel::importBackupFromUri)
    }
    var pendingLogsExportText by rememberSaveable { mutableStateOf<String?>(null) }
    val exportLogsLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        val text = pendingLogsExportText
        pendingLogsExportText = null
        if (uri != null && text != null) {
            viewModel.exportLogsToUri(text, uri)
        }
    }
    var pendingRulesExportText by rememberSaveable { mutableStateOf<String?>(null) }
    val exportRulesLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        val text = pendingRulesExportText
        pendingRulesExportText = null
        if (uri != null && text != null) {
            viewModel.exportRulesToUri(text, uri)
        }
    }
    var pendingConnectionsExportText by rememberSaveable { mutableStateOf<String?>(null) }
    val exportConnectionsLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        val text = pendingConnectionsExportText
        pendingConnectionsExportText = null
        if (uri != null && text != null) {
            viewModel.exportConnectionsToUri(text, uri)
        }
    }
    var pendingAccessControlExportText by rememberSaveable { mutableStateOf<String?>(null) }
    val exportAccessControlLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        val text = pendingAccessControlExportText
        pendingAccessControlExportText = null
        if (uri != null && text != null) {
            viewModel.exportAccessControlToUri(text, uri)
        }
    }
    val importCustomRulesLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        uri?.let(viewModel::importCustomRulesFromUri)
    }
    var pendingCustomRulesExportText by rememberSaveable { mutableStateOf<String?>(null) }
    val exportCustomRulesLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        val text = pendingCustomRulesExportText
        pendingCustomRulesExportText = null
        if (uri != null && text != null) {
            viewModel.exportCustomRulesToUri(text, uri)
        }
    }
    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            PulseVpnService.start(context)
            viewModel.confirmVpnStart()
        } else {
            viewModel.rejectVpnPermission()
        }
    }
    LaunchedEffect(requestVpnStart, state.vpnRunning) {
        if (!requestVpnStart) return@LaunchedEffect
        onRequestVpnStartConsumed()
        if (state.vpnRunning) return@LaunchedEffect
        if (onRequestVpn()) {
            viewModel.confirmVpnStart()
        } else {
            onLaunchVpnPermission(vpnPermissionLauncher)
        }
    }
    LaunchedEffect(state.autoStartVpn, state.vpnRunning) {
        if (autoStartAttempted || !state.autoStartVpn || state.vpnRunning) return@LaunchedEffect
        autoStartAttempted = true
        if (VpnService.prepare(context) == null) {
            PulseVpnService.start(context)
            viewModel.confirmVpnStart()
        } else {
            viewModel.notifyAutoStartVpnNeedsPermission()
    }
}

    PulseTheme(themeMode = state.themeMode) {
        PulseAppBackground(
            backgroundUri = state.backgroundImageUri,
            backgroundOpacityPercent = state.backgroundOpacityPercent,
            backgroundBlurDp = state.backgroundBlurDp,
        ) {
            PulseApp(
                state = state,
                onScreenChange = viewModel::setScreen,
                onToggleVpn = { enabled ->
                    if (enabled) {
                        if (onRequestVpn()) {
                            viewModel.confirmVpnStart()
                        } else {
                            onLaunchVpnPermission(vpnPermissionLauncher)
                        }
                    } else {
                        onStopVpn()
                        viewModel.setVpnRunning(false)
                    }
                },
                onModeChange = viewModel::setProxyMode,
                onRefreshDashboard = viewModel::refreshDashboard,
                onThemeChange = viewModel::setThemeMode,
                onProfileSelect = viewModel::selectProfile,
                onProxySelect = viewModel::selectProxy,
                onTestProxyDelays = viewModel::testProxyDelays,
                onTestProxyGroupDelays = viewModel::testProxyGroupDelays,
                onTestProxyDelay = viewModel::testProxyDelay,
                onRefreshProfile = viewModel::refreshProfile,
                onRefreshAllProfiles = viewModel::refreshAllProfiles,
                onRefreshAllProfilesWithProxy = viewModel::refreshAllProfilesWithProxy,
                onRefreshProfileWithProxy = viewModel::refreshProfileWithProxy,
                onUpdateProfileSource = viewModel::updateProfileSource,
                onRenameProfile = viewModel::renameProfile,
                onCopyProfileSource = viewModel::copyProfileSource,
                onOpenProfileEditor = viewModel::openProfileEditor,
                onShareProfileContent = viewModel::shareProfileContent,
                onExportProfileContent = { profile ->
                    pendingExportProfileId = profile.id
                    exportProfileLauncher.launch("${profile.name.toSafeProfileFilename()}.yaml")
                },
                onProfileEditorContentChange = viewModel::updateProfileEditorContent,
                onSaveProfileEditor = viewModel::saveProfileEditor,
                onShareProfileEditor = viewModel::shareProfileEditorContent,
                onExportProfileEditorToFile = { text ->
                    pendingProfileEditorExportText = text
                    exportProfileEditorLauncher.launch("${state.editingProfileName.toSafeProfileFilename()}.yaml")
                },
                onCloseProfileEditor = viewModel::closeProfileEditor,
                onDeleteProfile = viewModel::deleteProfile,
                onImportUrlChange = viewModel::updateImportUrl,
                onImportProfile = viewModel::importProfileFromUrl,
                onImportClipboardProfile = viewModel::importProfileFromClipboard,
                onImportProfileFile = {
                    profileFileLauncher.launch(arrayOf("application/yaml", "text/yaml", "text/x-yaml", "text/plain", "*/*"))
                },
                onRefreshLogs = viewModel::refreshLogs,
                onClearLogs = viewModel::clearLogs,
                onShareLogs = viewModel::shareLogs,
                onExportLogsToFile = { text ->
                    pendingLogsExportText = text
                    exportLogsLauncher.launch("pulse-logs.txt")
                },
                onRefreshRules = viewModel::refreshRules,
                onShareRules = viewModel::shareRules,
                onExportRulesToFile = { text ->
                    pendingRulesExportText = text
                    exportRulesLauncher.launch("pulse-rules.yaml")
                },
                onOpenCustomRules = viewModel::openCustomRules,
                onCloseCustomRules = viewModel::closeCustomRules,
                onAddCustomRule = viewModel::addCustomRule,
                onImportCustomRulesFromText = viewModel::importCustomRulesFromText,
                onImportCustomRulesFromFile = {
                    importCustomRulesLauncher.launch(arrayOf("application/yaml", "text/yaml", "text/x-yaml", "text/plain", "*/*"))
                },
                onExportCustomRulesToFile = { text ->
                    pendingCustomRulesExportText = text
                    exportCustomRulesLauncher.launch("pulse-custom-rules.yaml")
                },
                onUpdateCustomRule = viewModel::updateCustomRule,
                onDuplicateCustomRule = viewModel::duplicateCustomRule,
                onMoveCustomRule = viewModel::moveCustomRule,
                onDeleteCustomRule = viewModel::deleteCustomRule,
                onSaveCustomRules = viewModel::saveCustomRules,
                onShareCustomRules = viewModel::shareCustomRules,
                onRefreshProviders = viewModel::refreshProviders,
                onUpdateProvider = viewModel::updateProvider,
                onUpdateAllProviders = viewModel::updateAllProviders,
                onUpdateProviders = viewModel::updateProviders,
                onRefreshConnections = viewModel::refreshConnectionsQuietly,
                onCloseConnection = viewModel::closeConnection,
                onCloseAllConnections = viewModel::closeAllConnections,
                onClearClosedConnections = viewModel::clearClosedConnections,
                onShareConnections = viewModel::shareConnections,
                onExportConnectionsToFile = { text ->
                    pendingConnectionsExportText = text
                    exportConnectionsLauncher.launch("pulse-connections.txt")
                },
                onRestartCore = viewModel::restartCore,
                onAllowLanChange = viewModel::setAllowLan,
                onCoreLogLevelChange = viewModel::setCoreLogLevel,
                onAccessControlModeChange = viewModel::setAccessControlMode,
                onToggleAccessControlApp = viewModel::toggleAccessControlApp,
                onSetAccessControlApps = viewModel::setAccessControlApps,
                onInvertAccessControlApps = viewModel::invertAccessControlApps,
                onShareAccessControl = viewModel::shareAccessControl,
                onExportAccessControlToFile = { text ->
                    pendingAccessControlExportText = text
                    exportAccessControlLauncher.launch("pulse-access-control.txt")
                },
                onAutoStartVpnChange = viewModel::setAutoStartVpn,
                onAutoUpdateProfilesChange = viewModel::setAutoUpdateProfiles,
                onProxyUpdateProfilesChange = viewModel::setProxyUpdateProfiles,
                onDelayTestUrlChange = viewModel::setDelayTestUrl,
                onUpdateExternalResources = viewModel::updateExternalResources,
                onCheckForUpdates = viewModel::checkForUpdates,
                onDownloadAndInstallUpdate = viewModel::downloadAndInstallUpdate,
                onOpenUpdateRelease = viewModel::openUpdateRelease,
                onDisableUpdateCheckChange = viewModel::setDisableUpdateCheck,
                onWebDavEnabledChange = viewModel::setWebDavEnabled,
                onWebDavUrlChange = viewModel::setWebDavUrl,
                onWebDavUsernameChange = viewModel::setWebDavUsername,
                onWebDavPasswordChange = viewModel::setWebDavPassword,
                onUploadWebDavProfiles = viewModel::uploadWebDavProfiles,
                onDownloadWebDavProfiles = viewModel::downloadWebDavProfiles,
                onExportLocalBackup = {
                    exportBackupLauncher.launch("pulse-android-backup.json")
                },
                onImportLocalBackup = {
                    importBackupLauncher.launch(arrayOf("application/json", "text/json", "text/plain", "*/*"))
                },
                onChooseBackground = {
                    backgroundImageLauncher.launch(arrayOf("image/*"))
                },
                onClearBackground = {
                    viewModel.setBackgroundImageUri("")
                },
                onSelectBackground = viewModel::selectBackgroundImage,
                onDeleteBackground = viewModel::deleteBackgroundImage,
                onBackgroundOpacityChange = viewModel::setBackgroundOpacityPercent,
                onBackgroundBlurChange = viewModel::setBackgroundBlurDp,
            )
        }
    }
}

private fun String.toSafeProfileFilename(): String {
    return trim()
        .replace(Regex("""[\\/:*?"<>|]+"""), " ")
        .trim('.', '-', '_', ' ')
        .ifBlank { "pulse-profile" }
}
