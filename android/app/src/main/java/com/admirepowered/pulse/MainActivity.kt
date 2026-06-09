package com.admirepowered.pulse

import android.Manifest
import android.app.Activity
import android.app.StatusBarManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Icon
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
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.viewmodel.compose.viewModel
import com.admirepowered.pulse.core.PulseProfileLinkParser
import com.admirepowered.pulse.quick.PulseTileService
import com.admirepowered.pulse.ui.PulseApp
import com.admirepowered.pulse.ui.PulseAppViewModel
import com.admirepowered.pulse.ui.theme.PulseTheme
import com.admirepowered.pulse.vpn.PulseVpnService

class MainActivity : ComponentActivity() {
    private val incomingProfileUrl = mutableStateOf<String?>(null)

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermissionIfNeeded()
        incomingProfileUrl.value = PulseProfileLinkParser.extractProfileUrl(intent)
        setContent {
            PulseAndroidApp(
                incomingProfileUrl = incomingProfileUrl.value,
                onProfileUrlConsumed = { incomingProfileUrl.value = null },
                canRequestQuickTile = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU,
                onAddQuickTile = ::requestAddQuickTile,
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
        incomingProfileUrl.value = PulseProfileLinkParser.extractProfileUrl(intent)
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return
        notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    private fun requestAddQuickTile() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val manager = getSystemService(StatusBarManager::class.java)
        manager.requestAddTileService(
            ComponentName(this, PulseTileService::class.java),
            getString(R.string.app_name),
            Icon.createWithResource(this, R.drawable.ic_vpn_status),
            mainExecutor,
        ) {}
    }
}

@Composable
private fun PulseAndroidApp(
    incomingProfileUrl: String?,
    onProfileUrlConsumed: () -> Unit,
    canRequestQuickTile: Boolean,
    onAddQuickTile: () -> Unit,
    onRequestVpn: () -> Boolean,
    onStopVpn: () -> Unit,
    onLaunchVpnPermission: (androidx.activity.result.ActivityResultLauncher<Intent>) -> Unit,
) {
    val viewModel: PulseAppViewModel = viewModel()
    val context = LocalContext.current
    val state by viewModel.state.collectAsState()
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        viewModel.refreshRuntimeStatus()
    }
    LaunchedEffect(incomingProfileUrl) {
        val url = incomingProfileUrl ?: return@LaunchedEffect
        viewModel.importProfileFromUrl(url)
        onProfileUrlConsumed()
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

    PulseTheme(themeMode = state.themeMode) {
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
            onThemeChange = viewModel::setThemeMode,
            onProfileSelect = viewModel::selectProfile,
            onProxySelect = viewModel::selectProxy,
            onRefreshProfile = viewModel::refreshProfile,
            onImportUrlChange = viewModel::updateImportUrl,
            onImportProfile = viewModel::importProfileFromUrl,
            canRequestQuickTile = canRequestQuickTile,
            onAddQuickTile = onAddQuickTile,
        )
    }
}
