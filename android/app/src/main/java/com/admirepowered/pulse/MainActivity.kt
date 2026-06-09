package com.admirepowered.pulse

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.viewmodel.compose.viewModel
import com.admirepowered.pulse.ui.PulseApp
import com.admirepowered.pulse.ui.PulseAppViewModel
import com.admirepowered.pulse.ui.theme.PulseTheme
import com.admirepowered.pulse.vpn.PulseVpnService

class MainActivity : ComponentActivity() {
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermissionIfNeeded()
        setContent {
            PulseAndroidApp(
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

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return
        notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
    }
}

@Composable
private fun PulseAndroidApp(
    onRequestVpn: () -> Boolean,
    onStopVpn: () -> Unit,
    onLaunchVpnPermission: (androidx.activity.result.ActivityResultLauncher<Intent>) -> Unit,
) {
    val viewModel: PulseAppViewModel = viewModel()
    val context = LocalContext.current
    val state by viewModel.state.collectAsState()
    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) {
        PulseVpnService.start(context)
        viewModel.setVpnRunning(true)
    }

    PulseTheme(themeMode = state.themeMode) {
        PulseApp(
            state = state,
            onScreenChange = viewModel::setScreen,
            onToggleVpn = { enabled ->
                if (enabled) {
                    if (onRequestVpn()) {
                        viewModel.setVpnRunning(true)
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
        )
    }
}
