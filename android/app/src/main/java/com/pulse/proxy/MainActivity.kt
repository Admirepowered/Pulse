package com.pulse.proxy

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Rule
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import com.pulse.proxy.service.PulseVpnService
import com.pulse.proxy.ui.MainViewModel
import com.pulse.proxy.ui.screens.ConfigEditorScreen
import com.pulse.proxy.ui.screens.HomeScreen
import com.pulse.proxy.ui.screens.LogScreen
import com.pulse.proxy.ui.screens.RulesScreen
import com.pulse.proxy.ui.theme.PulseTheme

class MainActivity : ComponentActivity() {

    private val vpnPermissionRequest = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            // User granted VPN permission, now start the service
            startVpnService()
        }
    }

    private val notificationPermissionRequest = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ ->
        // Whether granted or not, proceed (notification is best-effort)
        proceedWithVpnStart()
    }

    private var mainViewModel: MainViewModel? = null

    private val profileFileRequest = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            mainViewModel?.importProfileFromUri(uri)
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, PulseVpnService::class.java)
        ContextCompat.startForegroundService(this, intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, PulseVpnService::class.java).apply {
            putExtra("action", "stop")
        }
        startService(intent)
    }

    private fun requestNotificationPermissionIfNeeded(onDone: () -> Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    this, Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionRequest.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        onDone()
    }

    private fun proceedWithVpnStart() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            // Need user consent for VPN permission
            vpnPermissionRequest.launch(prepareIntent)
        } else {
            // Already have VPN permission, start directly
            startVpnService()
        }
    }

    private fun handleStartVpn() {
        // Request notification permission first (Android 13+), then VPN
        requestNotificationPermissionIfNeeded {
            proceedWithVpnStart()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            PulseTheme {
                val viewModel: MainViewModel = viewModel()
                mainViewModel = viewModel
                var selectedTab by rememberSaveable { mutableIntStateOf(0) }

                Scaffold(
                    bottomBar = {
                        NavigationBar {
                            NavigationBarItem(
                                icon = { Icon(Icons.Default.Home, contentDescription = null) },
                                label = { Text("Home") },
                                selected = selectedTab == 0,
                                onClick = { selectedTab = 0 }
                            )
                            NavigationBarItem(
                                icon = { Icon(Icons.Default.Code, contentDescription = null) },
                                label = { Text("Config") },
                                selected = selectedTab == 1,
                                onClick = {
                                    viewModel.refreshConfigurationState()
                                    selectedTab = 1
                                }
                            )
                            NavigationBarItem(
                                icon = { Icon(Icons.Default.Rule, contentDescription = null) },
                                label = { Text("Rules") },
                                selected = selectedTab == 2,
                                onClick = {
                                    viewModel.refreshConfigurationState()
                                    selectedTab = 2
                                }
                            )
                            NavigationBarItem(
                                icon = { Icon(Icons.Default.List, contentDescription = null) },
                                label = { Text("Logs") },
                                selected = selectedTab == 3,
                                onClick = { selectedTab = 3 }
                            )
                        }
                    }
                ) { innerPadding ->
                    when (selectedTab) {
                        0 -> HomeScreen(
                            viewModel = viewModel,
                            onStartVpn = { handleStartVpn() },
                            onStopVpn = { stopVpnService() }
                        )
                        1 -> ConfigEditorScreen(
                            viewModel = viewModel,
                            onImportFile = {
                                profileFileRequest.launch(arrayOf("*/*"))
                            },
                            onBack = { selectedTab = 0 }
                        )
                        2 -> RulesScreen(
                            viewModel = viewModel,
                            onBack = { selectedTab = 0 }
                        )
                        3 -> LogScreen(
                            viewModel = viewModel,
                            onBack = { selectedTab = 0 }
                        )
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.getStringExtra("action") == "stop") {
            stopVpnService()
        }
    }
}
