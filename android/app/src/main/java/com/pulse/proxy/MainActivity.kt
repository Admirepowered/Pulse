package com.pulse.proxy

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.List
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
import androidx.lifecycle.viewmodel.compose.viewModel
import com.pulse.proxy.service.PulseVpnService
import com.pulse.proxy.ui.MainViewModel
import com.pulse.proxy.ui.screens.ConfigEditorScreen
import com.pulse.proxy.ui.screens.HomeScreen
import com.pulse.proxy.ui.screens.LogScreen
import com.pulse.proxy.ui.theme.PulseTheme

class MainActivity : ComponentActivity() {

    private val vpnRequest = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startService(Intent(this, PulseVpnService::class.java))
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            PulseTheme {
                val viewModel: MainViewModel = viewModel()
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
                                    viewModel.refreshConfig()
                                    selectedTab = 1
                                }
                            )
                            NavigationBarItem(
                                icon = { Icon(Icons.Default.List, contentDescription = null) },
                                label = { Text("Logs") },
                                selected = selectedTab == 2,
                                onClick = { selectedTab = 2 }
                            )
                        }
                    }
                ) { innerPadding ->
                    when (selectedTab) {
                        0 -> HomeScreen(viewModel)
                        1 -> ConfigEditorScreen(
                            viewModel = viewModel,
                            onBack = { selectedTab = 0 }
                        )
                        2 -> LogScreen(
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
        // Handle VPN stop intent
        if (intent.getStringExtra("action") == "stop") {
            val stopIntent = Intent(this, PulseVpnService::class.java).apply {
                putExtra("action", "stop")
            }
            startService(stopIntent)
        }
    }
}
