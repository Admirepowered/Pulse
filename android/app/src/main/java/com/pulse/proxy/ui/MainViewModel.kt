package com.pulse.proxy.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.pulse.proxy.config.ConfigManager
import com.pulse.proxy.data.LogEntry
import com.pulse.proxy.data.VpnStatus
import com.pulse.proxy.service.PulseVpnService
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val configManager = ConfigManager(application)

    private val _vpnStatus = MutableStateFlow(VpnStatus())
    val vpnStatus: StateFlow<VpnStatus> = _vpnStatus.asStateFlow()

    private val _logEntries = MutableStateFlow<List<LogEntry>>(emptyList())
    val logEntries: StateFlow<List<LogEntry>> = _logEntries.asStateFlow()

    private val _configContent = MutableStateFlow("")
    val configContent: StateFlow<String> = _configContent.asStateFlow()

    init {
        refreshConfig()
        startStatusPolling()
    }

    private fun startStatusPolling() {
        viewModelScope.launch {
            while (true) {
                val (running, tx, rx) = PulseVpnService.stats()
                _vpnStatus.value = VpnStatus(
                    running = running,
                    txBytes = tx,
                    rxBytes = rx
                )
                _logEntries.value = PulseVpnService.logBuffer.entries.value
                delay(1000L)
            }
        }
    }

    fun refreshConfig() {
        _configContent.value = configManager.readConfig()
    }

    fun saveConfig(content: String) {
        configManager.saveConfig(content)
    }

    fun isVpnRunning(): Boolean = PulseVpnService.isRunning
}
