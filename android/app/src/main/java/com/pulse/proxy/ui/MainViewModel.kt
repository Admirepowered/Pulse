package com.pulse.proxy.ui

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.pulse.proxy.config.ConfigManager
import com.pulse.proxy.data.ConfigUiState
import com.pulse.proxy.data.LogEntry
import com.pulse.proxy.data.VisualRule
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

    private val _configUiState = MutableStateFlow(ConfigUiState())
    val configUiState: StateFlow<ConfigUiState> = _configUiState.asStateFlow()

    init {
        refreshConfig()
        refreshConfigurationState()
        startStatusPolling()
    }

    private fun startStatusPolling() {
        viewModelScope.launch {
            while (true) {
                _vpnStatus.value = PulseVpnService.stats()
                _logEntries.value = PulseVpnService.logBuffer.entries.value
                delay(1000L)
            }
        }
    }

    fun refreshConfig() {
        _configContent.value = configManager.readConfig()
        refreshConfigurationState()
    }

    fun saveConfig(content: String) {
        configManager.saveConfig(content)
        refreshConfigurationState()
    }

    fun isVpnRunning(): Boolean = PulseVpnService.isRunning

    fun refreshConfigurationState(message: String = _configUiState.value.statusMessage) {
        val subscriptions = configManager.listSubscriptions()
        val selectedSubscriptionId = configManager.selectedSubscriptionId()
            .ifBlank { subscriptions.firstOrNull()?.id.orEmpty() }
        val endpoints = configManager.listEndpoints(selectedSubscriptionId)
        val savedEndpoint = configManager.selectedEndpointKey()
        val selectedEndpointKey = endpoints.firstOrNull { it.reference == savedEndpoint }?.reference
            ?: endpoints.firstOrNull { it.key == savedEndpoint }?.reference
            ?: endpoints.firstOrNull()?.reference.orEmpty()

        _configUiState.value = _configUiState.value.copy(
            subscriptions = subscriptions,
            selectedSubscriptionId = selectedSubscriptionId,
            endpoints = endpoints,
            selectedEndpointKey = selectedEndpointKey,
            rulesContent = configManager.readRules(),
            visualRules = configManager.readVisualRules(),
            statusMessage = message
        )
    }

    fun setSubscriptionUrl(url: String) {
        _configUiState.value = _configUiState.value.copy(subscriptionUrl = url)
    }

    fun updateSubscription() {
        val url = _configUiState.value.subscriptionUrl
        viewModelScope.launch {
            _configUiState.value = _configUiState.value.copy(statusMessage = "Importing profile from URL...")
            val message = configManager.updateSubscription(url)
            refreshConfigurationState(message)
        }
    }

    fun importProfileFromUri(uri: Uri) {
        viewModelScope.launch {
            _configUiState.value = _configUiState.value.copy(statusMessage = "Importing profile from file...")
            val message = configManager.importProfileFromUri(uri)
            refreshConfigurationState(message)
        }
    }

    fun selectSubscription(id: String) {
        configManager.setSelectedSubscription(id)
        refreshConfigurationState("Config selected")
    }

    fun selectEndpoint(reference: String) {
        configManager.setSelectedEndpoint(reference)
        refreshConfigurationState("Server selected")
    }

    fun saveRules(content: String) {
        configManager.saveRules(content)
        refreshConfigurationState("Rules saved")
    }

    fun addDefaultRules() {
        configManager.appendDefaultRules()
        refreshConfigurationState("Default rules added")
    }

    fun saveVisualRules(rules: List<VisualRule>) {
        configManager.saveVisualRules(rules)
        refreshConfigurationState("Rules saved")
    }
}
