package com.admirepowered.pulse.ui

enum class PulseScreen(val label: String) {
    Dashboard("主页"),
    Profiles("订阅"),
    Proxies("节点"),
    Connections("连接"),
    Settings("设置"),
}

enum class ProxyMode(val label: String) {
    Rule("规则"),
    Global("全局"),
    Direct("直连"),
}

enum class ThemeMode(val label: String) {
    System("跟随系统"),
    Light("浅色"),
    Dark("深色"),
}

data class ProfileItem(
    val id: String,
    val name: String,
    val url: String,
    val path: String,
    val providerCount: Int,
    val ruleCount: Int,
    val updatedAt: String,
)

data class ProxyItem(
    val id: String,
    val name: String,
    val group: String,
    val delayMs: Int?,
    val selected: Boolean,
)

data class ConnectionItem(
    val id: String,
    val host: String,
    val rule: String,
    val download: String,
    val upload: String,
    val speed: String,
)

data class TrafficSnapshot(
    val downloadTotal: String = "0 B",
    val uploadTotal: String = "0 B",
    val downloadSpeed: String = "0 B/s",
    val uploadSpeed: String = "0 B/s",
)

data class PulseAppState(
    val screen: PulseScreen = PulseScreen.Dashboard,
    val vpnRunning: Boolean = false,
    val proxyMode: ProxyMode = ProxyMode.Rule,
    val themeMode: ThemeMode = ThemeMode.System,
    val selectedProfileId: String = "default",
    val selectedProxyId: String = "auto",
    val refreshingProfileId: String? = null,
    val profiles: List<ProfileItem> = emptyList(),
    val proxies: List<ProxyItem> = emptyList(),
    val connections: List<ConnectionItem> = emptyList(),
    val traffic: TrafficSnapshot = TrafficSnapshot(),
    val loadingProxies: Boolean = false,
    val measuringProxies: Boolean = false,
    val measuringProxyId: String? = null,
    val proxyMessage: String = "",
    val loadingConnections: Boolean = false,
    val connectionMessage: String = "",
    val importUrl: String = "",
    val importBusy: Boolean = false,
    val profileMessage: String = "",
    val coreStatus: String = "",
    val allowLan: Boolean = false,
    val proxyUpdateProfiles: Boolean = true,
)
