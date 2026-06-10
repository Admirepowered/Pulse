package com.admirepowered.pulse.ui

enum class PulseScreen(val label: String) {
    Dashboard("主页"),
    Profiles("订阅"),
    Proxies("节点"),
    Connections("连接"),
    Rules("规则"),
    Providers("提供者"),
    ProfileEditor("编辑"),
    CustomRules("自定义规则"),
    Logs("日志"),
    AccessControl("访问控制"),
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

enum class AccessControlMode(val label: String) {
    Off("不限制应用"),
    Include("白名单"),
    Exclude("黑名单"),
}

enum class CoreLogLevel(val value: String, val label: String) {
    Silent("silent", "静默"),
    Error("error", "错误"),
    Warning("warning", "警告"),
    Info("info", "信息"),
    Debug("debug", "调试"),
}

data class ProfileItem(
    val id: String,
    val name: String,
    val url: String,
    val path: String,
    val providerCount: Int,
    val ruleCount: Int,
    val updatedAt: String,
    val subscription: SubscriptionInfoItem = SubscriptionInfoItem(),
)

data class SubscriptionInfoItem(
    val used: String = "",
    val available: String = "",
    val total: String = "",
    val expire: String = "",
    val updateInterval: String = "",
    val percent: Float = 0f,
    val hasData: Boolean = false,
)

data class ProxyItem(
    val id: String,
    val name: String,
    val group: String,
    val delayMs: Int?,
    val selected: Boolean,
)

data class ProxyGroupItem(
    val name: String,
    val type: String,
    val selectedName: String,
    val proxies: List<ProxyItem>,
)

data class ConnectionItem(
    val id: String,
    val host: String,
    val rule: String,
    val download: String,
    val upload: String,
    val destinationIp: String = "",
    val source: String = "",
    val network: String = "",
    val connectionType: String = "",
    val process: String = "",
    val chains: String = "",
    val rulePayload: String = "",
    val start: String = "",
    val closedAt: Long = 0,
    val downloadBytes: Long = 0,
    val uploadBytes: Long = 0,
    val downloadSpeed: String = "0 B/s",
    val uploadSpeed: String = "0 B/s",
    val downloadSpeedBytes: Long = 0,
    val uploadSpeedBytes: Long = 0,
)

data class RuleItem(
    val type: String,
    val payload: String,
    val proxy: String,
)

data class ProviderItem(
    val name: String,
    val kind: ProviderKind,
    val vehicle: String,
    val updatedAt: String,
    val count: Int,
)

enum class ProviderKind(val label: String) {
    Proxy("代理"),
    Rule("规则"),
}

data class AppAccessItem(
    val label: String,
    val packageName: String,
    val selected: Boolean,
    val systemApp: Boolean = false,
)

data class CustomRuleItem(
    val id: String,
    val type: String,
    val payload: String,
    val proxy: String,
    val noResolve: Boolean = false,
)

data class TrafficSnapshot(
    val downloadTotal: String = "0 B",
    val uploadTotal: String = "0 B",
    val downloadSpeed: String = "0 B/s",
    val uploadSpeed: String = "0 B/s",
    val downloadSpeedBytes: Long = 0,
    val uploadSpeedBytes: Long = 0,
    val memory: String = "0 B",
)

data class LogItem(
    val time: String,
    val level: String,
    val message: String,
    val source: String = "Pulse",
)

data class BackgroundImageItem(
    val id: String,
    val name: String,
    val path: String,
)

data class ExternalResourceItem(
    val name: String,
    val status: String,
    val ready: Boolean,
)

data class PulseAppState(
    val screen: PulseScreen = PulseScreen.Dashboard,
    val appVersion: String = "",
    val coreVersion: String = "",
    val vpnRunning: Boolean = false,
    val proxyMode: ProxyMode = ProxyMode.Rule,
    val themeMode: ThemeMode = ThemeMode.System,
    val selectedProfileId: String = "default",
    val selectedProxyId: String = "auto",
    val refreshingProfileId: String? = null,
    val editingProfileId: String? = null,
    val editingProfileName: String = "",
    val editingProfileContent: String = "",
    val loadingProfileContent: Boolean = false,
    val savingProfileContent: Boolean = false,
    val profileEditorMessage: String = "",
    val customRules: List<CustomRuleItem> = emptyList(),
    val customRulePolicies: List<String> = listOf("DIRECT", "REJECT"),
    val loadingCustomRules: Boolean = false,
    val savingCustomRules: Boolean = false,
    val customRuleMessage: String = "",
    val profiles: List<ProfileItem> = emptyList(),
    val proxyGroups: List<ProxyGroupItem> = emptyList(),
    val connections: List<ConnectionItem> = emptyList(),
    val closedConnections: List<ConnectionItem> = emptyList(),
    val traffic: TrafficSnapshot = TrafficSnapshot(),
    val loadingProxies: Boolean = false,
    val measuringProxies: Boolean = false,
    val measuringProxyId: String? = null,
    val measuringProxyGroupName: String? = null,
    val proxyMessage: String = "",
    val loadingConnections: Boolean = false,
    val connectionMessage: String = "",
    val rules: List<RuleItem> = emptyList(),
    val loadingRules: Boolean = false,
    val ruleMessage: String = "",
    val providers: List<ProviderItem> = emptyList(),
    val loadingProviders: Boolean = false,
    val updatingProviderName: String? = null,
    val providerMessage: String = "",
    val logs: List<LogItem> = emptyList(),
    val logMessage: String = "",
    val importUrl: String = "",
    val importBusy: Boolean = false,
    val profileMessage: String = "",
    val coreStatus: String = "",
    val coreRestarting: Boolean = false,
    val coreMessage: String = "",
    val allowLan: Boolean = false,
    val coreLogLevel: CoreLogLevel = CoreLogLevel.Info,
    val accessControlMode: AccessControlMode = AccessControlMode.Off,
    val accessControlApps: List<AppAccessItem> = emptyList(),
    val proxyUpdateProfiles: Boolean = true,
    val autoUpdateProfiles: Boolean = true,
    val autoStartVpn: Boolean = false,
    val delayTestUrl: String = "https://www.gstatic.com/generate_204",
    val backgroundImageUri: String = "",
    val backgrounds: List<BackgroundImageItem> = emptyList(),
    val backgroundOpacityPercent: Int = 28,
    val backgroundBlurDp: Int = 0,
    val updatingExternalResources: Boolean = false,
    val externalResourceMessage: String = "",
    val externalResources: List<ExternalResourceItem> = emptyList(),
    val disableUpdateCheck: Boolean = false,
    val webDavEnabled: Boolean = false,
    val webDavUrl: String = "",
    val webDavUsername: String = "",
    val webDavPassword: String = "",
    val syncingWebDav: Boolean = false,
    val webDavMessage: String = "",
    val checkingUpdate: Boolean = false,
    val updateMessage: String = "",
    val updateReleaseUrl: String = "",
    val updateAvailable: Boolean = false,
    val updateApkAssetName: String = "",
    val updateApkAssetUrl: String = "",
    val downloadingUpdate: Boolean = false,
)
