package com.pulse.proxy.data

data class SubscriptionProfile(
    val id: String,
    val name: String,
    val url: String,
    val fileName: String,
    val type: String = "url"
)

data class EndpointItem(
    val key: String,
    val reference: String,
    val name: String,
    val server: String,
    val type: String
) {
    val title: String
        get() = name.ifBlank { key }
}

data class ConfigUiState(
    val subscriptions: List<SubscriptionProfile> = emptyList(),
    val selectedSubscriptionId: String = "",
    val endpoints: List<EndpointItem> = emptyList(),
    val selectedEndpointKey: String = "",
    val subscriptionUrl: String = "",
    val rulesContent: String = "",
    val visualRules: List<VisualRule> = emptyList(),
    val statusMessage: String = ""
) {
    val selectedSubscription: SubscriptionProfile?
        get() = subscriptions.firstOrNull { it.id == selectedSubscriptionId }
}

enum class RuleActionOption(val value: String, val label: String) {
    Proxy("proxy", "Proxy"),
    Direct("direct", "Direct"),
    Reject("reject", "Reject")
}

enum class RuleConditionOption(val value: String, val label: String) {
    Domain("domains", "Domain"),
    DomainSuffix("domain-suffixes", "Domain suffix"),
    DomainKeyword("domain-keywords", "Keyword"),
    Region("region", "Region")
}

data class VisualRule(
    val id: String,
    val name: String,
    val action: RuleActionOption,
    val condition: RuleConditionOption,
    val value: String,
    val endpoint: String = "",
    val resolve: Boolean = false
)
