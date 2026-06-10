package com.admirepowered.pulse.core

import com.admirepowered.pulse.ui.ConnectionItem
import com.admirepowered.pulse.ui.ProviderKind
import com.admirepowered.pulse.ui.LogItem
import com.admirepowered.pulse.ui.ProviderItem
import com.admirepowered.pulse.ui.ProxyGroupItem
import com.admirepowered.pulse.ui.ProxyItem
import com.admirepowered.pulse.ui.ProxyMode
import com.admirepowered.pulse.ui.RuleItem
import com.admirepowered.pulse.ui.TrafficSnapshot
import java.net.SocketTimeoutException
import java.net.HttpURLConnection
import java.net.URLEncoder
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import org.json.JSONObject

data class MihomoConnectionSnapshot(
    val connections: List<ConnectionItem>,
    val memory: String,
)

object PulseMihomoApi {
    private const val BASE_URL = "http://127.0.0.1:9090"
    private const val DEFAULT_DELAY_URL = "https://www.gstatic.com/generate_204"

    fun proxies(): List<ProxyGroupItem> {
        val json = JSONObject(request("GET", "/proxies"))
        val proxies = json.getJSONObject("proxies")
        val result = mutableListOf<ProxyGroupItem>()
        val names = proxies.keys()
        while (names.hasNext()) {
            val groupName = names.next()
            val group = proxies.getJSONObject(groupName)
            val all = group.optJSONArray("all") ?: continue
            val selected = group.optString("now")
            val proxyItems = buildList {
                for (index in 0 until all.length()) {
                    val name = all.getString(index)
                    add(
                        ProxyItem(
                            id = "$groupName|$name",
                            name = name,
                            group = groupName,
                            delayMs = delayFor(proxies.optJSONObject(name)),
                            selected = name == selected,
                        ),
                    )
                }
            }
            result += ProxyGroupItem(
                name = groupName,
                type = group.optString("type", "Selector"),
                selectedName = selected,
                proxies = proxyItems,
            )
        }
        return result
    }

    fun selectProxy(id: String) {
        val parts = id.split("|", limit = 2)
        require(parts.size == 2) { "节点标识无效" }
        val group = URLEncoder.encode(parts[0], Charsets.UTF_8.name())
        val body = JSONObject().put("name", parts[1]).toString()
        request("PUT", "/proxies/$group", body)
    }

    fun testProxyDelays(proxies: List<ProxyItem>, url: String = DEFAULT_DELAY_URL): Int {
        val names = proxies
            .map { it.name }
            .filterNot { it in builtinProxyNames }
            .distinct()
        var measured = 0
        for (name in names) {
            val proxy = URLEncoder.encode(name, Charsets.UTF_8.name())
            val target = URLEncoder.encode(url, Charsets.UTF_8.name())
            runCatching {
                request("GET", "/proxies/$proxy/delay?timeout=3000&url=$target")
                measured++
            }
        }
        return measured
    }

    fun testProxyDelay(proxy: ProxyItem, url: String = DEFAULT_DELAY_URL) {
        require(proxy.name !in builtinProxyNames) { "内置节点无需测速" }
        val name = URLEncoder.encode(proxy.name, Charsets.UTF_8.name())
        val target = URLEncoder.encode(url, Charsets.UTF_8.name())
        request("GET", "/proxies/$name/delay?timeout=3000&url=$target")
    }

    fun setMode(mode: ProxyMode) {
        val mihomoMode = when (mode) {
            ProxyMode.Rule -> "rule"
            ProxyMode.Global -> "global"
            ProxyMode.Direct -> "direct"
        }
        PulseCoreBridge.setMode(mihomoMode).getOrThrow()
    }

    fun version(): String {
        val json = JSONObject(request("GET", "/version"))
        return json.optString("version")
            .ifBlank { json.optString("meta") }
            .ifBlank { "未知版本" }
    }

    fun connections(): List<ConnectionItem> {
        return connectionSnapshot().connections
    }

    fun connectionSnapshot(): MihomoConnectionSnapshot {
        val json = JSONObject(request("GET", "/connections"))
        return MihomoConnectionSnapshot(
            connections = parseConnections(json),
            memory = formatBytes(json.optLong("memory")),
        )
    }

    private fun parseConnections(json: JSONObject): List<ConnectionItem> {
        val connections = json.optJSONArray("connections") ?: return emptyList()
        return buildList {
            for (index in 0 until connections.length()) {
                val connection = connections.getJSONObject(index)
                val metadata = connection.optJSONObject("metadata")
                val host = metadata?.optString("host")?.takeIf { it.isNotBlank() }
                    ?: metadata?.optString("destinationIP")?.takeIf { it.isNotBlank() }
                    ?: connection.optString("id")
                add(
                    run {
                        val downloadBytes = connection.optLong("download")
                        val uploadBytes = connection.optLong("upload")
                        ConnectionItem(
                            id = connection.optString("id", "$index"),
                            host = host,
                            rule = connection.optString("rule", "-"),
                            download = formatBytes(downloadBytes),
                            upload = formatBytes(uploadBytes),
                            destinationIp = metadata?.optString("destinationIP").orEmpty(),
                            source = sourceAddress(metadata),
                            network = metadata?.optString("network").orEmpty(),
                            connectionType = metadata?.optString("type").orEmpty(),
                            process = metadata?.optString("process").orEmpty()
                                .ifBlank { metadata?.optString("processPath").orEmpty() },
                            chains = connection.optJSONArray("chains")?.let { chains ->
                                buildList {
                                    for (chainIndex in 0 until chains.length()) {
                                        chains.optString(chainIndex).takeIf { it.isNotBlank() }?.let(::add)
                                    }
                                }.joinToString(" / ")
                            }.orEmpty(),
                            rulePayload = connection.optString("rulePayload"),
                            start = connection.optString("start"),
                            downloadBytes = downloadBytes,
                            uploadBytes = uploadBytes,
                        )
                    },
                )
            }
        }
    }

    fun closeConnection(id: String) {
        val encoded = URLEncoder.encode(id, Charsets.UTF_8.name())
        request("DELETE", "/connections/$encoded")
    }

    fun closeAllConnections() {
        request("DELETE", "/connections")
    }

    fun rules(): List<RuleItem> {
        val json = JSONObject(request("GET", "/rules"))
        val rules = json.optJSONArray("rules") ?: return emptyList()
        return buildList {
            for (index in 0 until rules.length()) {
                val rule = rules.getJSONObject(index)
                add(
                    RuleItem(
                        type = rule.optString("type"),
                        payload = rule.optString("payload"),
                        proxy = rule.optString("proxy"),
                    ),
                )
            }
        }
    }

    fun providers(): List<ProviderItem> {
        return proxyProviders() + ruleProviders()
    }

    private fun proxyProviders(): List<ProviderItem> {
        val json = JSONObject(request("GET", "/providers/proxies"))
        val providers = json.optJSONObject("providers") ?: return emptyList()
        val rows = mutableListOf<ProviderItem>()
        val names = providers.keys()
        while (names.hasNext()) {
            val key = names.next()
            val provider = providers.getJSONObject(key)
            rows += ProviderItem(
                name = provider.optString("name").ifBlank { key },
                kind = ProviderKind.Proxy,
                vehicle = provider.optString("vehicleType"),
                updatedAt = provider.optString("updatedAt"),
                count = provider.optJSONArray("proxies")?.length() ?: 0,
            )
        }
        return rows
    }

    private fun ruleProviders(): List<ProviderItem> {
        val json = runCatching { JSONObject(request("GET", "/providers/rules")) }.getOrNull()
            ?: return emptyList()
        val providers = json.optJSONObject("providers") ?: return emptyList()
        val rows = mutableListOf<ProviderItem>()
        val names = providers.keys()
        while (names.hasNext()) {
            val key = names.next()
            val provider = providers.getJSONObject(key)
            rows += ProviderItem(
                name = provider.optString("name").ifBlank { key },
                kind = ProviderKind.Rule,
                vehicle = provider.optString("vehicleType"),
                updatedAt = provider.optString("updatedAt"),
                count = provider.optInt("ruleCount").takeIf { it > 0 }
                    ?: provider.optJSONArray("rules")?.length()
                    ?: 0,
            )
        }
        return rows
    }

    fun updateProvider(name: String, kind: ProviderKind = ProviderKind.Proxy) {
        val encoded = URLEncoder.encode(name, Charsets.UTF_8.name()).replace("+", "%20")
        val path = when (kind) {
            ProviderKind.Proxy -> "/providers/proxies/$encoded"
            ProviderKind.Rule -> "/providers/rules/$encoded"
        }
        request("PUT", path)
    }

    fun traffic(): TrafficSnapshot {
        val connection = URL("$BASE_URL/traffic").openConnection() as HttpURLConnection
        connection.connectTimeout = 2_500
        connection.readTimeout = 5_000
        connection.requestMethod = "GET"
        val code = connection.responseCode
        if (code !in 200..299) {
            val text = connection.errorStream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            throw IllegalStateException("mihomo API GET /traffic 返回 $code: $text")
        }
        val line = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readLine() }
        connection.disconnect()
        val json = JSONObject(line.orEmpty())
        val downloadSpeed = json.optLong("down")
        val uploadSpeed = json.optLong("up")
        return TrafficSnapshot(
            downloadTotal = formatBytes(json.optLong("downloadTotal")),
            uploadTotal = formatBytes(json.optLong("uploadTotal")),
            downloadSpeed = "${formatBytes(downloadSpeed)}/s",
            uploadSpeed = "${formatBytes(uploadSpeed)}/s",
            downloadSpeedBytes = downloadSpeed,
            uploadSpeedBytes = uploadSpeed,
        )
    }

    fun logs(level: String = "debug", limit: Int = 80): List<LogItem> {
        val encodedLevel = URLEncoder.encode(level, Charsets.UTF_8.name())
        val connection = URL("$BASE_URL/logs?level=$encodedLevel").openConnection() as HttpURLConnection
        connection.connectTimeout = 2_500
        connection.readTimeout = 1_200
        connection.requestMethod = "GET"
        val code = connection.responseCode
        if (code !in 200..299) {
            val text = connection.errorStream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            connection.disconnect()
            throw IllegalStateException("mihomo API GET /logs 返回 $code: $text")
        }
        val formatter = SimpleDateFormat("MM-dd HH:mm:ss", Locale.getDefault())
        val rows = mutableListOf<LogItem>()
        try {
            connection.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                while (rows.size < limit) {
                    val line = try {
                        reader.readLine()
                    } catch (_: SocketTimeoutException) {
                        null
                    } ?: break
                    val json = runCatching { JSONObject(line) }.getOrNull() ?: continue
                    val logLevel = json.optString("type")
                        .ifBlank { json.optString("level") }
                        .ifBlank { "INFO" }
                        .uppercase(Locale.getDefault())
                    val message = json.optString("payload")
                        .ifBlank { json.optString("message") }
                    if (message.isBlank()) continue
                    rows += LogItem(
                        time = formatter.format(Date()),
                        level = "MIHOMO-$logLevel",
                        message = message,
                        source = "mihomo",
                    )
                }
            }
        } finally {
            connection.disconnect()
        }
        return rows.asReversed()
    }

    private fun delayFor(proxy: JSONObject?): Int? {
        val history = proxy?.optJSONArray("history") ?: return null
        if (history.length() == 0) return null
        val delay = history.optJSONObject(history.length() - 1)?.optInt("delay", -1) ?: -1
        return delay.takeIf { it >= 0 }
    }

    private fun sourceAddress(metadata: JSONObject?): String {
        metadata ?: return ""
        val sourceIp = metadata.optString("sourceIP")
        val sourcePort = metadata.optString("sourcePort")
        return listOf(sourceIp, sourcePort)
            .filter { it.isNotBlank() && it != "0" }
            .joinToString(":")
    }

    private fun formatBytes(value: Long): String {
        val units = arrayOf("B", "KB", "MB", "GB", "TB")
        var size = value.toDouble()
        var index = 0
        while (size >= 1024 && index < units.lastIndex) {
            size /= 1024
            index++
        }
        return if (index == 0) {
            "${size.toLong()} ${units[index]}"
        } else {
            "%.1f %s".format(size, units[index])
        }
    }

    private fun request(method: String, path: String, body: String? = null): String {
        val connection = URL(BASE_URL + path).openConnection() as HttpURLConnection
        connection.connectTimeout = 2_500
        connection.readTimeout = 5_000
        connection.requestMethod = method
        connection.setRequestProperty("Content-Type", "application/json")
        if (body != null) {
            connection.doOutput = true
            connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        }
        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
        if (code !in 200..299) {
            throw IllegalStateException("mihomo API $method $path 返回 $code: $text")
        }
        return text
    }

    private val builtinProxyNames = setOf("DIRECT", "REJECT", "REJECT-DROP", "PASS")
}
